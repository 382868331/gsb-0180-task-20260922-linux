"""公开数据结构（冻结值对象）与配置。

所有字段均为严格整数 / 点分十进制 IPv4 字符串；构造时即校验，
非法输入抛 ValidationError，不静默纠正。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from ._validate import check_int, check_ipv4, check_port
from .errors import ValidationError

#: 时间与计数类整数的统一上限（含），避免无界整数被误用。
MAX_TIME = 2**63 - 1
#: 单批出站分配请求数上限（题面接口边界）。
MAX_BATCH_REQUESTS = 65535
#: 端口池容量上限（端口空间本身只有 65535 个可用端口）。
MAX_POOL_SIZE = 65535

_PROTOCOL_UDP = 17
_PROTOCOL_ICMP = 1


class DropReason(enum.Enum):
    """合成包被丢弃的原因（可机读枚举）。"""

    NO_MAPPING = "no_mapping"
    """出站方向找不到活跃映射（translate_outbound 不隐式建映射）。"""

    STALE_GENERATION = "stale_generation"
    """包携带的 generation 与映射当前 generation 不一致（迟到包）。"""

    PEER_MISMATCH = "peer_mismatch"
    """源/引用端点不是该公网端口映射记录的对端（地址依赖过滤）。"""

    DEST_MISMATCH = "dest_mismatch"
    """入站包目的地址不是本 NAT 的固定公网 IP。"""

    QUOTE_NOT_UDP = "quote_not_udp"
    """差错报文引用的原包不是 UDP（本库只按 UDP 映射做反向定位）。"""

    QUOTE_MALFORMED = "quote_malformed"
    """差错报文引用元组结构不完整，或引用的外层方向自相矛盾。"""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """IP:端口 端点。"""

    ip: str
    port: int

    def __post_init__(self) -> None:
        check_ipv4(self.ip, "Endpoint.ip")
        check_port(self.port, "Endpoint.port")


@dataclass(frozen=True, slots=True)
class FiveTuple:
    """改写后的五元组（本库只处理 UDP，protocol 固定 17）。"""

    protocol: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    def __post_init__(self) -> None:
        check_int(self.protocol, "FiveTuple.protocol", minimum=0, maximum=255)
        check_ipv4(self.src_ip, "FiveTuple.src_ip")
        check_port(self.src_port, "FiveTuple.src_port")
        check_ipv4(self.dst_ip, "FiveTuple.dst_ip")
        check_port(self.dst_port, "FiveTuple.dst_port")


@dataclass(frozen=True, slots=True)
class Packet:
    """合成 UDP 包。generation 为发送方观测到的映射代数，用于拒绝迟到包。

    不知道 generation 时传 0，表示"不参与代数校验"（按当前映射处理）。
    """

    src: Endpoint
    dst: Endpoint
    generation: int = 0
    payload: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.src, Endpoint):
            raise ValidationError(
                f"Packet.src must be Endpoint, got {type(self.src).__name__}"
            )
        if not isinstance(self.dst, Endpoint):
            raise ValidationError(
                f"Packet.dst must be Endpoint, got {type(self.dst).__name__}"
            )
        check_int(self.generation, "Packet.generation", minimum=0, maximum=MAX_TIME)
        if not isinstance(self.payload, (bytes, bytearray)):
            raise ValidationError(
                f"Packet.payload must be bytes, got {type(self.payload).__name__}"
            )


@dataclass(frozen=True, slots=True)
class ErrorPacket:
    """题内合成差错报文（ICMP 风格，protocol=1），不做真实协议栈。

    结构（题面明确给出的最小结构）::

        outer:     差错报文本身的外层端点
                     outer.src = 发出差错报文的网络设备
                     outer.dst = 本机公网端点（IP + 外端口）
        quoted:    被引用的原 UDP 数据报（NAT 重写后的公网侧五元组）
                     quoted.src = 本机公网端点（IP + 外端口）
                     quoted.dst = 原远端端点
                     quoted.protocol 必须为 UDP(17)
        generation: 创建映射时返回的世代标记。0 表示该合成入口不提供
                     世代标记（见 translate_error 的限制说明）。

    字段类型/取值非法抛 ValidationError；结构完整但无法定位映射的
    语义问题在 translate_error 中给出 DropReason。
    """

    outer_src: Endpoint
    outer_dst: Endpoint
    quoted_src: Endpoint
    quoted_dst: Endpoint
    quoted_protocol: int = _PROTOCOL_UDP
    generation: int = 0
    payload: bytes = b""

    def __post_init__(self) -> None:
        for name, ep in (("outer_src", self.outer_src),
                         ("outer_dst", self.outer_dst),
                         ("quoted_src", self.quoted_src),
                         ("quoted_dst", self.quoted_dst)):
            if not isinstance(ep, Endpoint):
                raise ValidationError(
                    f"ErrorPacket.{name} must be Endpoint, "
                    f"got {type(ep).__name__}"
                )
        check_int(self.quoted_protocol, "ErrorPacket.quoted_protocol",
                  minimum=0, maximum=255)
        check_int(self.generation, "ErrorPacket.generation",
                  minimum=0, maximum=MAX_TIME)
        if not isinstance(self.payload, (bytes, bytearray)):
            raise ValidationError(
                f"ErrorPacket.payload must be bytes, "
                f"got {type(self.payload).__name__}"
            )


@dataclass(frozen=True, slots=True)
class Mapping:
    """一条地址依赖映射的只读快照。

    key 即出站四元组 (内网IP, 内网端口, 目的IP, 目的端口)。
    expires_at == now 时映射已过期（严格大于才存活）。
    """

    key: tuple[str, int, str, int]
    internal: Endpoint
    remote: Endpoint
    external_port: int
    generation: int
    created_at: int
    last_seen: int
    expires_at: int

    def is_live(self, now: int) -> bool:
        check_int(now, "now", minimum=0, maximum=MAX_TIME)
        return now < self.expires_at


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    """批量出站分配的一项：一个出站四元组。"""

    internal: Endpoint
    remote: Endpoint

    def __post_init__(self) -> None:
        if not isinstance(self.internal, Endpoint):
            raise ValidationError(
                f"AllocationRequest.internal must be Endpoint, "
                f"got {type(self.internal).__name__}"
            )
        if not isinstance(self.remote, Endpoint):
            raise ValidationError(
                f"AllocationRequest.remote must be Endpoint, "
                f"got {type(self.remote).__name__}"
            )

    @property
    def key(self) -> tuple[str, int, str, int]:
        return (self.internal.ip, self.internal.port, self.remote.ip, self.remote.port)


@dataclass(frozen=True, slots=True)
class AllocationResult:
    """分配结果：mapping 为该 key 当前生效的映射（新建或复用）。"""

    key: tuple[str, int, str, int]
    mapping: Mapping
    created: bool
    """True=本次新建并占用端口；False=复用已存在的活跃映射。"""


@dataclass(frozen=True, slots=True)
class TranslationResult:
    """改写结果。accepted=False 时 rewritten 为 None，reason 给出丢弃原因。"""

    accepted: bool
    rewritten: FiveTuple | None
    reason: DropReason | None
    mapping: Mapping | None


@dataclass(frozen=True, slots=True)
class ErrorTranslationResult:
    """差错报文反向定位结果。

    accepted=True 时：
        outer_target: 差错报文改写后应投递的外层目标（内部端点），
                      五元组 protocol 固定为 ICMP(1)；
        quoted:      原样回显的被引用 UDP 五元组（protocol=17）；
        mapping_id:  采用映射的 ID（即该映射创建时返回的世代标记
                      generation，全局唯一、单调递增）。
    accepted=False 时 reason 为 DropReason，其余字段为 None。

    差错报文永不创建映射、不刷新 last_seen/expires_at。
    """

    accepted: bool
    outer_target: FiveTuple | None
    quoted: FiveTuple | None
    mapping_id: int | None
    reason: DropReason | None
    mapping: Mapping | None


@dataclass(frozen=True, slots=True)
class NATConfig:
    """NAT 实例配置（构造后不可变）。

    external_ports: 有限外端口池，可乱序给出，内部按升序去重；
                    分配时总是选当前最小的空闲端口。
    lifetime:       映射空闲存活时间（整数时间单位），>= 1。
    quarantine:     端口释放后的隔离时长 Q，期间不可复用，>= 0。
    search_budget:  单次分配最多检查的端口数，>= 1；默认等于池大小（全池扫描）。
    """

    public_ip: str
    external_ports: tuple[int, ...]
    lifetime: int = 300
    quarantine: int = 60
    search_budget: int | None = None

    def __post_init__(self) -> None:
        check_ipv4(self.public_ip, "NATConfig.public_ip")
        if isinstance(self.external_ports, (str, bytes)) or not isinstance(
            self.external_ports, (tuple, list)
        ):
            raise ValidationError(
                f"NATConfig.external_ports must be a tuple/list of ints, "
                f"got {type(self.external_ports).__name__}"
            )
        if len(self.external_ports) == 0:
            raise ValidationError("NATConfig.external_ports must be non-empty")
        if len(self.external_ports) > MAX_POOL_SIZE:
            raise ValidationError(
                f"NATConfig.external_ports length {len(self.external_ports)} "
                f"exceeds MAX_POOL_SIZE={MAX_POOL_SIZE}"
            )
        checked = [check_port(p, f"NATConfig.external_ports[{i}]")
                   for i, p in enumerate(self.external_ports)]
        if len(set(checked)) != len(checked):
            raise ValidationError("NATConfig.external_ports contains duplicates")
        object.__setattr__(self, "external_ports", tuple(sorted(checked)))

        check_int(self.lifetime, "NATConfig.lifetime", minimum=1, maximum=MAX_TIME)
        check_int(self.quarantine, "NATConfig.quarantine", minimum=0, maximum=MAX_TIME)
        if self.search_budget is None:
            object.__setattr__(self, "search_budget", len(checked))
        else:
            check_int(self.search_budget, "NATConfig.search_budget",
                      minimum=1, maximum=MAX_TIME)


def udp_five_tuple(src: Endpoint, dst: Endpoint) -> FiveTuple:
    """由两个端点构造 UDP 五元组。"""
    return FiveTuple(
        protocol=_PROTOCOL_UDP,
        src_ip=src.ip, src_port=src.port,
        dst_ip=dst.ip, dst_port=dst.port,
    )
