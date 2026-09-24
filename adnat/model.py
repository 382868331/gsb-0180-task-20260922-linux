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


class DropReason(enum.Enum):
    """合成包被丢弃的原因（可机读枚举）。"""

    NO_MAPPING = "no_mapping"
    """出站方向找不到活跃映射（translate_outbound 不隐式建映射）。"""

    STALE_GENERATION = "stale_generation"
    """包携带的 generation 与映射当前 generation 不一致（迟到包）。"""

    PEER_MISMATCH = "peer_mismatch"
    """入站包源端点不是该映射记录的对端（地址依赖过滤）。"""

    DEST_MISMATCH = "dest_mismatch"
    """入站包目的地址不是本 NAT 的固定公网 IP。"""


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


# --------------------------------------------------------------------- #
# 复制与接管：有序记录                                                    #
# --------------------------------------------------------------------- #


class JournalKind(enum.Enum):
    """有序记录的事件类型（映射生命周期）。"""

    CREATE = "create"
    """allocate 新建映射（复用已有映射不产生记录）。"""

    REFRESH = "refresh"
    """成功的包改写刷新 last_seen / expires_at。"""

    RELEASE = "release"
    """显式 release 移除映射（过期不进日志，见 README 设计取舍）。"""


class ApplyOutcome(enum.Enum):
    """apply_record 的应用结果。"""

    APPLIED = "applied"
    """新记录：已按序应用并追加到本地日志。"""

    DUPLICATE = "duplicate"
    """重复记录（序号已应用且内容完全一致）：幂等无操作，状态不变。"""


@dataclass(frozen=True, slots=True)
class JournalRecord:
    """一条有序映射生命周期记录（主实例生成，备用实例按序重放）。

    seq:           全局连续序号，从 1 开始，每条日志内无缺口。
    fence:         写入方的栅栏世代（初始 1；promote 后严格递增）。
    kind:          事件类型（CREATE / REFRESH / RELEASE）。
    key:           出站四元组 (内网IP, 内网端口, 目的IP, 目的端口)。
    at:            事件发生的时钟时刻（重放时驱动备用做同样的 housekeeping）。
    external_port: 映射的外端口（RELEASE 时为被释放的端口）。
    generation:    映射的 generation。
    expires_at:    CREATE/REFRESH 为新的过期时刻；RELEASE 固定为 None。
    """

    seq: int
    fence: int
    kind: JournalKind
    key: tuple[str, int, str, int]
    at: int
    external_port: int
    generation: int
    expires_at: int | None

    def __post_init__(self) -> None:
        check_int(self.seq, "JournalRecord.seq", minimum=1, maximum=MAX_TIME)
        check_int(self.fence, "JournalRecord.fence", minimum=1, maximum=MAX_TIME)
        if not isinstance(self.kind, JournalKind):
            raise ValidationError(
                f"JournalRecord.kind must be JournalKind, "
                f"got {type(self.kind).__name__} {self.kind!r}"
            )
        if not (isinstance(self.key, tuple) and len(self.key) == 4):
            raise ValidationError(
                f"JournalRecord.key must be (ip, port, ip, port) tuple, "
                f"got {self.key!r}"
            )
        check_ipv4(self.key[0], "JournalRecord.key[0] (internal ip)")
        check_port(self.key[1], "JournalRecord.key[1] (internal port)")
        check_ipv4(self.key[2], "JournalRecord.key[2] (remote ip)")
        check_port(self.key[3], "JournalRecord.key[3] (remote port)")
        check_int(self.at, "JournalRecord.at", minimum=0, maximum=MAX_TIME)
        check_port(self.external_port, "JournalRecord.external_port")
        check_int(self.generation, "JournalRecord.generation",
                  minimum=1, maximum=MAX_TIME)
        if self.kind is JournalKind.RELEASE:
            if self.expires_at is not None:
                raise ValidationError(
                    f"RELEASE record must have expires_at=None, "
                    f"got {self.expires_at!r}"
                )
        else:
            if self.expires_at is None:
                raise ValidationError(
                    f"{self.kind.name} record requires expires_at, got None"
                )
            check_int(self.expires_at, "JournalRecord.expires_at",
                      minimum=1, maximum=MAX_TIME)
            if self.expires_at <= self.at:
                raise ValidationError(
                    f"JournalRecord.expires_at={self.expires_at} must be "
                    f"> at={self.at}"
                )
