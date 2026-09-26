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

    FRAGMENT_OVERLAP_CONFLICT = "fragment_overlap_conflict"
    """同一片组内重叠区域字节不一致（或与已知总长矛盾），整组拒绝。"""

    FRAGMENT_TOO_LONG = "fragment_too_long"
    """重组后的总长度超过 max_datagram_size，整组拒绝。"""

    FRAGMENT_TOO_MANY = "fragment_too_many"
    """片组内分片数超过 max_fragments，整组拒绝。"""

    FRAGMENT_CACHE_FULL = "fragment_cache_full"
    """全实例分片缓存字节达到 max_cached_bytes，整组拒绝。"""


class Direction(enum.Enum):
    """分片数据报的方向。"""

    OUTBOUND = "outbound"
    """内网 -> 公网。"""

    INBOUND = "inbound"
    """公网 -> 内网。"""


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


#: IP 数据报 ID 为 16 位字段。
MAX_DATAGRAM_ID = 65535


@dataclass(frozen=True, slots=True)
class Fragment:
    """一个 UDP 数据报的分片（合成输入，非真实抓包）。

    同一数据报的所有片由 (direction, src_ip, dst_ip, protocol,
    datagram_id) 关联；非首片没有端口号，不能据此猜测映射。

    offset:        片内首字节在原始载荷中的字节偏移，必须是 8 的倍数。
    more_fragments: True 表示后面还有片；False 表示这是最后一片。
    src_port/dst_port: 仅首片（offset == 0）携带 UDP 端口；非首片必须为 None。
    """

    direction: Direction
    src_ip: str
    dst_ip: str
    protocol: int
    datagram_id: int
    offset: int
    more_fragments: bool
    payload: bytes
    src_port: int | None = None
    dst_port: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.direction, Direction):
            raise ValidationError(
                f"Fragment.direction must be Direction, "
                f"got {type(self.direction).__name__}"
            )
        check_ipv4(self.src_ip, "Fragment.src_ip")
        check_ipv4(self.dst_ip, "Fragment.dst_ip")
        check_int(self.protocol, "Fragment.protocol", minimum=0, maximum=255)
        if self.protocol != _PROTOCOL_UDP:
            raise ValidationError(
                f"Fragment.protocol must be 17 (UDP), got {self.protocol}"
            )
        check_int(self.datagram_id, "Fragment.datagram_id",
                  minimum=0, maximum=MAX_DATAGRAM_ID)
        check_int(self.offset, "Fragment.offset", minimum=0, maximum=MAX_TIME)
        if self.offset % 8 != 0:
            raise ValidationError(
                f"Fragment.offset={self.offset} must be a multiple of 8"
            )
        if not isinstance(self.more_fragments, bool):
            raise ValidationError(
                f"Fragment.more_fragments must be bool, "
                f"got {type(self.more_fragments).__name__}"
            )
        if not isinstance(self.payload, (bytes, bytearray)):
            raise ValidationError(
                f"Fragment.payload must be bytes, "
                f"got {type(self.payload).__name__}"
            )
        if len(self.payload) == 0:
            raise ValidationError("Fragment.payload must be non-empty")
        if self.more_fragments and len(self.payload) % 8 != 0:
            raise ValidationError(
                f"non-last Fragment.payload length {len(self.payload)} "
                f"must be a multiple of 8"
            )
        if self.offset == 0:
            if self.src_port is None or self.dst_port is None:
                raise ValidationError(
                    "first fragment (offset=0) must carry src_port/dst_port"
                )
            check_port(self.src_port, "Fragment.src_port")
            check_port(self.dst_port, "Fragment.dst_port")
        else:
            if self.src_port is not None or self.dst_port is not None:
                raise ValidationError(
                    "non-first fragment must not carry ports "
                    "(ports live only in the first fragment)"
                )

    @property
    def end(self) -> int:
        """本片覆盖区间的开区间右端（字节偏移）。"""
        return self.offset + len(self.payload)


@dataclass(frozen=True, slots=True)
class FragmentResult:
    """分片处理结果。

    accepted=True, complete=False: 片已暂存，数据报尚未齐。
    accepted=True, complete=True:  数据报齐全，rewritten 为按偏移升序、
                                   地址（首片含端口）已改写的全部片；
                                   关联状态已释放，同 ID 可安全复用。
    accepted=False: 整组被拒绝并释放，reason 给出原因。
    """

    accepted: bool
    complete: bool
    rewritten: tuple[Fragment, ...] | None
    reason: DropReason | None
    mapping: Mapping | None


@dataclass(frozen=True, slots=True)
class FragmentationConfig:
    """分片重组的资源上限（构造后不可变）。

    max_datagram_size: 单个数据报重组后总长度上限（字节）。
    max_fragments:     单个片组最多暂存的片数。
    max_cached_bytes:  全实例所有片组暂存字节总量上限。
    fragment_timeout:  片组逻辑超时（整数时间单位），从首片入缓存起算，
                       now >= created_at + timeout 时整组过期释放。
    """

    max_datagram_size: int = 65535
    max_fragments: int = 64
    max_cached_bytes: int = 262144
    fragment_timeout: int = 30

    def __post_init__(self) -> None:
        check_int(self.max_datagram_size,
                  "FragmentationConfig.max_datagram_size",
                  minimum=1, maximum=MAX_TIME)
        check_int(self.max_fragments, "FragmentationConfig.max_fragments",
                  minimum=1, maximum=MAX_TIME)
        check_int(self.max_cached_bytes,
                  "FragmentationConfig.max_cached_bytes",
                  minimum=1, maximum=MAX_TIME)
        check_int(self.fragment_timeout,
                  "FragmentationConfig.fragment_timeout",
                  minimum=1, maximum=MAX_TIME)
