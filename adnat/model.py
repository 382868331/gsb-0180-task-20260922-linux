"""公开数据结构（冻结值对象）与配置。

所有字段均为严格整数 / 点分十进制 IPv4 字符串；构造时即校验，
非法输入抛 ValidationError，不静默纠正。

多租户
------
``NATConfig(tenants=(TenantConfig(...), ...))`` 显式给出租户表后：

- 映射身份为 ``(tenant_id, 内网IP, 内网端口, 目的IP, 目的端口)``：不同
  租户即使内网四元组完全相同也互不撞映射、互不撞外端口；
- 每个租户只在自己的 ``external_ports`` 子集内按最小可用端口分配，
  子集互不重叠且只能取自 NAT 的总端口池；
- ``max_active_mappings`` 限制该租户候选时刻回收过期映射后的活跃映射数。

不传 ``tenants`` 时只有一个内部默认租户（拥有整个端口池、无额外配额），
旧接口签名与行为与单租户基线完全一致。
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

    身份为 (tenant, key)：tenant 为租户 ID（默认租户见
    ``adnat.core.DEFAULT_TENANT_ID``），key 是租户内出站四元组
    (内网IP, 内网端口, 目的IP, 目的端口)。expires_at == now 时映射已
    过期（严格大于才存活）。
    """

    key: tuple[str, int, str, int]
    internal: Endpoint
    remote: Endpoint
    external_port: int
    generation: int
    created_at: int
    last_seen: int
    expires_at: int
    tenant: str

    def is_live(self, now: int) -> bool:
        check_int(now, "now", minimum=0, maximum=MAX_TIME)
        return now < self.expires_at


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    """单租户批量出站分配的一项：一个出站四元组（租户由方法参数给出）。"""

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
class TenantAllocationRequest:
    """跨租户批量出站分配的一项：显式带上目标租户 ID。"""

    tenant_id: str
    internal: Endpoint
    remote: Endpoint

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not self.tenant_id:
            raise ValidationError(
                "TenantAllocationRequest.tenant_id must be a non-empty str, "
                f"got {self.tenant_id!r}"
            )
        if not isinstance(self.internal, Endpoint):
            raise ValidationError(
                f"TenantAllocationRequest.internal must be Endpoint, "
                f"got {type(self.internal).__name__}"
            )
        if not isinstance(self.remote, Endpoint):
            raise ValidationError(
                f"TenantAllocationRequest.remote must be Endpoint, "
                f"got {type(self.remote).__name__}"
            )

    @property
    def key(self) -> tuple[str, int, str, int]:
        return (self.internal.ip, self.internal.port, self.remote.ip, self.remote.port)


@dataclass(frozen=True, slots=True)
class AllocationResult:
    """分配结果：mapping 为该 (tenant, key) 当前生效的映射（新建或复用）。"""

    key: tuple[str, int, str, int]
    mapping: Mapping
    created: bool
    """True=本次新建并占用端口；False=复用已存在的活跃映射。"""
    tenant: str
    """本结果所属租户 ID。"""


@dataclass(frozen=True, slots=True)
class TranslationResult:
    """改写结果。accepted=False 时 rewritten 为 None，reason 给出丢弃原因。

    tenant 为命中映射所属租户：定位到映射（含代数不符 / 对端不符）时
    一定带回；连映射都没定位到（NO_MAPPING / DEST_MISMATCH）为 None。
    """

    accepted: bool
    rewritten: FiveTuple | None
    reason: DropReason | None
    mapping: Mapping | None
    tenant: str | None


@dataclass(frozen=True, slots=True)
class TenantConfig:
    """单个租户的固定配置（租户表构造后不可变）。

    tenant_id:           非空字符串 ID；租户表内不得重复。
    external_ports:      该租户独占的外端口子集，可乱序给出，内部升序
                         去重；必须是 NATConfig.external_ports 的子集，
                         且与其他租户子集不重叠。
    max_active_mappings: 候选时刻回收过期映射后，该租户活跃映射数上限，
                         >= 1（复用已有映射不占用配额）。
    """

    tenant_id: str
    external_ports: tuple[int, ...]
    max_active_mappings: int

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not self.tenant_id:
            raise ValidationError(
                f"TenantConfig.tenant_id must be a non-empty str, "
                f"got {self.tenant_id!r}"
            )
        if isinstance(self.external_ports, (str, bytes)) or not isinstance(
            self.external_ports, (tuple, list)
        ):
            raise ValidationError(
                f"TenantConfig.external_ports must be a tuple/list of ints, "
                f"got {type(self.external_ports).__name__}"
            )
        if len(self.external_ports) == 0:
            raise ValidationError(
                f"TenantConfig {self.tenant_id!r}: external_ports must be non-empty"
            )
        if len(self.external_ports) > MAX_POOL_SIZE:
            raise ValidationError(
                f"TenantConfig {self.tenant_id!r}: external_ports length "
                f"{len(self.external_ports)} exceeds MAX_POOL_SIZE={MAX_POOL_SIZE}"
            )
        checked = [
            check_port(p, f"TenantConfig[{self.tenant_id!r}].external_ports[{i}]")
            for i, p in enumerate(self.external_ports)
        ]
        if len(set(checked)) != len(checked):
            raise ValidationError(
                f"TenantConfig {self.tenant_id!r}: external_ports contains duplicates"
            )
        object.__setattr__(self, "external_ports", tuple(sorted(checked)))
        check_int(
            self.max_active_mappings,
            f"TenantConfig[{self.tenant_id!r}].max_active_mappings",
            minimum=1, maximum=MAX_POOL_SIZE,
        )


@dataclass(frozen=True, slots=True)
class NATConfig:
    """NAT 实例配置（构造后不可变）。

    external_ports: 有限外端口总池，可乱序给出，内部按升序去重；
                    分配时总是选当前最小的空闲端口。
    lifetime:       映射空闲存活时间（整数时间单位），>= 1。
    quarantine:     端口释放后的隔离时长 Q，期间不可复用，>= 0。
    search_budget:  每次分配调用最多检查的端口数，>= 1；跨租户批量中
                    在所有租户子集间共享计数；默认等于总池大小。
    tenants:        显式租户表；None = 单租户（默认租户独占全池，无配额）。
                    表内 ID 不重复、子集互不重叠且全部取自 external_ports，
                    否则 NATConfig 构造整体失败（ValidationError）。
    """

    public_ip: str
    external_ports: tuple[int, ...]
    lifetime: int = 300
    quarantine: int = 60
    search_budget: int | None = None
    tenants: tuple[TenantConfig, ...] | None = None

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
        pool = tuple(sorted(checked))
        object.__setattr__(self, "external_ports", pool)

        check_int(self.lifetime, "NATConfig.lifetime", minimum=1, maximum=MAX_TIME)
        check_int(self.quarantine, "NATConfig.quarantine", minimum=0, maximum=MAX_TIME)
        if self.search_budget is None:
            object.__setattr__(self, "search_budget", len(checked))
        else:
            check_int(self.search_budget, "NATConfig.search_budget",
                      minimum=1, maximum=MAX_TIME)

        # ---- 租户表整体校验：重复 ID / 子集重叠 / 越界任一即整体拒绝 ----
        if self.tenants is not None:
            if isinstance(self.tenants, (str, bytes)) or not isinstance(
                self.tenants, (tuple, list)
            ):
                raise ValidationError(
                    "NATConfig.tenants must be a tuple/list of TenantConfig, "
                    f"got {type(self.tenants).__name__}"
                )
            if len(self.tenants) == 0:
                raise ValidationError(
                    "NATConfig.tenants must be non-empty when provided"
                )
            for i, t in enumerate(self.tenants):
                if not isinstance(t, TenantConfig):
                    raise ValidationError(
                        f"NATConfig.tenants[{i}] must be TenantConfig, "
                        f"got {type(t).__name__}"
                    )
            ids = [t.tenant_id for t in self.tenants]
            if len(set(ids)) != len(ids):
                dupes = sorted({x for x in ids if ids.count(x) > 1})
                raise ValidationError(
                    f"NATConfig.tenants contains duplicate tenant ids: {dupes}"
                )
            pool_set = set(pool)
            claimed: set[int] = set()
            for t in self.tenants:
                for p in t.external_ports:
                    if p not in pool_set:
                        raise ValidationError(
                            f"TenantConfig {t.tenant_id!r}: port {p} is outside "
                            f"NATConfig.external_ports"
                        )
                    if p in claimed:
                        raise ValidationError(
                            f"TenantConfig {t.tenant_id!r}: port {p} overlaps "
                            f"another tenant's subset"
                        )
                    claimed.add(p)
            object.__setattr__(self, "tenants", tuple(self.tenants))


def udp_five_tuple(src: Endpoint, dst: Endpoint) -> FiveTuple:
    """由两个端点构造 UDP 五元组。"""
    return FiveTuple(
        protocol=_PROTOCOL_UDP,
        src_ip=src.ip, src_port=src.port,
        dst_ip=dst.ip, dst_port=dst.port,
    )
