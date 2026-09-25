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

#: 不传租户配置时的隐式默认租户 ID（旧接口固定作用于它）。
DEFAULT_TENANT = "default"

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

    UNKNOWN_TENANT = "unknown_tenant"
    """入站包外端口不属于任何已配置租户（无映射的一种细分）。"""


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

    映射身份 = (tenant, key)：tenant 为租户 ID，key 为租户内的出站四元组
    (内网IP, 内网端口, 目的IP, 目的端口)。不同租户允许出现完全相同的 key，
    它们是互不相关的两条映射，外端口也一定不同（租户子池互不重叠）。
    expires_at == now 时映射已过期（严格大于才存活）。
    """

    tenant: str
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
    """批量出站分配的一项：一个出站四元组（租户在调用处指定）。"""

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
class TenantRequest:
    """跨租户批量分配的一项：显式租户 ID + 一个出站四元组。"""

    tenant_id: str
    internal: Endpoint
    remote: Endpoint

    def __post_init__(self) -> None:
        check_tenant_id(self.tenant_id, "TenantRequest.tenant_id")
        if not isinstance(self.internal, Endpoint):
            raise ValidationError(
                f"TenantRequest.internal must be Endpoint, "
                f"got {type(self.internal).__name__}"
            )
        if not isinstance(self.remote, Endpoint):
            raise ValidationError(
                f"TenantRequest.remote must be Endpoint, "
                f"got {type(self.remote).__name__}"
            )

    @property
    def key(self) -> tuple[str, int, str, int]:
        return (self.internal.ip, self.internal.port, self.remote.ip, self.remote.port)


@dataclass(frozen=True, slots=True)
class AllocationResult:
    """分配结果：mapping 为该身份当前生效的映射（新建或复用）。"""

    tenant: str
    key: tuple[str, int, str, int]
    mapping: Mapping
    created: bool
    """True=本次新建并占用端口；False=复用已存在的活跃映射（不占配额）。"""


@dataclass(frozen=True, slots=True)
class TranslationResult:
    """改写结果。accepted=False 时 rewritten 为 None，reason 给出丢弃原因。

    tenant 给出命中映射所属租户；入站由外端口反查得到，出站沿用调用参数。
    未命中任何映射（DEST_MISMATCH / NO_MAPPING / UNKNOWN_TENANT）时为 None。
    """

    accepted: bool
    rewritten: FiveTuple | None
    reason: DropReason | None
    mapping: Mapping | None
    tenant: str | None = None


@dataclass(frozen=True, slots=True)
class TenantConfig:
    """一个租户的静态配置（构造后不可变）。

    tenant_id:       非空字符串，租户表内唯一。
    external_ports:  该租户专用的外端口子集；可乱序给出，内部升序去重。
    max_mappings:    最大活跃映射数（>=1）；None 表示不限——仅隐式默认租户
                     使用，显式租户表中不允许 None。
    """

    tenant_id: str
    external_ports: tuple[int, ...]
    max_mappings: int | None = None

    def __post_init__(self) -> None:
        check_tenant_id(self.tenant_id, "TenantConfig.tenant_id")
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
        checked = [check_port(p, f"TenantConfig {self.tenant_id!r}.external_ports[{i}]")
                   for i, p in enumerate(self.external_ports)]
        if len(set(checked)) != len(checked):
            raise ValidationError(
                f"TenantConfig {self.tenant_id!r}: external_ports contains duplicates"
            )
        object.__setattr__(self, "external_ports", tuple(sorted(checked)))
        if self.max_mappings is not None:
            check_int(self.max_mappings,
                      f"TenantConfig {self.tenant_id!r}.max_mappings",
                      minimum=1, maximum=MAX_POOL_SIZE)


def check_tenant_id(value: object, name: str) -> str:
    """租户 ID 必须是非空字符串（不做 strip/规范化，空白也是合法字符）。"""
    if not isinstance(value, str):
        raise ValidationError(
            f"{name} must be non-empty str, got {type(value).__name__} {value!r}"
        )
    if len(value) == 0:
        raise ValidationError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True, slots=True)
class NATConfig:
    """NAT 实例配置（构造后不可变）。

    external_ports: 总外端口池，可乱序给出，内部按升序去重；
                    分配时总是选当前最小的空闲端口。
    lifetime:       映射空闲存活时间（整数时间单位），>= 1。
    quarantine:     端口释放后的隔离时长 Q，期间不可复用，>= 0。
    search_budget:  单次分配中每个租户最多检查的端口数，>= 1；
                    默认等于总池大小（全池扫描）。
    tenants:        显式租户表；None（默认）= 单个隐式默认租户，独占总池且
                    无活跃配额——旧接口行为与基线完全一致。显式给出时：
                    每个租户有非空唯一 ID、非空端口子集与有限配额，子集两两
                    不重叠且只能取自 external_ports；任一规则违反则整体拒绝。
                    租户表构造后固定，不支持在线迁移。
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
        total_pool = tuple(sorted(checked))
        object.__setattr__(self, "external_ports", total_pool)

        check_int(self.lifetime, "NATConfig.lifetime", minimum=1, maximum=MAX_TIME)
        check_int(self.quarantine, "NATConfig.quarantine", minimum=0, maximum=MAX_TIME)
        if self.search_budget is None:
            object.__setattr__(self, "search_budget", len(checked))
        else:
            check_int(self.search_budget, "NATConfig.search_budget",
                      minimum=1, maximum=MAX_TIME)

        if self.tenants is None:
            object.__setattr__(self, "tenants", (
                TenantConfig(DEFAULT_TENANT, total_pool, None),
            ))
            return
        self._validate_tenants(total_pool)

    def _validate_tenants(self, total_pool: tuple[int, ...]) -> None:
        tenants = self.tenants
        if isinstance(tenants, (str, bytes)) or not isinstance(tenants, (tuple, list)):
            raise ValidationError(
                f"NATConfig.tenants must be a tuple/list of TenantConfig, "
                f"got {type(tenants).__name__}"
            )
        if len(tenants) == 0:
            raise ValidationError("NATConfig.tenants must be non-empty when given")
        for i, t in enumerate(tenants):
            if not isinstance(t, TenantConfig):
                raise ValidationError(
                    f"NATConfig.tenants[{i}] must be TenantConfig, "
                    f"got {type(t).__name__}"
                )
        ids = [t.tenant_id for t in tenants]
        if len(set(ids)) != len(ids):
            dupes = sorted({x for x in ids if ids.count(x) > 1})
            raise ValidationError(
                f"NATConfig.tenants contains duplicate tenant ids: {dupes}"
            )
        pool_set = set(total_pool)
        seen: set[int] = set()
        for t in tenants:
            if t.max_mappings is None:
                raise ValidationError(
                    f"tenant {t.tenant_id!r}: max_mappings is required "
                    f"(unlimited is only allowed for the implicit default tenant)"
                )
            overlap = seen.intersection(t.external_ports)
            if overlap:
                raise ValidationError(
                    f"tenant {t.tenant_id!r}: ports overlap with other "
                    f"tenants: {sorted(overlap)}"
                )
            out_of_pool = [p for p in t.external_ports if p not in pool_set]
            if out_of_pool:
                raise ValidationError(
                    f"tenant {t.tenant_id!r}: ports outside NATConfig.external_ports: "
                    f"{out_of_pool}"
                )
            seen.update(t.external_ports)
        object.__setattr__(self, "tenants", tuple(tenants))

    # ------------------------------------------------------------------ #
    # 租户表只读访问（构造后固定）                                        #
    # ------------------------------------------------------------------ #

    @property
    def tenant_ids(self) -> tuple[str, ...]:
        return tuple(t.tenant_id for t in self.tenants)

    def tenant(self, tenant_id: str) -> TenantConfig:
        """按 ID 取租户配置；不存在抛 KeyError（调用方负责包装成校验错误）。"""
        for t in self.tenants:
            if t.tenant_id == tenant_id:
                return t
        raise KeyError(tenant_id)

    def is_default_only(self) -> bool:
        """是否为隐式单默认租户配置（旧接口基线模式）。"""
        return (
            len(self.tenants) == 1
            and self.tenants[0].tenant_id == DEFAULT_TENANT
            and self.tenants[0].max_mappings is None
        )


def udp_five_tuple(src: Endpoint, dst: Endpoint) -> FiveTuple:
    """由两个端点构造 UDP 五元组。"""
    return FiveTuple(
        protocol=_PROTOCOL_UDP,
        src_ip=src.ip, src_port=src.port,
        dst_ip=dst.ip, dst_port=dst.port,
    )
