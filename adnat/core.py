"""地址依赖 NAT 核心：合成 UDP 状态库，不发任何网络包。

时间模型
--------
显式整数时钟：``advance(seconds)`` 推进虚拟时间；每次公开调用先按当前
时钟做 housekeeping（过期映射回收、隔离端口到期释放），再处理本次请求。
映射在 ``now >= expires_at`` 时过期（边界即死）；隔离端口在
``now >= released_at + quarantine`` 时可复用。

多租户
------
配置了 ``NATConfig.tenants`` 时，映射身份为
``(tenant_id, 内网IP, 内网端口, 目的IP, 目的端口)``：不同租户的相同内网
四元组是两条互不可见的映射；每个租户只在自己的端口子集内按最小可用端口
分配，并受 ``max_active_mappings`` 配额约束（复用不占配额）。入站按外端口
反解租户；查询 / 释放 / 出站必须显式指定租户，不能仅凭相同内网端点触及
另一家。未配置租户时只有内部默认租户（``DEFAULT_TENANT_ID``）独占全池、
无配额，旧接口行为与单租户基线完全一致。

原子性
------
``allocate_many`` / ``allocate_across_tenants`` 先完成全部校验、候选时刻
过期规划、配额检查与端口规划（纯函数，不改状态），全部可满足才一次性
提交；任何失败（ValidationError / QuotaExceededError /
PortExhaustionError / SearchBudgetExhaustedError）都使 NAT 状态与调用前
完全一致——不留下新映射、generation 不增长、时钟不推进。
"""

from __future__ import annotations

from dataclasses import dataclass

from ._validate import check_int
from .errors import (
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    DropReason,
    Endpoint,
    Mapping,
    NATConfig,
    Packet,
    TenantAllocationRequest,
    TenantConfig,
    TranslationResult,
    udp_five_tuple,
)

#: 租户内身份四元组：(内网IP, 内网端口, 目的IP, 目的端口)。
Key = tuple[str, int, str, int]
#: 含租户的完整映射身份：(tenant_id, key)。
TKey = tuple[str, Key]

#: 内部默认租户 ID。用户租户 ID 必须是非空字符串，因此空串永远只能由
#: "未显式指定租户"（tenant=None）到达，不会与任何真实租户重名。
DEFAULT_TENANT_ID = ""


@dataclass(slots=True)
class _Record:
    """内部可变映射记录；对外只暴露不可变 Mapping 快照。"""

    tenant: str
    internal: Endpoint
    remote: Endpoint
    external_port: int
    generation: int
    created_at: int
    last_seen: int
    expires_at: int

    def snapshot(self, key: Key) -> Mapping:
        return Mapping(
            key=key,
            internal=self.internal,
            remote=self.remote,
            external_port=self.external_port,
            generation=self.generation,
            created_at=self.created_at,
            last_seen=self.last_seen,
            expires_at=self.expires_at,
            tenant=self.tenant,
        )


@dataclass(slots=True)
class _TenantRuntime:
    """租户运行期视图（配置构造后固定）。"""

    config: TenantConfig | None          # None = 内部默认租户
    ports: tuple[int, ...]               # 升序独占子集
    max_active: int | None               # None = 不限配额


class AddressDependentNAT:
    """地址依赖（address-dependent）映射与过滤的 UDP NAT 模拟器。

    - 出站身份 = (租户, 内网IP, 内网端口, 目的IP, 目的端口)；同一内网端点
      访问不同目的会产生不同映射、不同外端口；不同租户彼此完全隔离。
    - 公网 IP 固定；外端口从该租户的独占子集中选最小空闲者。
    - 入站只接受来自映射所记录对端的包（地址依赖过滤），并按外端口反解
      出租户身份随结果返回。
    - 每条映射携带全局单调递增的 generation；包携带的 generation 不一致
      （且非 0）即判为迟到包并丢弃。
    """

    def __init__(self, config: NATConfig) -> None:
        if not isinstance(config, NATConfig):
            raise ValidationError(
                f"config must be NATConfig, got {type(config).__name__}"
            )
        self._config = config
        self._multitenant = config.tenants is not None
        self._now = 0
        self._mappings: dict[TKey, _Record] = {}
        self._port_to_key: dict[int, TKey] = {}
        # 隔离中的端口：port -> 释放时刻（进入隔离的时刻）。
        self._quarantine: dict[int, int] = {}
        self._next_generation = 1

        self._tenants: dict[str, _TenantRuntime] = {}
        if config.tenants is None:
            self._tenants[DEFAULT_TENANT_ID] = _TenantRuntime(
                config=None,
                ports=config.external_ports,
                max_active=None,
            )
        else:
            for t in config.tenants:
                self._tenants[t.tenant_id] = _TenantRuntime(
                    config=t,
                    ports=t.external_ports,
                    max_active=t.max_active_mappings,
                )

    # ------------------------------------------------------------------ #
    # 只读属性                                                            #
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> NATConfig:
        return self._config

    @property
    def now(self) -> int:
        """当前虚拟时钟（整数时间单位）。"""
        return self._now

    @property
    def tenant_ids(self) -> tuple[str, ...]:
        """已配置的真实租户 ID（不含内部默认租户）。"""
        if not self._multitenant:
            return ()
        return tuple(t.tenant_id for t in self._config.tenants)

    # ------------------------------------------------------------------ #
    # 内部：租户解析、时钟与 housekeeping                                 #
    # ------------------------------------------------------------------ #

    def _resolve_tenant(self, tenant: str | None) -> str:
        """把公开的 tenant 参数解析为内部租户 ID。

        - 未配置租户表（基线模式）：只允许 None（内部默认租户）；任何显式
          租户 ID 都拒绝，保证旧调用与基线完全一致；
        - 配置了租户表：必须显式给出表内非空 ID，None（沿用旧接口省略
          租户）同样拒绝，避免把请求误落入某个隐含租户。
        空串是内部默认租户的保留 ID，永远不接受公开传入。
        """
        if tenant is None:
            if self._multitenant:
                raise ValidationError(
                    "tenant must be specified explicitly: this NAT is "
                    "configured with an explicit tenant table"
                )
            return DEFAULT_TENANT_ID
        if not isinstance(tenant, str) or not tenant:
            raise ValidationError(
                f"tenant must be a non-empty str id, got {tenant!r}"
            )
        if tenant not in self._tenants:
            raise ValidationError(f"unknown tenant id {tenant!r}")
        return tenant

    def _check_clock(self, now: int) -> None:
        if now < self._now:
            raise ValidationError(
                f"clock cannot move backwards: now={now} < current={self._now}"
            )

    def _expired_tkeys_at(self, now: int) -> set[TKey]:
        """纯函数：在时刻 now 会过期的完整身份集合（不修改状态）。"""
        return {k for k, r in self._mappings.items() if now >= r.expires_at}

    def _housekeeping(self, now: int) -> list[TKey]:
        """提交时刻 now 的过期回收与隔离到期释放，返回本次过期身份（升序）。"""
        expired = sorted(
            (k for k, r in self._mappings.items() if now >= r.expires_at)
        )
        for tkey in expired:
            rec = self._mappings.pop(tkey)
            del self._port_to_key[rec.external_port]
            self._quarantine[rec.external_port] = now
        q_done = [p for p, t in self._quarantine.items()
                  if now >= t + self._config.quarantine]
        for p in q_done:
            del self._quarantine[p]
        self._now = now
        return expired

    def _plan_batch(self, new_items: list[TKey], now: int
                    ) -> dict[TKey, int]:
        """纯函数端口规划：跨租户批量共享一个搜索预算（不修改状态）。

        new_items 按"输入次序"给出完整身份 tkey=(tenant,key)（仅含新建
        项）；租户按其在输入中首次出现的次序处理，租户内按输入次序拿
        最小可用端口。
        预算按基线口径对实际检查过的端口计数，在所有租户子集间累加：
        - 租户子集全扫完仍不够 -> PortExhaustionError（带 tenant，证明无解）；
        - 检查数达到 budget 仍未齐 -> SearchBudgetExhaustedError（带 tenant，
          未证明无解）。
        """
        expired = self._expired_tkeys_at(now)
        used = {
            rec.external_port
            for tkey, rec in self._mappings.items()
            if tkey not in expired
        }
        # 隔离集合按"候选时刻提交 housekeeping 后"的投影计算，避免提前
        # 分配即将进入隔离的端口：
        # - 已在隔离且 now 未到 released_at + Q 的端口；
        # - 将在 now 过期回收的映射端口：提交时即以 now 进入隔离，Q>0 时
        #   本次分配绝不可用（Q=0 时 now >= now+0 立即可用，符合基线）。
        q = self._config.quarantine
        quarantined = {
            p for p, t in self._quarantine.items()
            if now < t + q
        }
        if q > 0:
            quarantined |= {
                rec.external_port
                for tkey, rec in self._mappings.items()
                if tkey in expired
            }
        budget = self._config.search_budget
        assert budget is not None  # NATConfig 保证非 None
        inspected = 0
        assignments: dict[TKey, int] = {}

        order: list[str] = []
        for tenant, _key in new_items:
            if tenant not in order:
                order.append(tenant)
        for tenant in order:
            rt = self._tenants[tenant]
            wanted = [tkey for tkey in new_items if tkey[0] == tenant]
            chosen: list[int] = []
            for port in rt.ports:
                if len(chosen) == len(wanted):
                    break
                if inspected >= budget:
                    raise SearchBudgetExhaustedError(
                        budget=budget, inspected=inspected,
                        needed=len(wanted), found=len(chosen), tenant=tenant,
                    )
                inspected += 1
                if port in used or port in quarantined:
                    continue
                chosen.append(port)
            if len(chosen) < len(wanted):
                raise PortExhaustionError(
                    needed=len(wanted), available=len(chosen),
                    pool_size=len(rt.ports), tenant=tenant,
                )
            for tkey, port in zip(wanted, chosen):
                assignments[tkey] = port
        return assignments

    def _check_quota(self, new_counts: dict[str, int],
                     live: set[TKey]) -> None:
        """配额检查（候选时刻过期回收后的口径），租户按 ID 升序报错确定。"""
        active: dict[str, int] = {}
        for tenant, _key in live:
            active[tenant] = active.get(tenant, 0) + 1
        for tenant in sorted(new_counts):
            rt = self._tenants[tenant]
            if rt.max_active is None:
                continue
            n_active = active.get(tenant, 0)
            n_new = new_counts[tenant]
            if n_active + n_new > rt.max_active:
                raise QuotaExceededError(
                    tenant=tenant, active=n_active,
                    requested=n_new, limit=rt.max_active,
                )

    def _check_expiry_overflow(self, now: int) -> None:
        if now > MAX_TIME - self._config.lifetime:
            raise ValidationError(
                f"now={now} + lifetime={self._config.lifetime} exceeds "
                f"MAX_TIME={MAX_TIME}"
            )

    def _commit(self, reqs: list[tuple[str, Key, Endpoint, Endpoint]],
                assignments: dict[TKey, int], now: int
                ) -> list[AllocationResult]:
        """一次性提交：housekeeping 后按输入次序建映射 / 复用映射。"""
        self._housekeeping(now)
        results: list[AllocationResult] = []
        for tenant, key, internal, remote in reqs:
            tkey = (tenant, key)
            rec = self._mappings.get(tkey)
            if rec is not None:
                results.append(AllocationResult(
                    key=key, mapping=rec.snapshot(key),
                    created=False, tenant=tenant))
                continue
            port = assignments[tkey]
            rec = _Record(
                tenant=tenant,
                internal=internal,
                remote=remote,
                external_port=port,
                generation=self._next_generation,
                created_at=now,
                last_seen=now,
                expires_at=now + self._config.lifetime,
            )
            self._next_generation += 1
            self._mappings[tkey] = rec
            self._port_to_key[port] = tkey
            results.append(AllocationResult(
                key=key, mapping=rec.snapshot(key),
                created=True, tenant=tenant))
        return results

    # ------------------------------------------------------------------ #
    # 出站分配                                                            #
    # ------------------------------------------------------------------ #

    def allocate(self, internal: Endpoint, remote: Endpoint,
                 *, at: int | None = None,
                 tenant: str | None = None) -> AllocationResult:
        """分配（或复用）单条出站映射。批量语义见 allocate_many。"""
        return self.allocate_many(
            [AllocationRequest(internal, remote)], at=at, tenant=tenant)[0]

    def allocate_many(self, requests, *, at: int | None = None,
                      tenant: str | None = None) -> list[AllocationResult]:
        """单个租户内的批量出站分配：要么全部成功，要么整体回滚。

        已存在活跃映射的 (tenant, key) 直接复用（不占新端口、不占配额）；
        同批重复 key 属于非法输入，抛 ValidationError。
        ``tenant=None`` 走内部默认租户；配置了租户表时必须给出表内 ID。
        """
        now = self._resolve_at(at)
        tenant_id = self._resolve_tenant(tenant)

        # ---- 阶段 1：全部输入校验（任何状态变更之前） ----
        if isinstance(requests, (str, bytes)) or not hasattr(requests, "__iter__"):
            raise ValidationError(
                f"requests must be an iterable of AllocationRequest, "
                f"got {type(requests).__name__}"
            )
        reqs = list(requests)
        if len(reqs) > MAX_BATCH_REQUESTS:
            raise ValidationError(
                f"batch size {len(reqs)} exceeds "
                f"MAX_BATCH_REQUESTS={MAX_BATCH_REQUESTS}"
            )
        for i, r in enumerate(reqs):
            if not isinstance(r, AllocationRequest):
                raise ValidationError(
                    f"requests[{i}] must be AllocationRequest, "
                    f"got {type(r).__name__}"
                )
        keys = [r.key for r in reqs]
        if len(set(keys)) != len(keys):
            raise ValidationError("duplicate keys within one batch")
        self._check_clock(now)
        self._check_expiry_overflow(now)

        # ---- 阶段 2：候选时刻过期规划（纯函数，不改状态） ----
        expired = self._expired_tkeys_at(now)
        live = set(self._mappings) - expired
        tkeys = [(tenant_id, k) for k in keys]
        new_items = [tk for tk in tkeys if tk not in live]

        # ---- 阶段 3：配额检查（不足单独报错，绝不伪装成端口耗尽） ----
        self._check_quota(
            {tenant_id: len(new_items)} if new_items else {}, live)

        # ---- 阶段 4：按输入次序规划端口（共享预算，纯函数） ----
        assignments = self._plan_batch(new_items, now)

        # ---- 阶段 5：一次性提交 ----
        ordered = [(tenant_id, r.key, r.internal, r.remote) for r in reqs]
        return self._commit(ordered, assignments, now)

    def allocate_across_tenants(self, requests, *, at: int | None = None
                                ) -> list[AllocationResult]:
        """跨租户批量出站分配：全部满足才提交。

        请求为 ``TenantAllocationRequest`` 列表，每项显式指定租户。任一
        租户超配额、端口子集不够或共享搜索预算耗尽，所有租户都不会留下
        新映射，generation 不增长、时钟不推进。检查顺序固定：

        1. 完整输入校验（类型、批大小、租户存在、批内 (tenant,key) 不重复、
           时钟、溢出）；
        2. 在候选时刻规划过期回收；
        3. 各租户配额检查（QuotaExceededError，独立于端口容量）；
        4. 按输入次序在各租户子集内分配最小可用端口，预算按实际检查的
           端口计数并在租户间共享；
        5. 全部成功才一次性提交。
        """
        now = self._resolve_at(at)

        # ---- 阶段 1：完整输入校验 ----
        if isinstance(requests, (str, bytes)) or not hasattr(requests, "__iter__"):
            raise ValidationError(
                "requests must be an iterable of TenantAllocationRequest, "
                f"got {type(requests).__name__}"
            )
        reqs = list(requests)
        if len(reqs) > MAX_BATCH_REQUESTS:
            raise ValidationError(
                f"batch size {len(reqs)} exceeds "
                f"MAX_BATCH_REQUESTS={MAX_BATCH_REQUESTS}"
            )
        for i, r in enumerate(reqs):
            if not isinstance(r, TenantAllocationRequest):
                raise ValidationError(
                    f"requests[{i}] must be TenantAllocationRequest, "
                    f"got {type(r).__name__}"
                )
        # TenantAllocationRequest 构造时已保证 tenant_id 非空；此处必须
        # 命中已配置租户表（默认租户不可经此入口指定）。
        for i, r in enumerate(reqs):
            if r.tenant_id not in self._tenants or r.tenant_id == DEFAULT_TENANT_ID:
                raise ValidationError(
                    f"requests[{i}] references unknown tenant id "
                    f"{r.tenant_id!r}"
                )
        tkeys = [(r.tenant_id, r.key) for r in reqs]
        if len(set(tkeys)) != len(tkeys):
            raise ValidationError(
                "duplicate (tenant, key) pairs within one cross-tenant batch"
            )
        self._check_clock(now)
        self._check_expiry_overflow(now)

        # ---- 阶段 2：候选时刻过期规划 ----
        expired = self._expired_tkeys_at(now)
        live = set(self._mappings) - expired
        new_items = [tk for tk in tkeys if tk not in live]

        # ---- 阶段 3：配额检查（先于一切端口规划） ----
        new_counts: dict[str, int] = {}
        for tid, _tk in new_items:
            new_counts[tid] = new_counts.get(tid, 0) + 1
        self._check_quota(new_counts, live)

        # ---- 阶段 4：按输入次序规划端口 ----
        assignments = self._plan_batch(new_items, now)

        # ---- 阶段 5：一次性提交 ----
        ordered = [(r.tenant_id, r.key, r.internal, r.remote) for r in reqs]
        return self._commit(ordered, assignments, now)

    # ------------------------------------------------------------------ #
    # 包改写                                                              #
    # ------------------------------------------------------------------ #

    def translate_outbound(self, packet: Packet, *, at: int | None = None,
                           tenant: str | None = None) -> TranslationResult:
        """出站：内网 -> 公网。不隐式建映射；无映射即丢弃（NO_MAPPING）。

        必须显式给出租户（None=默认租户）；相同内网四元组在不同租户下
        互不可见。
        """
        now = self._resolve_at(at)
        tenant_id = self._resolve_tenant(tenant)
        self._validate_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)
        key = (packet.src.ip, packet.src.port, packet.dst.ip, packet.dst.port)
        tkey = (tenant_id, key)
        rec = self._mappings.get(tkey)
        if rec is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None, None)
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION,
                rec.snapshot(key), tenant_id)
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(
            Endpoint(self._config.public_ip, rec.external_port), packet.dst)
        return TranslationResult(
            True, rewritten, None, rec.snapshot(key), tenant_id)

    def translate_inbound(self, packet: Packet, *, at: int | None = None
                          ) -> TranslationResult:
        """入站：公网 -> 内网。必须命中映射且源端点 == 映射对端。

        租户由外端口反解（端口子集互不重叠），结果带回租户身份。
        """
        now = self._resolve_at(at)
        self._validate_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)
        if packet.dst.ip != self._config.public_ip:
            return TranslationResult(False, None, DropReason.DEST_MISMATCH, None, None)
        tkey = self._port_to_key.get(packet.dst.port)
        if tkey is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None, None)
        tenant_id, key = tkey
        rec = self._mappings[tkey]
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION,
                rec.snapshot(key), tenant_id)
        if (packet.src.ip, packet.src.port) != (rec.remote.ip, rec.remote.port):
            return TranslationResult(
                False, None, DropReason.PEER_MISMATCH,
                rec.snapshot(key), tenant_id)
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(packet.src, rec.internal)
        return TranslationResult(
            True, rewritten, None, rec.snapshot(key), tenant_id)

    # ------------------------------------------------------------------ #
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    def release(self, key: Key, *, at: int | None = None,
                tenant: str | None = None) -> bool:
        """显式释放一条映射；端口进入隔离。

        作用域必须与映射租户一致：配置了租户表时须显式给出表内租户 ID，
        相同内网四元组在别的租户下不会被误释放。映射不存在返回 False。
        """
        now = self._resolve_at(at)
        tenant_id = self._resolve_tenant(tenant)
        self._validate_key(key)
        self._check_clock(now)
        self._housekeeping(now)
        tkey = (tenant_id, key)
        rec = self._mappings.pop(tkey, None)
        if rec is None:
            return False
        del self._port_to_key[rec.external_port]
        self._quarantine[rec.external_port] = now
        return True

    def advance(self, seconds: int) -> list:
        """显式推进虚拟时钟，返回本次过期的映射身份列表。

        无租户配置（旧接口）时元素为租户内四元组 key；配置了租户表时
        元素为完整身份 ``(tenant_id, key)``，避免跨租户同 key 不可区分。
        """
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        expired_tkeys = self._housekeeping(target)
        if self._multitenant:
            return list(expired_tkeys)
        return [key for _tenant, key in expired_tkeys]

    # ------------------------------------------------------------------ #
    # 只读快照                                                            #
    # ------------------------------------------------------------------ #

    def get_mapping(self, key: Key, *, tenant: str | None = None
                    ) -> Mapping | None:
        """按 (tenant, key) 查活跃映射快照；不存在或已过期返回 None。"""
        tenant_id = self._resolve_tenant(tenant)
        self._validate_key(key)
        rec = self._mappings.get((tenant_id, key))
        if rec is None or self._now >= rec.expires_at:
            return None
        return rec.snapshot(key)

    def snapshot_mappings(self, *, tenant: str | None = None) -> list[Mapping]:
        """当前活跃映射快照，按 (tenant, key) 排序（确定性输出）。

        tenant=None 返回全部租户；否则只返回指定租户。
        """
        tenant_id = self._resolve_tenant(tenant) if tenant is not None else None
        out: list[Mapping] = []
        for tid, key in sorted(self._mappings):
            if tenant_id is not None and tid != tenant_id:
                continue
            rec = self._mappings[(tid, key)]
            if self._now < rec.expires_at:
                out.append(rec.snapshot(key))
        return out

    def quarantined_ports(self) -> dict[int, int]:
        """隔离中的端口 -> 进入隔离的时刻。"""
        return dict(self._quarantine)

    def stats(self) -> dict[str, int]:
        """全局计数快照：活跃映射数 / 占用端口 / 隔离端口 / 空闲端口 / 时钟。"""
        live = sum(1 for r in self._mappings.values()
                   if self._now < r.expires_at)
        pool = len(self._config.external_ports)
        return {
            "now": self._now,
            "live_mappings": live,
            "ports_in_use": len(self._port_to_key),
            "ports_quarantined": len(self._quarantine),
            "ports_free": pool - len(self._port_to_key) - len(self._quarantine),
            "pool_size": pool,
        }

    def tenant_stats(self, tenant: str | None) -> dict[str, int | str | None]:
        """单个租户的计数快照（含配额口径）。"""
        tenant_id = self._resolve_tenant(tenant)
        rt = self._tenants[tenant_id]
        live = sum(1 for (tid, _k), r in self._mappings.items()
                   if tid == tenant_id and self._now < r.expires_at)
        in_use = sum(1 for p, (tid, _k) in self._port_to_key.items()
                     if tid == tenant_id)
        port_set = set(rt.ports)
        quar = sum(1 for p in self._quarantine if p in port_set)
        subset = len(rt.ports)
        return {
            "tenant": None if tenant_id == DEFAULT_TENANT_ID else tenant_id,
            "live_mappings": live,
            "ports_in_use": in_use,
            "ports_quarantined": quar,
            "ports_free": subset - in_use - quar,
            "subset_size": subset,
            "max_active_mappings": rt.max_active,
            "now": self._now,
        }

    # ------------------------------------------------------------------ #
    # 内部：校验辅助                                                      #
    # ------------------------------------------------------------------ #

    def _resolve_at(self, at: int | None) -> int:
        if at is None:
            return self._now
        return check_int(at, "at", minimum=0, maximum=MAX_TIME)

    @staticmethod
    def _validate_packet(packet: Packet) -> None:
        if not isinstance(packet, Packet):
            raise ValidationError(
                f"packet must be Packet, got {type(packet).__name__}"
            )

    @staticmethod
    def _validate_key(key: object) -> None:
        if not (isinstance(key, tuple) and len(key) == 4):
            raise ValidationError(
                f"key must be (ip, port, ip, port) tuple, got {key!r}"
            )
        from ._validate import check_ipv4, check_port
        check_ipv4(key[0], "key[0] (internal ip)")
        check_port(key[1], "key[1] (internal port)")
        check_ipv4(key[2], "key[2] (remote ip)")
        check_port(key[3], "key[3] (remote port)")
