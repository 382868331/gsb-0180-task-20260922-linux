"""地址依赖 NAT 核心：合成 UDP 状态库，不发任何网络包。

时间模型
--------
显式整数时钟：``advance`` / ``advance_tenants`` 推进虚拟时间；每次公开调用
先按当前时钟做 housekeeping（过期映射回收、隔离端口到期释放），再处理本次
请求。映射在 ``now >= expires_at`` 时过期（边界即死）；隔离端口在
``now >= released_at + quarantine`` 时可复用。

租户模型
--------
映射身份为 ``(tenant_id, key)``，key 仍是租户内的出站四元组
（内网IP, 内网端口, 目的IP, 目的端口）。两个租户可以拥有完全相同的内网
端点与四元组而互不影响：它们是两条独立映射，外端口分别取自互不重叠的
租户子池。入站仅凭外端口即可反查租户（端口全局唯一属主）。

- 未配置显式租户表时，NATConfig 自动生成唯一的隐式 ``default`` 租户
  （独占总池、无配额），旧接口行为与基线完全一致。
- 显式租户表构造后固定，不支持在线迁移。
- 复用已有映射不额外占配额；过期与释放立即解除活跃配额，但端口隔离期
  仍不能跳过（因此可能出现"配额有空、端口不可用"的 PortExhaustion）。

原子性
------
``allocate_many`` / ``allocate_across_tenants`` 严格按以下顺序处理，任一步
失败都在任何状态变更之前抛出，NAT 状态（含时钟、generation 序号）与调用
前完全一致：

  1. 完整输入校验（类型、租户存在、批内身份重复、时钟、溢出）；
  2. 在候选时刻规划过期回收（纯函数，不改状态）；
  3. 逐租户配额检查（不足抛 QuotaExceededError，绝不伪装成端口耗尽）；
  4. 按输入次序为各租户规划最小空闲端口（预算逐租户独立计数，
     预算耗尽 SearchBudgetExhaustedError；全子池不够 PortExhaustionError）；
  5. 一次性提交（housekeeping + 按输入次序建映射、发 generation）。
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
    DEFAULT_TENANT,
    MAX_BATCH_REQUESTS,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    DropReason,
    Endpoint,
    Mapping,
    NATConfig,
    Packet,
    TenantConfig,
    TenantRequest,
    TranslationResult,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]
#: 全局映射身份：(租户 ID, 租户内四元组)。
TKey = tuple[str, Key]


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
            tenant=self.tenant,
            key=key,
            internal=self.internal,
            remote=self.remote,
            external_port=self.external_port,
            generation=self.generation,
            created_at=self.created_at,
            last_seen=self.last_seen,
            expires_at=self.expires_at,
        )


class AddressDependentNAT:
    """地址依赖（address-dependent）映射与过滤的多租户 UDP NAT 模拟器。

    - 出站身份 = (租户, 内网IP, 内网端口, 目的IP, 目的端口)；同一租户内同一
      内网端点访问不同目的会产生不同映射、不同外端口。
    - 公网 IP 固定；外端口从该租户的专用子池中选最小空闲者（子池互不重叠）。
    - 入站只接受来自映射所记录对端的包（地址依赖过滤），外端口反查租户。
    - 每条映射携带全局单调递增的 generation；包携带的 generation 不一致
      （且非 0）即判为迟到包并丢弃。
    """

    def __init__(self, config: NATConfig) -> None:
        if not isinstance(config, NATConfig):
            raise ValidationError(
                f"config must be NATConfig, got {type(config).__name__}"
            )
        self._config = config
        self._now = 0
        self._mappings: dict[TKey, _Record] = {}
        # 外端口全局唯一属主：port -> (tenant, key)。子池互不重叠，
        # 因此一个端口在任何时刻至多属于一个租户的一条映射。
        self._port_owner: dict[int, TKey] = {}
        # 隔离中的端口：port -> 释放时刻（进入隔离的时刻）。
        self._quarantine: dict[int, int] = {}
        # 端口 -> 所属租户（子池互不重叠，构造后固定；O(1) 入站反查）。
        self._port_tenant: dict[int, str] = {
            p: cfg.tenant_id for cfg in config.tenants for p in cfg.external_ports
        }
        self._next_generation = 1

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

    # ------------------------------------------------------------------ #
    # 内部：租户解析与时钟 / housekeeping                                 #
    # ------------------------------------------------------------------ #

    def _tenant_cfg(self, tenant_id: str) -> TenantConfig:
        try:
            return self._config.tenant(tenant_id)
        except KeyError:
            raise ValidationError(f"unknown tenant_id {tenant_id!r}") from None

    def _check_clock(self, now: int) -> None:
        if now < self._now:
            raise ValidationError(
                f"clock cannot move backwards: now={now} < current={self._now}"
            )

    def _expired_at(self, now: int) -> set[TKey]:
        """纯函数：在时刻 now 会过期的身份集合（不修改状态）。"""
        return {tk for tk, r in self._mappings.items() if now >= r.expires_at}

    def _housekeeping(self, now: int) -> list[TKey]:
        """提交时刻 now 的过期回收与隔离到期释放，返回本次过期身份（升序）。"""
        expired = sorted(self._expired_at(now))
        for tk in expired:
            rec = self._mappings.pop(tk)
            del self._port_owner[rec.external_port]
            self._quarantine[rec.external_port] = now
        q_done = [p for p, t in self._quarantine.items()
                  if now >= t + self._config.quarantine]
        for p in q_done:
            del self._quarantine[p]
        self._now = now
        return expired

    def _plan_tenant_ports(self, cfg: TenantConfig, count: int,
                           now: int) -> list[int]:
        """纯函数：为租户 cfg 规划 count 个最小空闲端口（不修改状态）。

        只在该租户的子池内按端口升序检查，最多检查 search_budget 个
        （预算逐租户独立计数）：
        - 找齐 -> 返回端口列表；
        - 检查满 budget 仍未齐 -> SearchBudgetExhaustedError（未证明无解）；
        - 全子池查完仍不够 -> PortExhaustionError（证明无解）。

        与基线一致：候选时刻刚过期映射腾出的端口此刻尚未进入隔离表
        （housekeeping 未提交），若被本批选中则在提交时直接重新属主化。
        """
        if count == 0:
            return []
        expired = self._expired_at(now)
        used = {
            rec.external_port
            for tk, rec in self._mappings.items()
            if tk not in expired
        }
        quarantined = {
            p for p, t in self._quarantine.items()
            if now < t + self._config.quarantine
        }
        chosen: list[int] = []
        inspected = 0
        budget = self._config.search_budget
        assert budget is not None  # NATConfig 保证非 None
        for port in cfg.external_ports:
            if len(chosen) == count:
                break
            if inspected >= budget:
                raise SearchBudgetExhaustedError(
                    budget=budget, inspected=inspected,
                    needed=count, found=len(chosen), tenant=cfg.tenant_id,
                )
            inspected += 1
            if port in used or port in quarantined:
                continue
            chosen.append(port)
        if len(chosen) < count:
            raise PortExhaustionError(
                needed=count, available=len(chosen),
                pool_size=len(cfg.external_ports), tenant=cfg.tenant_id,
            )
        return chosen

    def _check_expiry_overflow(self, now: int) -> None:
        if now > MAX_TIME - self._config.lifetime:
            raise ValidationError(
                f"now={now} + lifetime={self._config.lifetime} exceeds "
                f"MAX_TIME={MAX_TIME}"
            )

    # ------------------------------------------------------------------ #
    # 出站分配                                                            #
    # ------------------------------------------------------------------ #

    def allocate(self, internal: Endpoint, remote: Endpoint, *,
                 tenant_id: str = DEFAULT_TENANT,
                 at: int | None = None) -> AllocationResult:
        """分配（或复用）单条出站映射。默认为旧接口的默认租户。"""
        return self.allocate_many(
            [AllocationRequest(internal, remote)],
            tenant_id=tenant_id, at=at,
        )[0]

    def allocate_many(self, requests, *,
                      tenant_id: str = DEFAULT_TENANT,
                      at: int | None = None) -> list[AllocationResult]:
        """单个租户内的批量出站分配：要么全成功，要么整体回滚。

        旧接口（tenant_id 默认 ``default``）在未配置显式租户表时与基线
        完全一致；显式租户表下必须传该表中存在的租户 ID。
        已存在活跃映射的身份直接复用（不占新端口、不占配额）；同批重复
        身份属于非法输入，抛 ValidationError。
        """
        # 旧接口的输入形状校验（保持基线错误口径）。
        if isinstance(requests, (str, bytes)) or not hasattr(requests, "__iter__"):
            raise ValidationError(
                f"requests must be an iterable of AllocationRequest, "
                f"got {type(requests).__name__}"
            )
        reqs = list(requests)
        for i, r in enumerate(reqs):
            if not isinstance(r, AllocationRequest):
                raise ValidationError(
                    f"requests[{i}] must be AllocationRequest, "
                    f"got {type(r).__name__}"
                )
        items = [TenantRequest(tenant_id, r.internal, r.remote) for r in reqs]
        return self._allocate(items, at)

    def allocate_across_tenants(self, items, *,
                                at: int | None = None
                                ) -> list[AllocationResult]:
        """跨租户批量出站分配：全部满足才提交，任何一租户失败则整体回滚。

        items 为 TenantRequest 序列（每项显式携带租户 ID）。失败时任何
        租户都不会留下新映射、generation 序号不增长、时钟不推进。
        固定检查顺序见模块 docstring。
        """
        if isinstance(items, (str, bytes)) or not hasattr(items, "__iter__"):
            raise ValidationError(
                f"items must be an iterable of TenantRequest, "
                f"got {type(items).__name__}"
            )
        reqs = list(items)
        for i, r in enumerate(reqs):
            if not isinstance(r, TenantRequest):
                raise ValidationError(
                    f"items[{i}] must be TenantRequest, got {type(r).__name__}"
                )
        return self._allocate(reqs, at)

    def _allocate(self, items: list[TenantRequest],
                  at: int | None) -> list[AllocationResult]:
        now = self._resolve_at(at)

        # ---- 阶段 1：完整输入校验（任何状态变更之前） ----
        if len(items) > MAX_BATCH_REQUESTS:
            raise ValidationError(
                f"batch size {len(items)} exceeds "
                f"MAX_BATCH_REQUESTS={MAX_BATCH_REQUESTS}"
            )
        identities: list[TKey] = [
            (r.tenant_id, r.key) for r in items
        ]
        if len(set(identities)) != len(identities):
            raise ValidationError("duplicate (tenant_id, key) within one batch")
        self._check_clock(now)
        self._check_expiry_overflow(now)
        # 所有租户都必须存在（先全部解析，任一未知即拒绝整批）。
        cfgs: dict[str, TenantConfig] = {}
        order: list[str] = []
        for r in items:
            if r.tenant_id not in cfgs:
                cfgs[r.tenant_id] = self._tenant_cfg(r.tenant_id)
                order.append(r.tenant_id)

        # ---- 阶段 2：候选时刻的过期回收（纯函数规划，不改状态） ----
        expired = self._expired_at(now)
        live = set(self._mappings) - expired

        # 按输入出现次序收集每个租户的"新建身份"（复用不进列表）。
        new_by_tenant: dict[str, list[TKey]] = {tid: [] for tid in order}
        for tk in identities:
            if tk not in live:
                new_by_tenant[tk[0]].append(tk)

        # ---- 阶段 3：配额检查（全部先于端口规划） ----
        active_counts = {
            tid: sum(1 for (t, _k) in live if t == tid) for tid in order
        }
        for tid in order:
            limit = cfgs[tid].max_mappings
            if limit is not None:
                want = active_counts[tid] + len(new_by_tenant[tid])
                if want > limit:
                    raise QuotaExceededError(
                        tenant_id=tid, active=active_counts[tid],
                        new=len(new_by_tenant[tid]), limit=limit,
                    )

        # ---- 阶段 4：按输入次序（租户首次出现次序）规划端口 ----
        plans: dict[str, list[int]] = {}
        for tid in order:
            plans[tid] = self._plan_tenant_ports(
                cfgs[tid], len(new_by_tenant[tid]), now)

        # ---- 阶段 5：一次性提交 ----
        self._housekeeping(now)
        port_iters = {tid: iter(plans[tid]) for tid in order}
        results: list[AllocationResult] = []
        for req, tk in zip(items, identities):
            rec = self._mappings.get(tk)
            if rec is not None:
                results.append(AllocationResult(
                    tenant=tk[0], key=tk[1],
                    mapping=rec.snapshot(tk[1]), created=False))
                continue
            tid = tk[0]
            port = next(port_iters[tid])
            rec = _Record(
                tenant=tid,
                internal=req.internal,
                remote=req.remote,
                external_port=port,
                generation=self._next_generation,
                created_at=now,
                last_seen=now,
                expires_at=now + self._config.lifetime,
            )
            self._next_generation += 1
            self._mappings[tk] = rec
            self._port_owner[port] = tk
            results.append(AllocationResult(
                tenant=tid, key=tk[1], mapping=rec.snapshot(tk[1]), created=True))
        return results

    # ------------------------------------------------------------------ #
    # 包改写                                                              #
    # ------------------------------------------------------------------ #

    def translate_outbound(self, packet: Packet, *,
                           tenant_id: str = DEFAULT_TENANT,
                           at: int | None = None) -> TranslationResult:
        """出站：内网 -> 公网。不隐式建映射；无映射即丢弃（NO_MAPPING）。

        映射查找严格限定在 tenant_id 内：另一租户拥有相同四元组不构成命中。
        """
        now = self._resolve_at(at)
        self._validate_packet(packet)
        cfg = self._tenant_cfg(tenant_id)  # 未知租户属于输入校验，先于 housekeeping
        self._check_clock(now)
        self._housekeeping(now)
        tk: TKey = (cfg.tenant_id,
                    (packet.src.ip, packet.src.port,
                     packet.dst.ip, packet.dst.port))
        rec = self._mappings.get(tk)
        if rec is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None)
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION,
                rec.snapshot(tk[1]), cfg.tenant_id)
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(
            Endpoint(self._config.public_ip, rec.external_port), packet.dst)
        return TranslationResult(
            True, rewritten, None, rec.snapshot(tk[1]), cfg.tenant_id)

    def translate_inbound(self, packet: Packet, *, at: int | None = None
                          ) -> TranslationResult:
        """入站：公网 -> 内网。必须命中映射且源端点 == 映射对端。

        租户由外端口反查：端口无属主但属于某租户子池 -> NO_MAPPING；
        端口不属于任何租户子池 -> UNKNOWN_TENANT。
        """
        now = self._resolve_at(at)
        self._validate_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)
        if packet.dst.ip != self._config.public_ip:
            return TranslationResult(False, None, DropReason.DEST_MISMATCH, None)
        tk = self._port_owner.get(packet.dst.port)
        if tk is None:
            if self._tenant_of_port(packet.dst.port) is None:
                return TranslationResult(
                    False, None, DropReason.UNKNOWN_TENANT, None)
            return TranslationResult(False, None, DropReason.NO_MAPPING, None)
        tid, key = tk
        rec = self._mappings[tk]
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION,
                rec.snapshot(key), tid)
        if (packet.src.ip, packet.src.port) != (rec.remote.ip, rec.remote.port):
            return TranslationResult(
                False, None, DropReason.PEER_MISMATCH, rec.snapshot(key), tid)
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(packet.src, rec.internal)
        return TranslationResult(
            True, rewritten, None, rec.snapshot(key), tid)

    def _tenant_of_port(self, port: int) -> str | None:
        """外端口属于哪个租户的子池（无论当前是否被占用）。"""
        return self._port_tenant.get(port)

    # ------------------------------------------------------------------ #
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    def release(self, key: Key, *,
                tenant_id: str = DEFAULT_TENANT,
                at: int | None = None) -> bool:
        """显式释放一条映射；端口进入该租户隔离。不存在返回 False（无变更）。

        只作用于指定租户：仅凭相同四元组不会误释放另一租户的映射。
        """
        now = self._resolve_at(at)
        self._validate_key(key)
        cfg = self._tenant_cfg(tenant_id)
        self._check_clock(now)
        self._housekeeping(now)
        rec = self._mappings.pop((cfg.tenant_id, key), None)
        if rec is None:
            return False
        del self._port_owner[rec.external_port]
        self._quarantine[rec.external_port] = now
        return True

    def advance(self, seconds: int) -> list[Key]:
        """显式推进虚拟时钟，返回本次过期的四元组 key 列表。

        仅适用于隐式默认租户配置（旧接口）；显式租户表下身份有歧义，
        请改用 advance_tenants。
        """
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        if not self._config.is_default_only():
            raise ValidationError(
                "advance() is ambiguous with an explicit tenant table; "
                "use advance_tenants(seconds) which returns (tenant_id, key)"
            )
        expired = self._housekeeping(target)
        return [key for _tid, key in expired]

    def advance_tenants(self, seconds: int) -> list[TKey]:
        """显式推进虚拟时钟，返回本次过期身份 (tenant_id, key) 列表（升序）。"""
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance_tenants({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        return self._housekeeping(target)

    # ------------------------------------------------------------------ #
    # 只读快照                                                            #
    # ------------------------------------------------------------------ #

    def get_mapping(self, key: Key, *,
                    tenant_id: str = DEFAULT_TENANT) -> Mapping | None:
        """按 (租户, key) 查活跃映射快照；不存在或已过期返回 None。"""
        self._validate_key(key)
        cfg = self._tenant_cfg(tenant_id)
        rec = self._mappings.get((cfg.tenant_id, key))
        if rec is None or self._now >= rec.expires_at:
            return None
        return rec.snapshot(key)

    def snapshot_mappings(self, *, tenant_id: str | None = None) -> list[Mapping]:
        """当前活跃映射快照，按 (租户, key) 排序（确定性输出）。

        tenant_id=None 返回全部租户；给定租户时只返回该租户，且租户必须存在。
        """
        if tenant_id is not None:
            self._tenant_cfg(tenant_id)
        return [
            rec.snapshot(key)
            for (tid, key), rec in sorted(self._mappings.items())
            if (tenant_id is None or tid == tenant_id)
            and self._now < rec.expires_at
        ]

    def quarantined_ports(self, *, tenant_id: str | None = None
                          ) -> dict[int, int]:
        """隔离中的端口 -> 进入隔离的时刻；可按租户子池过滤。"""
        if tenant_id is None:
            return dict(self._quarantine)
        cfg = self._tenant_cfg(tenant_id)
        subset = set(cfg.external_ports)
        return {p: t for p, t in self._quarantine.items() if p in subset}

    def stats(self, *, tenant_id: str | None = None) -> dict[str, int]:
        """计数快照：活跃映射数 / 占用端口 / 隔离端口 / 空闲端口 / 时钟。

        tenant_id=None 给全实例合计（pool_size 为总池）；给定租户时只统计
        该租户（pool_size 为该租户子池）。
        """
        if tenant_id is not None:
            cfg = self._tenant_cfg(tenant_id)
            subset = set(cfg.external_ports)
        else:
            cfg = None
            subset = None
        if cfg is None:
            live = sum(1 for r in self._mappings.values()
                       if self._now < r.expires_at)
            ports_in_use = len(self._port_owner)
            quar = len(self._quarantine)
            pool = len(self._config.external_ports)
        else:
            live = sum(1 for (t, _k), r in self._mappings.items()
                       if t == cfg.tenant_id and self._now < r.expires_at)
            ports_in_use = sum(1 for p in self._port_owner if p in subset)
            quar = sum(1 for p in self._quarantine if p in subset)
            pool = len(cfg.external_ports)
        return {
            "now": self._now,
            "live_mappings": live,
            "ports_in_use": ports_in_use,
            "ports_quarantined": quar,
            "ports_free": pool - ports_in_use - quar,
            "pool_size": pool,
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
