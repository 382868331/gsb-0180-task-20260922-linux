"""多租户独立字典参考实现（测试 oracle）。

与 tests/reference_nat.py 一样刻意不导入 adnat 的任何模块：只用字典与
元组重新实现"端口子集按租户隔离 + 每租户活跃配额 + 跨租户原子批量"这一
套契约，作为差分测试的期望值来源。

身份：tkey = (tenant_id, key)，key = (内网IP, 内网端口, 目的IP, 目的端口)。

接口（普通数据结构）：
    RefTenantNAT(public_ip, ports, lifetime, quarantine, budget, tenants)
        tenants = [(tenant_id, (port, ...), max_active), ...]
    .allocate_many(tenant, keys, at=None)
        -> [(tid, key, port, generation, created), ...]
    .allocate_across(items, at=None)        # items = [(tid, key), ...]
        -> 同上
    .outbound(pkt, tenant, at=None)
        -> ("ok", five, tid) | ("drop", reason, tid_or_None)
    .inbound(pkt, at=None)
        -> ("ok", five, tid) | ("drop", reason, tid_or_None)
    .release(tenant, key, at=None) -> bool
    .advance(seconds) -> [(tid, key), ...]  # 升序
    .signature() -> (now, live, quar)

异常 RefError.tag:
    "validation" / "port_exhausted" / "budget_exhausted" / "quota_exceeded"

检查顺序与被测核心固定一致：
完整输入校验 -> 候选时刻过期规划 -> 配额检查（tid 升序）
-> 按输入次序（租户按首次出现次序）扫描各租户子集，预算跨租户累加。
"""

from __future__ import annotations


class RefError(Exception):
    def __init__(self, tag: str, detail: str) -> None:
        self.tag = tag
        super().__init__(f"{tag}: {detail}")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_key(key) -> None:
    ok = (
        isinstance(key, tuple) and len(key) == 4
        and isinstance(key[0], str) and _is_int(key[1])
        and isinstance(key[2], str) and _is_int(key[3])
        and 1 <= key[1] <= 65535 and 1 <= key[3] <= 65535
    )
    if not ok:
        raise RefError("validation", f"bad key {key!r}")


def _check_pkt(pkt) -> None:
    ok = (
        isinstance(pkt, tuple) and len(pkt) == 5
        and isinstance(pkt[0], str) and _is_int(pkt[1])
        and isinstance(pkt[2], str) and _is_int(pkt[3])
        and _is_int(pkt[4]) and pkt[4] >= 0
        and 1 <= pkt[1] <= 65535 and 1 <= pkt[3] <= 65535
    )
    if not ok:
        raise RefError("validation", f"bad packet {pkt!r}")


class RefTenantNAT:
    """字典版多租户地址依赖 NAT：与 adnat 同一契约、独立实现。"""

    def __init__(self, public_ip, ports, lifetime, quarantine, budget, tenants):
        # ---- 配置校验（镜像 NATConfig + TenantConfig 的拒绝规则） ----
        if not isinstance(public_ip, str):
            raise RefError("validation", "public_ip must be str")
        ports = tuple(ports)
        if not ports or any(not _is_int(p) or not 1 <= p <= 65535 for p in ports):
            raise RefError("validation", "bad ports")
        if len(set(ports)) != len(ports):
            raise RefError("validation", "duplicate ports")
        pool = tuple(sorted(ports))
        if not _is_int(lifetime) or lifetime < 1:
            raise RefError("validation", "bad lifetime")
        if not _is_int(quarantine) or quarantine < 0:
            raise RefError("validation", "bad quarantine")
        if not _is_int(budget) or budget < 1:
            raise RefError("validation", "bad budget")
        if not tenants or not isinstance(tenants, (list, tuple)):
            raise RefError("validation", "tenants required")

        self.public_ip = public_ip
        self.pool = pool
        self.lifetime = lifetime
        self.quarantine = quarantine
        self.budget = budget
        self.config_order: list[str] = []
        self.subsets: dict[str, tuple[int, ...]] = {}
        self.max_active: dict[str, int] = {}

        pool_set = set(pool)
        claimed: set[int] = set()
        for i, t in enumerate(tenants):
            if not isinstance(t, (list, tuple)) or len(t) != 3:
                raise RefError("validation", f"bad tenant spec at {i}")
            tid, tports, limit = t
            if not isinstance(tid, str) or not tid:
                raise RefError("validation", f"bad tenant id at {i}: {tid!r}")
            if tid in self.subsets:
                raise RefError("validation", f"duplicate tenant id {tid!r}")
            tports = tuple(tports)
            if (not tports or
                    any(not _is_int(p) or not 1 <= p <= 65535 for p in tports)
                    or len(set(tports)) != len(tports)):
                raise RefError("validation", f"bad ports for tenant {tid!r}")
            if not _is_int(limit) or limit < 1:
                raise RefError("validation", f"bad limit for tenant {tid!r}")
            for p in tports:
                if p not in pool_set:
                    raise RefError(
                        "validation",
                        f"tenant {tid!r} port {p} outside pool")
                if p in claimed:
                    raise RefError(
                        "validation", f"port {p} overlaps another tenant")
                claimed.add(p)
            self.config_order.append(tid)
            self.subsets[tid] = tuple(sorted(tports))
            self.max_active[tid] = limit

        self.now = 0
        # tkey -> [port, generation, created_at, last_seen, expires_at]
        self.maps: dict[tuple, list] = {}
        self.port_owner: dict[int, tuple] = {}
        self.quarantined: dict[int, int] = {}
        self.next_gen = 1

    # ---- 内部 ----

    def _resolve_at(self, at):
        if at is None:
            return self.now
        if not _is_int(at) or at < 0:
            raise RefError("validation", f"bad at {at!r}")
        return at

    def _clock(self, now):
        if now < self.now:
            raise RefError("validation", "clock backwards")

    def _require_tenant(self, tenant):
        if not isinstance(tenant, str) or not tenant or tenant not in self.subsets:
            raise RefError("validation", f"unknown tenant {tenant!r}")
        return tenant

    def _expired(self, now):
        return {k for k, r in self.maps.items() if now >= r[4]}

    def _housekeep(self, now):
        expired = self._expired(now)
        for k in expired:
            port = self.maps[k][0]
            del self.maps[k]
            del self.port_owner[port]
            self.quarantined[port] = now
        for p in [p for p, t in self.quarantined.items()
                  if now >= t + self.quarantine]:
            del self.quarantined[p]
        self.now = now
        return sorted(expired)

    def _plan(self, new_items, now):
        """new_items = [(tid, tkey), ...]（仅新建项，保持输入次序）。

        返回 {tkey: port}；租户按首次出现次序，子集升序扫描，预算共享。
        """
        expired = self._expired(now)
        used = {r[0] for k, r in self.maps.items() if k not in expired}
        # 隔离集合按候选时刻 housekeeping 后的投影：将在 now 过期回收的
        # 端口提交时即以 now 进入隔离，Q>0 时本次不可分配（隔离期不可跳过）。
        quar = {p for p, t in self.quarantined.items()
                if now < t + self.quarantine}
        if self.quarantine > 0:
            quar |= {r[0] for k, r in self.maps.items() if k in expired}
        inspected = 0
        assignments: dict[tuple, int] = {}

        order: list[str] = []
        for tid, _tk in new_items:
            if tid not in order:
                order.append(tid)
        for tid in order:
            wanted = [tk for tk in new_items if tk[0] == tid]
            chosen: list[int] = []
            for port in self.subsets[tid]:
                if len(chosen) == len(wanted):
                    break
                if inspected >= self.budget:
                    raise RefError(
                        "budget_exhausted",
                        f"tenant={tid!r} budget={self.budget} "
                        f"inspected={inspected} needed={len(wanted)} "
                        f"found={len(chosen)}")
                inspected += 1
                if port in used or port in quar:
                    continue
                chosen.append(port)
            if len(chosen) < len(wanted):
                raise RefError(
                    "port_exhausted",
                    f"tenant={tid!r} needed={len(wanted)} "
                    f"available={len(chosen)} subset={len(self.subsets[tid])}")
            for tk, port in zip(wanted, chosen):
                assignments[tk] = port
        return assignments

    def _check_quota(self, new_items, live):
        counts: dict[str, int] = {}
        for tid, _tk in new_items:
            counts[tid] = counts.get(tid, 0) + 1
        active: dict[str, int] = {}
        for tid, _k in live:
            active[tid] = active.get(tid, 0) + 1
        for tid in sorted(counts):
            limit = self.max_active[tid]
            n_new, n_active = counts[tid], active.get(tid, 0)
            if n_active + n_new > limit:
                raise RefError(
                    "quota_exceeded",
                    f"tenant={tid!r} active={n_active} requested={n_new} "
                    f"limit={limit}")

    def _submit(self, items, now):
        """items = [(tid, key), ...]（输入次序）；规划/配额已通过。"""
        self._housekeep(now)
        out = []
        assignments_pending = getattr(self, "_pending", None)
        for tid, key in items:
            tkey = (tid, key)
            rec = self.maps.get(tkey)
            if rec is not None:
                out.append((tid, key, rec[0], rec[1], False))
                continue
            port = assignments_pending[tkey]
            self.maps[tkey] = [port, self.next_gen, now, now,
                               now + self.lifetime]
            gen = self.next_gen
            self.next_gen += 1
            self.port_owner[port] = tkey
            out.append((tid, key, port, gen, True))
        return out

    def _allocate(self, items, now):
        """公共分配流程：items=[(tid,key),...]，假定 tid 均已解析。"""
        now = self._resolve_at(now)
        for _tid, key in items:
            _check_key(key)
        tkeys = [(tid, key) for tid, key in items]
        if len(set(tkeys)) != len(tkeys):
            raise RefError("validation", "duplicate (tenant, key) in batch")
        self._clock(now)
        expired = self._expired(now)
        live = set(self.maps) - expired
        new_items = [tk for tk in tkeys if tk not in live]
        self._check_quota(new_items, live)
        self._pending = self._plan(new_items, now)
        try:
            return self._submit(items, now)
        finally:
            self._pending = None

    # ---- 公开操作 ----

    def allocate_many(self, tenant, keys, at=None):
        tid = self._require_tenant(tenant)
        keys = list(keys)
        return self._allocate([(tid, k) for k in keys], at)

    def allocate_across(self, items, at=None):
        items = list(items)
        for i, it in enumerate(items):
            if not isinstance(it, tuple) or len(it) != 2:
                raise RefError("validation", f"bad item at {i}: {it!r}")
        for tid, _key in items:
            self._require_tenant(tid)
        return self._allocate(items, at)

    def outbound(self, pkt, tenant, at=None):
        now = self._resolve_at(at)
        tid = self._require_tenant(tenant)
        _check_pkt(pkt)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        tkey = (tid, (s_ip, s_pt, d_ip, d_pt))
        rec = self.maps.get(tkey)
        if rec is None:
            return ("drop", "no_mapping", None)
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation", tid)
        rec[3] = now
        rec[4] = now + self.lifetime
        return ("ok", (17, self.public_ip, rec[0], d_ip, d_pt), tid)

    def inbound(self, pkt, at=None):
        now = self._resolve_at(at)
        _check_pkt(pkt)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        if d_ip != self.public_ip:
            return ("drop", "dest_mismatch", None)
        tkey = self.port_owner.get(d_pt)
        if tkey is None:
            return ("drop", "no_mapping", None)
        tid, key = tkey
        rec = self.maps[tkey]
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation", tid)
        if (s_ip, s_pt) != (key[2], key[3]):
            return ("drop", "peer_mismatch", tid)
        rec[3] = now
        rec[4] = now + self.lifetime
        return ("ok", (17, s_ip, s_pt, key[0], key[1]), tid)

    def release(self, tenant, key, at=None):
        now = self._resolve_at(at)
        tid = self._require_tenant(tenant)
        _check_key(key)
        self._clock(now)
        self._housekeep(now)
        rec = self.maps.pop((tid, key), None)
        if rec is None:
            return False
        del self.port_owner[rec[0]]
        self.quarantined[rec[0]] = now
        return True

    def advance(self, seconds):
        if not _is_int(seconds) or seconds < 0:
            raise RefError("validation", f"bad seconds {seconds!r}")
        return self._housekeep(self.now + seconds)

    def signature(self):
        live = tuple(sorted(
            (k, tuple(v)) for k, v in self.maps.items() if self.now < v[4]
        ))
        quar = tuple(sorted(self.quarantined.items()))
        return (self.now, live, quar, self.next_gen)
