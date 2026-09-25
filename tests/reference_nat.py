"""独立字典参考实现（测试 oracle）——多租户版。

刻意不导入 adnat.core / adnat.model：只用标准字典与元组重新实现同一套
契约，作为差分测试的期望值来源。它不从被测核心获取任何结果。

默认模式（tenants=None）与基线契约完全一致：
    RefNAT(public_ip, ports, lifetime, quarantine, budget)
    .allocate_many(keys, at=None)   -> list[(key, port, generation, created)]
    .outbound(pkt, at=None)         -> ("ok", five) | ("drop", reason)
    .inbound(pkt, at=None)          -> ("ok", five) | ("drop", reason)
    .release(key, at=None)          -> bool
    .advance(seconds)               -> list[key]
    .signature()                    -> (now, live_by_key, quar, next_gen)

多租户模式（tenants={"id": (ports_tuple, max_mappings), ...}）：
    .allocate_many(keys, at=None, tenant_id=...)
    .allocate_across_tenants(items, at=None)
                                    items=[(tenant_id, key), ...]
                                    -> list[(tenant_id, key, port, gen, created)]
    .outbound(pkt, at=None, tenant_id=...)
    .inbound(pkt, at=None)
    .release(key, at=None, tenant_id=...)
    .advance_tenants(seconds)       -> list[(tenant_id, key)]
    .signature_t()                  -> (now, live_by_identity, quar, next_gen)

异常：输入/容量问题抛 RefError，其 .tag 区分
    "validation" / "quota_exceeded" / "port_exhausted" / "budget_exhausted"
差分测试只比对 tag 与公开结果，不比对异常类型本身。

key      = (内网IP, 内网端口, 目的IP, 目的端口)
identity = (tenant_id, key)
pkt      = (src_ip, src_port, dst_ip, dst_port, generation)
five     = (17, src_ip, src_port, dst_ip, dst_port)
"""

from __future__ import annotations

DEFAULT_TENANT = "default"


class RefError(Exception):
    def __init__(self, tag: str, detail: str) -> None:
        self.tag = tag
        super().__init__(f"{tag}: {detail}")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_id(tid) -> None:
    if not isinstance(tid, str) or len(tid) == 0:
        raise RefError("validation", f"bad tenant_id {tid!r}")


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


def _normalize_tenants(tenants, total_ports):
    """与 NATConfig 同口径的租户表校验，返回 {tid: (ports_tuple, limit)}。"""
    if tenants is None:
        return {DEFAULT_TENANT: (tuple(sorted(total_ports)), None)}
    if not isinstance(tenants, (tuple, list, dict)):
        raise RefError("validation", "bad tenants container")
    normalized = {}
    if isinstance(tenants, dict):
        items = list(tenants.items())
    else:
        items = tenants
    seen_ports = set()
    pool = set(total_ports)
    for entry in items:
        if isinstance(tenants, dict):
            tid, spec = entry
            if not isinstance(spec, (tuple, list)) or len(spec) != 2:
                raise RefError("validation", f"bad tenant spec for {tid!r}")
            ports, limit = spec
        else:
            if not isinstance(entry, (tuple, list)) or len(entry) != 3:
                raise RefError("validation", f"bad tenant entry {entry!r}")
            tid, ports, limit = entry
        _check_id(tid)
        if tid in normalized:
            raise RefError("validation", f"duplicate tenant id {tid!r}")
        if (not isinstance(ports, (tuple, list)) or not ports
                or any(not _is_int(p) or not 1 <= p <= 65535 for p in ports)):
            raise RefError("validation", f"tenant {tid!r}: bad ports")
        if len(set(ports)) != len(ports):
            raise RefError("validation", f"tenant {tid!r}: duplicate ports")
        if limit is not None and (not _is_int(limit) or limit < 1):
            raise RefError("validation", f"tenant {tid!r}: bad max_mappings")
        ps = tuple(sorted(ports))
        overlap = seen_ports.intersection(ps)
        if overlap:
            raise RefError("validation",
                           f"tenant {tid!r}: overlapping ports {sorted(overlap)}")
        outside = [p for p in ps if p not in pool]
        if outside:
            raise RefError("validation",
                           f"tenant {tid!r}: ports outside pool {outside}")
        seen_ports.update(ps)
        normalized[tid] = (ps, limit)
    if not normalized:
        raise RefError("validation", "empty tenant table")
    return normalized


class RefNAT:
    """字典版多租户地址依赖 NAT：与 adnat 同一契约、独立实现。"""

    def __init__(self, public_ip, ports, lifetime, quarantine, budget=None,
                 tenants=None):
        if not isinstance(public_ip, str):
            raise RefError("validation", "public_ip must be str")
        ports = tuple(ports)
        if not ports or any(not _is_int(p) or not 1 <= p <= 65535 for p in ports):
            raise RefError("validation", "bad ports")
        if len(set(ports)) != len(ports):
            raise RefError("validation", "duplicate ports")
        if not _is_int(lifetime) or lifetime < 1:
            raise RefError("validation", "bad lifetime")
        if not _is_int(quarantine) or quarantine < 0:
            raise RefError("validation", "bad quarantine")
        if budget is None:
            budget = len(ports)
        if not _is_int(budget) or budget < 1:
            raise RefError("validation", "bad budget")
        self.public_ip = public_ip
        self.ports = tuple(sorted(ports))
        self.lifetime = lifetime
        self.quarantine = quarantine
        self.budget = budget
        # tenants: tid -> (sorted ports tuple, max_mappings|None)
        self.tenants = _normalize_tenants(tenants, self.ports)
        self.port_tenant = {p: tid for tid, (ps, _l) in self.tenants.items()
                            for p in ps}
        self.now = 0
        # identity -> [port, generation, created_at, last_seen, expires_at,
        #              internal, remote]
        self.maps = {}
        self.port_owner = {}      # port -> identity
        self.quarantined = {}     # port -> released_at
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

    def _require_tenant(self, tid):
        _check_id(tid)
        if tid not in self.tenants:
            raise RefError("validation", f"unknown tenant_id {tid!r}")

    def _expired(self, now):
        return {ident for ident, r in self.maps.items() if now >= r[4]}

    def _housekeep(self, now):
        expired = self._expired(now)
        for ident in expired:
            port = self.maps[ident][0]
            del self.maps[ident]
            del self.port_owner[port]
            self.quarantined[port] = now
        for p in [p for p, t in self.quarantined.items()
                  if now >= t + self.quarantine]:
            del self.quarantined[p]
        self.now = now
        return sorted(expired)

    def _plan(self, tid, count, now):
        """为租户 tid 规划 count 个最小空闲端口；预算逐租户独立计数。"""
        if count == 0:
            return []
        tenant_ports = self.tenants[tid][0]
        expired = self._expired(now)
        used = {r[0] for ident, r in self.maps.items() if ident not in expired}
        quar = {p for p, t in self.quarantined.items()
                if now < t + self.quarantine}
        chosen, inspected = [], 0
        for p in tenant_ports:
            if len(chosen) == count:
                break
            if inspected >= self.budget:
                raise RefError("budget_exhausted",
                               f"tenant={tid} budget={self.budget} "
                               f"needed={count} found={len(chosen)}")
            inspected += 1
            if p in used or p in quar:
                continue
            chosen.append(p)
        if len(chosen) < count:
            raise RefError("port_exhausted",
                           f"tenant={tid} needed={count} "
                           f"available={len(chosen)} pool={len(tenant_ports)}")
        return chosen

    def _allocate_identities(self, spec, now):
        """共享分配核心。spec = [(tid, key, internal_ep, remote_ep), ...]。

        固定顺序：输入校验 -> 候选时刻过期规划 -> 配额 -> 按租户首次出现
        次序规划端口 -> 一次性提交。
        """
        identities = [(tid, key) for tid, key, _i, _r in spec]
        if len(set(identities)) != len(identities):
            raise RefError("validation", "duplicate (tenant_id, key) in batch")
        for tid, key, _i, _r in spec:
            self._require_tenant(tid)
            _check_key(key)
        self._clock(now)

        expired = self._expired(now)
        live = set(self.maps) - expired
        order = []
        new_by = {}
        for tid, key, _i, _r in spec:
            if tid not in new_by:
                new_by[tid] = []
                order.append(tid)
            if (tid, key) not in live:
                new_by[tid].append((tid, key))

        # 配额检查整体先于端口规划。
        for tid in order:
            limit = self.tenants[tid][1]
            if limit is not None:
                active = sum(1 for (t, _k) in live if t == tid)
                want = active + len(new_by[tid])
                if want > limit:
                    raise RefError(
                        "quota_exceeded",
                        f"tenant={tid} active={active} new={len(new_by[tid])} "
                        f"limit={limit}")

        plans = {tid: self._plan(tid, len(new_by[tid]), now) for tid in order}

        self._housekeep(now)
        iters = {tid: iter(ps) for tid, ps in plans.items()}
        out = []
        for (tid, key, internal, remote) in spec:
            rec = self.maps.get((tid, key))
            if rec is not None:
                out.append((tid, key, rec[0], rec[1], False))
                continue
            port = next(iters[tid])
            self.maps[(tid, key)] = [
                port, self.next_gen, now, now, now + self.lifetime,
                internal, remote,
            ]
            self.next_gen += 1
            self.port_owner[port] = (tid, key)
            out.append((tid, key, port, self.maps[(tid, key)][1], True))
        return out

    # ---- 默认模式公开操作（基线契约） ----

    def allocate_many(self, keys, at=None, tenant_id=DEFAULT_TENANT):
        now = self._resolve_at(at)
        keys = list(keys)
        for k in keys:
            _check_key(k)
        spec = [(tenant_id, k, (k[0], k[1]), (k[2], k[3])) for k in keys]
        out = self._allocate_identities(spec, now)
        if tenant_id == DEFAULT_TENANT and DEFAULT_TENANT in self.tenants \
                and len(self.tenants) == 1:
            # 默认单租户模式：剥掉租户列，保持基线输出形状。
            return [(key, port, gen, created)
                    for _tid, key, port, gen, created in out]
        return out

    def allocate_across_tenants(self, items, at=None):
        """items = [(tenant_id, key), ...]"""
        now = self._resolve_at(at)
        items = list(items)
        spec = [(tid, key, (key[0], key[1]), (key[2], key[3]))
                for tid, key in items]
        return self._allocate_identities(spec, now)

    def outbound(self, pkt, at=None, tenant_id=DEFAULT_TENANT):
        now = self._resolve_at(at)
        _check_pkt(pkt)
        self._require_tenant(tenant_id)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        ident = (tenant_id, (s_ip, s_pt, d_ip, d_pt))
        rec = self.maps.get(ident)
        if rec is None:
            return ("drop", "no_mapping", None)
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation", tenant_id)
        rec[3] = now
        rec[4] = now + self.lifetime
        return ("ok", (17, self.public_ip, rec[0], d_ip, d_pt), tenant_id)

    def inbound(self, pkt, at=None):
        now = self._resolve_at(at)
        _check_pkt(pkt)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        if d_ip != self.public_ip:
            return ("drop", "dest_mismatch", None)
        ident = self.port_owner.get(d_pt)
        if ident is None:
            if d_pt not in self.port_tenant:
                return ("drop", "unknown_tenant", None)
            return ("drop", "no_mapping", None)
        tid, key = ident
        rec = self.maps[ident]
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation", tid)
        if (s_ip, s_pt) != (key[2], key[3]):
            return ("drop", "peer_mismatch", tid)
        rec[3] = now
        rec[4] = now + self.lifetime
        i_ip, i_pt = key[0], key[1]
        return ("ok", (17, s_ip, s_pt, i_ip, i_pt), tid)

    def release(self, key, at=None, tenant_id=DEFAULT_TENANT):
        now = self._resolve_at(at)
        _check_key(key)
        self._require_tenant(tenant_id)
        self._clock(now)
        self._housekeep(now)
        rec = self.maps.pop((tenant_id, key), None)
        if rec is None:
            return False
        del self.port_owner[rec[0]]
        self.quarantined[rec[0]] = now
        return True

    def advance(self, seconds):
        if not _is_int(seconds) or seconds < 0:
            raise RefError("validation", f"bad seconds {seconds!r}")
        expired = self._housekeep(self.now + seconds)
        if len(self.tenants) == 1 and DEFAULT_TENANT in self.tenants:
            return [key for _tid, key in expired]
        return expired

    def advance_tenants(self, seconds):
        if not _is_int(seconds) or seconds < 0:
            raise RefError("validation", f"bad seconds {seconds!r}")
        return self._housekeep(self.now + seconds)

    # ---- 状态签名 ----

    def signature(self):
        """默认模式规范化状态：剥掉租户列（与基线一致）。"""
        live = tuple(sorted(
            (key, tuple(v[:5])) for (tid, key), v in self.maps.items()
            if tid == DEFAULT_TENANT and self.now < v[4]
        ))
        quar = tuple(sorted(self.quarantined.items()))
        return (self.now, live, quar, self.next_gen)

    def signature_t(self):
        """多租户规范化状态：身份带租户。"""
        live = tuple(sorted(
            (ident, tuple(v[:5])) for ident, v in self.maps.items()
            if self.now < v[4]
        ))
        quar = tuple(sorted(self.quarantined.items()))
        return (self.now, live, quar, self.next_gen)
