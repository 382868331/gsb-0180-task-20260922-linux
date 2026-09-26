"""独立字典参考实现（测试 oracle）。

刻意不导入 adnat.core / adnat.model：只用标准字典与元组重新实现同一套
契约，作为差分测试的期望值来源。它不从被测核心获取任何结果。

接口（全部为普通数据结构）：
    RefNAT(public_ip, ports, lifetime, quarantine, budget)
    .allocate_many(keys, at=None)   -> list[(key, port, generation, created)]
    .outbound(pkt, at=None)         -> ("ok", five) | ("drop", reason)
    .inbound(pkt, at=None)          -> ("ok", five) | ("drop", reason)
    .release(key, at=None)          -> bool
    .advance(seconds)               -> list[key]
    .signature()                    -> 可比较的规范化状态元组

异常：输入/容量问题抛 RefError，其 .tag 区分
    "validation" / "port_exhausted" / "budget_exhausted"
差分测试只比对 tag 与公开结果，不比对异常类型本身。

key  = (内网IP, 内网端口, 目的IP, 目的端口)
pkt  = (src_ip, src_port, dst_ip, dst_port, generation)
five = (17, src_ip, src_port, dst_ip, dst_port)
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


class RefNAT:
    """字典版地址依赖 NAT：与 adnat 同一契约、独立实现。"""

    def __init__(self, public_ip, ports, lifetime, quarantine, budget=None):
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
        self.now = 0
        # key -> [port, generation, created_at, last_seen, expires_at]
        self.maps = {}
        self.port_owner = {}      # port -> key
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

    def _plan(self, count, now):
        expired = self._expired(now)
        used = {r[0] for k, r in self.maps.items() if k not in expired}
        quar = {p for p, t in self.quarantined.items()
                if now < t + self.quarantine}
        chosen, inspected = [], 0
        for p in self.ports:
            if len(chosen) == count:
                break
            if inspected >= self.budget:
                raise RefError("budget_exhausted",
                               f"budget={self.budget} needed={count}")
            inspected += 1
            if p in used or p in quar:
                continue
            chosen.append(p)
        if len(chosen) < count:
            raise RefError("port_exhausted",
                           f"needed={count} available={len(chosen)}")
        return chosen

    # ---- 公开操作 ----

    def allocate_many(self, keys, at=None):
        now = self._resolve_at(at)
        keys = list(keys)
        for k in keys:
            _check_key(k)
        if len(set(keys)) != len(keys):
            raise RefError("validation", "duplicate keys in batch")
        self._clock(now)
        expired = self._expired(now)
        live = set(self.maps) - expired
        new_keys = [k for k in keys if k not in live]
        ports = self._plan(len(new_keys), now)
        self._housekeep(now)
        out = []
        it = iter(ports)
        for k in keys:
            rec = self.maps.get(k)
            if rec is not None:
                out.append((k, rec[0], rec[1], False))
                continue
            port = next(it)
            self.maps[k] = [port, self.next_gen, now, now, now + self.lifetime]
            self.next_gen += 1
            self.port_owner[port] = k
            out.append((k, port, self.maps[k][1], True))
        return out

    def outbound(self, pkt, at=None):
        now = self._resolve_at(at)
        _check_pkt(pkt)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        key = (s_ip, s_pt, d_ip, d_pt)
        rec = self.maps.get(key)
        if rec is None:
            return ("drop", "no_mapping")
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation")
        rec[3] = now
        rec[4] = now + self.lifetime
        return ("ok", (17, self.public_ip, rec[0], d_ip, d_pt))

    def inbound(self, pkt, at=None):
        now = self._resolve_at(at)
        _check_pkt(pkt)
        self._clock(now)
        self._housekeep(now)
        s_ip, s_pt, d_ip, d_pt, gen = pkt
        if d_ip != self.public_ip:
            return ("drop", "dest_mismatch")
        key = self.port_owner.get(d_pt)
        if key is None:
            return ("drop", "no_mapping")
        rec = self.maps[key]
        if gen != 0 and gen != rec[1]:
            return ("drop", "stale_generation")
        if (s_ip, s_pt) != (key[2], key[3]):
            return ("drop", "peer_mismatch")
        rec[3] = now
        rec[4] = now + self.lifetime
        i_ip, i_pt = key[0], key[1]
        return ("ok", (17, s_ip, s_pt, i_ip, i_pt))

    def error(self, rep, at=None):
        """差错报文反查（独立字典实现）。

        rep = (outer_src_ip, outer_src_port, proto, q_src_ip, q_src_port,
               q_dst_ip, q_dst_port, generation)
        -> ("ok", (17, os_ip, os_pt, inner_ip, inner_pt), mapping_id)
           | ("drop", reason, mapping_id_or_None)
        不修改任何状态（不刷新、不创建）。
        """
        now = self._resolve_at(at)
        self._clock(now)
        if (not isinstance(rep, tuple) or len(rep) != 8
                or not _is_int(rep[1]) or not _is_int(rep[2])
                or not _is_int(rep[4]) or not _is_int(rep[6])
                or not _is_int(rep[7])
                or not all(isinstance(rep[i], str) for i in (0, 3, 5))):
            raise RefError("validation", f"bad error report {rep!r}")
        os_ip, os_pt, proto, qs_ip, qs_pt, qd_ip, qd_pt, gen = rep
        for v in (os_pt, qs_pt, qd_pt):
            if not 1 <= v <= 65535:
                raise RefError("validation", f"bad port in {rep!r}")
        if gen < 0:
            raise RefError("validation", f"bad generation {gen}")
        self._housekeep(now)
        if proto != 17 or qs_ip != self.public_ip:
            return ("drop", "bad_structure", None)
        cands = [(k, r) for k, r in self.maps.items()
                 if r[0] == qs_pt and now < r[4]]
        if not cands:
            return ("drop", "no_mapping", None)
        if len(cands) > 1:
            return ("drop", "ambiguous_reference", None)
        k, r = cands[0]
        mid = r[1]
        if gen != 0 and gen != r[1]:
            return ("drop", "stale_generation", mid)
        if (qd_ip, qd_pt) != (k[2], k[3]):
            return ("drop", "peer_mismatch", mid)
        return ("ok", (17, os_ip, os_pt, k[0], k[1]), mid)
    def release(self, key, at=None):
        now = self._resolve_at(at)
        _check_key(key)
        self._clock(now)
        self._housekeep(now)
        rec = self.maps.pop(key, None)
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
        """规范化状态：活跃映射、端口属主、隔离表、时钟、下一代号。"""
        live = tuple(sorted(
            (k, tuple(v)) for k, v in self.maps.items() if self.now < v[4]
        ))
        quar = tuple(sorted(self.quarantined.items()))
        return (self.now, live, quar, self.next_gen)
