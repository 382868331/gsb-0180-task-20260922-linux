"""多租户差分测试：被测核心 vs 独立字典多租户参考（reference_tenant_nat.py）。

参考实现不导入 adnat，双方只共享公开契约。随机操作在两侧各执行一次，
逐事件比对：异常 tag、分配结果（含租户）、改写五元组/丢弃原因/租户身份、
规范化状态签名（时钟、活跃映射、隔离表）。种子固定，失败可复现。

重点压力：
- 两个租户反复使用完全相同的内网四元组；
- 小子集 + 小配额频繁触发 quota / port / budget 三类失败及整批回滚；
- 跨租户批量混合新建/复用/失败；
- 过期边界与隔离期（含"配额已空但端口仍隔离"）。
"""

from __future__ import annotations

import random
import unittest

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    TenantAllocationRequest,
    TenantConfig,
    ValidationError,
)
from reference_tenant_nat import RefError, RefTenantNAT

PUB = "203.0.113.9"
POOL = (7001, 7002, 7003, 7004, 7005, 7006)
PORTS_A = (7001, 7002, 7003)
PORTS_B = (7004, 7005, 7006)
T_A, T_B = "alpha", "beta"
TENANTS = (T_A, T_B)

INTERNALS = [Endpoint("10.1.0.1", 5000), Endpoint("10.1.0.2", 5001)]
REMOTES = [Endpoint("198.51.100.1", 53), Endpoint("198.51.100.2", 443),
           Endpoint("203.0.113.200", 1234)]
KEYS = [(i.ip, i.port, r.ip, r.port) for i in INTERNALS for r in REMOTES]


def core_signature(nat: AddressDependentNAT):
    live = tuple(sorted(
        ((m.tenant, m.key), (m.external_port, m.generation, m.created_at,
                             m.last_seen, m.expires_at))
        for m in nat.snapshot_mappings()
    ))
    return (nat.now, live, tuple(sorted(nat.quarantined_ports().items())))


def ref_signature(ref: RefTenantNAT):
    now, live, quar, _gen = ref.signature()
    return (now, live, quar)


def core_tag(exc: Exception) -> str:
    if isinstance(exc, QuotaExceededError):
        return "quota_exceeded"
    if isinstance(exc, PortExhaustionError):
        return "port_exhausted"
    if isinstance(exc, SearchBudgetExhaustedError):
        return "budget_exhausted"
    if isinstance(exc, ValidationError):
        return "validation"
    return f"unexpected:{type(exc).__name__}"


def ref_tag(exc: Exception) -> str:
    if isinstance(exc, RefError):
        return exc.tag
    return f"unexpected:{type(exc).__name__}"


class Pair:
    def __init__(self, lifetime, quarantine, budget, max_a, max_b):
        self.core = AddressDependentNAT(NATConfig(
            public_ip=PUB, external_ports=POOL,
            lifetime=lifetime, quarantine=quarantine, search_budget=budget,
            tenants=(
                TenantConfig(T_A, PORTS_A, max_a),
                TenantConfig(T_B, PORTS_B, max_b),
            )))
        self.ref = RefTenantNAT(
            PUB, POOL, lifetime, quarantine,
            budget if budget is not None else len(POOL),
            [(T_A, PORTS_A, max_a), (T_B, PORTS_B, max_b)])
        # (tid, key) -> (port, gen)：生成命中改写/入站包所需观测值。
        self.known: dict[tuple, tuple[int, int]] = {}


class TestTenantDifferential(unittest.TestCase):
    def run_scenario(self, seed, steps, lifetime, quarantine, budget,
                     max_a, max_b):
        rng = random.Random(seed)
        pair = Pair(lifetime, quarantine, budget, max_a, max_b)
        core, ref = pair.core, pair.ref

        def check_state():
            self.assertEqual(core_signature(core), ref_signature(ref),
                             f"state diverged (seed={seed})")

        def do_single_batch(tid, keys):
            core_out = ref_out = None
            core_exc = ref_exc = None
            try:
                res = core.allocate_many(
                    [AllocationRequest(Endpoint(k[0], k[1]),
                                       Endpoint(k[2], k[3])) for k in keys],
                    tenant=tid)
                core_out = [(r.tenant, r.key, r.mapping.external_port,
                             r.mapping.generation, r.created) for r in res]
            except Exception as exc:  # noqa: BLE001 - 比对异常类别
                core_exc = exc
            try:
                ref_out = ref.allocate_many(tid, keys)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc),
                                 f"alloc exc mismatch tid={tid} keys={keys}: "
                                 f"{core_exc!r} vs {ref_exc!r}")
                self.assertIsNotNone(core_exc)
                self.assertIsNotNone(ref_exc)
            else:
                self.assertEqual(core_out, ref_out)
                for tid_, key, port, gen, _created in core_out:
                    pair.known[(tid_, key)] = (port, gen)
            check_state()

        def do_cross_batch(items):
            core_out = ref_out = None
            core_exc = ref_exc = None
            try:
                res = core.allocate_across_tenants([
                    TenantAllocationRequest(
                        tid, Endpoint(k[0], k[1]), Endpoint(k[2], k[3]))
                    for tid, k in items])
                core_out = [(r.tenant, r.key, r.mapping.external_port,
                             r.mapping.generation, r.created) for r in res]
            except Exception as exc:  # noqa: BLE001
                core_exc = exc
            try:
                ref_out = ref.allocate_across(items)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc),
                                 f"cross exc mismatch items={items}: "
                                 f"{core_exc!r} vs {ref_exc!r}")
                self.assertIsNotNone(core_exc)
                self.assertIsNotNone(ref_exc)
            else:
                self.assertEqual(core_out, ref_out)
                for tid, key, port, gen, _created in core_out:
                    pair.known[(tid, key)] = (port, gen)
            check_state()

        def do_outbound(tid, key, gen):
            pkt = Packet(Endpoint(key[0], key[1]), Endpoint(key[2], key[3]),
                         generation=gen)
            core_exc = ref_exc = None
            try:
                res = core.translate_outbound(pkt, tenant=tid)
                if res.accepted:
                    f = res.rewritten
                    core_out = ("ok", (f.protocol, f.src_ip, f.src_port,
                                       f.dst_ip, f.dst_port), res.tenant)
                else:
                    core_out = ("drop", res.reason.value, res.tenant)
            except Exception as exc:  # noqa: BLE001
                core_exc = exc
                core_out = None
            try:
                ref_out = ref.outbound(
                    (key[0], key[1], key[2], key[3], gen), tid)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
                ref_out = None
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc))
            else:
                self.assertEqual(core_out, ref_out, f"outbound {tid} {key}")
            check_state()

        def do_inbound(tid, key, port, src_ep, gen):
            pkt = Packet(src_ep, Endpoint(PUB, port), generation=gen)
            res = core.translate_inbound(pkt)
            if res.accepted:
                f = res.rewritten
                core_out = ("ok", (f.protocol, f.src_ip, f.src_port,
                                   f.dst_ip, f.dst_port), res.tenant)
            else:
                core_out = ("drop", res.reason.value, res.tenant)
            ref_out = ref.inbound(
                (src_ep.ip, src_ep.port, PUB, port, gen))
            self.assertEqual(core_out, ref_out,
                             f"inbound {src_ep} -> :{port} gen={gen}")
            check_state()

        def do_release(tid, key):
            self.assertEqual(core.release(key, tenant=tid),
                             ref.release(tid, key))
            check_state()

        def do_advance(seconds):
            self.assertEqual(core.advance(seconds), ref.advance(seconds))
            check_state()

        for _ in range(steps):
            roll = rng.random()
            if roll < 0.22:                       # 单租户批量
                tid = rng.choice(TENANTS)
                keys = rng.sample(KEYS, rng.randint(1, len(KEYS)))
                do_single_batch(tid, keys)
            elif roll < 0.42:                     # 跨租户批量
                n_items = rng.randint(1, 5)
                items = [(rng.choice(TENANTS), rng.choice(KEYS))
                         for _ in range(n_items)]
                do_cross_batch(items)
            elif roll < 0.60:                     # 出站
                tid = rng.choice(TENANTS)
                key = rng.choice(KEYS)
                known = pair.known.get((tid, key), (0, 0))[1]
                gen = rng.choice([0, known, known + 1, 1])
                do_outbound(tid, key, gen)
            elif roll < 0.78:                     # 入站
                if pair.known and rng.random() < 0.8:
                    (tid, key), (port, gen0) = rng.choice(
                        list(pair.known.items()))
                    gen = rng.choice([0, gen0, gen0 + 1])
                    if rng.random() < 0.6:
                        src = Endpoint(key[2], key[3])     # 正确对端
                    else:
                        src = rng.choice(REMOTES)
                else:
                    tid, key = rng.choice(TENANTS), rng.choice(KEYS)
                    port = rng.choice(POOL)
                    src = rng.choice(REMOTES)
                    gen = 0
                do_inbound(tid, key, port, src, gen)
            elif roll < 0.90:                     # 释放
                do_release(rng.choice(TENANTS), rng.choice(KEYS))
            else:                                 # 推进时钟
                do_advance(rng.randint(0, 8))

    def test_random_walks_match_reference(self):
        # (种子, 步数, 寿命, 隔离, 预算, alpha配额, beta配额)
        scenarios = [
            (1234, 500, 12, 5, None, 3, 3),
            (7, 500, 8, 3, None, 2, 1),
            (99, 500, 10, 4, 3, 2, 2),       # 预算 < 池：跨租户预算耗尽
            (2026, 500, 6, 2, 4, 1, 3),      # 频繁配额失败 + 短寿命
            (31337, 500, 15, 6, 2, 3, 2),
            (555, 500, 5, 0, None, 1, 1),    # Q=0：过期立即可用
            (8080, 500, 9, 7, 5, 2, 2),      # 长隔离：配额空但端口不可用
        ]
        for seed, steps, lifetime, quarantine, budget, max_a, max_b in scenarios:
            with self.subTest(seed=seed, lifetime=lifetime,
                              quarantine=quarantine, budget=budget,
                              max_a=max_a, max_b=max_b):
                self.run_scenario(seed, steps, lifetime, quarantine, budget,
                                  max_a, max_b)


if __name__ == "__main__":
    unittest.main()
