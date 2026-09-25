"""多租户差分测试：被测核心 vs 独立字典参考（tests/reference_nat.py）。

两租户使用完全相同的内网端点池（本题核心场景）。每个随机事件在两侧各
执行一次，比对公开结果（含租户身份、改写五元组、丢弃原因、异常 tag）
与规范化状态签名（含全局 generation 序号，验证失败回滚不发号）。
"""

from __future__ import annotations

import random
import unittest

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    NATConfig,
    Endpoint,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    TenantConfig,
    TenantRequest,
    ValidationError,
)
from reference_nat import RefError, RefNAT

PUB = "203.0.113.9"
TA, TB = "cust-alpha", "cust-beta"
PORTS_A = (7001, 7002, 7003)
PORTS_B = (7101, 7102, 7103)
ALL_PORTS = PORTS_A + PORTS_B
# 两家共用同一组合成内网地址 —— 跨租户同 key 是常态而非例外。
INTERNALS = [Endpoint("10.1.0.1", 5000), Endpoint("10.1.0.2", 5001)]
REMOTES = [Endpoint("198.51.100.1", 53), Endpoint("198.51.100.2", 443),
           Endpoint("203.0.113.200", 1234)]
KEYS = [(i.ip, i.port, r.ip, r.port) for i in INTERNALS for r in REMOTES]
TENANTS = (TA, TB)
TENANT_PORTS = {TA: PORTS_A, TB: PORTS_B}


def core_signature(nat: AddressDependentNAT):
    live = tuple(sorted(
        ((m.tenant, m.key),
         (m.external_port, m.generation, m.created_at,
          m.last_seen, m.expires_at))
        for m in nat.snapshot_mappings()
    ))
    return (nat.now, live,
            tuple(sorted(nat.quarantined_ports().items())),
            nat._next_generation)  # noqa: SLF001 - 差分测试需要验证回滚不发号


def ref_signature(ref: RefNAT):
    return ref.signature_t()


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


def norm_core_translation(res):
    if res.accepted:
        f = res.rewritten
        return ("ok", (f.protocol, f.src_ip, f.src_port,
                       f.dst_ip, f.dst_port), res.tenant)
    return ("drop", res.reason.value, res.tenant)


class Pair:
    def __init__(self, lifetime, quarantine, budget, limit):
        self.core = AddressDependentNAT(NATConfig(
            public_ip=PUB, external_ports=ALL_PORTS,
            lifetime=lifetime, quarantine=quarantine, search_budget=budget,
            tenants=(TenantConfig(TA, PORTS_A, limit),
                     TenantConfig(TB, PORTS_B, limit)),
        ))
        self.ref = RefNAT(
            PUB, ALL_PORTS, lifetime, quarantine,
            budget if budget is not None else len(ALL_PORTS),
            tenants={TA: (PORTS_A, limit), TB: (PORTS_B, limit)},
        )
        # (tid, key) -> 最近分配所得 generation / 外端口
        self.known_gen: dict[tuple, int] = {}
        self.known_port: dict[tuple, int] = {}


class TestTenantDifferential(unittest.TestCase):
    def run_scenario(self, seed, steps, lifetime, quarantine, budget, limit):
        rng = random.Random(seed)
        pair = Pair(lifetime, quarantine, budget, limit)
        core, ref = pair.core, pair.ref

        def check_state():
            self.assertEqual(core_signature(core), ref_signature(ref),
                             f"state diverged (seed={seed})")

        def do_alloc_one(tid, keys):
            core_exc = ref_exc = None
            core_out = ref_out = None
            try:
                res = core.allocate_many([
                    AllocationRequest(Endpoint(k[0], k[1]),
                                      Endpoint(k[2], k[3]))
                    for k in keys
                ], tenant_id=tid)
                core_out = [(r.tenant, r.key, r.mapping.external_port,
                             r.mapping.generation, r.created) for r in res]
            except Exception as exc:  # noqa: BLE001
                core_exc = exc
            try:
                ref_out = ref.allocate_many(keys, tenant_id=tid)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc),
                                 f"alloc exc mismatch tid={tid} keys={keys}")
                self.assertIsNotNone(core_exc)
                self.assertIsNotNone(ref_exc)
            else:
                self.assertEqual(core_out, ref_out,
                                 f"alloc mismatch tid={tid} keys={keys}")
                for tid2, k, port, gen, _c in core_out:
                    pair.known_gen[(tid2, k)] = gen
                    pair.known_port[(tid2, k)] = port
            check_state()

        def do_cross_batch(spec):
            """spec = [(tid, key), ...]，两侧走跨租户入口。"""
            core_exc = ref_exc = None
            core_out = ref_out = None
            try:
                res = core.allocate_across_tenants([
                    TenantRequest(tid, Endpoint(k[0], k[1]),
                                  Endpoint(k[2], k[3]))
                    for tid, k in spec
                ])
                core_out = [(r.tenant, r.key, r.mapping.external_port,
                             r.mapping.generation, r.created) for r in res]
            except Exception as exc:  # noqa: BLE001
                core_exc = exc
            try:
                ref_out = ref.allocate_across_tenants(spec)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc),
                                 f"cross exc mismatch spec={spec}")
                self.assertIsNotNone(core_exc)
                self.assertIsNotNone(ref_exc)
            else:
                self.assertEqual(core_out, ref_out, f"cross mismatch {spec}")
                for tid, k, port, gen, _c in core_out:
                    pair.known_gen[(tid, k)] = gen
                    pair.known_port[(tid, k)] = port
            check_state()

        def do_outbound(tid, key, gen):
            pkt = Packet(src=Endpoint(key[0], key[1]),
                         dst=Endpoint(key[2], key[3]), generation=gen)
            c = norm_core_translation(
                core.translate_outbound(pkt, tenant_id=tid))
            r = ref.outbound(
                (key[0], key[1], key[2], key[3], gen), tenant_id=tid)
            self.assertEqual(c, r, f"outbound tid={tid} {key} gen={gen}")
            check_state()

        def do_inbound(tid_hint, src_ep, dst_port, gen):
            pkt = Packet(src=src_ep, dst=Endpoint(PUB, dst_port),
                         generation=gen)
            c = norm_core_translation(core.translate_inbound(pkt))
            r = ref.inbound(
                (src_ep.ip, src_ep.port, PUB, dst_port, gen))
            self.assertEqual(c, r,
                             f"inbound {src_ep} -> :{dst_port} gen={gen}")
            check_state()

        def do_release(tid, key):
            c = core.release(key, tenant_id=tid)
            r = ref.release(key, tenant_id=tid)
            self.assertEqual(c, r, f"release tid={tid} {key}")
            check_state()

        def do_advance(seconds):
            c = core.advance_tenants(seconds)
            r = ref.advance_tenants(seconds)
            self.assertEqual(c, r, f"advance({seconds}) expired")
            check_state()

        for _ in range(steps):
            roll = rng.random()
            if roll < 0.20:                        # 单租户单条/小批量
                tid = rng.choice(TENANTS)
                n = rng.randint(1, 2)
                keys = rng.sample(KEYS, n) if n < len(KEYS) else list(KEYS)
                do_alloc_one(tid, keys)
            elif roll < 0.38:                      # 跨租户批量（可能失败回滚）
                n = rng.randint(1, 4)
                spec = [(rng.choice(TENANTS), rng.choice(KEYS))
                        for _ in range(n)]
                do_cross_batch(spec)
            elif roll < 0.58:                      # 出站包
                tid = rng.choice(TENANTS)
                key = rng.choice(KEYS)
                known = pair.known_gen.get((tid, key), 0)
                gen = rng.choice([0, known, known + 1, 1])
                do_outbound(tid, key, gen)
            elif roll < 0.76:                      # 入站包
                tid = rng.choice(TENANTS)
                key = rng.choice(KEYS)
                if rng.random() < 0.7:
                    port = pair.known_port.get((tid, key))
                    if port is None:
                        port = rng.choice(TENANT_PORTS[tid])
                else:
                    pool = (ALL_PORTS + (9999,))   # 9999 触发 unknown_tenant
                    port = rng.choice(pool)
                if rng.random() < 0.5:
                    src = Endpoint(key[2], key[3])
                else:
                    src = rng.choice(REMOTES)
                known = pair.known_gen.get((tid, key), 0)
                gen = rng.choice([0, known, known + 1])
                do_inbound(tid, src, port, gen)
            elif roll < 0.90:                      # 释放
                do_release(rng.choice(TENANTS), rng.choice(KEYS))
            else:                                  # 推进时钟
                do_advance(rng.randint(0, 6))

    def test_random_walks_match_reference(self):
        # (种子, 步数, 寿命, 隔离, 预算(None=全池), 每租户配额)
        scenarios = [
            (1234, 500, 400, 5, None, 3),
            (7, 500, 400, 3, None, 2),       # 小配额：频繁触发配额错误
            (99, 500, 400, 4, 2, 3),         # 预算 2 < 子池 3：预算耗尽
            (2026, 500, 400, 2, 1, 2),       # 预算 1：每个端口都计数
            (31337, 400, 3, 0, None, 2),     # 短寿命 + Q=0：过期立即复用
            (555, 400, 2, 6, None, 3),       # 短寿命 + 长隔离：端口荒
        ]
        for seed, steps, lifetime, quarantine, budget, limit in scenarios:
            with self.subTest(seed=seed, lifetime=lifetime,
                              quarantine=quarantine, budget=budget,
                              limit=limit):
                self.run_scenario(seed, steps, lifetime, quarantine,
                                  budget, limit)


if __name__ == "__main__":
    unittest.main()
