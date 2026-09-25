"""差分测试：被测核心 vs 独立字典参考（tests/reference_nat.py）。

参考实现不导入 adnat 核心，双方只共享同一套公开契约；每个随机操作在
两侧各执行一次，比对公开结果（改写五元组 / 丢弃原因 / 异常类别）与
规范化状态签名。随机种子固定，失败可复现。
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
    ValidationError,
)
from reference_nat import RefError, RefNAT

PUB = "203.0.113.9"
PORTS = (7001, 7002, 7003, 7004)
INTERNALS = [Endpoint("10.1.0.1", 5000), Endpoint("10.1.0.2", 5001)]
REMOTES = [Endpoint("198.51.100.1", 53), Endpoint("198.51.100.2", 443),
           Endpoint("203.0.113.200", 1234)]
KEYS = [(i.ip, i.port, r.ip, r.port) for i in INTERNALS for r in REMOTES]


def core_signature(nat: AddressDependentNAT):
    # 隐式默认租户模式：身份剥成租户内 key（与参考 signature() 同形）。
    live = tuple(sorted(
        (m.key, (m.external_port, m.generation, m.created_at,
                 m.last_seen, m.expires_at))
        for m in nat.snapshot_mappings()
    ))
    return (nat.now, live, tuple(sorted(nat.quarantined_ports().items())))


def ref_signature(ref: RefNAT):
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


def norm_core_translation(res):
    if res.accepted:
        f = res.rewritten
        return ("ok", (f.protocol, f.src_ip, f.src_port, f.dst_ip, f.dst_port),
                res.tenant)
    return ("drop", res.reason.value, res.tenant)


class Pair:
    """同步驱动被测核心与参考实现。"""

    def __init__(self, lifetime: int, quarantine: int, budget: int | None):
        self.core = AddressDependentNAT(NATConfig(
            public_ip=PUB, external_ports=PORTS,
            lifetime=lifetime, quarantine=quarantine, search_budget=budget,
        ))
        self.ref = RefNAT(PUB, PORTS, lifetime, quarantine,
                          budget if budget is not None else len(PORTS))
        self.known_gen: dict[tuple, int] = {}   # key -> 最近分配所得 generation
        self.known_port: dict[tuple, int] = {}  # key -> 最近分配所得外端口


class TestDifferential(unittest.TestCase):
    def run_scenario(self, seed: int, steps: int, lifetime: int,
                     quarantine: int, budget: int | None):
        rng = random.Random(seed)
        pair = Pair(lifetime, quarantine, budget)
        core, ref = pair.core, pair.ref

        def check_state():
            self.assertEqual(core_signature(core), ref_signature(ref),
                             f"state diverged (seed={seed})")

        def do_alloc(keys):
            core_out = ref_out = None
            core_exc = ref_exc = None
            try:
                res = core.allocate_many([
                    AllocationRequest(Endpoint(k[0], k[1]), Endpoint(k[2], k[3]))
                    for k in keys
                ])
                core_out = [(r.key, r.mapping.external_port,
                             r.mapping.generation, r.created) for r in res]
            except Exception as exc:  # noqa: BLE001 - 比对异常类别
                core_exc = exc
            try:
                ref_out = ref.allocate_many(keys)
            except Exception as exc:  # noqa: BLE001
                ref_exc = exc
            if core_exc is not None or ref_exc is not None:
                self.assertEqual(core_tag(core_exc), ref_tag(ref_exc),
                                 f"alloc exc mismatch keys={keys}")
                self.assertIsNotNone(core_exc)
                self.assertIsNotNone(ref_exc)
            else:
                self.assertEqual(core_out, ref_out, f"alloc mismatch {keys}")
                for k, port, gen, _created in core_out:
                    pair.known_gen[k] = gen
                    pair.known_port[k] = port
            check_state()

        def do_outbound(key, gen):
            pkt = Packet(src=Endpoint(key[0], key[1]),
                         dst=Endpoint(key[2], key[3]), generation=gen)
            core_res = norm_core_translation(core.translate_outbound(pkt))
            ref_res = ref.outbound((key[0], key[1], key[2], key[3], gen))
            self.assertEqual(core_res, ref_res, f"outbound {key} gen={gen}")
            check_state()

        def do_inbound(src_ep, dst_port, gen):
            pkt = Packet(src=src_ep, dst=Endpoint(PUB, dst_port),
                         generation=gen)
            core_res = norm_core_translation(core.translate_inbound(pkt))
            ref_res = ref.inbound(
                (src_ep.ip, src_ep.port, PUB, dst_port, gen))
            self.assertEqual(core_res, ref_res,
                             f"inbound {src_ep} -> :{dst_port} gen={gen}")
            check_state()

        def do_release(key):
            c = core.release(key)
            r = ref.release(key)
            self.assertEqual(c, r, f"release {key}")
            check_state()

        def do_advance(seconds):
            c = core.advance(seconds)
            r = ref.advance(seconds)
            self.assertEqual(c, r, f"advance({seconds}) expired keys")
            check_state()

        for _ in range(steps):
            roll = rng.random()
            if roll < 0.28:                       # 单条分配
                do_alloc([rng.choice(KEYS)])
            elif roll < 0.42:                     # 批量分配（可能超容量）
                keys = rng.sample(KEYS, rng.randint(1, len(KEYS)))
                do_alloc(keys)
            elif roll < 0.62:                     # 出站包
                key = rng.choice(KEYS)
                known = pair.known_gen.get(key, 0)
                gen = rng.choice([0, known, known + 1, 1])
                do_outbound(key, gen)
            elif roll < 0.80:                     # 入站包
                key = rng.choice(KEYS)
                port = pair.known_port.get(key, rng.choice(PORTS))
                if rng.random() < 0.5:
                    src = Endpoint(key[2], key[3])        # 正确对端
                else:
                    src = rng.choice(REMOTES)             # 可能错误对端
                known = pair.known_gen.get(key, 0)
                gen = rng.choice([0, known, known + 1])
                do_inbound(src, port, gen)
            elif roll < 0.92:                     # 释放
                do_release(rng.choice(KEYS))
            else:                                 # 推进时钟
                do_advance(rng.randint(0, 6))

    def test_random_walks_match_reference(self):
        # 多组 (种子, 寿命, 隔离, 预算)，覆盖过期/隔离/预算/耗尽路径。
        scenarios = [
            (1234, 400, 5, 2, None),
            (7, 400, 3, 4, None),
            (99, 400, 4, 0, 3),     # 预算 < 池大小：触发预算耗尽路径
            (2026, 400, 2, 1, None),
            (31337, 600, 6, 3, 2),
        ]
        for seed, steps, lifetime, quarantine, budget in scenarios:
            with self.subTest(seed=seed, lifetime=lifetime,
                              quarantine=quarantine, budget=budget):
                self.run_scenario(seed, steps, lifetime, quarantine, budget)


if __name__ == "__main__":
    unittest.main()
