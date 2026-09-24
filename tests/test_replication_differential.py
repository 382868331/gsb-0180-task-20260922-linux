"""复制链路差分测试：被测核心（主->日志->备用）vs 独立字典参考。

主实例在随机操作下产生有序日志；每条记录同时喂给被测备用实例与
tests/reference_nat.py 中的 RefStandby（纯字典、独立实现），逐条比对
应用结果与规范化状态签名。随机种子固定，失败可复现。
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
    RecordKind,
    ReplicationGapError,
    ValidationError,
)
from reference_nat import RefError, RefNAT, RefStandby

PUB = "203.0.113.9"
PORTS = (7001, 7002, 7003, 7004)
INTERNALS = [Endpoint("10.1.0.1", 5000), Endpoint("10.1.0.2", 5001)]
REMOTES = [Endpoint("198.51.100.1", 53), Endpoint("198.51.100.2", 443),
           Endpoint("203.0.113.200", 1234)]
KEYS = [(i.ip, i.port, r.ip, r.port) for i in INTERNALS for r in REMOTES]


def rec_to_tuple(rec) -> tuple:
    """JournalRecord -> 参考实现的中性元组形式。"""
    return (rec.seq, rec.epoch, rec.kind.value, rec.key, rec.at,
            rec.port, rec.generation, rec.expires_at)


def standby_signature(nat: AddressDependentNAT) -> tuple:
    live = tuple(sorted(
        (m.key, (m.external_port, m.generation, m.created_at,
                 m.last_seen, m.expires_at))
        for m in nat.snapshot_mappings()
    ))
    return (nat.now, live, tuple(sorted(nat.quarantined_ports().items())),
            nat.last_seq)


class TestReplicationDifferential(unittest.TestCase):
    def run_scenario(self, seed: int, steps: int, lifetime: int,
                     quarantine: int):
        rng = random.Random(seed)
        cfg = NATConfig(public_ip=PUB, external_ports=PORTS,
                        lifetime=lifetime, quarantine=quarantine)
        primary = AddressDependentNAT(cfg)
        standby = AddressDependentNAT(cfg, role="standby")
        ref = RefStandby(PORTS, lifetime, quarantine)
        known_gen: dict[tuple, int] = {}
        known_port: dict[tuple, int] = {}
        cursor = 0                      # 已转发给备用的日志序号

        def ship():
            """把主实例新产生的记录逐条发给两侧备用并比对。"""
            nonlocal cursor
            for rec in primary.journal(since=cursor):
                core_res = standby.apply_record(rec)
                ref_res = ref.apply(rec_to_tuple(rec))
                self.assertEqual(core_res.status.value, ref_res,
                                 f"apply result mismatch {rec!r}")
                self.assertEqual(standby_signature(standby), ref.signature(),
                                 f"standby diverged after {rec!r} (seed={seed})")
                cursor = rec.seq

        for _ in range(steps):
            roll = rng.random()
            if roll < 0.35:                       # 分配（含批量）
                keys = rng.sample(KEYS, rng.randint(1, 3))
                try:
                    res = primary.allocate_many([
                        AllocationRequest(Endpoint(k[0], k[1]),
                                          Endpoint(k[2], k[3]))
                        for k in keys
                    ])
                    for r in res:
                        known_gen[r.key] = r.mapping.generation
                        known_port[r.key] = r.mapping.external_port
                except Exception:                 # 容量类失败：无新记录
                    pass
            elif roll < 0.60:                     # 出站包
                key = rng.choice(KEYS)
                gen = rng.choice([0, known_gen.get(key, 0)])
                primary.translate_outbound(Packet(
                    src=Endpoint(key[0], key[1]),
                    dst=Endpoint(key[2], key[3]), generation=gen))
            elif roll < 0.75:                     # 入站包
                key = rng.choice(KEYS)
                port = known_port.get(key, rng.choice(PORTS))
                src = Endpoint(key[2], key[3]) if rng.random() < 0.7 \
                    else rng.choice(REMOTES)
                primary.translate_inbound(Packet(
                    src=src, dst=Endpoint(PUB, port),
                    generation=known_gen.get(key, 0)))
            elif roll < 0.88:                     # 释放
                primary.release(rng.choice(KEYS))
            else:                                 # 推进时钟
                primary.advance(rng.randint(0, 5))
            ship()

        # 随机重复投递：已应用记录应幂等（两侧一致）。
        if cursor > 0:
            for rec in primary.journal(since=0):
                if rng.random() < 0.3:
                    core_res = standby.apply_record(rec)
                    ref_res = ref.apply(rec_to_tuple(rec))
                    self.assertEqual(core_res.status.value, ref_res)
                    self.assertEqual(core_res.status.value, "duplicate")
            self.assertEqual(standby_signature(standby), ref.signature())

        # 随机缺口：两侧都必须拒绝且状态不变。
        if cursor > 1:
            log = primary.journal(since=0)
            skip_to = log[min(cursor - 1, rng.randint(1, cursor - 1))]
            fresh_core = AddressDependentNAT(cfg, role="standby")
            fresh_ref = RefStandby(PORTS, lifetime, quarantine)
            core_exc = ref_exc = None
            try:
                fresh_core.apply_record(skip_to)
            except (ReplicationGapError, ValidationError) as exc:
                core_exc = exc
            try:
                fresh_ref.apply(rec_to_tuple(skip_to))
            except RefError as exc:
                ref_exc = exc
            self.assertIsNotNone(core_exc)
            self.assertIsNotNone(ref_exc)
            self.assertEqual(fresh_core.last_seq, 0)
            self.assertEqual(fresh_ref.signature()[3], 0)

    def test_replication_matches_reference(self):
        scenarios = [
            (11, 300, 5, 2),
            (222, 300, 3, 0),
            (7777, 400, 4, 3),
        ]
        for seed, steps, lifetime, quarantine in scenarios:
            with self.subTest(seed=seed, lifetime=lifetime,
                              quarantine=quarantine):
                self.run_scenario(seed, steps, lifetime, quarantine)


class TestTakeoverDifferential(unittest.TestCase):
    """接管后新主的行为与同起点的独立参考实例一致。"""

    def test_post_takeover_allocation_matches_fresh_reference(self):
        cfg = NATConfig(public_ip=PUB, external_ports=PORTS,
                        lifetime=5, quarantine=2)
        primary = AddressDependentNAT(cfg)
        standby = AddressDependentNAT(cfg, role="standby")
        rng = random.Random(42)
        known: dict[tuple, int] = {}
        for _ in range(120):
            roll = rng.random()
            if roll < 0.5:
                key = rng.choice(KEYS)
                try:
                    r = primary.allocate(Endpoint(key[0], key[1]),
                                         Endpoint(key[2], key[3]))
                    known[key] = r.mapping.generation
                except Exception:
                    pass
            elif roll < 0.8:
                key = rng.choice(KEYS)
                primary.translate_outbound(Packet(
                    src=Endpoint(key[0], key[1]),
                    dst=Endpoint(key[2], key[3]),
                    generation=known.get(key, 0)))
            else:
                primary.advance(rng.randint(0, 3))
            for rec in primary.journal(since=standby.last_seq):
                standby.apply_record(rec)

        token = standby.promote(after_seq=standby.last_seq, new_epoch=2)
        primary.fence(token)
        # 用独立 RefStandby 重放同一日志，重建参考侧主状态（含过期派生
        # 的隔离项），再包成 RefNAT 继续驱动分配。
        replay = RefStandby(PORTS, 5, 2)
        next_gen = 1
        for rec in primary.journal(since=0):
            replay.apply(rec_to_tuple(rec))
            if rec.kind is RecordKind.CREATE:
                next_gen = max(next_gen, rec.generation + 1)
        ref = RefNAT(PUB, PORTS, 5, 2)
        ref.maps = {k: list(v) for k, v in replay.maps.items()}
        ref.port_owner = dict(replay.port_owner)
        ref.quarantined = dict(replay.quarantined)
        ref.now = replay.now
        ref.next_gen = next_gen
        self.assertEqual(standby.now, ref.now)
        for _ in range(60):
            roll = rng.random()
            key = rng.choice(KEYS)
            if roll < 0.6:
                try:
                    r = standby.allocate(Endpoint(key[0], key[1]),
                                         Endpoint(key[2], key[3]))
                    out = (r.mapping.external_port, r.mapping.generation,
                           r.created)
                except Exception:
                    out = "exhausted"
                try:
                    ref_out = ref.allocate_many([key])
                    ref_res = (ref_out[0][1], ref_out[0][2], ref_out[0][3])
                except RefError:
                    ref_res = "exhausted"
                self.assertEqual(out, ref_res, f"post-takeover alloc {key}")
            else:
                seconds = rng.randint(0, 2)
                c = standby.advance(seconds)
                r_ = ref.advance(seconds)
                self.assertEqual(c, r_)
            core_live = sorted(
                (m.key, m.external_port, m.generation, m.expires_at)
                for m in standby.snapshot_mappings())
            ref_live = sorted(
                (k, v[0], v[1], v[4]) for k, v in ref.maps.items()
                if ref.now < v[4])
            self.assertEqual(core_live, ref_live)


if __name__ == "__main__":
    unittest.main()
