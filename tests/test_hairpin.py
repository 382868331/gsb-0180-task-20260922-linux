"""hairpin 入口契约测试：手工计算期望值，不依赖任何参考实现。

场景（全部合成地址，不发网络包）：
- 公网 IP 203.0.113.7（TEST-NET-3），端口池 (6001, 6002, 6003, 6004)
- 内网端点 A=10.0.0.8:40000、B=10.0.0.9:40001，外部对端 R=198.51.100.10:53

手工五元组表（两方向，逐点核对）：

  步骤  t   动作                                   结果
  ----  --  -------------------------------------  --------------------------
  1     0   allocate(B, R)                         外端口 6001, gen 1, exp 10
  2     0   hairpin A -> 203.0.113.7:6001 (gen 1)  源 key (A,PUB,6001) 新建
                                                   外端口 6002, gen 2, exp 10
            改写五元组 = (17, 203.0.113.7:6002 -> 10.0.0.9:40001)
  3     0   hairpin B -> 203.0.113.7:6002 (gen 2)  源 key (B,PUB,6002) 新建
                                                   外端口 6003, gen 3, exp 10
            改写五元组 = (17, 203.0.113.7:6003 -> 10.0.0.8:40000)

方向 1 是 A 访问 B 的映射（目的折回 B），方向 2 是 B 回访 A 刚建映射的
外端口（目的折回 A）；两方向均经 hairpin 入口，五元组逐字段固定。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
)

PUB = "203.0.113.7"
A = Endpoint("10.0.0.8", 40000)
B = Endpoint("10.0.0.9", 40001)
R = Endpoint("198.51.100.10", 53)
KEY_B_R = (B.ip, B.port, R.ip, R.port)


def make_nat(ports=(6001, 6002, 6003, 6004), lifetime=10, quarantine=5
             ) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine,
    ))


def pkt(src: Endpoint, dst: Endpoint, gen: int = 0) -> Packet:
    return Packet(src=src, dst=dst, generation=gen, payload=b"x")


def five_tuple_of(res) -> tuple:
    f = res.rewritten
    return (f.protocol, f.src_ip, f.src_port, f.dst_ip, f.dst_port)


class TestHairpinTwoDirections(unittest.TestCase):
    """两内网端点互访对方映射：手工五元组表逐字段核对。"""

    def test_hand_computed_five_tuples_both_directions(self):
        nat = make_nat()
        m_b = nat.allocate(B, R).mapping          # 步骤 1
        self.assertEqual((m_b.external_port, m_b.generation, m_b.expires_at),
                         (6001, 1, 10))

        # 步骤 2：A -> B 的映射（方向 1）
        fwd = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertTrue(fwd.accepted)
        self.assertEqual(five_tuple_of(fwd),
                         (17, PUB, 6002, B.ip, B.port))
        self.assertEqual(fwd.source_mapping.key, (A.ip, A.port, PUB, 6001))
        self.assertEqual(fwd.source_mapping.external_port, 6002)
        self.assertEqual(fwd.source_mapping.generation, 2)
        self.assertEqual(fwd.destination_mapping.key, KEY_B_R)
        self.assertEqual(fwd.destination_mapping.external_port, 6001)
        self.assertEqual(fwd.destination_mapping.generation, 1)
        # 双方计时一起刷新（t=0 + lifetime=10）。
        self.assertEqual(fwd.source_mapping.expires_at, 10)
        self.assertEqual(fwd.destination_mapping.expires_at, 10)

        # 步骤 3：B -> A 刚建映射的外端口（方向 2，回访）
        back = nat.translate_hairpin(pkt(B, Endpoint(PUB, 6002), gen=2))
        self.assertTrue(back.accepted)
        self.assertEqual(five_tuple_of(back),
                         (17, PUB, 6003, A.ip, A.port))
        self.assertEqual(back.source_mapping.key, (B.ip, B.port, PUB, 6002))
        self.assertEqual(back.source_mapping.generation, 3)
        self.assertEqual(back.destination_mapping.generation, 2)
        self.assertEqual(nat.stats()["ports_in_use"], 3)

    def test_hairpin_is_explicit_exception_inbound_unchanged(self):
        """普通入站不被悄悄放宽：内网源直接走 translate_inbound 仍被过滤。"""
        nat = make_nat()
        nat.allocate(B, R)                        # 6001, 对端为 R
        # 同一内网包若走普通入站入口：源 A 不是映射对端 R -> 丢弃。
        via_inbound = nat.translate_inbound(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertFalse(via_inbound.accepted)
        self.assertIs(via_inbound.reason, DropReason.PEER_MISMATCH)
        # 同一包走 hairpin 入口才被折返（显式例外）。
        via_hairpin = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertTrue(via_hairpin.accepted)
        # 外部非对端源走 hairpin 也可以折返（hairpin 不过滤源），但普通
        # 入站规则不受影响：R 之外的入站包依旧 PEER_MISMATCH。
        stranger = Endpoint("192.0.2.66", 9999)
        still_filtered = nat.translate_inbound(
            pkt(stranger, Endpoint(PUB, 6001), gen=1))
        self.assertIs(still_filtered.reason, DropReason.PEER_MISMATCH)


class TestHairpinSourceMapping(unittest.TestCase):
    """源按原规则取得出站映射：已存在则复用，不重复占口。"""

    def test_source_existing_mapping_reused(self):
        nat = make_nat()
        nat.allocate(B, R)                        # 6001, gen 1
        # 预建源映射（与 hairpin 将使用的源 key 相同）。
        pre = nat.allocate(A, Endpoint(PUB, 6001))
        self.assertEqual((pre.mapping.external_port, pre.mapping.generation),
                         (6002, 2))
        before = nat.stats()["ports_in_use"]      # 2
        res = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertTrue(res.accepted)
        # 复用：同端口、同 generation，不占新容量。
        self.assertEqual(res.source_mapping.external_port, 6002)
        self.assertEqual(res.source_mapping.generation, 2)
        self.assertEqual(nat.stats()["ports_in_use"], before)

    def test_repeated_hairpin_reuses_source_mapping(self):
        nat = make_nat()
        nat.allocate(B, R)                        # 6001
        first = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)))
        second = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)))
        self.assertEqual(second.source_mapping.external_port,
                         first.source_mapping.external_port)
        self.assertEqual(second.source_mapping.generation,
                         first.source_mapping.generation)
        self.assertEqual(nat.stats()["ports_in_use"], 2)

    def test_hairpin_refreshes_both_timers(self):
        nat = make_nat()
        nat.allocate(B, R)                        # exp 10
        nat.advance(4)                            # t=4
        res = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)), at=5)
        # 双方 expires_at 都刷新到 5 + 10 = 15。
        self.assertEqual(res.source_mapping.expires_at, 15)
        self.assertEqual(res.destination_mapping.expires_at, 15)
        self.assertEqual(nat.get_mapping(KEY_B_R).expires_at, 15)


class TestHairpinDestinationValidity(unittest.TestCase):
    """目的映射必须属于当前公网 IP 且未过期；隔离期端口不可作目的。"""

    def test_destination_just_expired_boundary(self):
        nat = make_nat(lifetime=10)
        nat.allocate(B, R)                        # expires_at = 10
        # t=9：仍存活，hairpin 成功。
        nat.advance(9)
        alive = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)))
        self.assertTrue(alive.accepted)
        # 新 NAT 重放边界：t=10 == expires_at，边界即死。
        nat2 = make_nat(lifetime=10)
        nat2.allocate(B, R)
        dead = nat2.translate_hairpin(pkt(A, Endpoint(PUB, 6001)), at=10)
        self.assertFalse(dead.accepted)
        self.assertIs(dead.reason, DropReason.NO_MAPPING)
        self.assertIsNone(dead.source_mapping)
        self.assertIsNone(dead.destination_mapping)
        # 过期映射被本次 housekeeping 回收，端口进入隔离。
        self.assertIsNone(nat2.get_mapping(KEY_B_R))
        self.assertEqual(nat2.quarantined_ports(), {6001: 10})

    def test_quarantined_port_is_not_a_destination(self):
        nat = make_nat()
        nat.allocate(B, R)                        # 6001
        self.assertTrue(nat.release(KEY_B_R))     # 端口 6001 进入隔离
        self.assertEqual(nat.quarantined_ports(), {6001: 0})
        before = (nat.snapshot_mappings(), nat.stats(), nat.now)
        res = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)))
        self.assertFalse(res.accepted)
        self.assertIs(res.reason, DropReason.NO_MAPPING)
        # 隔离期端口不可作目的；也不为源建任何映射。
        self.assertEqual((nat.snapshot_mappings(), nat.stats(), nat.now), before)

    def test_dest_ip_mismatch(self):
        nat = make_nat()
        nat.allocate(B, R)
        res = nat.translate_hairpin(pkt(A, Endpoint("192.0.2.1", 6001)))
        self.assertFalse(res.accepted)
        self.assertIs(res.reason, DropReason.DEST_MISMATCH)


class TestHairpinGeneration(unittest.TestCase):
    """包携带的 generation 与目的映射不一致即拒绝，且不刷新目的计时。"""

    def test_stale_generation_rejected(self):
        nat = make_nat()
        nat.allocate(B, R)                        # gen 1, exp 10
        res = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=2))
        self.assertFalse(res.accepted)
        self.assertIs(res.reason, DropReason.STALE_GENERATION)
        # 拒绝时给出目的映射快照，但不刷新其计时，也不建源映射。
        self.assertIsNotNone(res.destination_mapping)
        self.assertEqual(res.destination_mapping.generation, 1)
        self.assertEqual(nat.get_mapping(KEY_B_R).expires_at, 10)
        self.assertEqual(nat.stats()["ports_in_use"], 1)
        # generation=0 不参与校验；正确 generation 通过。
        self.assertTrue(nat.translate_hairpin(
            pkt(A, Endpoint(PUB, 6001), gen=0)).accepted)
        nat3 = make_nat()
        nat3.allocate(B, R)
        self.assertTrue(nat3.translate_hairpin(
            pkt(A, Endpoint(PUB, 6001), gen=1)).accepted)


class TestHairpinAllocationRollback(unittest.TestCase):
    """源端口池耗尽 -> 抛 PortExhaustionError，状态与调用前完全一致。"""

    def test_exhaustion_leaves_destination_timers_untouched(self):
        nat = make_nat(ports=(6001,), lifetime=10)
        nat.allocate(B, R)                        # 占满唯一端口
        before = (nat.snapshot_mappings(), nat.stats(), nat.now,
                  nat.quarantined_ports())
        with self.assertRaises(PortExhaustionError) as ctx:
            nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001)))
        self.assertEqual((ctx.exception.needed, ctx.exception.available,
                          ctx.exception.pool_size), (1, 0, 1))
        after = (nat.snapshot_mappings(), nat.stats(), nat.now,
                 nat.quarantined_ports())
        self.assertEqual(before, after)
        # 目的映射计时不变（未被刷新）。
        m = nat.get_mapping(KEY_B_R)
        self.assertEqual((m.last_seen, m.expires_at), (0, 10))


class TestHairpinSelfAccess(unittest.TestCase):
    """自己访问自己的映射允许，但不重复扣容量。"""

    def test_self_hairpin_via_own_external_port(self):
        nat = make_nat()
        nat.allocate(A, R)                        # 6001, gen 1
        res = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertTrue(res.accepted)
        # 目的折回 A 自己；源新建映射 (A -> PUB:6001) 占 6002。
        self.assertEqual(five_tuple_of(res), (17, PUB, 6002, A.ip, A.port))
        self.assertEqual(res.destination_mapping.internal, A)
        self.assertEqual(nat.stats()["ports_in_use"], 2)
        # 再次访问：源映射复用，容量不变。
        again = nat.translate_hairpin(pkt(A, Endpoint(PUB, 6001), gen=1))
        self.assertEqual(again.source_mapping.generation,
                         res.source_mapping.generation)
        self.assertEqual(nat.stats()["ports_in_use"], 2)

    def test_source_key_equals_destination_key_no_double_count(self):
        """源 key 与目的 key 相同（映射的对端就是自己的公网端口）时，
        源映射即目的映射本身：只复用，不新建、不占第二个端口。"""
        nat = make_nat()
        own = Endpoint(PUB, 6001)
        nat.allocate(A, own)                      # key (A, PUB, 6001) -> 6001
        res = nat.translate_hairpin(pkt(A, own, gen=1))
        self.assertTrue(res.accepted)
        self.assertEqual(res.source_mapping.key, res.destination_mapping.key)
        self.assertEqual(res.source_mapping.generation,
                         res.destination_mapping.generation)
        # 双方是同一映射：源改写端口即目的端口，目的折回 A。
        self.assertEqual(five_tuple_of(res), (17, PUB, 6001, A.ip, A.port))
        self.assertEqual(nat.stats()["ports_in_use"], 1)   # 不重复扣容量
        self.assertEqual(res.source_mapping.expires_at, 10)  # 只刷新一次


if __name__ == "__main__":
    unittest.main()
