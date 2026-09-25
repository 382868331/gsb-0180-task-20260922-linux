"""Hairpin（内网折返）契约测试：手工五元组表，逐包核对两方向改写。

覆盖题面要求的验收点：
- 两个内网端点互访对方公网端点，手工五元组表核对去/回两个方向；
- 源已有出站映射 -> 复用，不重复扣容量；
- 目的映射刚到期（边界即死）-> NO_MAPPING，端口进隔离；
- 隔离期端口不能作为源的新外端口，边界时刻解除；
- generation 不匹配 -> STALE_GENERATION，双方计时均不变；
- 源分配失败（端口耗尽 / 搜索预算耗尽）-> 整体回滚，目的计时不变；
- 自己访问自己的映射允许，但容量只扣一次；
- 入站过滤的 hairpin 例外只在新入口生效，普通入站不被放宽。

全部地址合成，不发任何网络包。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    HairpinResult,
    NATConfig,
    Packet,
    PortExhaustionError,
    SearchBudgetExhaustedError,
    ValidationError,
)

PUB = "203.0.113.7"
OTHER = "192.0.2.1"
A = Endpoint("10.0.0.8", 4000)          # 内网端点 A
B = Endpoint("10.0.0.9", 5000)          # 内网端点 B
C = Endpoint("10.0.0.10", 6000)         # 第三个内网端点
RA = Endpoint("198.51.100.10", 53)      # A 的映射对端
RB = Endpoint("198.51.100.20", 443)     # B 的映射对端
RC = Endpoint("198.51.100.30", 8000)    # C 的映射对端
KEY_A = (A.ip, A.port, RA.ip, RA.port)
KEY_B = (B.ip, B.port, RB.ip, RB.port)
KEY_C = (C.ip, C.port, RC.ip, RC.port)


def make_nat(ports=(6001, 6002, 6003, 6004), lifetime=100, quarantine=10,
             budget=None) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine, search_budget=budget,
    ))


def hp(src: Endpoint, dst_port: int, gen: int = 0) -> Packet:
    return Packet(src=src, dst=Endpoint(PUB, dst_port),
                  generation=gen, payload=b"hairpin")


def four(f) -> tuple:
    return (f.protocol, f.src_ip, f.src_port, f.dst_ip, f.dst_port)


class TestHairpinTwoEndpointsBidirectional(unittest.TestCase):
    """两个内网端点互访对方仍有效的公网映射，手工五元组表核对两方向。"""

    def test_hand_computed_five_tuple_table_both_directions(self):
        nat = make_nat()
        ma = nat.allocate(A, RA).mapping   # 6001, gen 1
        mb = nat.allocate(B, RB).mapping   # 6002, gen 2
        self.assertEqual((ma.external_port, ma.generation), (6001, 1))
        self.assertEqual((mb.external_port, mb.generation), (6002, 2))

        # ---- 去程：B 访问 A 的公网端点 PUB:6001 ----
        # 目的映射 M_A 的内网端点 A 成为新目的；
        # 源按 (B, PUB:6001) 取得新出站映射，拿最小空闲 6003, gen 3。
        fwd = nat.translate_hairpin(hp(B, 6001, gen=1))
        # 手工五元组表（去程）：
        #   原始: 10.0.0.9:5000 -> 203.0.113.7:6001
        #   改写: 203.0.113.7:6003 -> 10.0.0.8:4000
        self._assert_ok(fwd, (17, PUB, 6003, A.ip, A.port))
        self.assertTrue(fwd.source_created)
        self.assertEqual(fwd.source_mapping.external_port, 6003)
        self.assertEqual(fwd.source_mapping.generation, 3)
        self.assertEqual(fwd.source_mapping.key,
                         (B.ip, B.port, PUB, 6001))
        self.assertEqual(fwd.source_mapping.remote, Endpoint(PUB, 6001))
        self.assertEqual(fwd.destination_mapping.external_port, 6001)
        self.assertEqual(fwd.destination_mapping.generation, 1)
        self.assertEqual(fwd.destination_mapping.key, KEY_A)

        # ---- 回程：A 回复看到的源 PUB:6003 ----
        # 6003 此刻的属主是源映射 (B,PUB:6001) -> 内网端点 B；
        # A 的回复按 (A, PUB:6003) 取新源映射 6004, gen 4。
        rev = nat.translate_hairpin(hp(A, 6003, gen=3))
        # 手工五元组表（回程）：
        #   原始: 10.0.0.8:4000 -> 203.0.113.7:6003
        #   改写: 203.0.113.7:6004 -> 10.0.0.9:5000
        self._assert_ok(rev, (17, PUB, 6004, B.ip, B.port))
        self.assertTrue(rev.source_created)
        self.assertEqual(rev.source_mapping.external_port, 6004)
        self.assertEqual(rev.source_mapping.generation, 4)
        self.assertEqual(rev.destination_mapping.external_port, 6003)
        self.assertEqual(rev.destination_mapping.generation, 3)
        self.assertEqual(rev.destination_mapping.internal, B)

        self.assertEqual(nat.stats()["ports_in_use"], 4)

        # ---- 去程重放：源映射已存在 -> 复用，不新建、不扣容量 ----
        again = nat.translate_hairpin(hp(B, 6001, gen=1))
        self._assert_ok(again, (17, PUB, 6003, A.ip, A.port))
        self.assertFalse(again.source_created)
        self.assertEqual(again.source_mapping.external_port, 6003)
        self.assertEqual(again.source_mapping.generation, 3)
        self.assertEqual(nat.stats()["ports_in_use"], 4)

    def _assert_ok(self, res: HairpinResult, expected_five: tuple) -> None:
        self.assertIsInstance(res, HairpinResult)
        self.assertTrue(res.accepted, msg=f"unexpected drop {res.reason}")
        self.assertIsNone(res.reason)
        self.assertEqual(four(res.rewritten), expected_five)
        self.assertIsNotNone(res.source_mapping)
        self.assertIsNotNone(res.destination_mapping)


class TestHairpinSourceMappingReuse(unittest.TestCase):
    """源已有同 key 的出站映射 -> 直接复用，不重复扣容量。"""

    def test_preexisting_source_mapping_reused(self):
        nat = make_nat(ports=(6001, 6002))
        nat.allocate(A, RA)                       # 6001 gen1：目的映射
        pre = nat.allocate(B, Endpoint(PUB, 6001))  # 6002 gen2：源映射已建
        self.assertTrue(pre.created)
        self.assertEqual(nat.stats()["ports_in_use"], 2)

        res = nat.translate_hairpin(hp(B, 6001, gen=1))
        self.assertTrue(res.accepted)
        self.assertFalse(res.source_created)
        self.assertEqual(res.source_mapping.external_port, 6002)
        self.assertEqual(res.source_mapping.generation, 2)
        self.assertEqual(res.destination_mapping.external_port, 6001)
        # 复用不产生新映射、不占新端口。
        self.assertEqual(nat.stats()["ports_in_use"], 2)
        # 再来一次仍复用。
        res2 = nat.translate_hairpin(hp(B, 6001, gen=1))
        self.assertFalse(res2.source_created)
        self.assertEqual(nat.stats()["ports_in_use"], 2)


class TestHairpinDestinationExpiry(unittest.TestCase):
    """目的映射必须未过期：边界即死；目的刚到期 -> NO_MAPPING。"""

    def test_destination_just_expired(self):
        nat = make_nat(ports=(6001, 6002), lifetime=10, quarantine=5)
        ma = nat.allocate(A, RA)                  # expires_at=10
        self.assertEqual(ma.mapping.expires_at, 10)
        nat.advance(9)                            # t=9：存活，可折返
        ok = nat.translate_hairpin(hp(B, 6001, gen=1), at=9)
        self.assertTrue(ok.accepted)
        self.assertEqual(ok.destination_mapping.expires_at, 19)  # 被刷新
        # 目的与本次所建源映射都在 t=19 到期（边界即死）。
        expired = nat.advance(10)                 # t=19
        self.assertEqual(sorted(expired),
                         sorted([KEY_A, (B.ip, B.port, PUB, 6001)]))
        self.assertIsNone(nat.get_mapping(KEY_A))
        # 过期端口均进隔离。
        self.assertEqual(nat.quarantined_ports(), {6001: 19, 6002: 19})

        dead = nat.translate_hairpin(hp(B, 6001))
        self.assertFalse(dead.accepted)
        self.assertIs(dead.reason, DropReason.NO_MAPPING)
        self.assertIsNone(dead.rewritten)
        self.assertIsNone(dead.destination_mapping)
        self.assertEqual(nat.stats()["live_mappings"], 0)

    def test_destination_port_never_mapped(self):
        nat = make_nat()
        res = nat.translate_hairpin(hp(B, 6003))
        self.assertFalse(res.accepted)
        self.assertIs(res.reason, DropReason.NO_MAPPING)
        self.assertEqual(nat.stats()["live_mappings"], 0)

    def test_destination_wrong_public_ip(self):
        nat = make_nat()
        nat.allocate(A, RA)
        res = nat.translate_hairpin(
            Packet(B, Endpoint(OTHER, 6001), generation=1))
        self.assertFalse(res.accepted)
        self.assertIs(res.reason, DropReason.DEST_MISMATCH)
        self.assertIsNone(res.source_mapping)
        self.assertIsNone(res.destination_mapping)


class TestHairpinQuarantine(unittest.TestCase):
    """隔离期端口不能分配给源；边界时刻（now == released_at + Q）解除。"""

    def test_quarantined_port_unavailable_until_boundary(self):
        nat = make_nat(ports=(6001, 6002), lifetime=100, quarantine=10)
        ma = nat.allocate(A, RA)                 # 6001：目的映射
        nat.allocate(C, RC)                      # 6002：占掉另一口
        self.assertTrue(nat.release(KEY_C))      # 6002 t=0 起隔离至 t=10

        # t=5：池里没有可用于源的端口 -> 分配失败，目的计时不变。
        with self.assertRaises(PortExhaustionError):
            nat.translate_hairpin(hp(B, 6001), at=5)
        still = nat.get_mapping(KEY_A)
        self.assertEqual((still.last_seen, still.expires_at), (0, 100))
        self.assertEqual(nat.stats()["ports_in_use"], 1)
        self.assertIn(6002, nat.quarantined_ports())

        # t=10：边界解除，6002 可分配给源。
        ok = nat.translate_hairpin(hp(B, 6001, gen=1), at=10)
        self.assertTrue(ok.accepted)
        self.assertEqual(ok.source_mapping.external_port, 6002)
        self.assertEqual(ok.source_mapping.created_at, 10)
        self.assertEqual(nat.quarantined_ports(), {})


class TestHairpinStaleGeneration(unittest.TestCase):
    """generation 不匹配 -> STALE_GENERATION：不分配、不刷新任何计时。"""

    def test_stale_generation_drops_without_touching_timers(self):
        nat = make_nat(ports=(6001, 6002))
        nat.allocate(A, RA)                      # 6001 gen1
        before_dest = nat.get_mapping(KEY_A)
        pre = nat.allocate(B, Endpoint(PUB, 6001))  # 源映射 6002 gen2
        before_src = nat.get_mapping((B.ip, B.port, PUB, 6001))

        stale = nat.translate_hairpin(hp(B, 6001, gen=999))
        self.assertFalse(stale.accepted)
        self.assertIs(stale.reason, DropReason.STALE_GENERATION)
        # 双方快照仍可用于定位，且计时保持调用前的值。
        self.assertEqual(stale.destination_mapping.generation, 1)
        self.assertEqual(stale.source_mapping.generation, 2)
        self.assertEqual(
            (nat.get_mapping(KEY_A).last_seen,
             nat.get_mapping(KEY_A).expires_at),
            (before_dest.last_seen, before_dest.expires_at))
        self.assertEqual(
            (nat.get_mapping((B.ip, B.port, PUB, 6001)).last_seen,
             nat.get_mapping((B.ip, B.port, PUB, 6001)).expires_at),
            (before_src.last_seen, before_src.expires_at))

        # gen=0 不参与校验 -> 正常折返。
        ok = nat.translate_hairpin(hp(B, 6001, gen=0))
        self.assertTrue(ok.accepted)

    def test_stale_generation_creates_no_source_mapping(self):
        nat = make_nat(ports=(6001, 6002))
        nat.allocate(A, RA)
        stale = nat.translate_hairpin(hp(B, 6001, gen=42))
        self.assertIs(stale.reason, DropReason.STALE_GENERATION)
        # 未建任何源映射，容量与代数计数都未消耗。
        self.assertEqual(nat.stats()["ports_in_use"], 1)
        follow = nat.allocate(B, RB)
        self.assertTrue(follow.created)
        self.assertEqual(follow.mapping.external_port, 6002)
        self.assertEqual(follow.mapping.generation, 2)  # gen2 未被失败消耗


class TestHairpinAllocationRollback(unittest.TestCase):
    """源分配失败：目的查找与规划不提交，目的计时、容量、状态全部不变。"""

    def test_pool_exhaustion_rollback_keeps_destination_timers(self):
        nat = make_nat(ports=(6001,), lifetime=100, quarantine=0)
        nat.allocate(A, RA)                      # 唯一端口 6001 被目的占用
        before = nat.snapshot_mappings()
        with self.assertRaises(PortExhaustionError) as ctx:
            nat.translate_hairpin(hp(B, 6001))
        self.assertEqual(
            (ctx.exception.needed, ctx.exception.available,
             ctx.exception.pool_size),
            (1, 0, 1))
        # 状态与调用前完全一致。
        self.assertEqual(nat.snapshot_mappings(), before)
        self.assertEqual(nat.stats()["ports_in_use"], 1)
        d = nat.get_mapping(KEY_A)
        self.assertEqual((d.last_seen, d.expires_at), (0, 100))
        # 换个时刻再失败一次：目的计时依旧不动。
        with self.assertRaises(PortExhaustionError):
            nat.translate_hairpin(hp(B, 6001), at=50)
        d = nat.get_mapping(KEY_A)
        self.assertEqual((d.last_seen, d.expires_at), (0, 100))
        self.assertEqual(nat.now, 50)           # 时钟本身按 housekeeping 推进

    def test_search_budget_exhaustion_rollback(self):
        # 预算=1：规划源端口时第一口 6001 已被目的占用，预算即尽，
        # 未扫描全池（不能断定无解）-> SearchBudgetExhaustedError。
        nat = make_nat(ports=(6001, 6002, 6003), budget=1)
        nat.allocate(A, RA)                      # 6001
        before = nat.snapshot_mappings()
        with self.assertRaises(SearchBudgetExhaustedError) as ctx:
            nat.translate_hairpin(hp(B, 6001))
        err = ctx.exception
        self.assertNotIsInstance(err, PortExhaustionError)
        self.assertEqual((err.budget, err.inspected, err.needed, err.found),
                         (1, 1, 1, 0))
        self.assertEqual(nat.snapshot_mappings(), before)
        self.assertEqual(nat.stats()["ports_in_use"], 1)
        # 同等状态下放大预算后同一请求成功 -> 之前确为预算问题，拿到 6002。
        nat2 = make_nat(ports=(6001, 6002, 6003), budget=3)
        nat2.allocate(A, RA)
        ok = nat2.translate_hairpin(hp(B, 6001, gen=1))
        self.assertTrue(ok.accepted)
        self.assertEqual(ok.source_mapping.external_port, 6002)


class TestHairpinSelfAccess(unittest.TestCase):
    """自己访问自己的映射：允许，目的=自身内网端点；容量只扣源这一份。"""

    def test_self_hairpin_charges_capacity_once(self):
        nat = make_nat(ports=(6001, 6002), quarantine=0)
        ma = nat.allocate(A, RA)                 # 6001 gen1
        res = nat.translate_hairpin(hp(A, 6001, gen=1))
        self.assertTrue(res.accepted)
        # 目的映射就是 A 自己那条，源映射是另一条 key（remote=公网端点）。
        self.assertEqual(res.destination_mapping.key, ma.key)
        self.assertEqual(res.source_mapping.key, (A.ip, A.port, PUB, 6001))
        self.assertEqual(res.source_mapping.external_port, 6002)
        self.assertEqual(four(res.rewritten), (17, PUB, 6002, A.ip, A.port))
        # 两条映射、两个端口；目的映射没有被扣第二次容量。
        self.assertEqual(nat.stats()["ports_in_use"], 2)
        again = nat.translate_hairpin(hp(A, 6001, gen=1))
        self.assertFalse(again.source_created)
        self.assertEqual(nat.stats()["ports_in_use"], 2)


class TestHairpinDoesNotRelaxInbound(unittest.TestCase):
    """hairpin 只是新入口的明确例外：普通入站过滤维持原样。"""

    def test_normal_inbound_still_rejects_internal_source(self):
        nat = make_nat()
        nat.allocate(A, RA)                      # 6001, 记录对端 RA
        # 内网 B 直接走普通入站入口打到 6001：源 != RA -> 仍 PEER_MISMATCH。
        plain = nat.translate_inbound(hp(B, 6001))
        self.assertFalse(plain.accepted)
        self.assertIs(plain.reason, DropReason.PEER_MISMATCH)
        # 合法对端的普通入站照旧通过。
        ok = nat.translate_inbound(
            Packet(RA, Endpoint(PUB, 6001), generation=1))
        self.assertTrue(ok.accepted)
        self.assertEqual(four(ok.rewritten), (17, RA.ip, RA.port, A.ip, A.port))
        # 目的 IP 不对在 hairpin 入口同样拒绝，且不会误建源映射。
        wrong = nat.translate_hairpin(
            Packet(B, Endpoint(OTHER, 6001), generation=1))
        self.assertIs(wrong.reason, DropReason.DEST_MISMATCH)
        self.assertEqual(nat.stats()["live_mappings"], 1)


class TestHairpinValidation(unittest.TestCase):
    def test_bad_packet_and_clock(self):
        nat = make_nat()
        nat.allocate(A, RA)
        with self.assertRaises(ValidationError):
            nat.translate_hairpin("not a packet")
        nat.advance(5)
        with self.assertRaises(ValidationError):
            nat.translate_hairpin(hp(B, 6001), at=2)   # 时钟回退
        # 失败校验不留状态。
        self.assertEqual(nat.stats()["live_mappings"], 1)


if __name__ == "__main__":
    unittest.main()
