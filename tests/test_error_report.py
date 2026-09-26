"""差错报文入口的契约测试 + 独立字典对照（oracle）。

覆盖本轮要求：
- 同端口不同远端的引用 -> PEER_MISMATCH / 正确命中
- 过期端口被新连接复用后，旧 generation 引用 -> STALE_GENERATION
- 重复差错报文不污染状态（不刷新 last_seen/expires_at）
- 差错与正常回包穿插，状态只被正常流量推进
- 结构不完整 -> BAD_STRUCTURE；无映射 -> NO_MAPPING；无法唯一定位 -> AMBIGUOUS
对照方式：本文件内用一个独立字典 EXPECT 手工登记 (quoted 四元组) -> 期望结论，
并逐项与 tests/reference_nat.py 的独立字典实现比对，不调用被测核心得到期望值。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    ErrorReport,
    FiveTuple,
    NATConfig,
    Packet,
    ValidationError,
)
from reference_nat import RefError, RefNAT

PUB = "203.0.113.7"
A = Endpoint("10.0.0.8", 40000)
B = Endpoint("10.0.0.9", 50000)
R1 = Endpoint("198.51.100.10", 53)
R2 = Endpoint("198.51.100.11", 53)
SRC = Endpoint("192.0.2.254", 1)          # 差错报文外层源（中间设备）


def make_nat(ports=(6001, 6002), lifetime=100, quarantine=10):
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine,
    ))


def quoted(public_port: int, remote: Endpoint) -> FiveTuple:
    return FiveTuple(17, PUB, public_port, remote.ip, remote.port)


def err(public_port: int, remote: Endpoint, gen: int,
        outer_src: Endpoint = SRC) -> ErrorReport:
    return ErrorReport(outer_src=outer_src, quoted=quoted(public_port, remote),
                       generation=gen)


def ref_call(ref: RefNAT, report: ErrorReport, at=None):
    q = report.quoted
    return ref.error(
        (report.outer_src.ip, report.outer_src.port, q.protocol,
         q.src_ip, q.src_port, q.dst_ip, q.dst_port, report.generation),
        at=at)


class ErrorReportCrossCheck(unittest.TestCase):
    """独立字典对照：EXPECT 手工登记期望，并与独立参考实现逐项比对。"""

    def setUp(self):
        self.nat = make_nat()
        self.ref = RefNAT(PUB, (6001, 6002), 100, 10)

    def alloc_both(self, internal, remote, at=None):
        r = self.nat.allocate(internal, remote, at=at)
        self.ref.allocate_many(
            [(internal.ip, internal.port, remote.ip, remote.port)], at=at)
        return r

    def assertRefAgrees(self, report: ErrorReport, expect, at=None):
        """expect = ("ok", (17, os_ip, os_pt, i_ip, i_pt), mid) / ("drop", reason, mid)"""
        got = self.nat.translate_error(report, at=at)
        if expect[0] == "ok":
            self.assertTrue(got.accepted, f"expected ok, got {got.reason}")
            f = got.rewritten
            self.assertEqual(
                (f.protocol, f.src_ip, f.src_port, f.dst_ip, f.dst_port),
                expect[1])
            self.assertEqual(got.mapping_id, expect[2])
            self.assertEqual((got.outer_dst.ip, got.outer_dst.port),
                             (expect[1][3], expect[1][4]))
            tag = ("ok", (f.protocol, f.src_ip, f.src_port,
                          f.dst_ip, f.dst_port), got.mapping_id)
        else:
            self.assertFalse(got.accepted)
            self.assertEqual(got.reason.value, expect[1])
            self.assertEqual(got.mapping_id, expect[2])
            tag = ("drop", got.reason.value, got.mapping_id)
        self.assertEqual(tag, ref_call(self.ref, report, at=at))

    def test_same_port_different_remote_and_normal_hit(self):
        m1 = self.alloc_both(A, R1)
        m2 = self.alloc_both(A, R2)
        self.assertEqual((m1.mapping.external_port, m2.mapping.external_port),
                         (6001, 6002))
        # 独立字典：引用键 -> 期望（手写，不来自核心）。
        expect = {
            (6001, R1.ip, R1.port, m1.mapping.generation):
                ("ok", (17, SRC.ip, SRC.port, A.ip, A.port), 1),
            (6002, R2.ip, R2.port, m2.mapping.generation):
                ("ok", (17, SRC.ip, SRC.port, A.ip, A.port), 2),
            (6001, R2.ip, R2.port, m1.mapping.generation):
                ("drop", "peer_mismatch", 1),
            (6002, R1.ip, R1.port, m2.mapping.generation):
                ("drop", "peer_mismatch", 2),
        }
        for (port, rip, rport, gen), want in expect.items():
            self.assertRefAgrees(err(port, Endpoint(rip, rport), gen), want)

    def test_expired_reuse_stale_reference_rejected(self):
        # 旧连接过期（端口隔离结束）后，新连接复用同端口、新 generation。
        self.alloc_both(A, R1)                    # gen 1, port 6001
        self.nat.advance(100)
        self.ref.advance(100)                    # t=100：过期进隔离
        self.nat.advance(10)
        self.ref.advance(10)                     # t=110：隔离结束
        m2 = self.alloc_both(B, R2)              # 复用 6001, gen 2
        self.assertEqual(m2.mapping.external_port, 6001)
        self.assertEqual(m2.mapping.generation, 2)
        # 旧引用（旧五元组 + 旧世代标记）：世代先判 stale。
        self.assertRefAgrees(err(6001, R1, gen=1),
                             ("drop", "stale_generation", 2))
        # 旧引用不带世代（gen=0）：落到对端不匹配，无法靠五元组排除复用。
        self.assertRefAgrees(err(6001, R1, gen=0),
                             ("drop", "peer_mismatch", 2))
        # 新连接的当前引用正常命中。
        self.assertRefAgrees(err(6001, R2, gen=2),
                             ("ok", (17, SRC.ip, SRC.port, B.ip, B.port), 2))

    def test_identical_tuple_reuse_cannot_be_distinguished_without_generation(self):
        # 相同五元组复用：gen=0 时新连接会把旧引用当作自己（README 声明的限制）；
        # 携带正确世代标记时仍能命中当前映射。
        self.alloc_both(A, R1)                    # gen 1
        self.nat.advance(100)
        self.ref.advance(100)
        self.nat.advance(10)
        self.ref.advance(10)
        m2 = self.alloc_both(A, R1)              # 完全相同五元组，gen 2
        self.assertEqual(m2.mapping.generation, 2)
        # 旧世代标记 -> 明确判迟到。
        self.assertRefAgrees(err(6001, R1, gen=1),
                             ("drop", "stale_generation", 2))
        # 无世代信息 -> 无法排除，按当前映射命中（限制，非承诺识别）。
        self.assertRefAgrees(err(6001, R1, gen=0),
                             ("ok", (17, SRC.ip, SRC.port, A.ip, A.port), 2))

    def test_duplicate_errors_do_not_refresh_interleaved_with_traffic(self):
        m = self.alloc_both(A, R1)
        gen = m.mapping.generation
        self.nat.advance(50)
        self.ref.advance(50)
        before = self.nat.get_mapping(m.key)
        # 连续重复差错：每次成功反查，但 expires_at 不变（不延长寿命）。
        for _ in range(3):
            res = self.nat.translate_error(err(6001, R1, gen))
            self.assertTrue(res.accepted)
            self.assertEqual(self.nat.get_mapping(m.key).expires_at,
                             before.expires_at)
        # 正常回包穿插：只有正常入站包刷新寿命。
        self.nat.translate_inbound(
            Packet(src=R1, dst=Endpoint(PUB, 6001), generation=gen))
        self.ref.inbound((R1.ip, R1.port, PUB, 6001, gen))
        refreshed = self.nat.get_mapping(m.key)
        self.assertEqual(refreshed.expires_at,
                         self.nat.now + self.nat.config.lifetime)
        self.assertGreater(refreshed.expires_at, before.expires_at)
        # 刷新后再发差错，仍不延长。
        res = self.nat.translate_error(err(6001, R1, gen))
        self.assertTrue(res.accepted)
        self.assertEqual(self.nat.get_mapping(m.key).expires_at,
                         refreshed.expires_at)
        # 映射随正常流量的寿命到期；差错本身从未保活。
        self.nat.advance(99)
        self.ref.advance(99)
        self.assertIsNotNone(self.nat.get_mapping(m.key))
        self.nat.advance(1)
        self.ref.advance(1)
        self.assertIsNone(self.nat.get_mapping(m.key))
        # 过期后引用 -> NO_MAPPING；ref 一致。
        self.assertRefAgrees(err(6001, R1, gen),
                             ("drop", "no_mapping", None))


class ErrorReportDrops(unittest.TestCase):
    """结构/定位类丢弃原因。"""

    def setUp(self):
        self.nat = make_nat()
        self.ref = RefNAT(PUB, (6001, 6002), 100, 10)
        self.nat.allocate(A, R1)
        self.ref.allocate_many([(A.ip, A.port, R1.ip, R1.port)])

    def assertDrop(self, report: ErrorReport, reason: str, mid):
        got = self.nat.translate_error(report)
        self.assertFalse(got.accepted)
        self.assertEqual(got.reason.value, reason)
        self.assertEqual(got.mapping_id, mid)
        self.assertEqual(("drop", reason, mid), ref_call(self.ref, report))

    def test_bad_structure(self):
        # 非 UDP 协议号。
        self.assertDrop(
            ErrorReport(SRC, FiveTuple(6, PUB, 6001, R1.ip, R1.port), 1),
            "bad_structure", None)
        # 引用源不是 NAT 公网 IP（方向/结构不符）。
        self.assertDrop(
            ErrorReport(SRC, FiveTuple(17, "192.0.2.9", 6001, R1.ip, R1.port), 1),
            "bad_structure", None)
        # 结构错误时 quoted 仍回显。
        got = self.nat.translate_error(
            ErrorReport(SRC, FiveTuple(17, "192.0.2.9", 6001, R1.ip, R1.port), 1))
        self.assertIsNotNone(got.quoted)
        self.assertIsNone(got.rewritten)
        self.assertIsNone(got.outer_dst)

    def test_no_mapping_for_unknown_port(self):
        self.assertDrop(err(6002, R1, gen=1), "no_mapping", None)

    def test_stale_generation(self):
        self.assertDrop(err(6001, R1, gen=99), "stale_generation", 1)

    def test_peer_mismatch(self):
        self.assertDrop(err(6001, R2, gen=1), "peer_mismatch", 1)

    def test_error_never_creates_or_extends(self):
        nat = make_nat(ports=(6001,), lifetime=100, quarantine=0)
        # 未分配的端口：差错绝不隐式建映射。
        res = nat.translate_error(err(6001, R1, gen=0))
        self.assertIs(res.reason, DropReason.NO_MAPPING)
        self.assertEqual(nat.stats()["live_mappings"], 0)

    def test_bad_input_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            ErrorReport("not-an-endpoint", quoted(6001, R1), 1)
        with self.assertRaises(ValidationError):
            ErrorReport(SRC, quoted(6001, R1), generation=True)
        with self.assertRaises(ValidationError):
            self.nat.translate_error("not-a-report")
        with self.assertRaises(RefError):
            self.ref.error(("192.0.2.254", 1, 17, PUB, 6001,
                            R1.ip, R1.port, True))


if __name__ == "__main__":
    unittest.main()
