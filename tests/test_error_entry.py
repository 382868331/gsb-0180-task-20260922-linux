"""差错报文入口（translate_error）契约 + 独立字典对照测试。

覆盖本轮要求的全部场景：
- 正常反向定位：返回改写后的外层目标（ICMP,1）、引用 UDP 五元组、映射 ID；
- 同端口不同远端：地址依赖对端不匹配 -> PEER_MISMATCH；
- 过期复用：旧世代标记引用已被复用的端口 -> STALE_GENERATION；
- 重复差错：多次差错结果一致，且不延长寿命、不污染状态；
- 正常回包穿插：差错不刷新寿命，回包才刷新，状态不被污染；
- 结构不完整/非 UDP/目的错误：QUOTE_* / DEST_MISMATCH / NO_MAPPING；
- 每个用例同时与独立字典参考（reference_nat.RefNAT，不导入被测核心）
  逐字段对照，状态签名在每个操作后保持一致。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    ErrorPacket,
    NATConfig,
    Packet,
    ValidationError,
)
from reference_nat import RefError, RefNAT

PUB = "203.0.113.7"
PORTS = (6100, 6101, 6102)
HOST = Endpoint("10.0.0.8", 40000)
PEER_A = Endpoint("198.51.100.1", 443)
PEER_B = Endpoint("198.51.100.2", 443)
KEY_A = (HOST.ip, HOST.port, PEER_A.ip, PEER_A.port)


def _core_sig(nat):
    live = tuple(sorted(
        (m.key, (m.external_port, m.generation, m.created_at,
                 m.last_seen, m.expires_at))
        for m in nat.snapshot_mappings()
    ))
    pgens = tuple(sorted(
        (p, tuple(sorted(gs))) for p, gs in nat.port_generations().items()
    ))
    return (nat.now, live,
            tuple(sorted(nat.quarantined_ports().items())), pgens)


def _ref_sig(ref):
    now, live, quar, _nxt, pgens = ref.signature()
    return (now, live, quar, pgens)


class _Dual:
    """被测核心 + 独立字典参考，同步操作并逐结果对照。"""

    def __init__(self, lifetime=300, quarantine=0):
        self.core = AddressDependentNAT(NATConfig(
            public_ip=PUB, external_ports=PORTS,
            lifetime=lifetime, quarantine=quarantine))
        self.ref = RefNAT(PUB, PORTS, lifetime, quarantine, len(PORTS))

    def alloc(self, internal, remote, at=None):
        c = self.core.allocate(internal, remote, at=at).mapping
        r = self.ref.allocate_many(
            [(internal.ip, internal.port, remote.ip, remote.port)], at=at)[0]
        assert (c.external_port, c.generation) == (r[1], r[2])
        return c

    def release(self, key, at=None):
        assert self.core.release(key, at=at) == self.ref.release(key, at=at)

    def advance(self, seconds):
        assert self.core.advance(seconds) == self.ref.advance(seconds)

    def error(self, ep, at=None):
        res = self.core.translate_error(ep, at=at)
        r = self.ref.error((
            ep.outer_src.ip, ep.outer_src.port,
            ep.outer_dst.ip, ep.outer_dst.port,
            ep.quoted_src.ip, ep.quoted_src.port,
            ep.quoted_dst.ip, ep.quoted_dst.port,
            ep.quoted_protocol, ep.generation,
        ), at=at)
        if res.accepted:
            o, q = res.outer_target, res.quoted
            got = ("ok",
                   (o.protocol, o.src_ip, o.src_port, o.dst_ip, o.dst_port),
                   (q.protocol, q.src_ip, q.src_port, q.dst_ip, q.dst_port),
                   res.mapping_id)
        else:
            got = ("drop", res.reason.value)
        assert got == r, f"core={got} ref={r}"
        return res

    def sig_equal(self):
        assert _core_sig(self.core) == _ref_sig(self.ref)


def make_error(peer: Endpoint, port: int, generation: int,
               *, outer_src: Endpoint | None = None,
               quoted_dst: Endpoint | None = None,
               quoted_src: Endpoint | None = None,
               outer_dst_ip: str = PUB,
               quoted_protocol: int = 17) -> ErrorPacket:
    outer_dst = Endpoint(outer_dst_ip, port)
    return ErrorPacket(
        outer_src=outer_src or peer,
        outer_dst=outer_dst,
        quoted_src=quoted_src or outer_dst,
        quoted_dst=quoted_dst or peer,
        quoted_protocol=quoted_protocol,
        generation=generation,
    )


class TestErrorEntry(unittest.TestCase):
    def test_successful_reverse_lookup(self):
        d = _Dual()
        m = d.alloc(HOST, PEER_A)
        res = d.error(make_error(PEER_A, m.external_port, m.generation))
        self.assertTrue(res.accepted)
        self.assertEqual(res.mapping_id, m.generation)
        o = res.outer_target
        self.assertEqual(
            (o.protocol, o.src_ip, o.src_port, o.dst_ip, o.dst_port),
            (1, PEER_A.ip, PEER_A.port, HOST.ip, HOST.port))
        q = res.quoted
        self.assertEqual(
            (q.protocol, q.src_ip, q.src_port, q.dst_ip, q.dst_port),
            (17, PUB, m.external_port, PEER_A.ip, PEER_A.port))
        d.sig_equal()

    def test_generation_zero_skips_generation_check(self):
        d = _Dual()
        m = d.alloc(HOST, PEER_A)
        res = d.error(make_error(PEER_A, m.external_port, 0))
        self.assertTrue(res.accepted)
        self.assertEqual(res.mapping_id, m.generation)
        d.sig_equal()

    def test_same_port_different_remote_is_peer_mismatch(self):
        d = _Dual()
        m = d.alloc(HOST, PEER_A)
        res = d.error(make_error(
            PEER_A, m.external_port, m.generation, outer_src=PEER_B))
        self.assertFalse(res.accepted)
        self.assertEqual(res.reason, DropReason.PEER_MISMATCH)
        res2 = d.error(make_error(
            PEER_B, m.external_port, 0, quoted_dst=PEER_B))
        self.assertFalse(res2.accepted)
        self.assertEqual(res2.reason, DropReason.PEER_MISMATCH)
        d.sig_equal()

    def test_dest_and_protocol_and_malformed(self):
        d = _Dual()
        m = d.alloc(HOST, PEER_A)
        bad_dst = d.error(make_error(
            PEER_A, m.external_port, m.generation,
            outer_dst_ip="198.51.100.9"))
        self.assertEqual(bad_dst.reason, DropReason.DEST_MISMATCH)
        not_udp = d.error(make_error(
            PEER_A, m.external_port, m.generation, quoted_protocol=6))
        self.assertEqual(not_udp.reason, DropReason.QUOTE_NOT_UDP)
        malformed = d.error(make_error(
            PEER_A, m.external_port, m.generation,
            quoted_src=Endpoint(PUB, m.external_port + 1)))
        self.assertEqual(malformed.reason, DropReason.QUOTE_MALFORMED)
        free = d.error(make_error(PEER_A, 6102, 0))
        self.assertEqual(free.reason, DropReason.NO_MAPPING)
        d.sig_equal()

    def test_expired_port_reuse_stale_generation(self):
        d = _Dual(lifetime=10, quarantine=0)
        old = d.alloc(HOST, PEER_A)
        old_gen, port = old.generation, old.external_port
        d.advance(10)                       # 边界即死：映射过期
        stale = d.error(make_error(PEER_A, port, old_gen))
        self.assertEqual(stale.reason, DropReason.STALE_GENERATION)
        self.assertEqual(
            d.error(make_error(PEER_A, port, 0)).reason,
            DropReason.NO_MAPPING)
        new = d.alloc(HOST, PEER_B, at=10)
        self.assertEqual(new.external_port, port)
        self.assertNotEqual(new.generation, old_gen)
        stale2 = d.error(make_error(PEER_A, port, old_gen))
        self.assertEqual(stale2.reason, DropReason.STALE_GENERATION)
        ok = d.error(make_error(PEER_B, port, new.generation))
        self.assertTrue(ok.accepted)
        self.assertEqual(ok.mapping_id, new.generation)
        d.sig_equal()

    def test_duplicate_errors_do_not_extend_or_pollute(self):
        d = _Dual(lifetime=10, quarantine=0)
        m = d.alloc(HOST, PEER_A)
        port, gen = m.external_port, m.generation
        before = d.core.get_mapping(KEY_A)
        for t in (1, 5, 9):
            res = d.error(make_error(PEER_A, port, gen), at=t)
            self.assertTrue(res.accepted)
        after = d.core.get_mapping(KEY_A)
        self.assertEqual(
            (before.last_seen, before.expires_at),
            (after.last_seen, after.expires_at))
        d.advance(10)
        self.assertIsNone(d.core.get_mapping(KEY_A))
        d.sig_equal()

    def test_errors_interleaved_with_normal_return_traffic(self):
        d = _Dual(lifetime=10, quarantine=0)
        m = d.alloc(HOST, PEER_A)
        port, gen = m.external_port, m.generation
        e1 = d.error(make_error(PEER_A, port, gen), at=9)
        self.assertTrue(e1.accepted)
        self.assertEqual(d.core.get_mapping(KEY_A).expires_at, 10)
        back = d.core.translate_inbound(
            Packet(src=PEER_A, dst=Endpoint(PUB, port), generation=gen), at=9)
        self.assertTrue(back.accepted)
        d.ref.inbound((PEER_A.ip, PEER_A.port, PUB, port, gen), at=9)
        self.assertEqual(d.core.get_mapping(KEY_A).expires_at, 19)
        e2 = d.error(make_error(PEER_A, port, gen), at=9)
        self.assertTrue(e2.accepted)
        self.assertEqual(e2.mapping_id, e1.mapping_id)
        self.assertEqual(d.core.get_mapping(KEY_A).expires_at, 19)
        d.sig_equal()
        d.advance(10)
        self.assertEqual(
            d.error(make_error(PEER_A, port, gen), at=19).reason,
            DropReason.STALE_GENERATION)
        d.sig_equal()

    def test_two_remotes_two_ports_address_dependent(self):
        d = _Dual()
        ma = d.alloc(HOST, PEER_A)
        mb = d.alloc(HOST, PEER_B)
        self.assertNotEqual(ma.external_port, mb.external_port)
        ra = d.error(make_error(PEER_A, ma.external_port, ma.generation))
        rb = d.error(make_error(PEER_B, mb.external_port, mb.generation))
        self.assertTrue(ra.accepted and rb.accepted)
        self.assertEqual(ra.mapping_id, ma.generation)
        self.assertEqual(rb.mapping_id, mb.generation)
        cross = d.error(make_error(PEER_B, mb.external_port, ma.generation))
        self.assertEqual(cross.reason, DropReason.STALE_GENERATION)
        d.sig_equal()

    def test_invalid_error_packet_input_raises_validation_error(self):
        d = _Dual()
        with self.assertRaises(ValidationError):
            d.core.translate_error(
                make_error(PEER_A, 6100, True))  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            ErrorPacket(
                outer_src=PEER_A,
                outer_dst=("x", 1),  # type: ignore[arg-type]
                quoted_src=Endpoint(PUB, 6100),
                quoted_dst=PEER_A)
        with self.assertRaises(ValidationError):
            ErrorPacket(
                outer_src=PEER_A, outer_dst=Endpoint(PUB, 6100),
                quoted_src=Endpoint(PUB, 6100), quoted_dst=PEER_A,
                quoted_protocol=17, generation=1 << 63)
        with self.assertRaises(ValidationError):
            d.core.translate_error(
                make_error(PEER_A, 6100, 1), at=-1)
        with self.assertRaises(RefError):
            d.ref.error(
                (PEER_A.ip, PEER_A.port, PUB, 6100,
                 PUB, 6100, PEER_A.ip, PEER_A.port, 17, True))


if __name__ == "__main__":
    unittest.main()
