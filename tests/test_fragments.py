"""分片入口契约测试：手工期望值 + 独立重组对照。

覆盖：
- 乱序到达：非首片先暂存，首片到达后连带吐出，冻结同一映射世代
- 首片永不到：逻辑超时后整组释放，缓存归零
- 过期映射复用：映射换代后旧组迟到片拒绝（STALE_GENERATION），ID 复用不串包
- 重叠冲突：重叠区字节不一致整组拒绝；完全重复片幂等
- 上限：总长度 / 片数 / 缓存字节
- 独立重组原始载荷，核对字节没有改动
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    Direction,
    DropReason,
    Endpoint,
    Fragment,
    FragmentStatus,
    NATConfig,
    Packet,
    ValidationError,
)

PUB = "203.0.113.7"
A_IP, A_PORT = "10.0.0.8", 40000
R_IP, R_PORT = "198.51.100.10", 53
KEY = (A_IP, A_PORT, R_IP, R_PORT)


def make_nat(**kw) -> AddressDependentNAT:
    cfg = dict(public_ip=PUB, external_ports=(6001, 6002, 6003),
               lifetime=10, quarantine=5, fragment_timeout=4,
               max_datagram_size=65535, max_fragments=8,
               max_cached_bytes=4096)
    cfg.update(kw)
    return AddressDependentNAT(NATConfig(**cfg))


def frag(payload: bytes, offset: int, mf: bool, *, dg_id: int = 7,
         direction: Direction = Direction.OUTBOUND,
         src_ip: str = A_IP, dst_ip: str = R_IP,
         src_port: int = 0, dst_port: int = 0, generation: int = 0) -> Fragment:
    return Fragment(direction=direction, src_ip=src_ip, dst_ip=dst_ip,
                    protocol=17, datagram_id=dg_id, offset=offset,
                    more_fragments=mf, payload=payload,
                    src_port=src_port, dst_port=dst_port, generation=generation)


def outbound_frags(payload: bytes, size: int, *, dg_id: int = 7) -> list[Fragment]:
    """把原始载荷切成首片带端口的分片序列。"""
    out = []
    for off in range(0, len(payload), size):
        chunk = payload[off:off + size]
        out.append(frag(chunk, off, off + size < len(payload), dg_id=dg_id,
                        src_port=A_PORT if off == 0 else 0,
                        dst_port=R_PORT if off == 0 else 0))
    return out


def reassemble(rewritten) -> bytes:
    """独立重组：按 offset 把改写片的载荷铺回字节流。"""
    buf = bytearray()
    for rf in rewritten:
        end = rf.offset + len(rf.payload)
        if len(buf) < end:
            buf.extend(b"\x00" * (end - len(buf)))
        buf[rf.offset:end] = rf.payload
    return bytes(buf)


class TestOutOfOrder(unittest.TestCase):
    """乱序：非首片先到只能暂存；首片到达后全部按同一冻结世代改写。"""

    def test_non_first_buffered_then_flushed(self):
        nat = make_nat()
        payload = bytes(range(1, 25))  # 24 字节原始载荷
        f0, f1, f2 = outbound_frags(payload, 8)
        r2 = nat.process_fragment(f2)
        self.assertEqual(r2.status, FragmentStatus.BUFFERED)
        self.assertEqual(r2.rewritten, ())
        # 非首片先到不会隐式建映射（不能凭 ID 猜连接）。
        self.assertIsNone(nat.get_mapping(KEY))
        r0 = nat.process_fragment(f0)
        self.assertEqual(r0.status, FragmentStatus.FORWARDED)
        # 首片到达连带吐出暂存片：f0 + f2。
        self.assertEqual([rf.offset for rf in r0.rewritten], [0, 16])
        gen = nat.get_mapping(KEY).generation
        ext = nat.get_mapping(KEY).external_port
        for rf in r0.rewritten:
            self.assertEqual((rf.five_tuple.src_ip, rf.five_tuple.src_port),
                             (PUB, ext))
            self.assertEqual((rf.five_tuple.dst_ip, rf.five_tuple.dst_port),
                             (R_IP, R_PORT))
        r1 = nat.process_fragment(f1)
        self.assertEqual(r1.status, FragmentStatus.COMPLETE)
        # 数据报到齐后关联释放，缓存归零。
        self.assertEqual(nat.fragment_groups(), [])
        self.assertEqual(nat.stats()["fragment_cached_bytes"], 0)
        # 独立重组核对字节没有改动。
        merged = reassemble(r0.rewritten + r1.rewritten)
        self.assertEqual(merged, payload)
        # 后续片使用冻结的同一映射世代。
        self.assertEqual(nat.get_mapping(KEY).generation, gen)

    def test_complete_releases_id_for_reuse(self):
        nat = make_nat()
        payload = b"abcdefghijklmnop"
        for f in outbound_frags(payload, 8):
            nat.process_fragment(f)
        self.assertEqual(nat.fragment_groups(), [])
        # 同一 datagram_id 立即复用：全新一组，不串旧状态。
        r = nat.process_fragment(outbound_frags(b"WXYZ", 4)[0])
        self.assertEqual(r.status, FragmentStatus.COMPLETE)
        self.assertEqual(reassemble(r.rewritten), b"WXYZ")


class TestFirstNeverArrives(unittest.TestCase):
    """首片永不到：暂存组逻辑超时后释放，不占用缓存、不建映射。"""

    def test_timeout_releases_group(self):
        nat = make_nat()
        nat.process_fragment(frag(b"12345678", 8, True))
        nat.process_fragment(frag(b"abcdefgh", 16, False))
        self.assertEqual(len(nat.fragment_groups()), 1)
        self.assertEqual(nat.stats()["fragment_cached_bytes"], 16)
        expired = nat.advance(4)  # last_seen=0, timeout=4 -> now=4 边界即死
        self.assertEqual(expired, [])
        self.assertEqual(nat.fragment_groups(), [])
        self.assertEqual(nat.stats()["fragment_cached_bytes"], 0)
        self.assertIsNone(nat.get_mapping(KEY))

    def test_activity_refreshes_group_timeout(self):
        nat = make_nat()
        nat.process_fragment(frag(b"12345678", 8, True))
        nat.advance(3)
        nat.process_fragment(frag(b"abcdefgh", 16, False))  # last_seen=3
        nat.advance(3)  # now=6 < 3+4，未超时
        self.assertEqual(len(nat.fragment_groups()), 1)
        nat.advance(1)  # now=7 >= 3+4，超时
        self.assertEqual(nat.fragment_groups(), [])


class TestExpiredMappingReuse(unittest.TestCase):
    """映射过期被复用后，旧数据报的迟到片不得跟随新映射。"""

    def test_stale_group_rejected_after_mapping_rebuilt(self):
        # fragment_timeout(30) > lifetime(10)：映射先过期，分片组仍存活。
        nat = make_nat(fragment_timeout=30)
        first = frag(b"HEAD", 0, True, src_port=A_PORT, dst_port=R_PORT)
        r = nat.process_fragment(first)
        self.assertEqual(r.status, FragmentStatus.FORWARDED)
        old_gen = nat.get_mapping(KEY).generation
        nat.advance(10)  # 映射过期（now=10 >= expires_at=10）
        nat.advance(5)   # 过隔离期 Q=5，端口可复用
        # 同一四元组重新建映射：世代换代（可能复用同一端口）。
        nat.process_fragment(frag(b"HEAD", 0, True, dg_id=99,
                                  src_port=A_PORT, dst_port=R_PORT))
        new_gen = nat.get_mapping(KEY).generation
        self.assertNotEqual(old_gen, new_gen)
        # 旧数据报（id=7）的迟到片：整组拒绝，不跟随新映射。
        late = nat.process_fragment(frag(b"tailtail", 4, False, dg_id=7))
        self.assertEqual(late.status, FragmentStatus.DROPPED)
        self.assertEqual(late.reason, DropReason.STALE_GENERATION)
        # 旧组（id=7）已释放；只剩 id=99 的新组。
        self.assertEqual([g.key[4] for g in nat.fragment_groups()], [99])
        # id=7 之后可作为全新数据报复用。
        fresh = nat.process_fragment(frag(b"HEAD", 0, False, dg_id=7,
                                          src_port=A_PORT, dst_port=R_PORT))
        self.assertEqual(fresh.status, FragmentStatus.COMPLETE)


class TestOverlapAndDuplicate(unittest.TestCase):
    """重叠冲突整组拒绝；完全重复片幂等。"""

    def test_overlap_conflict_rejects_group(self):
        nat = make_nat()
        nat.process_fragment(frag(b"abcdefgh", 0, True,
                                  src_port=A_PORT, dst_port=R_PORT))
        r = nat.process_fragment(frag(b"efXXXXXX", 4, False))
        self.assertEqual(r.status, FragmentStatus.DROPPED)
        self.assertEqual(r.reason, DropReason.OVERLAP_CONFLICT)
        self.assertEqual(nat.fragment_groups(), [])
        self.assertEqual(nat.stats()["fragment_cached_bytes"], 0)

    def test_consistent_overlap_accepted(self):
        nat = make_nat()
        r0 = nat.process_fragment(frag(b"abcdefgh", 0, True,
                                       src_port=A_PORT, dst_port=R_PORT))
        r = nat.process_fragment(frag(b"efgh", 4, False))
        self.assertEqual(r.status, FragmentStatus.COMPLETE)
        self.assertEqual(reassemble(r0.rewritten + r.rewritten), b"abcdefgh")

    def test_exact_duplicate_idempotent(self):
        nat = make_nat()
        nat.process_fragment(frag(b"12345678", 8, True))
        before = (nat.fragment_groups(), nat.stats()["fragment_cached_bytes"])
        r = nat.process_fragment(frag(b"12345678", 8, True))
        self.assertEqual(r.status, FragmentStatus.DUPLICATE)
        self.assertEqual(r.rewritten, ())
        after = (nat.fragment_groups(), nat.stats()["fragment_cached_bytes"])
        self.assertEqual(before, after)


class TestLimits(unittest.TestCase):
    """总长度、片数、缓存字节上限。"""

    def test_datagram_too_large(self):
        nat = make_nat(max_datagram_size=10)
        r = nat.process_fragment(frag(b"12345678", 8, False))
        self.assertEqual(r.status, FragmentStatus.DROPPED)
        self.assertEqual(r.reason, DropReason.DATAGRAM_TOO_LARGE)

    def test_too_many_fragments(self):
        nat = make_nat(max_fragments=2)
        nat.process_fragment(frag(b"aaaaaaaa", 8, True))
        nat.process_fragment(frag(b"bbbbbbbb", 16, True))
        r = nat.process_fragment(frag(b"cccccccc", 24, False))
        self.assertEqual(r.status, FragmentStatus.DROPPED)
        self.assertEqual(r.reason, DropReason.TOO_MANY_FRAGMENTS)
        self.assertEqual(nat.fragment_groups(), [])

    def test_cache_full(self):
        nat = make_nat(max_cached_bytes=10)
        nat.process_fragment(frag(b"aaaaaaaa", 8, True, dg_id=1))
        r = nat.process_fragment(frag(b"bbbbbbbb", 8, True, dg_id=2))
        self.assertEqual(r.status, FragmentStatus.DROPPED)
        self.assertEqual(r.reason, DropReason.CACHE_FULL)
        # 第一组不受影响。
        self.assertEqual(len(nat.fragment_groups()), 1)


class TestInboundFragments(unittest.TestCase):
    """入站分片：首片按外端口命中既有映射，改写到内网端点。"""

    def test_inbound_rewrite(self):
        nat = make_nat()
        nat.allocate(Endpoint(A_IP, A_PORT), Endpoint(R_IP, R_PORT))
        payload = b"reply-payload!!"  # 15 字节
        f0 = frag(payload[:8], 0, True, direction=Direction.INBOUND,
                  src_ip=R_IP, dst_ip=PUB, src_port=R_PORT, dst_port=6001)
        f1 = frag(payload[8:], 8, False, direction=Direction.INBOUND,
                  src_ip=R_IP, dst_ip=PUB)
        r1 = nat.process_fragment(f1)
        self.assertEqual(r1.status, FragmentStatus.BUFFERED)
        r0 = nat.process_fragment(f0)
        self.assertEqual(r0.status, FragmentStatus.COMPLETE)
        for rf in r0.rewritten:
            self.assertEqual((rf.five_tuple.dst_ip, rf.five_tuple.dst_port),
                             (A_IP, A_PORT))
            self.assertEqual((rf.five_tuple.src_ip, rf.five_tuple.src_port),
                             (R_IP, R_PORT))
        self.assertEqual(reassemble(r0.rewritten), payload)

    def test_inbound_no_mapping_dropped(self):
        nat = make_nat()
        r = nat.process_fragment(frag(b"HEAD", 0, False,
                                      direction=Direction.INBOUND,
                                      src_ip=R_IP, dst_ip=PUB,
                                      src_port=R_PORT, dst_port=6002))
        self.assertEqual(r.status, FragmentStatus.DROPPED)
        self.assertEqual(r.reason, DropReason.NO_MAPPING)


class TestFragmentValidation(unittest.TestCase):
    """分片输入校验：非首片不得带端口；仅 UDP。"""

    def test_non_first_with_ports_rejected(self):
        with self.assertRaises(ValidationError):
            frag(b"x", 8, True, src_port=1)

    def test_first_without_ports_rejected(self):
        with self.assertRaises(ValidationError):
            frag(b"x", 0, True)

    def test_non_udp_rejected(self):
        with self.assertRaises(ValidationError):
            Fragment(direction=Direction.OUTBOUND, src_ip=A_IP, dst_ip=R_IP,
                     protocol=6, datagram_id=1, offset=0, more_fragments=False,
                     payload=b"x", src_port=1, dst_port=2)


class TestOldEntryUnchanged(unittest.TestCase):
    """旧非分片入口行为不变：不隐式建映射；分片建的映射可用于整包。"""

    def test_translate_outbound_still_no_implicit_mapping(self):
        nat = make_nat()
        r = nat.translate_outbound(
            Packet(src=Endpoint(A_IP, A_PORT), dst=Endpoint(R_IP, R_PORT)))
        self.assertFalse(r.accepted)
        self.assertEqual(r.reason, DropReason.NO_MAPPING)

    def test_fragment_mapping_usable_by_packet_path(self):
        nat = make_nat()
        nat.process_fragment(frag(b"HEAD", 0, True,
                                  src_port=A_PORT, dst_port=R_PORT))
        gen = nat.get_mapping(KEY).generation
        r = nat.translate_outbound(
            Packet(src=Endpoint(A_IP, A_PORT), dst=Endpoint(R_IP, R_PORT),
                   generation=gen))
        self.assertTrue(r.accepted)
        self.assertEqual(r.rewritten.src_ip, PUB)


if __name__ == "__main__":
    unittest.main()
