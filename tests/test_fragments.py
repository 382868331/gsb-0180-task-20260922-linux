"""分片重组测试：乱序、首片永不到、过期映射复用、重叠冲突、上限与幂等。

独立对照：reassemble() 只用排序+拼接重组原始载荷，不导入被测核心的
任何重组逻辑，用于核对改写后的片载荷字节未被改动。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    Direction,
    DropReason,
    Endpoint,
    Fragment,
    FragmentationConfig,
    NATConfig,
    PortExhaustionError,
    ValidationError,
)

PUB = "203.0.113.7"
HOST = Endpoint("10.0.0.8", 40000)
SERVER = Endpoint("198.51.100.10", 443)
DID = 4242


def make_nat(**frag_kw) -> AddressDependentNAT:
    return AddressDependentNAT(
        NATConfig(public_ip=PUB, external_ports=(6100, 6101),
                  lifetime=100, quarantine=10),
        FragmentationConfig(**frag_kw),
    )


def frag(offset: int, payload: bytes, *, mf: bool, did: int = DID,
         direction: Direction = Direction.OUTBOUND,
         src: str = HOST.ip, dst: str = SERVER.ip,
         src_port: int | None = None, dst_port: int | None = None) -> Fragment:
    if offset == 0:
        src_port = HOST.port if src_port is None else src_port
        dst_port = SERVER.port if dst_port is None else dst_port
    else:
        src_port = dst_port = None
    return Fragment(direction=direction, src_ip=src, dst_ip=dst, protocol=17,
                    datagram_id=did, offset=offset, more_fragments=mf,
                    payload=payload, src_port=src_port, dst_port=dst_port)


def reassemble(fragments) -> bytes:
    """独立重组 oracle：按偏移把各片写入缓冲区，仅用于核对载荷字节。"""
    buf = bytearray()
    for f in fragments:
        end = f.offset + len(f.payload)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[f.offset:end] = f.payload
    return bytes(buf)


def split_payload(payload: bytes, size: int) -> list[tuple[int, bytes, bool]]:
    """把载荷切成 size 字节的片（最后一片可短），返回 (offset, data, mf)。"""
    out = []
    for off in range(0, len(payload), size):
        chunk = payload[off:off + size]
        out.append((off, chunk, off + size < len(payload)))
    return out


class TestOutOfOrderReassembly(unittest.TestCase):
    """乱序到达：非首片先暂存，首片到达后全部按同一冻结映射改写。"""

    def test_out_of_order_outbound(self):
        nat = make_nat()
        payload = bytes(range(256)) * 2            # 512 字节确定性载荷
        pieces = split_payload(payload, 64)        # 8 片
        # 乱序投递：首片最后到。
        results = []
        for off, chunk, mf in pieces[:0:-1]:
            r = nat.process_fragment(frag(off, chunk, mf=mf))
            self.assertTrue(r.accepted)
            self.assertFalse(r.complete)
            results.append(r)
        self.assertIsNone(nat.get_mapping(
            (HOST.ip, HOST.port, SERVER.ip, SERVER.port)))
        # 首片到达 -> 建映射，整组完成。
        off, chunk, mf = pieces[0]
        final = nat.process_fragment(frag(off, chunk, mf=mf))
        self.assertTrue(final.complete)
        self.assertIsNotNone(final.mapping)
        ext = final.mapping.external_port
        # 全部片地址已改写：源=公网IP，首片源端口=外端口，非首片无端口。
        self.assertEqual(len(final.rewritten), len(pieces))
        for f in final.rewritten:
            self.assertEqual((f.src_ip, f.dst_ip), (PUB, SERVER.ip))
            if f.offset == 0:
                self.assertEqual((f.src_port, f.dst_port), (ext, SERVER.port))
            else:
                self.assertIsNone(f.src_port)
        # 独立重组核对：载荷字节与原始数据报完全一致。
        self.assertEqual(reassemble(final.rewritten), payload)
        # 完成后关联已释放。
        self.assertEqual(nat.fragment_stats()["fragment_groups"], 0)

    def test_inbound_reassembly_uses_existing_mapping(self):
        nat = make_nat()
        m = nat.allocate(HOST, SERVER).mapping
        payload = b"reply-payload-0123456789abcdef" * 3
        pieces = split_payload(payload, 16)
        for off, chunk, mf in pieces[1:][::-1]:
            r = nat.process_fragment(frag(
                off, chunk, mf=mf, direction=Direction.INBOUND,
                src=SERVER.ip, dst=PUB))
            self.assertFalse(r.complete)
        off, chunk, mf = pieces[0]
        final = nat.process_fragment(frag(
            off, chunk, mf=mf, direction=Direction.INBOUND,
            src=SERVER.ip, dst=PUB, src_port=SERVER.port,
            dst_port=m.external_port))
        self.assertTrue(final.complete)
        for f in final.rewritten:
            self.assertEqual((f.dst_ip,), (HOST.ip,))
        self.assertEqual(final.rewritten[0].dst_port, HOST.port)
        self.assertEqual(reassemble(final.rewritten), payload)


class TestFirstFragmentNeverArrives(unittest.TestCase):
    """首片永不到：非首片只暂存，超时后整组释放，同 ID 可干净复用。"""

    def test_buffer_then_timeout(self):
        nat = make_nat(fragment_timeout=30)
        r = nat.process_fragment(frag(64, b"x" * 64, mf=True))
        self.assertTrue(r.accepted)
        self.assertFalse(r.complete)
        # 暂存期间不建映射（不能凭数据报 ID 猜连接）。
        self.assertEqual(nat.stats()["live_mappings"], 0)
        self.assertEqual(nat.fragment_stats(),
                         {"fragment_groups": 1, "fragment_cached_bytes": 64})
        # 边界：t=29 仍存活，t=30 边界即死。
        nat.advance(29)
        self.assertEqual(nat.fragment_stats()["fragment_groups"], 1)
        nat.advance(1)
        self.assertEqual(nat.fragment_stats(),
                         {"fragment_groups": 0, "fragment_cached_bytes": 0})
        # 同 ID 复用：新首片正常建组，不受旧组影响。
        r = nat.process_fragment(frag(0, b"HEAD0000", mf=True))
        self.assertTrue(r.accepted)
        self.assertEqual(nat.stats()["live_mappings"], 1)


class TestExpiredMappingReuse(unittest.TestCase):
    """映射过期且端口被复用后，旧数据报的后续片不得跟随新映射。"""

    def test_stale_generation_after_port_reuse(self):
        nat = make_nat(fragment_timeout=1000)   # 片组要比映射活得久
        # 首片建映射（gen=1，外端口 6100）。
        r = nat.process_fragment(frag(0, b"HEAD0000", mf=True))
        self.assertTrue(r.accepted)
        key = (HOST.ip, HOST.port, SERVER.ip, SERVER.port)
        self.assertEqual(nat.get_mapping(key).generation, 1)
        # 映射过期，端口隔离结束后被另一条连接复用（gen=2）。
        nat.advance(100)
        nat.advance(10)                        # 隔离 Q=10 结束
        other = Endpoint("10.0.0.9", 5000)
        m2 = nat.allocate(other, SERVER).mapping
        self.assertEqual(m2.external_port, 6100)
        self.assertEqual(m2.generation, 2)
        # 旧数据报的非首片到达：冻结世代已失效 -> 整组拒绝并释放。
        r = nat.process_fragment(frag(8, b"TAIL0000", mf=False))
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.STALE_GENERATION)
        self.assertEqual(nat.fragment_stats()["fragment_groups"], 0)
        # 新映射不受影响。
        self.assertEqual(nat.get_mapping(
            (other.ip, other.port, SERVER.ip, SERVER.port)).generation, 2)


class TestOverlapConflict(unittest.TestCase):
    def test_conflicting_overlap_rejects_group(self):
        nat = make_nat()
        nat.process_fragment(frag(0, b"AAAAAAAA" * 2, mf=True))   # [0,16)
        nat.process_fragment(frag(24, b"BBBBBBBB", mf=False))     # [24,32)
        # 与已暂存片重叠 8 字节但内容不同 -> 整组拒绝。
        r = nat.process_fragment(frag(8, b"ZZZZZZZZ", mf=True))
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.FRAGMENT_OVERLAP_CONFLICT)
        self.assertEqual(nat.fragment_stats()["fragment_groups"], 0)
        # 拒绝后同 ID 重新来一组可正常工作（ID 复用不串包）。
        payload = b"0123456789abcdef"
        r = nat.process_fragment(frag(0, payload[:8], mf=True))
        self.assertTrue(r.accepted)
        r = nat.process_fragment(frag(8, payload[8:], mf=False))
        self.assertTrue(r.complete)
        self.assertEqual(reassemble(r.rewritten), payload)

    def test_consistent_overlap_and_exact_duplicate_are_idempotent(self):
        nat = make_nat()
        nat.process_fragment(frag(0, b"AAAABBBBCCCCDDDD", mf=True))
        # 重叠但字节一致：接受。
        r = nat.process_fragment(frag(8, b"CCCCDDDD", mf=True))
        self.assertTrue(r.accepted)
        # 完全重复片：幂等。
        r = nat.process_fragment(frag(0, b"AAAABBBBCCCCDDDD", mf=True))
        self.assertTrue(r.accepted)
        self.assertFalse(r.complete)
        self.assertEqual(nat.fragment_stats()["fragment_cached_bytes"], 24)
        r = nat.process_fragment(frag(16, b"EEEE", mf=False))
        self.assertTrue(r.complete)
        self.assertEqual(reassemble(r.rewritten), b"AAAABBBBCCCCDDDDEEEE")


class TestLimits(unittest.TestCase):
    def test_too_many_fragments(self):
        nat = make_nat(max_fragments=2)
        nat.process_fragment(frag(0, b"AAAAAAAA", mf=True))
        nat.process_fragment(frag(8, b"BBBBBBBB", mf=True))
        r = nat.process_fragment(frag(16, b"CCCCCCCC", mf=False))
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.FRAGMENT_TOO_MANY)
        self.assertEqual(nat.fragment_stats()["fragment_groups"], 0)

    def test_cache_bytes_limit_is_global(self):
        nat = make_nat(max_cached_bytes=20)
        nat.process_fragment(frag(0, b"AAAAAAAA", mf=True, did=1))
        nat.process_fragment(frag(0, b"BBBBBBBB", mf=True, did=2))
        # 第三组 8 字节会使总量 32 > 24 -> 该组拒绝，前两组不受影响。
        r = nat.process_fragment(frag(0, b"CCCCCCCC", mf=True, did=3))
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.FRAGMENT_CACHE_FULL)
        self.assertEqual(nat.fragment_stats(),
                         {"fragment_groups": 2, "fragment_cached_bytes": 16})

    def test_total_length_limit(self):
        nat = make_nat(max_datagram_size=16)
        nat.process_fragment(frag(0, b"AAAAAAAA", mf=True))
        r = nat.process_fragment(frag(8, b"BBBBBBBBB", mf=False))  # 8+9=17
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.FRAGMENT_TOO_LONG)

    def test_conflicting_last_fragments_rejected(self):
        nat = make_nat()
        nat.process_fragment(frag(0, b"AAAAAAAA", mf=True))
        nat.process_fragment(frag(16, b"BBBBBBBB", mf=False))  # total=24
        r = nat.process_fragment(frag(8, b"CCCC", mf=False))   # total=12 矛盾
        self.assertFalse(r.accepted)
        self.assertIs(r.reason, DropReason.FRAGMENT_OVERLAP_CONFLICT)


class TestFragmentValidation(unittest.TestCase):
    def test_invalid_fragments_rejected(self):
        with self.assertRaises(ValidationError):
            frag(1, b"AAAAAAAA", mf=True)              # 偏移非 8 倍数
        with self.assertRaises(ValidationError):
            frag(0, b"AAA", mf=True)                   # 非末片长度非 8 倍数
        with self.assertRaises(ValidationError):
            Fragment(direction=Direction.OUTBOUND, src_ip=HOST.ip,
                     dst_ip=SERVER.ip, protocol=17, datagram_id=1,
                     offset=8, more_fragments=True, payload=b"AAAAAAAA",
                     src_port=1, dst_port=2)           # 非首片带端口
        with self.assertRaises(ValidationError):
            Fragment(direction=Direction.OUTBOUND, src_ip=HOST.ip,
                     dst_ip=SERVER.ip, protocol=6, datagram_id=1,
                     offset=0, more_fragments=False, payload=b"AAAAAAAA",
                     src_port=1, dst_port=2)           # 非 UDP
        with self.assertRaises(ValidationError):
            frag(0, b"", mf=False)                     # 空载荷
        nat = make_nat()
        with self.assertRaises(ValidationError):
            nat.process_fragment("not a fragment")

    def test_port_exhaustion_leaves_no_partial_state(self):
        nat = AddressDependentNAT(
            NATConfig(public_ip=PUB, external_ports=(6100,), lifetime=100),
            FragmentationConfig())
        nat.allocate(Endpoint("10.0.0.9", 1), SERVER)  # 占满唯一端口
        before = (nat.snapshot_mappings(), nat.fragment_stats())
        with self.assertRaises(PortExhaustionError):
            nat.process_fragment(frag(0, b"AAAAAAAA", mf=True))
        after = (nat.snapshot_mappings(), nat.fragment_stats())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
