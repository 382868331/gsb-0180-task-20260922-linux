"""契约测试：手工计算的期望值，不依赖任何参考实现。

覆盖题面要求的验收点：
- 同一内网端点、不同目的 -> 不同映射（地址依赖）
- 超时边界（expires_at == now 即过期；隔离 Q 边界）
- 端口耗尽时批量分配整体回滚
- generation 迟到包拒绝
以及输入校验、搜索预算与证明无解的区分、入站过滤。
"""

from __future__ import annotations

import unittest

from adnat import (
    MAX_BATCH_REQUESTS,
    AddressDependentNAT,
    AllocationRequest,
    DropReason,
    Endpoint,
    NATConfig,
    NATError,
    Packet,
    PortExhaustionError,
    SearchBudgetExhaustedError,
    ValidationError,
)

PUB = "203.0.113.7"
A = Endpoint("10.0.0.8", 40000)          # 内网端点
R1 = Endpoint("198.51.100.10", 53)       # 目的 1
R2 = Endpoint("198.51.100.11", 53)       # 目的 2
KEY1 = (A.ip, A.port, R1.ip, R1.port)
KEY2 = (A.ip, A.port, R2.ip, R2.port)


def make_nat(ports=(6001, 6002, 6003), lifetime=10, quarantine=5,
             budget=None) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine, search_budget=budget,
    ))


def pkt(src: Endpoint, dst: Endpoint, gen: int = 0) -> Packet:
    return Packet(src=src, dst=dst, generation=gen, payload=b"x")


class TestAddressDependentMapping(unittest.TestCase):
    """同一内网端点、不同目的 -> 两条独立映射；入站按对端过滤。"""

    def test_same_internal_different_remote(self):
        nat = make_nat()
        r1 = nat.allocate(A, R1)
        r2 = nat.allocate(A, R2)
        # 不同目的 -> 不同映射、不同外端口；池内最小空闲优先。
        self.assertTrue(r1.created)
        self.assertTrue(r2.created)
        self.assertEqual(r1.mapping.external_port, 6001)
        self.assertEqual(r2.mapping.external_port, 6002)
        self.assertEqual(r1.mapping.generation, 1)
        self.assertEqual(r2.mapping.generation, 2)
        # 重复分配同 key -> 复用，不新建。
        again = nat.allocate(A, R1)
        self.assertFalse(again.created)
        self.assertEqual(again.mapping.external_port, 6001)
        self.assertEqual(again.mapping.generation, 1)
        self.assertEqual(nat.stats()["ports_in_use"], 2)

        # 出站改写：源换成 (公网IP, 外端口)，目的不变。
        out = nat.translate_outbound(pkt(A, R1, gen=1))
        self.assertTrue(out.accepted)
        self.assertEqual(
            (out.rewritten.src_ip, out.rewritten.src_port,
             out.rewritten.dst_ip, out.rewritten.dst_port, out.rewritten.protocol),
            (PUB, 6001, R1.ip, R1.port, 17),
        )
        # 入站：R2 的包打到 R1 的外端口 -> 对端不匹配，丢弃。
        wrong_peer = nat.translate_inbound(
            pkt(R2, Endpoint(PUB, 6001), gen=1))
        self.assertFalse(wrong_peer.accepted)
        self.assertIs(wrong_peer.reason, DropReason.PEER_MISMATCH)
        # 入站：R1 -> 6001 命中，改写回内网端点。
        ok = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6001), gen=1))
        self.assertTrue(ok.accepted)
        self.assertEqual(
            (ok.rewritten.src_ip, ok.rewritten.src_port,
             ok.rewritten.dst_ip, ok.rewritten.dst_port),
            (R1.ip, R1.port, A.ip, A.port),
        )

    def test_unsorted_pool_still_picks_smallest_free(self):
        nat = make_nat(ports=(6003, 6001, 6002))
        self.assertEqual(nat.allocate(A, R1).mapping.external_port, 6001)
        self.assertEqual(nat.allocate(A, R2).mapping.external_port, 6002)


class TestTimeoutBoundary(unittest.TestCase):
    """expires_at == now 即过期；流量刷新过期时间；隔离 Q 边界精确。"""

    def test_expiry_boundary(self):
        nat = make_nat(lifetime=10)
        nat.allocate(A, R1)
        nat.advance(9)                       # t=9 < 10：存活
        self.assertIsNotNone(nat.get_mapping(KEY1))
        expired = nat.advance(1)             # t=10 == expires_at：过期
        self.assertEqual(expired, [KEY1])
        self.assertIsNone(nat.get_mapping(KEY1))
        self.assertEqual(nat.stats()["live_mappings"], 0)
        # 过期端口进入隔离，t=15 才解除（quarantine=5）。
        self.assertEqual(nat.quarantined_ports(), {6001: 10})
        nat.advance(4)                       # t=14：仍在隔离
        self.assertEqual(nat.quarantined_ports(), {6001: 10})
        nat.advance(1)                       # t=15：隔离解除
        self.assertEqual(nat.quarantined_ports(), {})

    def test_traffic_refreshes_expiry(self):
        nat = make_nat(lifetime=10)
        nat.allocate(A, R1)                  # expires_at = 10
        nat.advance(9)
        nat.translate_outbound(pkt(A, R1))   # 刷新 -> expires_at = 19
        self.assertEqual(nat.get_mapping(KEY1).expires_at, 19)
        nat.advance(9)                       # t=18：存活
        self.assertEqual(nat.advance(1), [KEY1])  # t=19：过期

    def test_quarantine_blocks_reuse_until_boundary(self):
        nat = make_nat(ports=(6001, 6002), lifetime=100, quarantine=5)
        nat.allocate(A, R1)                  # 6001
        self.assertTrue(nat.release(KEY1))   # t=0 释放，隔离至 t=5
        nat.advance(4)                       # t=4：6001 仍隔离
        r = nat.allocate(A, R2)
        self.assertEqual(r.mapping.external_port, 6002)  # 只能拿 6002
        nat.advance(1)                       # t=5：6001 解除隔离
        b = Endpoint("10.0.0.9", 40000)
        r2 = nat.allocate(b, R1)
        self.assertEqual(r2.mapping.external_port, 6001)  # 最小空闲复用


class TestPortExhaustionRollback(unittest.TestCase):
    """容量不足 -> PortExhaustionError，全批回滚，状态与调用前一致。"""

    def test_batch_rolls_back_atomically(self):
        nat = make_nat(ports=(6001, 6002), lifetime=100)
        nat.allocate(A, R1)                  # 占 6001，池内剩 1
        before = (nat.snapshot_mappings(), nat.stats(), nat.now)
        reqs = [AllocationRequest(A, R2),
                AllocationRequest(Endpoint("10.0.0.9", 1), R1),
                AllocationRequest(Endpoint("10.0.0.9", 2), R1)]
        with self.assertRaises(PortExhaustionError) as ctx:
            nat.allocate_many(reqs)
        err = ctx.exception
        self.assertIsInstance(err, NATError)
        self.assertEqual((err.needed, err.available, err.pool_size), (3, 1, 2))
        # 全批回滚：无任何部分分配，时钟未动。
        after = (nat.snapshot_mappings(), nat.stats(), nat.now)
        self.assertEqual(before, after)
        # 池内剩余 1 个时，单条分配成功且拿最小空闲。
        ok = nat.allocate(A, R2)
        self.assertEqual(ok.mapping.external_port, 6002)

    def test_exhaustion_then_recovery_after_expiry(self):
        nat = make_nat(ports=(6001,), lifetime=10, quarantine=0)
        nat.allocate(A, R1)                  # 占满，expires_at=10
        with self.assertRaises(PortExhaustionError):
            nat.allocate(A, R2)
        nat.advance(10)                      # 过期回收（Q=0 立即可用）
        ok = nat.allocate(A, R2)
        self.assertEqual(ok.mapping.external_port, 6001)

    def test_duplicate_keys_in_batch_rejected_before_mutation(self):
        nat = make_nat()
        before = nat.snapshot_mappings()
        req = AllocationRequest(A, R1)
        with self.assertRaises(ValidationError):
            nat.allocate_many([req, req])
        self.assertEqual(nat.snapshot_mappings(), before)

    def test_batch_mixed_reuse_and_create(self):
        nat = make_nat()
        nat.allocate(A, R1)                  # 6001
        results = nat.allocate_many([
            AllocationRequest(A, R1),        # 复用
            AllocationRequest(A, R2),        # 新建 6002
        ])
        self.assertEqual([(r.created, r.mapping.external_port) for r in results],
                         [(False, 6001), (True, 6002)])


class TestSearchBudget(unittest.TestCase):
    """预算耗尽与证明无解是两种不同异常。"""

    def test_budget_exhausted_is_not_port_exhausted(self):
        # 池 4 口，预算 2：占 1 口后申请 2 个新映射，
        # 检查 2 口即耗尽预算（找到 1），不能断定无解。
        nat = make_nat(ports=(6001, 6002, 6003, 6004), lifetime=100, budget=2)
        nat.allocate(A, R1)                  # 6001
        reqs = [AllocationRequest(A, R2),
                AllocationRequest(Endpoint("10.0.0.9", 1), R1)]
        before = nat.snapshot_mappings()
        with self.assertRaises(SearchBudgetExhaustedError) as ctx:
            nat.allocate_many(reqs)
        err = ctx.exception
        self.assertNotIsInstance(err, PortExhaustionError)
        self.assertEqual((err.budget, err.inspected, err.needed, err.found),
                         (2, 2, 2, 1))
        self.assertEqual(nat.snapshot_mappings(), before)   # 回滚
        # 同样请求在充足预算下成功 -> 之前确实只是预算问题。
        nat2 = make_nat(ports=(6001, 6002, 6003, 6004), lifetime=100, budget=4)
        nat2.allocate(A, R1)
        got = nat2.allocate_many(reqs)
        self.assertEqual([r.mapping.external_port for r in got], [6002, 6003])


class TestGenerationLatePacket(unittest.TestCase):
    """映射重建后 generation 递增；携带旧 generation 的迟到包被拒绝。"""

    def test_stale_generation_rejected_both_directions(self):
        nat = make_nat(ports=(6001,), lifetime=100, quarantine=5)
        first = nat.allocate(A, R1)
        self.assertEqual(first.mapping.generation, 1)
        nat.release(KEY1)
        nat.advance(5)                       # 隔离结束，6001 可复用
        second = nat.allocate(A, R1)
        self.assertEqual(second.mapping.generation, 2)
        self.assertEqual(second.mapping.external_port, 6001)

        # 迟到入站包：旧 generation=1 -> 拒绝。
        stale_in = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6001), gen=1))
        self.assertFalse(stale_in.accepted)
        self.assertIs(stale_in.reason, DropReason.STALE_GENERATION)
        # 迟到出站包同理。
        stale_out = nat.translate_outbound(pkt(A, R1, gen=1))
        self.assertFalse(stale_out.accepted)
        self.assertIs(stale_out.reason, DropReason.STALE_GENERATION)
        # 当前 generation=2 正常通过；generation=0 表示不参与校验。
        self.assertTrue(nat.translate_inbound(
            pkt(R1, Endpoint(PUB, 6001), gen=2)).accepted)
        self.assertTrue(nat.translate_outbound(pkt(A, R1, gen=0)).accepted)

    def test_generation_is_per_mapping(self):
        nat = make_nat()
        nat.allocate(A, R1)                  # gen 1
        nat.allocate(A, R2)                  # gen 2
        # R1 的包带 R2 的 generation -> 对 R1 的映射而言是错的。
        bad = nat.translate_outbound(pkt(A, R1, gen=2))
        self.assertIs(bad.reason, DropReason.STALE_GENERATION)


class TestInboundFiltering(unittest.TestCase):
    def test_dest_mismatch_and_no_mapping(self):
        nat = make_nat()
        nat.allocate(A, R1)                  # 6001
        # 目的不是本 NAT 公网 IP。
        r = nat.translate_inbound(pkt(R1, Endpoint("192.0.2.1", 6001)))
        self.assertIs(r.reason, DropReason.DEST_MISMATCH)
        # 目的端口无映射。
        r = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6002)))
        self.assertIs(r.reason, DropReason.NO_MAPPING)
        # 出站无映射不隐式创建。
        r = nat.translate_outbound(pkt(A, R2))
        self.assertIs(r.reason, DropReason.NO_MAPPING)
        self.assertEqual(nat.stats()["live_mappings"], 1)


class TestRelease(unittest.TestCase):
    def test_release_semantics(self):
        nat = make_nat()
        nat.allocate(A, R1)
        self.assertTrue(nat.release(KEY1))       # 存在 -> True
        self.assertFalse(nat.release(KEY1))      # 已释放 -> False，无变更
        self.assertFalse(nat.release(KEY2))      # 从未存在 -> False
        self.assertIsNone(nat.get_mapping(KEY1))
        # 释放后入站包无映射。
        r = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6001)))
        self.assertIs(r.reason, DropReason.NO_MAPPING)


class TestInputValidation(unittest.TestCase):
    """非法输入给可定位错误，不静默纠正；NaN/Infinity/bool 一律拒绝。"""

    def test_endpoint_and_config_validation(self):
        bad_ports = [0, 65536, True, 3.0, float("nan"), float("inf"), "53"]
        for p in bad_ports:
            with self.assertRaises(ValidationError, msg=f"port={p!r}"):
                Endpoint("10.0.0.1", p)
        for ip in ["999.1.1.1", "10.0.0.01", "10.0.0", "10.0.0.1 ", 123]:
            with self.assertRaises(ValidationError, msg=f"ip={ip!r}"):
                Endpoint(ip, 53)
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=())
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001, 6001))
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,), lifetime=0)
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,), quarantine=-1)
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,), search_budget=0)

    def test_nan_inf_bool_rejected_everywhere(self):
        nat = make_nat()
        bad_numbers = [float("nan"), float("inf"), -float("inf"), True, 1.5]
        for v in bad_numbers:
            with self.assertRaises(ValidationError, msg=f"advance({v!r})"):
                nat.advance(v)
            with self.assertRaises(ValidationError, msg=f"at={v!r}"):
                nat.allocate(A, R1, at=v)
            with self.assertRaises(ValidationError, msg=f"gen={v!r}"):
                Packet(src=A, dst=R1, generation=v)

    def test_packet_and_key_type_validation(self):
        nat = make_nat()
        with self.assertRaises(ValidationError):
            nat.translate_outbound("not a packet")
        with self.assertRaises(ValidationError):
            Packet(src=A, dst=R1, generation=-1)
        with self.assertRaises(ValidationError):
            nat.release(("10.0.0.8", 40000, "198.51.100.10"))  # 长度不足
        with self.assertRaises(ValidationError):
            nat.allocate_many([AllocationRequest(A, R1), "bogus"])

    def test_clock_monotonicity_and_batch_limit(self):
        nat = make_nat()
        nat.advance(5)
        with self.assertRaises(ValidationError):
            nat.allocate(A, R1, at=2)        # 时钟回退
        with self.assertRaises(ValidationError):
            nat.advance(-1)
        req = AllocationRequest(A, R1)
        with self.assertRaises(ValidationError):
            nat.allocate_many([req] * (MAX_BATCH_REQUESTS + 1))
        # 失败校验不改变状态。
        self.assertEqual(nat.now, 5)
        self.assertEqual(nat.snapshot_mappings(), [])


if __name__ == "__main__":
    unittest.main()
