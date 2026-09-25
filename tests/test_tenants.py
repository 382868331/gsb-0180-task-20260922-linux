"""多租户契约测试：手工期望值，不依赖参考实现。

覆盖验收点：
- 租户表配置整体拒绝（重复 ID / 子集重叠 / 越界 / 空 ID）
- 两个租户使用完全相同的内网地址：映射、端口、查询、释放、改写全隔离
- 配额不足单独报 QuotaExceededError，绝不伪装成端口耗尽
- 复用不占配额；恰好到期才释放配额；隔离期内配额空但端口仍不可用
- 跨租户批量：一租户失败（配额/端口/预算）全部回滚——无新映射、
  generation 不增、时钟不动、隔离表不变
- 检查顺序固定：输入校验 -> 候选时刻过期规划 -> 配额 -> 按输入次序端口
- 入站按外端口反解租户并随结果带回
- 未配置租户时旧调用与基线一致
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    DropReason,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    TenantAllocationRequest,
    TenantConfig,
    ValidationError,
)

PUB = "203.0.113.7"
POOL = (6200, 6201, 6202, 6203, 6204, 6205)
PORTS_A = (6200, 6201, 6202)
PORTS_B = (6203, 6204, 6205)
T_A = "alpha"
T_B = "beta"

A = Endpoint("10.0.0.8", 40000)          # 两个租户共用的同一内网端点
B = Endpoint("10.0.0.9", 40001)
R1 = Endpoint("198.51.100.10", 53)
R2 = Endpoint("198.51.100.11", 53)
R3 = Endpoint("198.51.100.12", 53)
KEY1 = (A.ip, A.port, R1.ip, R1.port)
KEY2 = (A.ip, A.port, R2.ip, R2.port)


def cfg(*, ports_a=PORTS_A, ports_b=PORTS_B, max_a=3, max_b=3,
        lifetime=100, quarantine=5, budget=None, pool=POOL) -> NATConfig:
    return NATConfig(
        public_ip=PUB, external_ports=pool,
        lifetime=lifetime, quarantine=quarantine, search_budget=budget,
        tenants=(
            TenantConfig(tenant_id=T_A, external_ports=ports_a,
                         max_active_mappings=max_a),
            TenantConfig(tenant_id=T_B, external_ports=ports_b,
                         max_active_mappings=max_b),
        ))


def nat(**kw) -> AddressDependentNAT:
    return AddressDependentNAT(cfg(**kw))


def tareq(tid: str, internal: Endpoint, remote: Endpoint) -> TenantAllocationRequest:
    return TenantAllocationRequest(tid, internal, remote)


def pkt(src: Endpoint, dst: Endpoint, gen: int = 0) -> Packet:
    return Packet(src=src, dst=dst, generation=gen, payload=b"x")


class TestTenantConfigValidation(unittest.TestCase):
    """租户表构造后固定；重复 ID / 重叠 / 越界整体拒绝。"""

    def test_duplicate_tenant_id_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(
                public_ip=PUB, external_ports=POOL,
                tenants=(
                    TenantConfig("same", (6200,), 1),
                    TenantConfig("same", (6201,), 1),
                ))

    def test_overlapping_subsets_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(
                public_ip=PUB, external_ports=POOL,
                tenants=(
                    TenantConfig(T_A, (6200, 6201), 2),
                    TenantConfig(T_B, (6201, 6202), 2),   # 6201 重叠
                ))

    def test_port_outside_pool_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(
                public_ip=PUB, external_ports=POOL,
                tenants=(TenantConfig(T_A, (6200, 9999), 2),))

    def test_empty_or_nonstring_id_rejected(self):
        for bad in ("", 0, None):
            with self.assertRaises(ValidationError, msg=f"id={bad!r}"):
                TenantConfig(bad, (6200,), 1)

    def test_subset_empty_duplicate_and_bad_limit_rejected(self):
        with self.assertRaises(ValidationError):
            TenantConfig(T_A, (), 1)
        with self.assertRaises(ValidationError):
            TenantConfig(T_A, (6200, 6200), 1)
        with self.assertRaises(ValidationError):
            TenantConfig(T_A, (6200,), 0)

    def test_tenants_container_rules(self):
        good = TenantConfig(T_A, (6200,), 1)
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=POOL, tenants=())
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=POOL, tenants=(good, "x"))
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=POOL, tenants="alpha")

    def test_subsets_need_not_cover_whole_pool(self):
        # 合起来只需"取自"总池，不强制覆盖；未分配端口不属于任何租户。
        c = NATConfig(
            public_ip=PUB, external_ports=POOL,
            tenants=(
                TenantConfig(T_A, (6200,), 1),
                TenantConfig(T_B, (6203,), 1),
            ))
        self.assertEqual(
            AddressDependentNAT(c).tenant_ids, (T_A, T_B))


class TestSameInternalAddressIsolation(unittest.TestCase):
    """相同内网 IP:端口 在两个租户下不得互相撞映射/撞端口。"""

    def test_identical_internal_five_tuple_isolated(self):
        n = nat()
        ra = n.allocate(A, R1, tenant=T_A)
        rb = n.allocate(A, R1, tenant=T_B)
        self.assertTrue(ra.created and rb.created)
        self.assertEqual((ra.tenant, ra.mapping.external_port, ra.mapping.generation),
                         (T_A, 6200, 1))
        self.assertEqual((rb.tenant, rb.mapping.external_port, rb.mapping.generation),
                         (T_B, 6203, 2))
        self.assertEqual(ra.mapping.tenant, T_A)
        self.assertEqual(rb.mapping.tenant, T_B)
        # 同租户同 key 再分配 -> 复用，不新建、不占新端口。
        again = n.allocate(A, R1, tenant=T_A)
        self.assertFalse(again.created)
        self.assertEqual(again.mapping.external_port, 6200)
        self.assertEqual(again.mapping.generation, 1)

    def test_queries_and_snapshots_are_tenant_scoped(self):
        n = nat()
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R1, tenant=T_B)
        n.allocate(A, R2, tenant=T_A)
        self.assertEqual(n.get_mapping(KEY1, tenant=T_A).external_port, 6200)
        self.assertEqual(n.get_mapping(KEY1, tenant=T_B).external_port, 6203)
        self.assertIsNone(n.get_mapping(KEY2, tenant=T_B))     # 只在 alpha 有
        snap_a = n.snapshot_mappings(tenant=T_A)
        snap_b = n.snapshot_mappings(tenant=T_B)
        self.assertEqual({m.tenant for m in snap_a}, {T_A})
        self.assertEqual({m.tenant for m in snap_b}, {T_B})
        self.assertEqual(len(snap_a), 2)
        self.assertEqual(len(snap_b), 1)
        all_snap = n.snapshot_mappings()
        self.assertEqual(len(all_snap), 3)                      # 管理员视图
        self.assertEqual(n.tenant_ids, (T_A, T_B))

    def test_release_cannot_touch_other_tenant(self):
        n = nat()
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R2, tenant=T_A)
        # KEY2 只属于 alpha；在 beta 下释放返回 False 且 alpha 映射完好。
        self.assertFalse(n.release(KEY2, tenant=T_B))
        self.assertIsNotNone(n.get_mapping(KEY2, tenant=T_A))
        self.assertTrue(n.release(KEY2, tenant=T_A))
        self.assertIsNone(n.get_mapping(KEY2, tenant=T_A))
        # alpha 的 KEY1 不受影响。
        self.assertIsNotNone(n.get_mapping(KEY1, tenant=T_A))

    def test_outbound_is_tenant_scoped(self):
        n = nat()
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R1, tenant=T_B)
        # beta 从未建 A->R2：不能借到 alpha 的同 key 映射。
        miss = n.translate_outbound(pkt(A, R2), tenant=T_B)
        self.assertFalse(miss.accepted)
        self.assertIs(miss.reason, DropReason.NO_MAPPING)
        self.assertIsNone(miss.tenant)
        # 同包在 alpha 命中，结果带回 alpha 身份。
        n.allocate(A, R2, tenant=T_A)
        hit_a = n.translate_outbound(pkt(A, R2), tenant=T_A)
        self.assertTrue(hit_a.accepted)
        self.assertEqual(hit_a.tenant, T_A)
        self.assertEqual(
            (hit_a.rewritten.src_ip, hit_a.rewritten.src_port),
            (PUB, 6201))
        # beta 访问 R1 走自己的外端口 6203。
        hit_b = n.translate_outbound(pkt(A, R1), tenant=T_B)
        self.assertTrue(hit_b.accepted)
        self.assertEqual(hit_b.rewritten.src_port, 6203)
        self.assertEqual(hit_b.tenant, T_B)

    def test_inbound_resolves_tenant_from_external_port(self):
        n = nat()
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R1, tenant=T_B)
        in_a = n.translate_inbound(pkt(R1, Endpoint(PUB, 6200)))
        in_b = n.translate_inbound(pkt(R1, Endpoint(PUB, 6203)))
        self.assertTrue(in_a.accepted and in_b.accepted)
        self.assertEqual(in_a.tenant, T_A)
        self.assertEqual(in_b.tenant, T_B)
        self.assertEqual((in_a.rewritten.dst_ip, in_a.rewritten.dst_port),
                         (A.ip, A.port))
        # 对端不符 / 代数不符：映射已定位，租户身份仍带回。
        peer = n.translate_inbound(pkt(R2, Endpoint(PUB, 6200)))
        self.assertIs(peer.reason, DropReason.PEER_MISMATCH)
        self.assertEqual(peer.tenant, T_A)
        stale = n.translate_inbound(pkt(R1, Endpoint(PUB, 6203), gen=99))
        self.assertIs(stale.reason, DropReason.STALE_GENERATION)
        self.assertEqual(stale.tenant, T_B)
        # 任何租户都没有的端口 / 错误公网 IP：无租户身份。
        none = n.translate_inbound(pkt(R1, Endpoint(PUB, 6201)))
        # 6201 未分配
        self.assertIs(none.reason, DropReason.NO_MAPPING)
        self.assertIsNone(none.tenant)
        dest = n.translate_inbound(pkt(R1, Endpoint("192.0.2.1", 6200)))
        self.assertIs(dest.reason, DropReason.DEST_MISMATCH)
        self.assertIsNone(dest.tenant)

    def test_tenant_required_in_multitenant_mode(self):
        n = nat()
        with self.assertRaises(ValidationError):
            n.allocate(A, R1)
        with self.assertRaises(ValidationError):
            n.release(KEY1)
        with self.assertRaises(ValidationError):
            n.get_mapping(KEY1)
        with self.assertRaises(ValidationError):
            n.translate_outbound(pkt(A, R1))
        with self.assertRaises(ValidationError):
            n.allocate(A, R1, tenant="gamma")
        with self.assertRaises(ValidationError):
            n.allocate(A, R1, tenant="")


class TestQuotaSemantics(unittest.TestCase):
    """配额：独立于端口容量的错误种类；复用不占配额。"""

    def test_quota_error_is_not_port_exhaustion(self):
        n = nat(max_a=2)
        n.allocate(A, R1, tenant=T_A)               # 6200
        n.allocate(A, R2, tenant=T_A)               # 6201 活跃=2=配额
        with self.assertRaises(QuotaExceededError) as ctx:
            n.allocate(B, R1, tenant=T_A)           # 端口还空着 6202
        err = ctx.exception
        self.assertNotIsInstance(err, PortExhaustionError)
        self.assertEqual((err.tenant, err.active, err.requested, err.limit),
                         (T_A, 2, 1, 2))
        self.assertEqual(n.tenant_stats(T_A)["live_mappings"], 2)

    def test_reuse_does_not_consume_quota(self):
        n = nat(max_a=2)
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R2, tenant=T_A)
        # 配额已满，纯复用批成功。
        res = n.allocate_many(
            [AllocationRequest(A, R1), AllocationRequest(A, R2)], tenant=T_A)
        self.assertEqual([r.created for r in res], [False, False])
        # 混一个新建 -> 配额失败。
        with self.assertRaises(QuotaExceededError):
            n.allocate_many(
                [AllocationRequest(A, R1), AllocationRequest(B, R1)],
                tenant=T_A)

    def test_quota_freed_at_exact_expiry_boundary(self):
        # 恰好到期：t=9 仍占配额；t=10 候选时刻回收后配额空出。
        n = nat(ports_a=(6200,), ports_b=PORTS_B, max_a=1,
                lifetime=10, quarantine=0)
        n.allocate(A, R1, tenant=T_A)               # expires_at=10
        n.advance(9)
        self.assertIsNotNone(n.get_mapping(KEY1, tenant=T_A))
        with self.assertRaises(QuotaExceededError):
            n.allocate(A, R2, tenant=T_A, at=9)
        ok = n.allocate(A, R2, tenant=T_A, at=10)   # 边界即死 -> 配额释放
        self.assertTrue(ok.created)
        self.assertEqual(ok.mapping.external_port, 6200)  # Q=0 立即复用
        self.assertEqual(ok.mapping.generation, 2)
        self.assertIsNone(n.get_mapping(KEY1, tenant=T_A))

    def test_quota_free_but_port_still_quarantined(self):
        # 配额已空出（活跃 0），但端口仍在隔离期 -> 端口耗尽而非配额错误。
        n = nat(ports_a=(6200,), ports_b=PORTS_B, max_a=1, quarantine=5)
        n.allocate(A, R1, tenant=T_A)
        self.assertTrue(n.release(KEY1, tenant=T_A))
        self.assertEqual(n.tenant_stats(T_A)["live_mappings"], 0)
        with self.assertRaises(PortExhaustionError) as ctx:
            n.allocate(A, R2, tenant=T_A, at=4)     # t=4 仍隔离
        err = ctx.exception
        self.assertNotIsInstance(err, QuotaExceededError)
        self.assertEqual((err.tenant, err.needed, err.available, err.pool_size),
                         (T_A, 1, 0, 1))
        ok = n.allocate(A, R2, tenant=T_A, at=5)    # t=5 隔离解除
        self.assertTrue(ok.created)
        self.assertEqual(ok.mapping.external_port, 6200)

    def test_quota_free_but_expired_port_quarantined(self):
        # 过期路径同上：过期释放配额，但端口隔离到期前不可用。
        n = nat(ports_a=(6200,), ports_b=PORTS_B, max_a=1,
                lifetime=10, quarantine=5)
        n.allocate(A, R1, tenant=T_A)
        n.advance(10)                              # t=10 回收，隔离至 15
        self.assertEqual(n.tenant_stats(T_A)["live_mappings"], 0)
        with self.assertRaises(PortExhaustionError):
            n.allocate(A, R2, tenant=T_A, at=14)   # t=14 仍隔离
        ok = n.allocate(A, R2, tenant=T_A, at=15)  # t=15 隔离解除
        self.assertEqual(ok.mapping.external_port, 6200)


class TestCrossTenantBatch(unittest.TestCase):
    """跨租户批量：全部满足才提交。"""

    def test_mixed_tenant_batch_commits_together(self):
        n = nat()
        n.allocate(A, R1, tenant=T_A)               # 6200 gen1
        res = n.allocate_across_tenants([
            tareq(T_A, A, R2),                       # 新建 6201 gen2
            tareq(T_B, B, R1),                       # 新建 6203 gen3
            tareq(T_A, A, R1),                       # 复用，不占端口/配额
        ])
        self.assertEqual(
            [(r.tenant, r.created, r.mapping.external_port) for r in res],
            [(T_A, True, 6201), (T_B, True, 6203), (T_A, False, 6200)])
        self.assertEqual([r.mapping.generation for r in res], [2, 3, 1])

    def test_quota_failure_rolls_back_everyone(self):
        n = nat(max_b=1)
        n.allocate(A, R1, tenant=T_A)               # gen1 6200
        n.allocate(A, R1, tenant=T_B)               # gen2 6203，beta 配额满
        before = (n.snapshot_mappings(), n.stats(),
                  n.quarantined_ports(), n.now)
        with self.assertRaises(QuotaExceededError) as ctx:
            n.allocate_across_tenants([
                tareq(T_A, B, R1),                   # alpha 本可成功
                tareq(T_B, B, R2),                   # beta 超配额
            ])
        self.assertEqual(ctx.exception.tenant, T_B)
        after = (n.snapshot_mappings(), n.stats(),
                 n.quarantined_ports(), n.now)
        self.assertEqual(before, after)              # 零副作用
        # generation 未因失败批增长：下一条成功映射仍是 gen3。
        nxt = n.allocate(B, R1, tenant=T_A)
        self.assertEqual(nxt.mapping.generation, 3)

    def test_port_failure_in_later_tenant_rolls_back_earlier(self):
        # 输入次序 alpha 在前且规划成功，beta 端口不够 -> 整体回滚。
        n = nat(ports_a=(6200, 6201, 6202), ports_b=(6203,),
                max_a=3, max_b=3)
        n.allocate(A, R1, tenant=T_B)               # 占掉 beta 唯一口 6203
        with self.assertRaises(PortExhaustionError) as ctx:
            n.allocate_across_tenants([
                tareq(T_A, B, R1),                   # 本可拿 6200
                tareq(T_B, B, R1),
                tareq(T_B, B, R2),                   # beta 需要 2 个新口
            ])
        err = ctx.exception
        self.assertEqual((err.tenant, err.needed, err.available),
                         (T_B, 2, 0))
        self.assertIsNone(n.get_mapping(
            (B.ip, B.port, R1.ip, R1.port), tenant=T_A))
        self.assertEqual(n.stats()["ports_in_use"], 1)

    def test_quota_phase_precedes_port_planning(self):
        # alpha 配额可行但端口全在隔离（规划必失败）；beta 超配额。
        # 固定顺序要求配额先报 -> QuotaExceededError，与输入次序无关。
        n = nat(ports_a=(6200,), ports_b=(6203,), max_a=1, max_b=1,
                quarantine=50)
        m = n.allocate(A, R1, tenant=T_A)
        n.release(KEY1, tenant=T_A)                 # alpha 活跃 0，6200 隔离
        n.allocate(A, R1, tenant=T_B)               # beta 活跃 1=配额
        with self.assertRaises(QuotaExceededError) as ctx:
            n.allocate_across_tenants([
                tareq(T_A, B, R1),                   # 先扫也会失败于端口
                tareq(T_B, B, R2),                   # 但配额检查先行
            ])
        self.assertEqual(ctx.exception.tenant, T_B)
        self.assertEqual(n.stats()["live_mappings"], 1)

    def test_shared_search_budget_counts_actual_inspections(self):
        pool = tuple(range(6200, 6208))
        pa = tuple(range(6200, 6204))
        pb = tuple(range(6204, 6208))
        n = nat(pool=pool, ports_a=pa, ports_b=pb,
                max_a=4, max_b=4, budget=3)
        with self.assertRaises(SearchBudgetExhaustedError) as ctx:
            n.allocate_across_tenants([
                tareq(T_A, A, R1),                   # 检查 6200（1）找到
                tareq(T_B, A, R1),                   # 6204（2）
                tareq(T_B, A, R2),                   # 6205（3）
                tareq(T_B, A, R3),                   # 预算耗尽：找到 2/3
            ])
        err = ctx.exception
        self.assertEqual(
            (err.budget, err.inspected, err.needed, err.found, err.tenant),
            (3, 3, 3, 2, T_B))
        self.assertEqual(n.stats()["live_mappings"], 0)
        # 预算=4：同一批实际只检查 4 个端口即全部成功。
        n2 = nat(pool=pool, ports_a=pa, ports_b=pb,
                 max_a=4, max_b=4, budget=4)
        res = n2.allocate_across_tenants([
            tareq(T_A, A, R1),
            tareq(T_B, A, R1),
            tareq(T_B, A, R2),
            tareq(T_B, A, R3),
        ])
        self.assertEqual([r.mapping.external_port for r in res],
                         [6200, 6204, 6205, 6206])

    def test_budget_counts_ports_skipped_as_used(self):
        # 被占用/隔离而跳过的端口同样消耗实际检查计数（基线口径）。
        pool = tuple(range(6200, 6208))
        pa = tuple(range(6200, 6204))
        pb = tuple(range(6204, 6208))
        n = nat(pool=pool, ports_a=pa, ports_b=pb,
                max_a=4, max_b=4, budget=3)
        n.allocate(A, R1, tenant=T_A)               # 6200 占用
        with self.assertRaises(SearchBudgetExhaustedError) as ctx:
            n.allocate_across_tenants([
                tareq(T_A, A, R2),                   # 6200 跳过(1)、6200->6201(2)
                tareq(T_B, A, R1),                   # 6204(3) 找到 1
                tareq(T_B, A, R2),                   # 预算耗尽 found=1/2
            ])
        err = ctx.exception
        self.assertEqual(
            (err.budget, err.inspected, err.needed, err.found, err.tenant),
            (3, 3, 2, 1, T_B))

    def test_input_validation_before_any_planning(self):
        n = nat(max_b=1)
        n.allocate(A, R1, tenant=T_B)               # beta 已满
        # 未知租户：即使同批 beta 也超配额，仍先报输入校验。
        with self.assertRaises(ValidationError):
            n.allocate_across_tenants([
                tareq("gamma", B, R1),
                tareq(T_B, B, R2),
            ])
        # 批内 (tenant,key) 重复：先于配额/容量检查。
        dup = tareq(T_B, B, R2)
        with self.assertRaises(ValidationError):
            n.allocate_across_tenants([dup, dup])
        # 失败不留痕迹。
        self.assertEqual(n.stats()["live_mappings"], 1)
        self.assertEqual(n.now, 0)

    def test_advance_reports_full_tenant_identity(self):
        n = nat(lifetime=10, quarantine=0)
        n.allocate(A, R1, tenant=T_A)
        n.allocate(A, R1, tenant=T_B)
        expired = n.advance(10)
        self.assertEqual(expired, [(T_A, KEY1), (T_B, KEY1)])


class TestLegacySingleTenant(unittest.TestCase):
    """不传租户配置：旧接口行为与基线一致。"""

    def make_legacy(self):
        return AddressDependentNAT(NATConfig(
            public_ip=PUB, external_ports=(6001, 6002, 6003),
            lifetime=10, quarantine=5))

    def test_legacy_calls_unchanged(self):
        n = self.make_legacy()
        r = n.allocate(A, R1)
        self.assertEqual(r.mapping.external_port, 6001)
        self.assertEqual(r.tenant, "")
        r2 = n.allocate(A, R2)
        self.assertEqual(r2.mapping.external_port, 6002)
        self.assertTrue(n.release(KEY1))
        out = n.translate_outbound(pkt(A, R2))
        self.assertTrue(out.accepted)
        self.assertEqual(out.tenant, "")        # 命中默认租户：id 为空串
        back = n.translate_inbound(pkt(R2, Endpoint(PUB, 6002)))
        self.assertTrue(back.accepted)
        self.assertEqual(back.tenant, "")
        miss = n.translate_inbound(pkt(R2, Endpoint(PUB, 6003)))
        self.assertIsNone(miss.tenant)          # 未定位到映射才是 None
        self.assertEqual(n.advance(10), [KEY2])   # 旧形状：裸 key

    def test_legacy_rejects_tenant_arguments(self):
        n = self.make_legacy()
        with self.assertRaises(ValidationError):
            n.allocate(A, R1, tenant=T_A)
        with self.assertRaises(ValidationError):
            n.allocate(A, R1, tenant="")
        with self.assertRaises(ValidationError):
            n.allocate_across_tenants([tareq(T_A, A, R1)])


if __name__ == "__main__":
    unittest.main()
