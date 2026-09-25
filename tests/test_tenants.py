"""多租户契约测试：手工计算的期望值，不依赖参考实现。

重点验收（题面）：
- 两个租户使用完全相同的内网 IP/端口与五元组 -> 映射互不撞车；
  查询/release/出站严格按租户作用域，入站由外端口反查租户。
- 租户表配置：重叠、越界、重复 ID、缺配额等整体拒绝。
- 跨租户批量：全部满足才提交；配额/端口/预算任一失败整体回滚
  （无新映射、generation 不增长、时钟不推进）。
- 配额不足单独报 QuotaExceededError，绝不伪装成端口耗尽。
- 恰好到期边界；隔离期内配额已释放但端口仍不可用 -> PortExhaustion。
- 无租户配置的旧调用与基线一致（advance 仍返回租户内 key）。
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    DEFAULT_TENANT,
    DropReason,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    TenantConfig,
    TenantRequest,
    ValidationError,
)

PUB = "203.0.113.7"
TA = "cust-alpha"
TB = "cust-beta"
# 两家客户使用完全相同的内网地址空间——这是本题的核心场景。
HOST = Endpoint("10.0.0.8", 40000)
R1 = Endpoint("198.51.100.10", 53)
R2 = Endpoint("198.51.100.11", 53)
KEY1 = (HOST.ip, HOST.port, R1.ip, R1.port)
KEY2 = (HOST.ip, HOST.port, R2.ip, R2.port)

PORTS_A = (6001, 6002, 6003)
PORTS_B = (6101, 6102, 6103)
ALL_PORTS = PORTS_A + PORTS_B


def make_nat(*, lifetime=10, quarantine=5, budget=None,
             ports_a=PORTS_A, ports_b=PORTS_B,
             limit_a=3, limit_b=3,
             tenants=None) -> AddressDependentNAT:
    if tenants is None:
        pool = tuple(sorted(ports_a + ports_b))
        tenants = (
            TenantConfig(TA, ports_a, limit_a),
            TenantConfig(TB, ports_b, limit_b),
        )
    else:
        pool = tuple(sorted(p for t in tenants for p in t.external_ports))
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=pool,
        lifetime=lifetime, quarantine=quarantine, search_budget=budget,
        tenants=tenants,
    ))


def make_legacy_nat(ports=(6001, 6002, 6003), *, lifetime=10, quarantine=5,
                    budget=None) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine, search_budget=budget,
    ))


def pkt(src: Endpoint, dst: Endpoint, gen: int = 0) -> Packet:
    return Packet(src=src, dst=dst, generation=gen, payload=b"x")


class TestTenantConfigValidation(unittest.TestCase):
    """租户表非法时整体拒绝（NATConfig 构造失败，没有部分生效）。"""

    def test_overlapping_subsets_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001, 6002, 6101),
                      tenants=(TenantConfig(TA, (6001, 6002), 2),
                               TenantConfig(TB, (6002, 6101), 2)))

    def test_ports_outside_pool_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001, 6101),
                      tenants=(TenantConfig(TA, (6001, 9999), 2),
                               TenantConfig(TB, (6101,), 1)))

    def test_duplicate_tenant_ids_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001, 6002),
                      tenants=(TenantConfig("same", (6001,), 1),
                               TenantConfig("same", (6002,), 1)))

    def test_empty_id_and_bad_limit_rejected(self):
        with self.assertRaises(ValidationError):
            TenantConfig("", (6001,), 1)
        with self.assertRaises(ValidationError):
            TenantConfig(TA, (6001,), 0)
        with self.assertRaises(ValidationError):
            TenantConfig(TA, (), 1)
        with self.assertRaises(ValidationError):
            TenantConfig(TA, (6001, 6001), 1)
        # 显式租户表中不允许无限配额（None 仅隐式默认租户可用）。
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,),
                      tenants=(TenantConfig(TA, (6001,), None),))

    def test_empty_table_and_wrong_type_rejected(self):
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,), tenants=())
        with self.assertRaises(ValidationError):
            NATConfig(public_ip=PUB, external_ports=(6001,),
                      tenants=("not-a-config",))

    def test_subsets_need_not_cover_full_pool(self):
        # 总池允许有未分配给任何租户的剩余端口。
        cfg = NATConfig(
            public_ip=PUB, external_ports=(6001, 6002, 6003),
            tenants=(TenantConfig(TA, (6001,), 1),))
        self.assertEqual(cfg.tenant_ids, (TA,))


class TestSameInternalAddressIsolation(unittest.TestCase):
    """相同内网端点跨租户隔离：不同映射、不同端口、互不可见、互不误放。"""

    def test_identical_five_tuple_gets_distinct_mappings(self):
        nat = make_nat()
        ra = nat.allocate(HOST, R1, tenant_id=TA)
        rb = nat.allocate(HOST, R1, tenant_id=TB)
        self.assertTrue(ra.created and rb.created)
        self.assertEqual(ra.tenant, TA)
        self.assertEqual(rb.tenant, TB)
        self.assertEqual(ra.mapping.key, rb.mapping.key)  # 租户内 key 相同
        self.assertEqual(ra.mapping.external_port, 6001)  # 各自子池最小
        self.assertEqual(rb.mapping.external_port, 6101)  # 端口绝不相同
        self.assertNotEqual(ra.mapping.generation, rb.mapping.generation)

    def test_get_mapping_is_tenant_scoped(self):
        nat = make_nat()
        nat.allocate(HOST, R1, tenant_id=TA)
        # B 没有这条映射——A 的存在不会让 B "查到" 它。
        self.assertIsNone(nat.get_mapping(KEY1, tenant_id=TB))
        self.assertIsNotNone(nat.get_mapping(KEY1, tenant_id=TA))
        nat.allocate(HOST, R1, tenant_id=TB)
        # 两家都有同 key 映射，快照是两条独立记录。
        snap = nat.snapshot_mappings()
        self.assertEqual(len(snap), 2)
        self.assertEqual({m.tenant for m in snap}, {TA, TB})
        self.assertEqual({m.external_port for m in snap}, {6001, 6101})

    def test_release_is_tenant_scoped(self):
        nat = make_nat()
        nat.allocate(HOST, R1, tenant_id=TA)
        nat.allocate(HOST, R1, tenant_id=TB)
        self.assertTrue(nat.release(KEY1, tenant_id=TA))
        self.assertFalse(nat.release(KEY1, tenant_id=TA))   # A 已释放
        # B 的同 key 映射毫发无损。
        self.assertIsNone(nat.get_mapping(KEY1, tenant_id=TA))
        self.assertIsNotNone(nat.get_mapping(KEY1, tenant_id=TB))
        self.assertEqual(nat.stats(tenant_id=TA)["live_mappings"], 0)
        self.assertEqual(nat.stats(tenant_id=TB)["live_mappings"], 1)

    def test_outbound_is_tenant_scoped(self):
        nat = make_nat()
        ma = nat.allocate(HOST, R1, tenant_id=TA).mapping
        mb = nat.allocate(HOST, R1, tenant_id=TB).mapping
        # 同一个合成包，按不同租户发送 -> 各自命中自己的映射/外端口。
        out_a = nat.translate_outbound(pkt(HOST, R1), tenant_id=TA)
        out_b = nat.translate_outbound(pkt(HOST, R1), tenant_id=TB)
        self.assertTrue(out_a.accepted and out_b.accepted)
        self.assertEqual(out_a.rewritten.src_port, ma.external_port)
        self.assertEqual(out_b.rewritten.src_port, mb.external_port)
        self.assertEqual(out_a.tenant, TA)
        self.assertEqual(out_b.tenant, TB)
        # 存在但无映射 -> NO_MAPPING。
        miss = nat.translate_outbound(pkt(HOST, R2), tenant_id=TB)
        self.assertFalse(miss.accepted)
        self.assertIs(miss.reason, DropReason.NO_MAPPING)

    def test_inbound_resolves_tenant_from_external_port(self):
        nat = make_nat()
        ma = nat.allocate(HOST, R1, tenant_id=TA).mapping
        mb = nat.allocate(HOST, R1, tenant_id=TB).mapping
        # 外端口 6001 -> A，6101 -> B；入站改写回同一个内网端点，
        # 但 TranslationResult 必须带回正确租户身份。
        ina = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6001)))
        inb = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6101)))
        self.assertTrue(ina.accepted and inb.accepted)
        self.assertEqual(ina.tenant, TA)
        self.assertEqual(inb.tenant, TB)
        self.assertEqual(ma.external_port, 6001)
        self.assertEqual(mb.external_port, 6101)
        # 子池内但无映射 -> NO_MAPPING；不属于任何租户子池 -> UNKNOWN_TENANT。
        free_in_a = nat.translate_inbound(pkt(R1, Endpoint(PUB, 6002)))
        self.assertIs(free_in_a.reason, DropReason.NO_MAPPING)
        unowned = nat.translate_inbound(pkt(R1, Endpoint(PUB, 9999)))
        self.assertIs(unowned.reason, DropReason.UNKNOWN_TENANT)

    def test_unknown_tenant_rejected_everywhere(self):
        nat = make_nat()
        with self.assertRaises(ValidationError):
            nat.allocate(HOST, R1, tenant_id="ghost")
        with self.assertRaises(ValidationError):
            nat.allocate_many([AllocationRequest(HOST, R1)], tenant_id="ghost")
        with self.assertRaises(ValidationError):
            nat.translate_outbound(pkt(HOST, R1), tenant_id="ghost")
        with self.assertRaises(ValidationError):
            nat.release(KEY1, tenant_id="ghost")
        with self.assertRaises(ValidationError):
            nat.get_mapping(KEY1, tenant_id="ghost")
        with self.assertRaises(ValidationError):
            nat.stats(tenant_id="ghost")


class TestQuota(unittest.TestCase):
    """活跃映射配额：复用不占额，过期/释放即还；不足单列异常。"""

    def test_quota_exceeded_is_not_port_exhaustion(self):
        # 子池 3 口、配额 2：第三个新映射时端口明明有空，仍是配额错误。
        nat = make_nat(limit_a=2, limit_b=2)
        nat.allocate(HOST, R1, tenant_id=TA)
        nat.allocate(Endpoint("10.0.0.9", 1), R1, tenant_id=TA)
        before = (nat.snapshot_mappings(), nat.now)
        with self.assertRaises(QuotaExceededError) as ctx:
            nat.allocate(Endpoint("10.0.0.9", 2), R1, tenant_id=TA)
        err = ctx.exception
        self.assertEqual((err.tenant_id, err.active, err.new, err.limit),
                         (TA, 2, 1, 2))
        self.assertNotIsInstance(err, PortExhaustionError)
        # 配额失败零副作用。
        self.assertEqual((nat.snapshot_mappings(), nat.now), before)
        # 另一租户不受影响，仍可正常分配。
        self.assertTrue(nat.allocate(HOST, R1, tenant_id=TB).created)

    def test_reuse_does_not_consume_quota(self):
        nat = make_nat(limit_a=1, limit_b=1)
        nat.allocate(HOST, R1, tenant_id=TA)
        # 配额已满，但同 key 反复分配是复用，不报错。
        again = nat.allocate(HOST, R1, tenant_id=TA)
        self.assertFalse(again.created)
        batch = nat.allocate_many([AllocationRequest(HOST, R1)], tenant_id=TA)
        self.assertFalse(batch[0].created)
        # 批内同一身份重复出现仍属非法输入（与基线一致）。
        with self.assertRaises(ValidationError):
            nat.allocate_many(
                [AllocationRequest(HOST, R1),
                 AllocationRequest(HOST, R1)], tenant_id=TA)

    def test_release_and_expiry_return_quota(self):
        nat = make_nat(limit_a=1, limit_b=1, lifetime=10)
        nat.allocate(HOST, R1, tenant_id=TA)
        # 释放即还配额（端口仍在隔离，换新端口也可能受限——另见隔离用例）。
        self.assertTrue(nat.release(KEY1, tenant_id=TA))
        # 子池 3 口：6001 隔离中，6002 空闲，所以新映射能拿到 6002。
        r = nat.allocate(HOST, R2, tenant_id=TA)
        self.assertTrue(r.created)
        self.assertEqual(r.mapping.external_port, 6002)
        # 过期同样还配额：推进到恰好 expires_at（边界即死）。
        expired = nat.advance_tenants(10)
        self.assertEqual(expired, [(TA, KEY2)])
        self.assertTrue(nat.allocate(HOST, R1, tenant_id=TA).created)


class TestQuarantineVsQuota(unittest.TestCase):
    """隔离期内配额已释放，但端口仍不可用：必须是端口耗尽而非成功/配额错。"""

    def test_quota_free_but_port_still_quarantined(self):
        # A 子池 2 口、配额 2：两条映射占满；释放 6001 后
        # 活跃=1（配额有空位 1），但 6001 隔离中、6002 在用。
        nat = make_nat(ports_a=(6001, 6002), ports_b=(6101, 6102),
                       limit_a=2, limit_b=2, quarantine=5)
        nat.allocate(HOST, R1, tenant_id=TA)          # 6001
        nat.allocate(HOST, R2, tenant_id=TA)          # 6002
        self.assertTrue(nat.release(KEY1, tenant_id=TA))
        self.assertEqual(nat.stats(tenant_id=TA)["live_mappings"], 1)
        # 申请 1 个新映射：配额 1+1=2 通过；端口规划无口可给 -> 端口耗尽。
        with self.assertRaises(PortExhaustionError) as ctx:
            nat.allocate(Endpoint("10.0.0.9", 7), R1, tenant_id=TA)
        self.assertEqual(ctx.exception.tenant, TA)
        self.assertEqual((ctx.exception.needed, ctx.exception.available), (1, 0))
        # 隔离期满后同请求成功，复用刚解封的 6001（最小空闲）。
        nat.advance_tenants(5)
        ok = nat.allocate(Endpoint("10.0.0.9", 7), R1, tenant_id=TA)
        self.assertEqual(ok.mapping.external_port, 6001)

    def test_quarantine_boundary_exact(self):
        nat = make_nat(ports_a=(6001,), ports_b=(6101,),
                       limit_a=1, limit_b=1, quarantine=5)
        nat.allocate(HOST, R1, tenant_id=TA)
        nat.release(KEY1, tenant_id=TA)
        nat.advance_tenants(4)                          # t=4 仍隔离
        with self.assertRaises(PortExhaustionError):
            nat.allocate(HOST, R2, tenant_id=TA)
        self.assertEqual(nat.quarantined_ports(tenant_id=TA), {6001: 0})
        nat.advance_tenants(1)                          # t=5 边界解除
        self.assertEqual(nat.quarantined_ports(tenant_id=TA), {})
        self.assertEqual(nat.allocate(HOST, R2, tenant_id=TA)
                         .mapping.external_port, 6001)


class TestCrossTenantBatch(unittest.TestCase):
    """跨租户批量：全部满足才提交，检查顺序固定。"""

    def test_success_interleaved_ports_and_generations(self):
        nat = make_nat()
        results = nat.allocate_across_tenants([
            TenantRequest(TA, HOST, R1),     # A 6001 gen1
            TenantRequest(TB, HOST, R1),     # B 6101 gen2（同 key 合法）
            TenantRequest(TA, HOST, R2),     # A 6002 gen3
        ])
        self.assertEqual(
            [(r.tenant, r.key, r.mapping.external_port,
              r.mapping.generation, r.created) for r in results],
            [(TA, KEY1, 6001, 1, True),
             (TB, KEY1, 6101, 2, True),
             (TA, KEY2, 6002, 3, True)],
        )

    def test_quota_failure_in_one_tenant_rolls_back_all(self):
        # A 配额 1，B 配额 1：A 在批里要 2 个新映射 -> 整批失败，
        # B 也不能留下映射，generation 不增长，时钟不推进。
        nat = make_nat(limit_a=1, limit_b=1)
        before = (nat.snapshot_mappings(), nat.stats(), nat.now)
        with self.assertRaises(QuotaExceededError) as ctx:
            nat.allocate_across_tenants([
                TenantRequest(TA, HOST, R1),
                TenantRequest(TB, HOST, R1),
                TenantRequest(TA, HOST, R2),
            ])
        self.assertEqual(ctx.exception.tenant_id, TA)
        self.assertEqual((nat.snapshot_mappings(), nat.stats(), nat.now), before)
        # 序号未增长：之后首次成功分配的 generation 仍是 1。
        first = nat.allocate(HOST, R1, tenant_id=TB)
        self.assertEqual(first.mapping.generation, 1)

    def test_port_failure_in_one_tenant_rolls_back_all(self):
        # A 子池 2 口、B 子池 1 口；B 先占掉自己唯一口，再让跨批中
        # A 要 3 个（超 A 子池）-> 端口耗尽，B 本次的新映射也回滚。
        nat = make_nat(ports_a=(6001, 6002), ports_b=(6101,),
                       limit_a=5, limit_b=5)
        nat.allocate(HOST, R1, tenant_id=TB)            # B 6101 已占
        before = (nat.snapshot_mappings(), nat.stats(), nat.now)
        with self.assertRaises(PortExhaustionError) as ctx:
            nat.allocate_across_tenants([
                TenantRequest(TB, HOST, R2),            # B 已无端口
                TenantRequest(TA, Endpoint("10.0.0.9", 1), R1),
            ])
        self.assertEqual(ctx.exception.tenant, TB)
        self.assertEqual((nat.snapshot_mappings(), nat.stats(), nat.now), before)

    def test_budget_failure_rolls_back_globally(self):
        # 预算 1：每家从各自子池最小端口扫起；最小端口被占用时，
        # 检查 1 个即预算耗尽（逐租户独立计数）-> 整批回滚。
        nat = make_nat(budget=1, limit_a=5, limit_b=5)
        nat.allocate(HOST, R1, tenant_id=TA)            # A 6001
        nat.allocate(HOST, R1, tenant_id=TB)            # B 6101
        before = nat.snapshot_mappings()
        with self.assertRaises(SearchBudgetExhaustedError) as ctx:
            nat.allocate_across_tenants([
                TenantRequest(TA, HOST, R2),            # A：扫到 6001 占用即停
                TenantRequest(TB, HOST, R2),
            ])
        err = ctx.exception
        self.assertEqual((err.tenant, err.budget, err.inspected,
                          err.needed, err.found), (TA, 1, 1, 1, 0))
        self.assertEqual(nat.snapshot_mappings(), before)
        # 预算 3 时同样请求成功，证明之前只是预算问题。
        nat2 = make_nat(budget=3, limit_a=5, limit_b=5)
        nat2.allocate(HOST, R1, tenant_id=TA)
        ok = nat2.allocate_across_tenants([
            TenantRequest(TA, HOST, R2),
            TenantRequest(TB, HOST, R2),
        ])
        self.assertEqual([r.mapping.external_port for r in ok], [6002, 6101])

    def test_check_order_validation_quota_then_ports(self):
        nat = make_nat(limit_a=1, limit_b=1)
        # 未知租户（输入校验）优先于任何容量检查。
        with self.assertRaises(ValidationError):
            nat.allocate_across_tenants([
                TenantRequest("ghost", HOST, R1),
                TenantRequest(TA, HOST, R1),
                TenantRequest(TA, HOST, R2),       # 此行同时构成 A 超配额
            ])
        # 同一租户身份在批内重复 -> 输入校验。
        dup = TenantRequest(TA, HOST, R1)
        with self.assertRaises(ValidationError):
            nat.allocate_across_tenants([dup, dup])
        # A 同时超配额且 B 端口不足：配额检查先于端口规划，
        # 必须报 QuotaExceededError 而不是端口错误。
        nat.allocate(HOST, R1, tenant_id=TB)       # B 唯一口 6101 占用
        with self.assertRaises(QuotaExceededError):
            nat.allocate_across_tenants([
                TenantRequest(TA, HOST, R1),       # 复用，不占额
                TenantRequest(TA, HOST, R2),       # A 配额仅 1 -> 超
                TenantRequest(TB, HOST, R2),       # B 无端口（本应端口耗尽）
            ])

    def test_reuse_in_cross_batch_consumes_neither_quota_nor_port(self):
        nat = make_nat(limit_a=1, limit_b=1)
        nat.allocate(HOST, R1, tenant_id=TA)
        results = nat.allocate_across_tenants([
            TenantRequest(TA, HOST, R1),           # 复用
            TenantRequest(TB, HOST, R1),           # 新建
        ])
        self.assertEqual([r.created for r in results], [False, True])
        self.assertEqual(nat.stats(tenant_id=TA)["ports_in_use"], 1)


class TestExpiryAcrossTenants(unittest.TestCase):
    """恰好到期边界在多租户下的行为。"""

    def test_identical_keys_expire_together_at_boundary(self):
        nat = make_nat(lifetime=10, quarantine=5)
        nat.allocate(HOST, R1, tenant_id=TA)
        nat.allocate(HOST, R1, tenant_id=TB)
        nat.advance_tenants(9)                       # t=9：两家都存活
        self.assertIsNotNone(nat.get_mapping(KEY1, tenant_id=TA))
        self.assertIsNotNone(nat.get_mapping(KEY1, tenant_id=TB))
        expired = nat.advance_tenants(1)             # t=10：边界即死
        self.assertEqual(expired, [(TA, KEY1), (TB, KEY1)])
        self.assertIsNone(nat.get_mapping(KEY1, tenant_id=TA))
        self.assertIsNone(nat.get_mapping(KEY1, tenant_id=TB))
        # 两个端口都进入各自租户的隔离表。
        self.assertEqual(nat.quarantined_ports(tenant_id=TA), {6001: 10})
        self.assertEqual(nat.quarantined_ports(tenant_id=TB), {6101: 10})
        self.assertEqual(nat.stats(tenant_id=TA)["live_mappings"], 0)
        nat.advance_tenants(5)                       # t=15：同时解除
        self.assertEqual(nat.quarantined_ports(), {})


class TestLegacyDefaultTenant(unittest.TestCase):
    """不传租户配置：旧接口行为与基线一致。"""

    def test_legacy_shapes_unchanged(self):
        nat = make_legacy_nat(lifetime=10, quarantine=5)
        r = nat.allocate(HOST, R1)
        self.assertEqual(r.tenant, DEFAULT_TENANT)
        self.assertTrue(nat.config.is_default_only())
        # advance 返回租户内 key（不带租户列），与基线一致。
        self.assertEqual(nat.advance(10), [KEY1])
        # 旧的无租户过滤快照/统计形状不变。
        self.assertEqual(nat.stats()["pool_size"], 3)

    def test_legacy_advance_rejected_with_explicit_table(self):
        nat = make_nat()
        with self.assertRaises(ValidationError):
            nat.advance(1)
        # advance_tenants 在任何配置下都可用。
        self.assertEqual(nat.advance_tenants(1), [])

    def test_legacy_unknown_default_tenant_after_explicit_table(self):
        nat = make_nat()  # 表中没有 "default"
        with self.assertRaises(ValidationError):
            nat.allocate(HOST, R1)                 # 旧调用默认走 default
        with self.assertRaises(ValidationError):
            nat.release(KEY1)


if __name__ == "__main__":
    unittest.main()
