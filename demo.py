"""demo.py —— 多租户地址依赖 NAT 的离线演示（固定输入，真实计算，无 sleep）。

运行：python demo.py
内容（全部使用合成地址，不发任何网络包）：
  1. 两个客户 cust-alpha / cust-beta 使用完全相同的内网 IP 与端口，
     各自拿到互不相干的映射与外端口（子池互不重叠）。
  2. 出站 / 入站改写：出站按调用租户命中，入站由外端口反查租户。
  3. 查询与 release 严格租户作用域：A 的释放不动 B 的同 key 映射。
  4. 跨租户批量分配：全部满足才提交。
  5. 一次真实的跨租户批量失败（A 超配额）：QuotaExceededError，
     B 的新映射一起回滚，generation 序号不增长、时钟不推进。
  6. 隔离期内配额已释放但端口仍不可用 -> PortExhaustionError（不是配额错）。
  7. 恰好到期边界（expires_at == now 即过期），两家同 key 同时过期。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    TenantConfig,
    TenantRequest,
)

PUB = "203.0.113.7"
TA, TB = "cust-alpha", "cust-beta"
PORTS_A = (6001, 6002, 6003)
PORTS_B = (6101, 6102, 6103)
# 两家客户的内网地址完全一样 —— 本题的核心场景。
HOST_A = Endpoint("10.0.0.8", 40000)
HOST_B = Endpoint("10.0.0.8", 40000)
DNS = Endpoint("198.51.100.10", 53)
NTP = Endpoint("198.51.100.11", 123)


def make_nat(*, lifetime=30, quarantine=10):
    return AddressDependentNAT(NATConfig(
        public_ip=PUB,
        external_ports=PORTS_A + PORTS_B,
        lifetime=lifetime, quarantine=quarantine,
        tenants=(
            TenantConfig(TA, PORTS_A, max_mappings=2),
            TenantConfig(TB, PORTS_B, max_mappings=2),
        ),
    ))


def show_five(tag, five):
    print(f"    {tag}: ({five.protocol}, {five.src_ip}:{five.src_port}"
          f" -> {five.dst_ip}:{five.dst_port})")


def main() -> None:
    nat = make_nat()
    print(f"NAT 公网IP={PUB}  总端口池={PORTS_A + PORTS_B}")
    print(f"租户 {TA}: 子池{PORTS_A} 配额2")
    print(f"租户 {TB}: 子池{PORTS_B} 配额2")
    print(f"两家的内网端点完全相同: {HOST_A.ip}:{HOST_A.port}")

    print("\n[1] 相同内网地址、相同对端 -> 两条互不撞车的映射")
    ma = nat.allocate(HOST_A, DNS, tenant_id=TA).mapping
    mb = nat.allocate(HOST_B, DNS, tenant_id=TB).mapping
    print(f"    {TA}: gen={ma.generation} 外端口={ma.external_port}"
          f" 内网={ma.internal.ip}:{ma.internal.port} 对端={ma.remote.ip}")
    print(f"    {TB}: gen={mb.generation} 外端口={mb.external_port}"
          f" 内网={mb.internal.ip}:{mb.internal.port} 对端={mb.remote.ip}")
    assert ma.external_port != mb.external_port
    assert ma.key == mb.key and ma.tenant != mb.tenant

    print("\n[2] 包改写：出站按租户命中，入站按外端口反查租户")
    out_a = nat.translate_outbound(
        Packet(src=HOST_A, dst=DNS, generation=ma.generation), tenant_id=TA)
    out_b = nat.translate_outbound(
        Packet(src=HOST_B, dst=DNS, generation=mb.generation), tenant_id=TB)
    show_five(f"出站[{TA}]", out_a.rewritten)
    show_five(f"出站[{TB}]", out_b.rewritten)
    assert out_a.tenant == TA and out_b.tenant == TB
    in_a = nat.translate_inbound(
        Packet(src=DNS, dst=Endpoint(PUB, ma.external_port),
               generation=ma.generation))
    show_five(f"入站 :{ma.external_port} -> ", in_a.rewritten)
    assert in_a.tenant == TA
    assert (in_a.rewritten.dst_ip, in_a.rewritten.dst_port) == (HOST_A.ip, HOST_A.port)

    print("\n[3] 查询 / release 严格租户作用域")
    nat.release((HOST_A.ip, HOST_A.port, DNS.ip, DNS.port), tenant_id=TA)
    look_a = nat.get_mapping((HOST_A.ip, HOST_A.port, DNS.ip, DNS.port),
                             tenant_id=TA)
    look_b = nat.get_mapping((HOST_B.ip, HOST_B.port, DNS.ip, DNS.port),
                             tenant_id=TB)
    print(f"    release[{TA}] 后：A 查到 {look_a}；B 仍查到 gen="
          f"{look_b.generation if look_b else None} 端口="
          f"{look_b.external_port if look_b else None}")
    assert look_a is None and look_b is not None
    # A 把映射重新建回来（6001 在隔离，拿最小空闲 6002），后面要用。
    nat.allocate(HOST_A, DNS, tenant_id=TA)

    print("\n[4] 跨租户批量：全部满足才提交")
    ok = nat.allocate_across_tenants([
        TenantRequest(TA, Endpoint("10.0.0.8", 40000), NTP),   # A 第二条
        TenantRequest(TB, Endpoint("10.0.0.8", 40000), NTP),   # B 第二条
    ])
    for r in ok:
        print(f"    {r.tenant}: key 对端={r.mapping.remote.ip}:{r.mapping.remote.port}"
              f" 外端口={r.mapping.external_port} gen={r.mapping.generation}"
              f" created={r.created}")

    print("\n[5] 真实批量失败：A 超配额（两家都只配 2 条），整批回滚")
    print(f"    失败前: {nat.stats()}")
    before = (nat.snapshot_mappings(), nat.stats(), nat.now)
    try:
        nat.allocate_across_tenants([
            TenantRequest(TA, Endpoint("10.0.0.9", 5001), DNS),  # A 第 3 条
            TenantRequest(TB, Endpoint("10.0.0.9", 5002), DNS),  # B 也想要
        ])
        raise AssertionError("应当抛出 QuotaExceededError")
    except QuotaExceededError as exc:
        print(f"    触发 {type(exc).__name__}: {exc}")
    after = (nat.snapshot_mappings(), nat.stats(), nat.now)
    assert before == after, "回滚后状态必须与调用前完全一致"
    print(f"    回滚验证: stats 前后一致，B 也没有留下新映射")
    print(f"    失败后: {nat.stats()}")
    # generation 序号未增长：B 下一条成功映射的 gen 紧接 [4] 之后。
    # （[1] gen1/2，[3]重建 gen3，[4] gen4/5 -> 下一条应为 gen6）
    nxt = nat.allocate(HOST_B, DNS, tenant_id=TB)  # 复用，不发号
    assert not nxt.created
    print("    B 对已有映射的分配仍是复用（不发号、不占配额）")

    print("\n[6] 隔离期：配额已空出但端口仍不可用 -> PortExhaustion（非配额错）")
    # A 当前两条：6002(DNS) 与 6003(NTP)；6001 仍在隔离。释放 6003 后
    # 活跃=1（配额有空位），但 6001/6003 都在隔离、6002 在用。
    nat.release((HOST_A.ip, HOST_A.port, NTP.ip, NTP.port), tenant_id=TA)
    print(f"    A stats: {nat.stats(tenant_id=TA)}  "
          f"隔离端口: {nat.quarantined_ports(tenant_id=TA)}")
    try:
        nat.allocate(Endpoint("10.0.0.9", 5005), DNS, tenant_id=TA)
        raise AssertionError("应当抛出 PortExhaustionError")
    except PortExhaustionError as exc:
        print(f"    触发 {type(exc).__name__}: needed={exc.needed} "
              f"available={exc.available} pool_size={exc.pool_size} "
              f"tenant={exc.tenant!r}")
        assert not isinstance(exc, QuotaExceededError)

    print("\n[7] 恰好到期：t=30 == expires_at，两家同 key 映射边界即死")
    # 此前所有操作都在 t=0（失败回滚不推进时钟），直接推进到 30。
    expired = nat.advance_tenants(30 - nat.now)
    print(f"    当前时钟 t={nat.now}，本次过期身份数={len(expired)}")
    for tid, key in expired:
        print(f"    过期: tenant={tid} key={key}")
    assert nat.stats()["live_mappings"] == 0

    print("\n演示完成：两个租户的地址隔离、作用域查询/释放、跨租户批量")
    print("成功与真实失败回滚、配额 vs 端口耗尽区分、到期边界均按预期发生。")


if __name__ == "__main__":
    main()
