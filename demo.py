"""demo.py —— 多租户地址依赖 NAT 的离线演示（固定输入，真实计算，无 sleep）。

运行：./.venv/bin/python demo.py

内容（全部合成地址，不发任何网络包、不读账号密钥）：
  1. 租户表：alpha / beta 各持不重叠外端口子集与活跃配额；
  2. 两个租户使用完全相同的内网地址 10.0.0.8:40000 访问同一目的——
     映射身份、外端口、出站/入站改写全部按租户隔离，入站由外端口反解租户；
  3. 跨租户批量成功（混合新建与复用）；
  4. 一次真实的跨租户批量失败：beta 超配额，整批回滚——alpha 也不留下
     新映射，generation 不增长、时钟不推进、隔离表不变；
  5. 配额错误与端口耗尽严格分开：配额已空出但端口仍在隔离期 ->
     PortExhaustionError 而不是 QuotaExceededError；
  6. 恰好到期边界：过期释放配额，端口随后还要走完隔离期。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
    QuotaExceededError,
    TenantAllocationRequest,
    TenantConfig,
)

PUB = "203.0.113.7"
POOL = (6300, 6301, 6302, 6303, 6304)
PORTS_A = (6300, 6301, 6302)
PORTS_B = (6303, 6304)
T_A, T_B = "alpha", "beta"

# 两个租户背后同一台内网主机（合成地址）。
HOST = Endpoint("10.0.0.8", 40000)
OTHER = Endpoint("10.0.0.9", 40001)
WEB1 = Endpoint("198.51.100.10", 443)
WEB2 = Endpoint("198.51.100.20", 443)
WEB3 = Endpoint("198.51.100.30", 443)
KEY_WEB1 = (HOST.ip, HOST.port, WEB1.ip, WEB1.port)


def line(title: str) -> None:
    print(f"\n[{title}]")


def show_mapping(tag: str, m, created: bool | None = None) -> None:
    flag = "" if created is None else f" {'新建' if created else '复用'}"
    print(f"    {tag}: tenant={m.tenant} 内网={m.internal.ip}:{m.internal.port}"
          f" 对端={m.remote.ip}:{m.remote.port} 外端口={m.external_port}"
          f" gen={m.generation}{flag}")


def main() -> None:
    nat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=POOL, lifetime=30, quarantine=10,
        tenants=(
            TenantConfig(tenant_id=T_A, external_ports=PORTS_A,
                         max_active_mappings=3),
            TenantConfig(tenant_id=T_B, external_ports=PORTS_B,
                         max_active_mappings=2),
        )))
    print(f"NAT 公网IP={PUB} 总端口池={POOL} lifetime=30 quarantine=10")
    print(f"租户表（构造后固定）：")
    print(f"    alpha: 子集={PORTS_A} max_active=3")
    print(f"    beta : 子集={PORTS_B} max_active=2")
    print(f"    tenant_ids={nat.tenant_ids}")

    line("1] 相同内网地址的跨租户隔离（同一主机、同一目的）")
    ra = nat.allocate(HOST, WEB1, tenant=T_A)
    rb = nat.allocate(HOST, WEB1, tenant=T_B)
    show_mapping("alpha 分配", ra.mapping, ra.created)
    show_mapping("beta 分配", rb.mapping, rb.created)
    assert ra.mapping.external_port == 6300 and rb.mapping.external_port == 6303
    assert ra.mapping.generation == 1 and rb.mapping.generation == 2
    # 查询必须显式带租户：同一四元组在两家各查到各的。
    assert nat.get_mapping(KEY_WEB1, tenant=T_A).external_port == 6300
    assert nat.get_mapping(KEY_WEB1, tenant=T_B).external_port == 6303

    line("2] 同一个内网包在两个租户下改写出不同外端口；入站反解租户")
    for tid, port in ((T_A, 6300), (T_B, 6303)):
        out = nat.translate_outbound(
            Packet(src=HOST, dst=WEB1, generation=nat.get_mapping(
                KEY_WEB1, tenant=tid).generation), tenant=tid)
        f = out.rewritten
        print(f"    出站[{tid}] {HOST.ip}:{HOST.port} -> {WEB1.ip}:{WEB1.port}"
              f" 改写为 {f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port}"
              f"（结果租户={out.tenant}）")
        back = nat.translate_inbound(
            Packet(src=WEB1, dst=Endpoint(PUB, port)))
        g = back.rewritten
        print(f"    入站    {WEB1.ip}:{WEB1.port} -> {PUB}:{port} 命中租户="
              f"{back.tenant}，改写回 {g.dst_ip}:{g.dst_port}")
        assert back.tenant == tid and (g.dst_ip, g.dst_port) == (HOST.ip, HOST.port)

    line("3] 跨租户批量成功（alpha 新建 + beta 新建 + alpha 复用）")
    ok = nat.allocate_across_tenants([
        TenantAllocationRequest(T_A, HOST, WEB2),     # 新建 6301 gen3
        TenantAllocationRequest(T_B, OTHER, WEB1),    # 新建 6304 gen4
        TenantAllocationRequest(T_A, HOST, WEB1),     # 复用 6300 gen1
    ])
    for r in ok:
        show_mapping("批量结果", r.mapping, r.created)
    assert [r.created for r in ok] == [True, True, False]
    assert nat.tenant_stats(T_A)["live_mappings"] == 2
    assert nat.tenant_stats(T_B)["live_mappings"] == 2

    line("4] 真实跨租户批量失败：beta 配额已满 -> 整批回滚")
    print("    beta 当前活跃=2=配额；本批 alpha 要新建 6302，"
          "beta 要再新建一条（超配额）。")
    before = (nat.snapshot_mappings(), nat.stats(),
              nat.quarantined_ports(), nat.now)
    try:
        nat.allocate_across_tenants([
            TenantAllocationRequest(T_A, OTHER, WEB2),    # alpha 本可成功
            TenantAllocationRequest(T_B, OTHER, WEB3),    # beta 超配额
        ])
        raise AssertionError("应当抛出 QuotaExceededError")
    except QuotaExceededError as exc:
        print(f"    触发 QuotaExceededError（不是端口耗尽）：{exc}")
    after = (nat.snapshot_mappings(), nat.stats(),
             nat.quarantined_ports(), nat.now)
    assert before == after, "回滚后状态必须与调用前完全一致"
    print("    回滚验证：snapshot / stats / 隔离表 / 时钟 调用前后完全一致；")
    nxt = nat.allocate(OTHER, WEB3, tenant=T_A)
    print(f"    失败批未消耗序号：随后 alpha 新映射 gen={nxt.mapping.generation}"
          f"（预期 5）、外端口={nxt.mapping.external_port}（预期 6302）")
    assert nxt.mapping.generation == 5 and nxt.mapping.external_port == 6302

    line("5] 配额错误 ≠ 端口耗尽：配额空出但端口仍在隔离期")
    key_other = (OTHER.ip, OTHER.port, WEB3.ip, WEB3.port)
    nat.release(key_other, tenant=T_A)
    print(f"    alpha 释放 6302，活跃降为 {nat.tenant_stats(T_A)['live_mappings']}"
          f"（配额已空出），端口进入隔离 Q=10。")
    try:
        nat.allocate(HOST, WEB3, tenant=T_A, at=4)
        raise AssertionError("应当抛出 PortExhaustionError")
    except PortExhaustionError as exc:
        print(f"    候选时刻 t=4 仍隔离 -> PortExhaustionError：{exc}")
    except QuotaExceededError:
        raise AssertionError("配额已空出，不得伪装成配额错误")

    line("6] 恰好到期边界：过期释放配额，端口随后走完隔离期")
    print("    beta 的两条映射 expires_at=30；t=29 仍占配额，t=30 边界即死。")
    try:
        nat.allocate(OTHER, WEB2, tenant=T_B, at=29)
        raise AssertionError("t=29 beta 应仍超配额")
    except QuotaExceededError as exc:
        print(f"    t=29 -> {type(exc).__name__}: active={exc.active} "
              f"requested={exc.requested} limit={exc.limit}")
    nat.advance(30)
    print(f"    advance(30) 后 beta 活跃={nat.tenant_stats(T_B)['live_mappings']}，"
          f"其端口在隔离表中："
          f"{ {p: t for p, t in nat.quarantined_ports().items() if p in PORTS_B} }")
    try:
        nat.allocate(OTHER, WEB2, tenant=T_B)   # t=30，Q 未满
        raise AssertionError("隔离期内端口仍不可用")
    except PortExhaustionError:
        print("    t=30 配额已空但端口仍隔离 -> PortExhaustionError（隔离期未跳过）")
    nat.advance(10)                              # t=40 隔离到期
    recovered = nat.allocate(OTHER, WEB2, tenant=T_B)
    print(f"    t=40 隔离到期，beta 重新分配：外端口={recovered.mapping.external_port}"
          f" gen={recovered.mapping.generation}")
    assert recovered.mapping.external_port == 6303

    print("\n演示完成：两租户相同内网地址隔离、跨租户批量成功与真实失败"
          "整批回滚、配额/端口两类错误区分、恰好到期与隔离边界均按预期发生。")


if __name__ == "__main__":
    main()
