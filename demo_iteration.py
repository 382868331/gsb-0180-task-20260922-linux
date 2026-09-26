#!/usr/bin/env python3
"""本轮迭代演示：差错报文入口（离线真实计算，无 sleep、无预录输出）。

场景：
1. 两条地址依赖映射（同内网端点、不同远端，不同外端口），
   差错报文按被引用的原 UDP 五元组反查内部端点；
2. 同端口引用不同远端 -> 明确丢弃 PEER_MISMATCH；
3. 映射过期、端口隔离结束后被新连接复用（同端口、新 generation），
   携带旧世代标记的引用 -> STALE_GENERATION；
4. 重复差错报文穿插正常回包：差错不刷新寿命，只有正常流量保活。

运行：python demo_iteration.py
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    Endpoint,
    ErrorReport,
    FiveTuple,
    NATConfig,
    Packet,
)

PUB = "203.0.113.7"
INNER = Endpoint("10.0.0.8", 40000)
R_DNS = Endpoint("198.51.100.10", 53)
R_NTP = Endpoint("198.51.100.11", 123)
REPORTER = Endpoint("192.0.2.254", 1)


def quoted(port: int, remote: Endpoint) -> FiveTuple:
    return FiveTuple(17, PUB, port, remote.ip, remote.port)


def show(title: str, result) -> None:
    print(f"--- {title}")
    if result.accepted:
        f = result.rewritten
        print("  接受")
        print(f"    外层目标 outer_dst = {result.outer_dst.ip}:{result.outer_dst.port}")
        print(f"    改写后五元组       = UDP {f.src_ip}:{f.src_port} "
              f"-> {f.dst_ip}:{f.dst_port}")
        print(f"    采用映射 ID        = {result.mapping_id}")
    else:
        print(f"  丢弃：{result.reason.value}（mapping_id={result.mapping_id}）")


def main() -> None:
    nat = AddressDependentNAT(NATConfig(
        public_ip=PUB,
        external_ports=(6100, 6101, 6102),
        lifetime=300,
        quarantine=60,
    ))

    print("== 1. 建两条地址依赖映射 ==")
    dns = nat.allocate(INNER, R_DNS)
    ntp = nat.allocate(INNER, R_NTP)
    print(f"  DNS 映射：外端口 {dns.mapping.external_port}，"
          f"映射 ID/世代 {dns.mapping.generation}，expires_at="
          f"{dns.mapping.expires_at}")
    print(f"  NTP 映射：外端口 {ntp.mapping.external_port}，"
          f"映射 ID/世代 {ntp.mapping.generation}，expires_at="
          f"{ntp.mapping.expires_at}")

    print()
    print("== 2. 差错报文反查（正常结果 + 边界丢弃） ==")
    show("正确引用 DNS 原包",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6100, R_DNS),
                         generation=dns.mapping.generation)))
    show("正确引用 NTP 原包",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6101, R_NTP),
                         generation=ntp.mapping.generation)))
    show("同端口 6100 却引用 NTP 远端（对端不匹配）",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6100, R_NTP),
                         generation=dns.mapping.generation)))
    show("引用非 UDP 协议号（结构不完整）",
         nat.translate_error(
             ErrorReport(REPORTER, FiveTuple(6, PUB, 6100,
                                             R_DNS.ip, R_DNS.port), 1)))
    show("引用不存在的外端口 6102（无映射）",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6102, R_DNS), generation=1)))

    print()
    print("== 3. 过期 + 端口复用后的旧引用 ==")
    key_dns = dns.key
    nat.advance(300)                     # t=300：DNS 映射过期进隔离
    assert nat.get_mapping(key_dns) is None
    nat.advance(60)                      # t=360：隔离结束，6100 可复用
    newcomer = Endpoint("10.0.0.9", 55000)
    new_map = nat.allocate(newcomer, R_DNS, at=360)
    print(f"  新连接复用端口：外端口 {new_map.mapping.external_port}，"
          f"新映射 ID/世代 {new_map.mapping.generation}")
    show("旧引用携带旧世代标记 1（端口复用，STALE_GENERATION）",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6100, R_DNS), generation=1), at=360))
    show("新连接自己的引用（正常命中新内部端点）",
         nat.translate_error(
             ErrorReport(REPORTER, quoted(6100, R_DNS),
                         generation=new_map.mapping.generation), at=360))

    print()
    print("== 4. 重复差错不延长寿命；正常回包才保活 ==")
    ntp_key = ntp.key
    # t=360 时原 NTP 映射已过期；重新分配一条用于保活演示。
    ntp2 = nat.allocate(INNER, R_NTP, at=360)
    ntp_key = ntp2.key
    ntp_gen = ntp2.mapping.generation
    ntp_port = ntp2.mapping.external_port
    expires_before = nat.get_mapping(ntp_key).expires_at
    for i in range(3):
        r = nat.translate_error(
            ErrorReport(REPORTER, quoted(ntp_port, R_NTP),
                        generation=ntp_gen), at=360)
        assert r.accepted
    expires_after_errors = nat.get_mapping(ntp_key).expires_at
    print(f"  连发 3 次差错前后 expires_at：{expires_before} -> "
          f"{expires_after_errors}（不变）")
    nat.translate_inbound(
        Packet(src=R_NTP, dst=Endpoint(PUB, ntp_port),
               generation=ntp_gen), at=400)
    expires_after_inbound = nat.get_mapping(ntp_key).expires_at
    print(f"  一次正常回包后 expires_at：{expires_after_inbound}（被刷新）")
    assert expires_after_errors == expires_before
    assert expires_after_inbound > expires_before

    print()
    print("演示完成：差错入口只做只读反查，不建映射、不刷新寿命。")


if __name__ == "__main__":
    main()
