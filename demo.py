"""demo.py —— 地址依赖 NAT 模块的离线演示（固定输入，真实计算，无 sleep）。

运行：python demo.py
内容：
  1. 正常路径：同一内网端点访问两个不同目的 -> 两条地址依赖映射，
     出站改写 + 入站命中改写（两种映射都体现）。
  2. 实际触发的拒绝/异常边界：
     a. 端口池耗尽 -> 批量分配抛 PortExhaustionError 并整体回滚；
     b. 入站对端不匹配 -> 丢弃（PEER_MISMATCH）；
     c. 映射重建后旧 generation 的迟到包 -> 丢弃（STALE_GENERATION）。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
)

PUB = "203.0.113.7"
POOL = (6100, 6101, 6102, 6103, 6104, 6105)
HOST = Endpoint("10.0.0.8", 40000)
WEB_A = Endpoint("198.51.100.10", 443)
WEB_B = Endpoint("198.51.100.20", 443)


def show_five(tag, five):
    print(f"    {tag}: ({five.protocol}, {five.src_ip}:{five.src_port}"
          f" -> {five.dst_ip}:{five.dst_port})")


def main() -> None:
    nat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=POOL, lifetime=30, quarantine=10,
    ))
    print(f"NAT 公网IP={PUB} 端口池={POOL} lifetime=30 quarantine=10")

    print("\n[1] 正常路径：同一内网端点 -> 两个不同目的（两种映射）")
    m1 = nat.allocate(HOST, WEB_A).mapping
    m2 = nat.allocate(HOST, WEB_B).mapping
    for m in (m1, m2):
        print(f"    映射 gen={m.generation} 外端口={m.external_port}"
              f" 对端={m.remote.ip}:{m.remote.port} expires_at={m.expires_at}")
    out = nat.translate_outbound(
        Packet(src=HOST, dst=WEB_A, generation=m1.generation))
    print(f"  出站 {HOST.ip}:{HOST.port} -> {WEB_A.ip}:{WEB_A.port} 改写:")
    show_five("五元组", out.rewritten)
    back = nat.translate_inbound(
        Packet(src=WEB_A, dst=Endpoint(PUB, m1.external_port),
               generation=m1.generation))
    print(f"  入站 {WEB_A.ip}:{WEB_A.port} -> {PUB}:{m1.external_port} 改写:")
    show_five("五元组", back.rewritten)
    assert back.rewritten.dst_ip == HOST.ip and back.rewritten.dst_port == HOST.port

    print("\n[2a] 异常边界：端口池耗尽 -> 批量分配整体回滚")
    filler = [AllocationRequest(Endpoint("10.0.0.9", p), WEB_A)
              for p in (5001, 5002, 5003, 5004)]   # 占满剩余 4 口
    nat.allocate_many(filler)
    print(f"    已占用端口数: {nat.stats()['ports_in_use']}/{nat.stats()['pool_size']}")
    before = nat.stats()
    try:
        nat.allocate_many([AllocationRequest(Endpoint("10.0.0.9", 5005), WEB_A),
                           AllocationRequest(Endpoint("10.0.0.9", 5006), WEB_A)])
        raise AssertionError("应当抛出 PortExhaustionError")
    except PortExhaustionError as exc:
        print(f"    触发 PortExhaustionError: {exc}")
    after = nat.stats()
    assert before == after, "回滚后状态必须与调用前一致"
    print(f"    回滚验证: stats 调用前后一致 (ports_in_use={after['ports_in_use']})")

    print("\n[2b] 拒绝边界：入站包来自错误对端 -> 丢弃")
    stranger = Endpoint("192.0.2.66", 9999)
    dropped = nat.translate_inbound(
        Packet(src=stranger, dst=Endpoint(PUB, m1.external_port)))
    print(f"    {stranger.ip}:{stranger.port} -> {PUB}:{m1.external_port}"
          f"  accepted={dropped.accepted} reason={dropped.reason.value}")
    assert not dropped.accepted

    print("\n[2c] 拒绝边界：映射重建后旧 generation 的迟到包 -> 丢弃")
    key1 = m1.key
    old_gen = m1.generation
    nat.release(key1)
    print(f"    释放映射 gen={old_gen}，端口 {m1.external_port} 进入隔离 Q=10")
    nat.advance(10)      # 隔离结束
    m1b = nat.allocate(HOST, WEB_A).mapping
    print(f"    重建映射 gen={m1b.generation} 外端口={m1b.external_port}")
    late = nat.translate_inbound(
        Packet(src=WEB_A, dst=Endpoint(PUB, m1b.external_port),
               generation=old_gen))
    print(f"    迟到包(gen={old_gen}) accepted={late.accepted}"
          f" reason={late.reason.value}")
    fresh = nat.translate_inbound(
        Packet(src=WEB_A, dst=Endpoint(PUB, m1b.external_port),
               generation=m1b.generation))
    print(f"    当前包(gen={m1b.generation}) accepted={fresh.accepted}")
    assert not late.accepted and fresh.accepted

    print("\n[2d] 内部回转：两台内网设备经对方公网映射互访")
    hp = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=(6100, 6101), lifetime=30, quarantine=5))
    host_b = Endpoint("10.0.0.10", 40001)
    ma = hp.allocate(HOST, Endpoint(PUB, 6101)).mapping    # HOST -> B 的公网映射
    mb = hp.allocate(host_b, Endpoint(PUB, 6100)).mapping   # B -> HOST 的公网映射
    print(f"    HOST 映射: 外端口 {ma.external_port} 对端 PUB:{mb.external_port}"
          f" gen={ma.generation}")
    print(f"    B    映射: 外端口 {mb.external_port} 对端 PUB:{ma.external_port}"
          f" gen={mb.generation}")
    hreq = hp.translate_outbound(
        Packet(src=HOST, dst=Endpoint(PUB, mb.external_port),
               generation=ma.generation))
    print("    回转请求改写:")
    show_five("五元组", hreq.rewritten)
    assert (hreq.rewritten.src_ip, hreq.rewritten.src_port,
            hreq.rewritten.dst_ip, hreq.rewritten.dst_port) == \
           (PUB, ma.external_port, host_b.ip, host_b.port)
    hrep = hp.translate_outbound(
        Packet(src=host_b, dst=Endpoint(PUB, ma.external_port),
               generation=mb.generation))
    print("    回转返回改写:")
    show_five("五元组", hrep.rewritten)
    assert (hrep.rewritten.src_ip, hrep.rewritten.src_port,
            hrep.rewritten.dst_ip, hrep.rewritten.dst_port) == \
           (PUB, mb.external_port, HOST.ip, HOST.port)
    # 过滤不被绕过：B 的映射释放、端口隔离后被对端 WEB_A 的新设备复用，
    # HOST 的回转包对端不匹配，被 PEER_MISMATCH 拒绝，不会送给新设备。
    hp.release(mb.key)
    hp.advance(5)
    stranger = Endpoint("10.0.0.11", 40002)
    hp.allocate(stranger, WEB_A)                     # 复用 6101，对端是 WEB_A
    blocked = hp.translate_outbound(
        Packet(src=HOST, dst=Endpoint(PUB, mb.external_port),
               generation=ma.generation))
    print(f"    端口已重新分配给对端 WEB_A 的新设备：accepted={blocked.accepted}"
          f" reason={blocked.reason.value}（不会送给新设备）")
    assert not blocked.accepted and blocked.reason.value == "peer_mismatch"

    print("\n[3] 时钟推进与过期")
    expired = nat.advance(30)   # 所有映射 lifetime=30 到期
    print(f"    advance(30) 过期映射数: {len(expired)}, "
          f"剩余活跃映射: {nat.stats()['live_mappings']}")
    assert nat.stats()["live_mappings"] == 0

    print("\n演示完成：正常路径与三类拒绝/异常边界均按预期发生。")


if __name__ == "__main__":
    main()
