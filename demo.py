"""demo.py —— 地址依赖 NAT 模块的离线演示（固定输入，真实计算，无 sleep）。

运行：./.venv/bin/python demo.py
内容：
  1. 正常路径：同一内网端点访问两个不同目的 -> 两条地址依赖映射，
     出站改写 + 入站命中改写（两种映射都体现）。
  2. 实际触发的拒绝/异常边界：
     a. 端口池耗尽 -> 批量分配抛 PortExhaustionError 并整体回滚；
     b. 入站对端不匹配 -> 丢弃（PEER_MISMATCH）；
     c. 映射重建后旧 generation 的迟到包 -> 丢弃（STALE_GENERATION）。
  3. Hairpin（内网折返）：两个内网端点互访对方公网端点，手工核对去/回
     两方向五元组与双方 generation；并实际触发一次"目的刚到期 ->
     NO_MAPPING"和一次"源端口耗尽 -> 整体回滚、目的计时不变"。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    DropReason,
    Endpoint,
    NATConfig,
    Packet,
    PortExhaustionError,
)

PUB = "203.0.113.7"
POOL = (6100, 6101, 6102, 6103, 6104, 6105)
HOST = Endpoint("10.0.0.8", 40000)
PEER_B = Endpoint("10.0.0.9", 50000)      # hairpin 对端内网主机
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

    print("\n[3] 时钟推进与过期")
    expired = nat.advance(30)   # 所有映射 lifetime=30 到期
    print(f"    advance(30) 过期映射数: {len(expired)}, "
          f"剩余活跃映射: {nat.stats()['live_mappings']}")
    assert nat.stats()["live_mappings"] == 0

    print("\n[4] Hairpin：内网主机访问仍有效的公网映射，折返回内网")
    hnat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=(6200, 6201, 6202, 6203),
        lifetime=30, quarantine=10,
    ))
    ma = hnat.allocate(HOST, WEB_A).mapping       # HOST -> WEB_A: 6200 gen1
    mb = hnat.allocate(PEER_B, WEB_B).mapping     # PEER_B -> WEB_B: 6201 gen2
    print(f"    目的映射 {HOST.ip}:{HOST.port} <-> {WEB_A.ip}:{WEB_A.port}"
          f" 外端口={ma.external_port} gen={ma.generation}")
    print(f"    对端主机 {PEER_B.ip}:{PEER_B.port} 外端口={mb.external_port}"
          f" gen={mb.generation}")

    # 去程：PEER_B 访问 HOST 的公网端点 PUB:6200
    fwd = hnat.translate_hairpin(
        Packet(src=PEER_B, dst=Endpoint(PUB, ma.external_port),
               generation=ma.generation))
    print(f"  去程 {PEER_B.ip}:{PEER_B.port} -> {PUB}:{ma.external_port}:")
    show_five("折回五元组", fwd.rewritten)
    print(f"    源映射: 外端口={fwd.source_mapping.external_port}"
          f" gen={fwd.source_mapping.generation} created={fwd.source_created}"
          f" key对端={fwd.source_mapping.remote.ip}:{fwd.source_mapping.remote.port}")
    print(f"    目的映射: 外端口={fwd.destination_mapping.external_port}"
          f" gen={fwd.destination_mapping.generation}"
          f" -> 内网 {fwd.destination_mapping.internal.ip}:"
          f"{fwd.destination_mapping.internal.port}")
    assert (fwd.rewritten.src_ip, fwd.rewritten.src_port) == (PUB, 6202)
    assert (fwd.rewritten.dst_ip, fwd.rewritten.dst_port) == \
        (HOST.ip, HOST.port)
    assert fwd.source_mapping.generation == 3 and fwd.destination_mapping.generation == 1

    # 回程：HOST 回复看到的源 PUB:6202
    rev = hnat.translate_hairpin(
        Packet(src=HOST, dst=Endpoint(PUB, 6202), generation=3))
    print(f"  回程 {HOST.ip}:{HOST.port} -> {PUB}:6202:")
    show_five("折回五元组", rev.rewritten)
    print(f"    双方 generation: 源 gen={rev.source_mapping.generation},"
          f" 目的 gen={rev.destination_mapping.generation}")
    assert (rev.rewritten.src_ip, rev.rewritten.src_port) == (PUB, 6203)
    assert (rev.rewritten.dst_ip, rev.rewritten.dst_port) == \
        (PEER_B.ip, PEER_B.port)

    # 去程重放：源映射复用，不再扣容量
    again = hnat.translate_hairpin(
        Packet(src=PEER_B, dst=Endpoint(PUB, ma.external_port),
               generation=ma.generation))
    print(f"  去程重放: accepted={again.accepted}"
          f" source_created={again.source_created}"
          f" 占用端口数={hnat.stats()['ports_in_use']}")
    assert not again.source_created and hnat.stats()["ports_in_use"] == 4

    print("\n[4a] Hairpin 边界：目的映射刚到期 -> NO_MAPPING")
    hnat.advance(30)   # lifetime=30 到期（边界即死），6200/6202 进隔离
    dead = hnat.translate_hairpin(
        Packet(src=PEER_B, dst=Endpoint(PUB, 6200)))
    print(f"    accepted={dead.accepted} reason={dead.reason.value}"
          f" 隔离端口={sorted(hnat.quarantined_ports())}")
    assert not dead.accepted and dead.reason is DropReason.NO_MAPPING

    print("\n[4b] Hairpin 边界：源端口耗尽 -> 整体回滚，目的计时不变")
    enat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=(6200,), lifetime=30, quarantine=0))
    only = enat.allocate(HOST, WEB_A).mapping
    before = (only.last_seen, only.expires_at, enat.stats()["ports_in_use"])
    try:
        enat.translate_hairpin(
            Packet(src=PEER_B, dst=Endpoint(PUB, 6200)))
        raise AssertionError("应当抛出 PortExhaustionError")
    except PortExhaustionError as exc:
        print(f"    触发 {type(exc).__name__}: {exc}")
    after_map = enat.get_mapping(only.key)
    after = (after_map.last_seen, after_map.expires_at,
             enat.stats()["ports_in_use"])
    print(f"    回滚验证: 目的计时 {before[:2]} -> {after[:2]} 未变化，"
          f"占用端口数仍为 {after[2]}")
    assert before == after

    print("\n演示完成：正常路径、三类拒绝/异常边界与 hairpin 折返"
          "（含两方向五元组、双方 generation、到期与耗尽回滚）均按预期发生。")


if __name__ == "__main__":
    main()
