"""demo_iteration.py —— 差错报文反向定位入口的离线演示（本轮新增）。

运行：python demo_iteration.py
无 sleep、无预录输出、不发包；全部结果由 adnat 真实计算，秒级完成。

内容（与 tests/test_error_entry.py 的独立字典对照相互呼应）：
  1. 正常差错：按引用的原 UDP 五元组找回内部端点，输出外层目标、
     引用元组与映射 ID；
  2. 同端口不同远端：对端不匹配 -> PEER_MISMATCH；
  3. 过期复用：旧世代标记 -> STALE_GENERATION，新世代标记正常命中；
  4. 重复差错穿插正常回包：差错不延长寿命，回包才延长，状态不被污染。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    DropReason,
    Endpoint,
    ErrorPacket,
    NATConfig,
    Packet,
)

PUB = "203.0.113.7"
POOL = (6100, 6101, 6102)
HOST = Endpoint("10.0.0.8", 40000)
PEER_A = Endpoint("198.51.100.1", 443)
PEER_B = Endpoint("198.51.100.2", 443)


def error_for(peer: Endpoint, port: int, generation: int,
              *, outer_src: Endpoint | None = None,
              quoted_dst: Endpoint | None = None) -> ErrorPacket:
    public_ep = Endpoint(PUB, port)
    return ErrorPacket(
        outer_src=outer_src or peer,
        outer_dst=public_ep,
        quoted_src=public_ep,
        quoted_dst=quoted_dst or peer,
        generation=generation,
    )


def show(tag: str, res) -> None:
    if res.accepted:
        o, q = res.outer_target, res.quoted
        print(f"    {tag}: 接受 mapping_id={res.mapping_id}")
        print(f"      外层目标: ({o.protocol}, {o.src_ip}:{o.src_port}"
              f" -> {o.dst_ip}:{o.dst_port})")
        print(f"      引用元组: ({q.protocol}, {q.src_ip}:{q.src_port}"
              f" -> {q.dst_ip}:{q.dst_port})")
    else:
        print(f"    {tag}: 丢弃 reason={res.reason.value}")


def main() -> None:
    nat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=POOL,
        lifetime=10, quarantine=0,
    ))
    print(f"NAT 公网IP={PUB} 端口池={POOL} lifetime=10 quarantine=0")

    print("\n[1] 正常差错报文：引用原 UDP 五元组 -> 找回内部端点")
    ma = nat.allocate(HOST, PEER_A).mapping
    print(f"    映射: {HOST.ip}:{HOST.port} <-> {PEER_A.ip}:{PEER_A.port}"
          f" 外端口={ma.external_port} generation(mapping_id)={ma.generation}")
    ok = nat.translate_error(
        error_for(PEER_A, ma.external_port, ma.generation))
    show("差错", ok)
    assert ok.accepted
    assert ok.outer_target.dst_ip == HOST.ip
    assert ok.outer_target.dst_port == HOST.port
    assert ok.quoted.src_port == ma.external_port

    print("\n[2] 同端口不同远端：地址依赖对端不匹配 -> 丢弃")
    bad_peer = nat.translate_error(
        error_for(PEER_A, ma.external_port, ma.generation,
                  outer_src=PEER_B))
    show("外层源为其他远端", bad_peer)
    bad_quote = nat.translate_error(
        error_for(PEER_B, ma.external_port, 0, quoted_dst=PEER_B))
    show("引用远端为其他远端", bad_quote)
    assert bad_peer.reason is DropReason.PEER_MISMATCH
    assert bad_quote.reason is DropReason.PEER_MISMATCH

    print("\n[3] 过期 + 端口复用：世代标记排除旧引用")
    old_gen, port = ma.generation, ma.external_port
    nat.advance(10)  # 边界即死
    stale_dead = nat.translate_error(error_for(PEER_A, port, old_gen), at=10)
    show("过期后旧引用(带旧generation)", stale_dead)
    assert stale_dead.reason is DropReason.STALE_GENERATION
    no_gen = nat.translate_error(error_for(PEER_A, port, 0), at=10)
    show("过期后旧引用(无generation)", no_gen)
    assert no_gen.reason is DropReason.NO_MAPPING
    mb = nat.allocate(HOST, PEER_B, at=10).mapping
    print(f"    端口 {port} 被新映射复用: 新 mapping_id={mb.generation}")
    assert mb.external_port == port
    stale_reuse = nat.translate_error(
        error_for(PEER_A, port, old_gen), at=10)
    show("复用后旧世代引用", stale_reuse)
    fresh = nat.translate_error(
        error_for(PEER_B, port, mb.generation), at=10)
    show("复用后新世代引用", fresh)
    assert stale_reuse.reason is DropReason.STALE_GENERATION
    assert fresh.accepted and fresh.mapping_id == mb.generation

    print("\n[4] 重复差错穿插正常回包：差错不延寿，回包延寿，状态不污染")
    key = mb.key
    e1 = nat.translate_error(error_for(PEER_B, port, mb.generation), at=10)
    assert nat.get_mapping(key).expires_at == 20
    print(f"    差错后 expires_at={nat.get_mapping(key).expires_at}（不变）")
    nat.translate_inbound(
        Packet(src=PEER_B, dst=Endpoint(PUB, port),
               generation=mb.generation), at=10)
    assert nat.get_mapping(key).expires_at == 20  # now=10 + 10
    print(f"    正常回包后 expires_at={nat.get_mapping(key).expires_at}（已刷新）")
    e2 = nat.translate_error(error_for(PEER_B, port, mb.generation), at=10)
    print(f"    重复差错: accepted={e2.accepted} mapping_id={e2.mapping_id}"
          f" expires_at={nat.get_mapping(key).expires_at}（仍为20）")
    assert e1.mapping_id == e2.mapping_id
    assert nat.get_mapping(key).expires_at == 20
    nat.advance(10)
    gone = nat.translate_error(error_for(PEER_B, port, mb.generation), at=20)
    show("寿命边界再发旧引用", gone)
    assert gone.reason is DropReason.STALE_GENERATION

    print("\n演示完成：正常差错、对端不匹配、过期复用、重复/穿插行为均符合契约。")


if __name__ == "__main__":
    main()
