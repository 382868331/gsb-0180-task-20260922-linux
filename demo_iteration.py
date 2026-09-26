"""demo_iteration.py —— 分片入口演示（固定输入，真实计算，无 sleep，秒级完成）。

运行：python demo_iteration.py
内容：
  1. 正常路径：出站数据报乱序分片（非首片先到暂存），首片到达后按
     冻结的同一映射世代改写全部片段，并独立重组核对字节没有改动。
  2. 实际触发的边界：
     a. 重叠分片内容不一致 -> 整组拒绝（OVERLAP_CONFLICT）；
     b. 映射过期被复用后旧数据报的迟到片 -> 拒绝（STALE_GENERATION）。
"""

from __future__ import annotations

from adnat import (
    AddressDependentNAT,
    Direction,
    Endpoint,
    Fragment,
    FragmentStatus,
    NATConfig,
)

PUB = "203.0.113.7"
A_IP, A_PORT = "10.0.0.8", 40000
R_IP, R_PORT = "198.51.100.10", 53
KEY = (A_IP, A_PORT, R_IP, R_PORT)


def frag(payload, offset, mf, *, dg_id, src_port=0, dst_port=0):
    return Fragment(direction=Direction.OUTBOUND, src_ip=A_IP, dst_ip=R_IP,
                    protocol=17, datagram_id=dg_id, offset=offset,
                    more_fragments=mf, payload=payload,
                    src_port=src_port, dst_port=dst_port)


def chop(payload, size, *, dg_id):
    out = []
    for off in range(0, len(payload), size):
        out.append(frag(payload[off:off + size], off,
                        off + size < len(payload), dg_id=dg_id,
                        src_port=A_PORT if off == 0 else 0,
                        dst_port=R_PORT if off == 0 else 0))
    return out


def reassemble(rewritten):
    """独立重组：按 offset 铺回字节流（不依赖库内状态）。"""
    buf = bytearray()
    for rf in rewritten:
        end = rf.offset + len(rf.payload)
        if len(buf) < end:
            buf.extend(b"\x00" * (end - len(buf)))
        buf[rf.offset:end] = rf.payload
    return bytes(buf)


def main() -> None:
    nat = AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=(6100, 6101, 6102),
        lifetime=10, quarantine=5, fragment_timeout=30,
    ))
    print(f"NAT 公网IP={PUB} 端口池=(6100,6101,6102) "
          f"lifetime=10 quarantine=5 fragment_timeout=30")

    print("\n== 1. 正常路径：乱序分片 -> 冻结世代改写 -> 独立重组核对 ==")
    payload = bytes(range(1, 33))  # 32 字节原始载荷
    f0, f1, f2, f3 = chop(payload, 8, dg_id=7)
    r = nat.process_fragment(f2)
    print(f"  非首片 offset=16 先到: {r.status.value}（暂存，不猜连接）")
    r = nat.process_fragment(f3)
    print(f"  非首片 offset=24 先到: {r.status.value}")
    r = nat.process_fragment(f0)
    m = nat.get_mapping(KEY)
    print(f"  首片到达: {r.status.value}，连带吐出 "
          f"{[rf.offset for rf in r.rewritten]}，"
          f"外端口={m.external_port}，冻结世代={m.generation}")
    emitted = list(r.rewritten)
    r = nat.process_fragment(f1)
    emitted += r.rewritten
    print(f"  末片到达: {r.status.value}（关联释放，id 可复用）")
    merged = reassemble(emitted)
    assert merged == payload, "重组字节与原始载荷不一致"
    print(f"  独立重组 {len(merged)} 字节 == 原始载荷：True；"
          f"改写后五元组 src={PUB}:{m.external_port}")
    print(f"  暂存组数={len(nat.fragment_groups())}，"
          f"缓存字节={nat.stats()['fragment_cached_bytes']}")

    print("\n== 2a. 边界：重叠分片内容不一致 -> 整组拒绝 ==")
    nat.process_fragment(frag(b"abcdefgh", 0, True, dg_id=8,
                              src_port=A_PORT, dst_port=R_PORT))
    r = nat.process_fragment(frag(b"efXXXXXX", 4, False, dg_id=8))
    print(f"  重叠区 'efgh' vs 'efXX': {r.status.value} "
          f"reason={r.reason.value}，剩余暂存组={[g.key[4] for g in nat.fragment_groups()]}")

    print("\n== 2b. 边界：映射过期复用后旧数据报迟到片 -> 拒绝 ==")
    nat.process_fragment(frag(b"HEAD", 0, True, dg_id=9,
                              src_port=A_PORT, dst_port=R_PORT))
    old_gen = nat.get_mapping(KEY).generation
    nat.advance(10)  # 映射过期
    nat.advance(5)   # 过隔离期
    nat.process_fragment(frag(b"HEAD", 0, True, dg_id=10,
                              src_port=A_PORT, dst_port=R_PORT))
    new_gen = nat.get_mapping(KEY).generation
    print(f"  映射换代: generation {old_gen} -> {new_gen}")
    r = nat.process_fragment(frag(b"tail", 4, False, dg_id=9))
    print(f"  id=9 迟到片: {r.status.value} reason={r.reason.value}"
          f"（不跟随新映射，避免 ID 复用串包）")


if __name__ == "__main__":
    main()

