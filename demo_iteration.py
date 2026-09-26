"""demo_iteration.py —— 分片重组迭代的离线演示（固定输入，真实计算，无 sleep）。

运行：python demo_iteration.py
内容：
  1. 正常路径：出站数据报分片乱序到达（非首片先暂存），首片到达后
     建立映射并冻结世代，全部片按同一映射改写；独立重组核对载荷字节。
  2. 实际触发的边界：
     a. 重叠片字节冲突 -> 整组拒绝并释放；
     b. 首片永不到 -> 暂存片逻辑超时释放，同 ID 干净复用；
     c. 映射过期且端口被复用后旧数据报迟到片 -> STALE_GENERATION 拒绝。
"""

from __future__ import annotations

import time

from adnat import (
    AddressDependentNAT,
    Direction,
    DropReason,
    Fragment,
    FragmentationConfig,
    NATConfig,
)

PUB = "203.0.113.7"
HOST = ("10.0.0.8", 40000)
SERVER = ("198.51.100.10", 443)


def frag(did, offset, payload, mf, ports=None):
    src_port = dst_port = None
    if ports is not None:
        src_port, dst_port = ports
    return Fragment(direction=Direction.OUTBOUND, src_ip=HOST[0],
                    dst_ip=SERVER[0], protocol=17, datagram_id=did,
                    offset=offset, more_fragments=mf, payload=payload,
                    src_port=src_port, dst_port=dst_port)


def reassemble(fragments):
    """独立重组：按偏移写入缓冲区，核对载荷字节未被改写。"""
    buf = bytearray()
    for f in fragments:
        end = f.offset + len(f.payload)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[f.offset:end] = f.payload
    return bytes(buf)


def main() -> None:
    started = time.monotonic()
    nat = AddressDependentNAT(
        NATConfig(public_ip=PUB, external_ports=(6100, 6101),
                  lifetime=100, quarantine=10),
        FragmentationConfig(max_datagram_size=65535, max_fragments=64,
                            max_cached_bytes=1 << 18, fragment_timeout=30),
    )
    print(f"NAT 公网IP={PUB} lifetime=100 quarantine=10 fragment_timeout=30")

    print("\n[1] 正常路径：分片乱序到达，首片最后到")
    payload = bytes(range(256)) * 2                     # 512 字节
    pieces = [(off, payload[off:off + 64], off + 64 < len(payload))
              for off in range(0, len(payload), 64)]
    did = 9001
    for off, chunk, mf in pieces[:0:-1]:                # 非首片逆序先投
        r = nat.process_fragment(frag(did, off, chunk, mf))
        assert r.accepted and not r.complete
    print(f"    暂存 {len(pieces) - 1} 片（无端口，未建映射）: "
          f"{nat.fragment_stats()}")
    off, chunk, mf = pieces[0]
    final = nat.process_fragment(frag(did, off, chunk, mf,
                                      ports=(HOST[1], SERVER[1])))
    ext = final.mapping.external_port
    print(f"    首片到达 -> 建映射 gen={final.mapping.generation} "
          f"外端口={ext}，整组 {len(final.rewritten)} 片完成改写")
    print(f"    首片改写: {HOST[0]}:{HOST[1]} -> {PUB}:{ext}")
    restored = reassemble(final.rewritten)
    print(f"    独立重组 {len(restored)} 字节，与原始载荷一致: "
          f"{restored == payload}")
    assert restored == payload
    assert nat.fragment_stats()["fragment_groups"] == 0

    print("\n[2a] 边界：重叠片字节冲突 -> 整组拒绝并释放")
    nat.process_fragment(frag(9002, 0, b"AAAAAAAA" * 2, True,
                              ports=(HOST[1], SERVER[1])))
    nat.process_fragment(frag(9002, 24, b"BBBBBBBB", False))
    r = nat.process_fragment(frag(9002, 8, b"ZZZZZZZZ", True))
    print(f"    冲突片 accepted={r.accepted} reason={r.reason.value}")
    assert r.reason is DropReason.FRAGMENT_OVERLAP_CONFLICT
    assert nat.fragment_stats()["fragment_groups"] == 0
    print("    关联已释放，同 ID 复用不串包")

    print("\n[2b] 边界：首片永不到 -> 暂存片逻辑超时释放")
    nat.process_fragment(frag(9003, 64, b"x" * 64, True))
    print(f"    暂存中: {nat.fragment_stats()} (不凭 ID 猜连接，未建映射)")
    nat.advance(30)
    print(f"    advance(30) 后: {nat.fragment_stats()}")
    assert nat.fragment_stats()["fragment_groups"] == 0

    print("\n[2c] 边界：映射过期、端口被复用后旧数据报迟到片 -> 拒绝")
    nat2 = AddressDependentNAT(
        NATConfig(public_ip=PUB, external_ports=(6100,), lifetime=100,
                  quarantine=10),
        FragmentationConfig(fragment_timeout=1000),
    )
    nat2.process_fragment(frag(9004, 0, b"HEAD0000", True,
                               ports=(HOST[1], SERVER[1])))
    nat2.advance(100)                                   # 映射过期，端口进隔离
    nat2.advance(10)                                    # 隔离 Q=10 结束
    from adnat import AllocationRequest, Endpoint
    m2 = nat2.allocate_many([AllocationRequest(
        Endpoint("10.0.0.9", 5000), Endpoint(*SERVER))])[0].mapping
    print(f"    端口 6100 被新连接复用 gen={m2.generation}")
    r = nat2.process_fragment(frag(9004, 8, b"TAIL0000", False))
    print(f"    旧数据报迟到片 accepted={r.accepted} reason={r.reason.value}")
    assert r.reason is DropReason.STALE_GENERATION

    elapsed = time.monotonic() - started
    print(f"\n演示完成：正常路径与三类边界均按预期发生（耗时 {elapsed:.3f}s）。")
    assert elapsed < 90


if __name__ == "__main__":
    main()
