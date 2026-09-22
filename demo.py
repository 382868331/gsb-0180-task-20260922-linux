"""Fixed-input demo of the synthetic address-dependent NAT library.

Runs fully offline in well under 8 seconds. Prints one normal translated
result and one actually-triggered rejection (a late packet dropped by
generation mismatch), plus the two mapping behaviors of an
address-dependent NAT.
"""

from nat_sim import CapacityError, NatConfig, NatTable

PUB = "203.0.113.7"


def show(title):
    print(f"\n== {title} ==")


def main():
    table = NatTable(
        NatConfig(
            public_ip=PUB,
            port_pool=(40000, 40001, 40002),
            mapping_timeout=30,
            quarantine_time=10,
        )
    )

    show("Mapping behavior 1: same internal endpoint, two destinations "
         "-> two independent mappings")
    a = table.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
    b = table.outbound("10.0.0.5", 5000, "198.51.100.2", 443)
    print(f"10.0.0.5:5000 -> 198.51.100.1:80   rewritten {a.five_tuple}")
    print(f"10.0.0.5:5000 -> 198.51.100.2:443  rewritten {b.five_tuple}")
    print(f"distinct external ports: {a.ext_port} vs {b.ext_port}")

    show("Mapping behavior 2: identical 4-tuple reuses its mapping")
    again = table.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
    print(f"created={again.created}, ext_port={again.ext_port} "
          f"(unchanged), generation={again.generation}")

    show("Normal inbound translation (correct peer + generation)")
    r = table.inbound("198.51.100.1", 80, a.ext_port, a.generation)
    print(f"ok={r.ok}, rewritten {r.five_tuple}")

    show("Actually-triggered rejection: late packet, stale generation")
    # Let the first mapping expire and be re-created on the same port;
    # the port's generation bumps, so the old packet is late.
    table.advance(30)          # now=30: first mapping expires (alive while now<30)
    table.advance(10)          # now=40: quarantine Q=10 over, port reusable
    fresh = table.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
    print(f"re-created mapping: ext_port={fresh.ext_port}, "
          f"generation {a.generation} -> {fresh.generation}")
    late = table.inbound("198.51.100.1", 80, a.ext_port, a.generation)
    print(f"late packet with old generation {a.generation}: "
          f"ok={late.ok}, drop_reason={late.drop_reason.value}")

    show("Bonus boundary: atomic batch rollback on pool exhaustion")
    snap_before = table.snapshot()
    try:
        table.outbound_batch([
            ("10.0.0.7", 7000, "198.51.100.9", 9000),
            ("10.0.0.8", 7000, "198.51.100.9", 9000),
            ("10.0.0.9", 7000, "198.51.100.9", 9000),  # exceeds free pool
        ])
    except CapacityError as exc:
        print(f"CapacityError: {exc}")
    print(f"state unchanged after rollback: "
          f"{table.snapshot() == snap_before}")


if __name__ == "__main__":
    main()
