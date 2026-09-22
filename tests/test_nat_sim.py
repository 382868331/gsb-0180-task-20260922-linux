"""Unit and differential tests for nat_sim (stdlib unittest only)."""

import random
import unittest

from nat_sim import (
    CapacityError,
    DropReason,
    NatConfig,
    NatTable,
    ValidationError,
)
from reference import RefNat

PUB = "203.0.113.7"
POOL = (40000, 40001, 40002)


def make_table(pool=POOL, timeout=30, quarantine=10):
    return NatTable(
        NatConfig(
            public_ip=PUB,
            port_pool=pool,
            mapping_timeout=timeout,
            quarantine_time=quarantine,
        )
    )


class TestMappingSemantics(unittest.TestCase):
    def test_same_internal_endpoint_different_destinations(self):
        """Address-dependent mapping: one internal endpoint, two peers ->
        two independent mappings with distinct external ports."""
        t = make_table()
        a = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        b = t.outbound("10.0.0.5", 5000, "198.51.100.2", 443)
        self.assertTrue(a.ok and b.ok)
        self.assertTrue(a.created and b.created)
        self.assertNotEqual(a.ext_port, b.ext_port)
        self.assertEqual(a.ext_port, 40000)  # smallest free first
        self.assertEqual(b.ext_port, 40001)
        self.assertEqual(a.five_tuple.src_ip, PUB)
        self.assertEqual(a.five_tuple.src_port, 40000)
        self.assertEqual(a.five_tuple.dst_ip, "198.51.100.1")
        self.assertEqual(a.five_tuple.dst_port, 80)
        self.assertEqual(a.five_tuple.protocol, "UDP")

    def test_same_key_reuses_mapping_and_refreshes_expiry(self):
        t = make_table(timeout=30)
        a = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        t.advance(25)
        b = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        self.assertFalse(b.created)
        self.assertEqual(a.ext_port, b.ext_port)
        # refreshed at t=25 -> alive until t=55; still alive at 54
        t.advance(29)
        c = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        self.assertFalse(c.created)

    def test_inbound_rewritten_tuple(self):
        t = make_table()
        out = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        r = t.inbound("198.51.100.1", 80, out.ext_port, out.generation)
        self.assertTrue(r.ok)
        self.assertEqual(r.five_tuple.dst_ip, "10.0.0.5")
        self.assertEqual(r.five_tuple.dst_port, 5000)
        self.assertEqual(r.five_tuple.src_ip, "198.51.100.1")
        self.assertEqual(r.five_tuple.src_port, 80)


class TestTimeoutAndQuarantine(unittest.TestCase):
    def test_timeout_boundary(self):
        """Alive while now < created+T; expired when now >= created+T."""
        t = make_table(timeout=30, quarantine=0)
        out = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        t.advance(29)  # now=29 < 30: still alive
        r = t.inbound("198.51.100.1", 80, out.ext_port, out.generation)
        self.assertTrue(r.ok)
        t.advance(1)  # now=30 >= 30: expired
        r = t.inbound("198.51.100.1", 80, out.ext_port, out.generation)
        self.assertFalse(r.ok)
        self.assertEqual(r.drop_reason, DropReason.NO_MAPPING)

    def test_quarantine_blocks_reuse_until_q_elapses(self):
        t = make_table(pool=(40000,), timeout=10, quarantine=7)
        t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        t.advance(10)  # expired at now=10, quarantined until 17
        r = t.outbound("10.0.0.6", 5000, "198.51.100.1", 80)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, DropReason.POOL_EXHAUSTED)
        t.advance(6)  # now=16 < 17: still quarantined
        self.assertFalse(t.outbound("10.0.0.6", 5000, "198.51.100.1", 80).ok)
        t.advance(1)  # now=17: released
        r = t.outbound("10.0.0.6", 5000, "198.51.100.1", 80)
        self.assertTrue(r.ok)
        self.assertEqual(r.ext_port, 40000)

    def test_smallest_free_port_is_chosen(self):
        t = make_table(timeout=10, quarantine=0)
        t.outbound("10.0.0.1", 1, "198.51.100.1", 80)  # 40000
        t.outbound("10.0.0.2", 1, "198.51.100.1", 80)  # 40001
        t.advance(10)  # both expire, both released (Q=0)
        r = t.outbound("10.0.0.3", 1, "198.51.100.1", 80)
        self.assertEqual(r.ext_port, 40000)


class TestExhaustionAndBatchRollback(unittest.TestCase):
    def test_single_outbound_pool_exhausted(self):
        t = make_table(pool=(40000,))
        self.assertTrue(t.outbound("10.0.0.1", 1, "198.51.100.1", 80).ok)
        r = t.outbound("10.0.0.2", 1, "198.51.100.1", 80)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, DropReason.POOL_EXHAUSTED)

    def test_batch_rolls_back_atomically(self):
        t = make_table(pool=(40000, 40001))
        before = t.snapshot()
        batch = [
            ("10.0.0.1", 1, "198.51.100.1", 80),
            ("10.0.0.2", 1, "198.51.100.1", 80),
            ("10.0.0.3", 1, "198.51.100.1", 80),  # needs a 3rd port
        ]
        with self.assertRaises(CapacityError):
            t.outbound_batch(batch)
        self.assertEqual(t.snapshot(), before)  # no partial change

    def test_batch_success_and_duplicates_within_batch(self):
        t = make_table(pool=(40000, 40001))
        results = t.outbound_batch([
            ("10.0.0.1", 1, "198.51.100.1", 80),
            ("10.0.0.1", 1, "198.51.100.1", 80),  # same key: one new mapping
            ("10.0.0.2", 1, "198.51.100.1", 80),
        ])
        self.assertEqual([r.ok for r in results], [True, True, True])
        self.assertEqual(results[0].ext_port, results[1].ext_port)
        self.assertNotEqual(results[0].ext_port, results[2].ext_port)

    def test_batch_existing_mappings_do_not_consume_capacity(self):
        t = make_table(pool=(40000,))
        t.outbound("10.0.0.1", 1, "198.51.100.1", 80)  # pool now full
        # batch only touches the existing mapping -> fits
        results = t.outbound_batch([("10.0.0.1", 1, "198.51.100.1", 80)])
        self.assertTrue(results[0].ok)


class TestGenerationAndFiltering(unittest.TestCase):
    def test_late_packet_rejected_by_generation(self):
        t = make_table(pool=(40000,), timeout=10, quarantine=0)
        first = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        t.advance(10)  # expires; port free again immediately (Q=0)
        second = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        self.assertEqual(first.ext_port, second.ext_port)
        self.assertNotEqual(first.generation, second.generation)
        # late packet from the previous incarnation
        late = t.inbound("198.51.100.1", 80, first.ext_port, first.generation)
        self.assertFalse(late.ok)
        self.assertEqual(late.drop_reason, DropReason.STALE_GENERATION)
        # current generation still passes
        ok = t.inbound("198.51.100.1", 80, second.ext_port, second.generation)
        self.assertTrue(ok.ok)

    def test_peer_mismatch_is_filtered(self):
        t = make_table()
        out = t.outbound("10.0.0.5", 5000, "198.51.100.1", 80)
        # different peer IP
        r = t.inbound("198.51.100.9", 80, out.ext_port, out.generation)
        self.assertEqual(r.drop_reason, DropReason.PEER_MISMATCH)
        # same IP, different port
        r = t.inbound("198.51.100.1", 81, out.ext_port, out.generation)
        self.assertEqual(r.drop_reason, DropReason.PEER_MISMATCH)

    def test_no_mapping_drop(self):
        t = make_table()
        r = t.inbound("198.51.100.1", 80, 40000, 1)
        self.assertEqual(r.drop_reason, DropReason.NO_MAPPING)


class TestValidation(unittest.TestCase):
    def test_bool_rejected_for_int_params(self):
        t = make_table()
        with self.assertRaises(ValidationError):
            t.advance(True)
        with self.assertRaises(ValidationError):
            t.outbound("10.0.0.1", True, "198.51.100.1", 80)
        with self.assertRaises(ValidationError):
            t.inbound("198.51.100.1", 80, 40000, False)

    def test_nan_and_infinity_rejected(self):
        t = make_table()
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValidationError):
                t.advance(bad)
            with self.assertRaises(ValidationError):
                t.outbound("10.0.0.1", bad, "198.51.100.1", 80)

    def test_float_not_silently_coerced(self):
        t = make_table()
        with self.assertRaises(ValidationError):
            t.advance(1.0)

    def test_negative_time_rejected(self):
        t = make_table()
        with self.assertRaises(ValidationError):
            t.advance(-1)

    def test_bad_ip_and_port_rejected(self):
        t = make_table()
        with self.assertRaises(ValidationError):
            t.outbound("not-an-ip", 1, "198.51.100.1", 80)
        with self.assertRaises(ValidationError):
            t.outbound("10.0.0.1", 70000, "198.51.100.1", 80)
        with self.assertRaises(ValidationError):
            t.outbound("10.0.0.1", -1, "198.51.100.1", 80)

    def test_config_validation(self):
        with self.assertRaises(ValidationError):  # empty pool
            make_table(pool=())
        with self.assertRaises(ValidationError):  # duplicate ports
            make_table(pool=(40000, 40000))
        with self.assertRaises(ValidationError):  # timeout must be >= 1
            make_table(timeout=0)
        with self.assertRaises(ValidationError):  # quarantine must be >= 0
            make_table(quarantine=-1)
        with self.assertRaises(ValidationError):  # pool port out of range
            make_table(pool=(65536,))

    def test_error_message_names_parameter(self):
        t = make_table()
        try:
            t.advance(True)
        except ValidationError as exc:
            self.assertIn("seconds", str(exc))
        else:
            self.fail("expected ValidationError")

    def test_batch_validation_failure_leaves_state_unchanged(self):
        t = make_table()
        before = t.snapshot()
        with self.assertRaises(ValidationError):
            t.outbound_batch([
                ("10.0.0.1", 1, "198.51.100.1", 80),
                ("10.0.0.2", "oops", "198.51.100.1", 80),
            ])
        self.assertEqual(t.snapshot(), before)


class TestDifferentialAgainstReference(unittest.TestCase):
    """Deterministic random operation sequence; the dict-based reference
    (tests/reference.py, no import of nat_sim) computes expectations."""

    def test_random_sequence_matches_reference(self):
        rng = random.Random(20260922)
        pool = (40000, 40001, 40002)
        timeout, quarantine = 12, 5
        table = make_table(pool=pool, timeout=timeout, quarantine=quarantine)
        ref = RefNat(PUB, pool, timeout, quarantine)

        hosts = [f"10.0.0.{i}" for i in range(1, 5)]
        peers = [f"198.51.100.{i}" for i in range(1, 5)]

        for step in range(600):
            op = rng.randrange(3)
            if op == 0:
                dt = rng.randrange(0, 9)
                table.advance(dt)
                ref.advance(dt)
            elif op == 1:
                pkt = (rng.choice(hosts), rng.randrange(1, 6),
                       rng.choice(peers), rng.randrange(1, 6))
                got = table.outbound(*pkt)
                want = ref.outbound(*pkt)
                self.assertEqual(
                    (got.ok, got.ext_port, got.generation, got.created),
                    want,
                    f"step {step} outbound {pkt}",
                )
                if not got.ok:
                    self.assertEqual(got.reason, DropReason.POOL_EXHAUSTED)
            else:
                ext = rng.choice(pool)
                gen = rng.randrange(0, 4)
                pkt = (rng.choice(peers), rng.randrange(1, 6))
                got = table.inbound(pkt[0], pkt[1], ext, gen)
                want = ref.inbound(pkt[0], pkt[1], ext, gen)
                got_s = "ok" if got.ok else got.drop_reason.value
                self.assertEqual(got_s, want, f"step {step} inbound")

        # final structural agreement
        snap = table.snapshot()
        self.assertEqual(snap["now"], ref.now)
        self.assertEqual(set(snap["free_ports"]), set(ref._free()))
        self.assertEqual(snap["quarantined"], ref.quar)
        self.assertEqual(
            {k: (v["ext_port"], v["generation"], v["expires_at"])
             for k, v in snap["mappings"].items()},
            {k: (v[0], v[1], v[2]) for k, v in ref.maps.items()},
        )


if __name__ == "__main__":
    unittest.main()
