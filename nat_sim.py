"""Synthetic UDP NAT state library: address-dependent endpoint lifecycle.

This module simulates the state table of an address-dependent NAT
(endpoint-dependent mapping AND endpoint-dependent filtering) for UDP.
It never sends or receives network packets; it only maintains state and
rewrites synthetic 5-tuples.

Contract summary (see README.md for the full contract):

* Outbound mapping key = (internal IP, internal port, destination IP,
  destination port). The public IP is fixed per table. The external port
  is the smallest currently-free port of a finite configured pool.
* Inbound packets are accepted only from the exact peer (IP, port) of an
  existing mapping (address-dependent filtering).
* Time is an explicit integer clock advanced via ``advance()``. A mapping
  created/refreshed at time ``t`` with timeout ``T`` is alive while
  ``now < t + T`` and expires when ``now >= t + T``.
* When a mapping expires, its external port is quarantined for Q time
  units; it becomes allocatable again when ``now >= quarantine_until``.
* Every allocation of an external port bumps that port's generation.
  Synthetic inbound packets carry a generation; a mismatch means the
  packet is late (belongs to a previous incarnation) and is dropped.
* ``outbound_batch`` is atomic: if the pool cannot satisfy every new
  mapping in the batch, a ``CapacityError`` is raised and no state
  changes.

Only standard-library modules are used.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

__all__ = [
    "PROTOCOL",
    "MIN_PORT",
    "MAX_PORT",
    "NatError",
    "ValidationError",
    "CapacityError",
    "DropReason",
    "FiveTuple",
    "OutboundResult",
    "InboundResult",
    "NatConfig",
    "NatTable",
]

PROTOCOL = "UDP"
MIN_PORT = 0
MAX_PORT = 65535


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class NatError(Exception):
    """Base class for all errors raised by this library."""


class ValidationError(NatError, ValueError):
    """An input violated the contract. The message names the parameter."""


class CapacityError(NatError):
    """A batch could not be satisfied from the port pool.

    Raised *before* any state change; the table is left untouched.
    """


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


class DropReason(Enum):
    """Why a packet was not translated."""

    NO_MAPPING = "no_mapping"  # no live mapping on that external port
    PEER_MISMATCH = "peer_mismatch"  # mapping exists but peer differs
    STALE_GENERATION = "stale_generation"  # late packet, old generation
    POOL_EXHAUSTED = "pool_exhausted"  # outbound: no free external port


@dataclass(frozen=True)
class FiveTuple:
    """A synthetic UDP 5-tuple."""

    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(frozen=True)
class OutboundResult:
    """Result of an outbound translation attempt."""

    ok: bool
    five_tuple: Optional[FiveTuple]  # rewritten tuple when ok
    reason: Optional[DropReason]  # set when not ok
    ext_port: Optional[int]  # external port of the mapping when ok
    generation: Optional[int]  # generation of the mapping when ok
    created: bool  # True if this call created the mapping


@dataclass(frozen=True)
class InboundResult:
    """Result of an inbound filtering/translation attempt."""

    ok: bool
    five_tuple: Optional[FiveTuple]  # rewritten tuple when ok
    drop_reason: Optional[DropReason]  # set when not ok


@dataclass(frozen=True)
class NatConfig:
    """Static configuration of a NAT table.

    ``port_pool`` is the finite set of usable external ports (a ``range``
    or any iterable of ints). ``mapping_timeout`` is the idle lifetime T
    in integer time units (>= 1). ``quarantine_time`` is Q (>= 0).
    """

    public_ip: str
    port_pool: tuple
    mapping_timeout: int
    quarantine_time: int


# ---------------------------------------------------------------------------
# Validation helpers (fail loudly, name the parameter, never silently fix)
# ---------------------------------------------------------------------------


def _require_int(name: str, value, *, minimum=None, maximum=None) -> int:
    if isinstance(value, bool):
        raise ValidationError(
            f"{name}: bool is not accepted as an integer (got {value!r})"
        )
    if isinstance(value, float):
        if math.isnan(value):
            raise ValidationError(f"{name}: NaN is not a valid integer")
        if math.isinf(value):
            raise ValidationError(f"{name}: Infinity is not a valid integer")
        raise ValidationError(
            f"{name}: expected int, got float {value!r}; "
            "non-integral types are rejected, not coerced"
        )
    if not isinstance(value, int):
        raise ValidationError(
            f"{name}: expected int, got {type(value).__name__} ({value!r})"
        )
    if minimum is not None and value < minimum:
        raise ValidationError(f"{name}: {value} < minimum {minimum}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{name}: {value} > maximum {maximum}")
    return value


def _require_ip(name: str, value) -> str:
    if not isinstance(value, str):
        raise ValidationError(
            f"{name}: expected str IP address, got "
            f"{type(value).__name__} ({value!r})"
        )
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"{name}: invalid IP address {value!r}") from exc
    return value


def _require_port(name: str, value) -> int:
    return _require_int(name, value, minimum=MIN_PORT, maximum=MAX_PORT)


# ---------------------------------------------------------------------------
# Internal mapping record
# ---------------------------------------------------------------------------


@dataclass
class _Mapping:
    int_ip: str
    int_port: int
    dst_ip: str
    dst_port: int
    ext_port: int
    generation: int
    expires_at: int  # alive while now < expires_at


# ---------------------------------------------------------------------------
# The NAT table
# ---------------------------------------------------------------------------


class NatTable:
    """Address-dependent synthetic UDP NAT state table."""

    def __init__(self, config: NatConfig):
        if not isinstance(config, NatConfig):
            raise ValidationError(
                f"config: expected NatConfig, got {type(config).__name__}"
            )
        public_ip = _require_ip("config.public_ip", config.public_ip)

        if isinstance(config.port_pool, (str, bytes)):
            raise ValidationError("config.port_pool: must be an iterable of int ports")
        try:
            pool = list(config.port_pool)
        except TypeError as exc:
            raise ValidationError(
                "config.port_pool: must be an iterable of int ports"
            ) from exc
        if not pool:
            raise ValidationError("config.port_pool: pool must not be empty")
        checked = []
        for i, p in enumerate(pool):
            checked.append(_require_port(f"config.port_pool[{i}]", p))
        if len(set(checked)) != len(checked):
            raise ValidationError(
                f"config.port_pool: duplicate ports are rejected: {sorted(checked)}"
            )
        pool = sorted(checked)

        timeout = _require_int(
            "config.mapping_timeout", config.mapping_timeout, minimum=1
        )
        quarantine = _require_int(
            "config.quarantine_time", config.quarantine_time, minimum=0
        )

        self._public_ip = public_ip
        self._pool = tuple(pool)
        self._timeout = timeout
        self._quarantine = quarantine

        self._now = 0
        # key -> _Mapping, key = (int_ip, int_port, dst_ip, dst_port)
        self._mappings: dict = {}
        # ext_port -> _Mapping (reverse index, kept in sync with _mappings)
        self._by_ext_port: dict = {}
        # ext_port -> time at which the port leaves quarantine
        self._quarantined_until: dict = {}
        # ext_port -> monotonically increasing generation counter
        self._port_generation = {p: 0 for p in self._pool}

    # -- introspection -----------------------------------------------------

    @property
    def now(self) -> int:
        """Current integer clock value."""
        return self._now

    @property
    def public_ip(self) -> str:
        return self._public_ip

    def snapshot(self) -> dict:
        """Read-only structural view for tests and diagnostics."""
        return {
            "now": self._now,
            "mappings": {
                key: {
                    "ext_port": m.ext_port,
                    "generation": m.generation,
                    "expires_at": m.expires_at,
                }
                for key, m in sorted(self._mappings.items())
            },
            "free_ports": tuple(self._free_ports()),
            "quarantined": dict(sorted(self._quarantined_until.items())),
        }

    # -- time --------------------------------------------------------------

    def advance(self, seconds: int) -> None:
        """Advance the clock by a non-negative integer amount.

        Expires mappings whose ``expires_at <= now`` (their ports enter
        quarantine until ``now + Q``) and releases ports whose quarantine
        ended at or before ``now``.
        """
        seconds = _require_int("seconds", seconds, minimum=0)
        self._now += seconds

        expired = [k for k, m in self._mappings.items() if m.expires_at <= self._now]
        for key in expired:
            m = self._mappings.pop(key)
            del self._by_ext_port[m.ext_port]
            self._quarantined_until[m.ext_port] = self._now + self._quarantine

        for port in [p for p, until in self._quarantined_until.items()
                     if until <= self._now]:
            del self._quarantined_until[port]

    # -- outbound ------------------------------------------------------------

    def outbound(
        self, int_ip: str, int_port: int, dst_ip: str, dst_port: int
    ) -> OutboundResult:
        """Translate one outbound synthetic packet.

        Reuses the existing mapping for the 4-tuple key (refreshing its
        expiry) or creates a new one with the smallest free external port.
        Never raises for pool exhaustion; returns ``ok=False`` with
        ``reason=POOL_EXHAUSTED`` instead.
        """
        key = self._validate_packet(int_ip, int_port, dst_ip, dst_port)

        mapping = self._mappings.get(key)
        if mapping is not None:
            mapping.expires_at = self._now + self._timeout
            return OutboundResult(
                ok=True,
                five_tuple=self._rewritten_out(mapping, dst_ip, dst_port),
                reason=None,
                ext_port=mapping.ext_port,
                generation=mapping.generation,
                created=False,
            )

        free = self._free_ports()
        if not free:
            return OutboundResult(
                ok=False,
                five_tuple=None,
                reason=DropReason.POOL_EXHAUSTED,
                ext_port=None,
                generation=None,
                created=False,
            )

        ext_port = free[0]
        self._port_generation[ext_port] += 1
        mapping = _Mapping(
            int_ip=key[0],
            int_port=key[1],
            dst_ip=key[2],
            dst_port=key[3],
            ext_port=ext_port,
            generation=self._port_generation[ext_port],
            expires_at=self._now + self._timeout,
        )
        self._mappings[key] = mapping
        self._by_ext_port[ext_port] = mapping
        return OutboundResult(
            ok=True,
            five_tuple=self._rewritten_out(mapping, dst_ip, dst_port),
            reason=None,
            ext_port=ext_port,
            generation=mapping.generation,
            created=True,
        )

    def outbound_batch(self, packets: Sequence[tuple]) -> list:
        """Atomically translate a batch of outbound packets.

        Every element must be ``(int_ip, int_port, dst_ip, dst_port)``.
        All inputs are validated first; then the number of *new* mappings
        is checked against the number of free ports. If capacity is
        insufficient, ``CapacityError`` is raised and the table is left
        completely unchanged (full rollback by construction: nothing was
        applied yet).
        """
        if isinstance(packets, (str, bytes)) or not hasattr(packets, "__iter__"):
            raise ValidationError(
                f"packets: expected an iterable of 4-tuples, got "
                f"{type(packets).__name__}"
            )
        keys = []
        for i, pkt in enumerate(packets):
            try:
                a, b, c, d = pkt
            except (TypeError, ValueError) as exc:
                raise ValidationError(
                    f"packets[{i}]: expected a 4-tuple "
                    f"(int_ip, int_port, dst_ip, dst_port), got {pkt!r}"
                ) from exc
            keys.append(
                self._validate_packet(a, b, c, d, prefix=f"packets[{i}]")
            )

        planned = set()
        needed = 0
        for key in keys:
            if key not in self._mappings and key not in planned:
                planned.add(key)
                needed += 1
        free_count = len(self._free_ports())
        if needed > free_count:
            raise CapacityError(
                f"outbound_batch: need {needed} new external port(s) but "
                f"only {free_count} free; batch rejected, state unchanged"
            )

        return [self.outbound(*key) for key in keys]

    # -- inbound -------------------------------------------------------------

    def inbound(
        self, src_ip: str, src_port: int, ext_port: int, generation: int
    ) -> InboundResult:
        """Filter and translate one inbound synthetic packet.

        The packet arrives from ``(src_ip, src_port)`` addressed to the
        table's external port ``ext_port`` and carries the ``generation``
        the sender learned when the mapping was created. Checks, in order:

        1. a live mapping exists on ``ext_port`` (else NO_MAPPING);
        2. the mapping's peer equals ``(src_ip, src_port)`` (else
           PEER_MISMATCH — address-dependent filtering);
        3. ``generation`` equals the mapping's generation (else
           STALE_GENERATION — a late packet from a previous incarnation).
        """
        src_ip = _require_ip("src_ip", src_ip)
        src_port = _require_port("src_port", src_port)
        ext_port = _require_port("ext_port", ext_port)
        generation = _require_int("generation", generation, minimum=0)

        mapping = self._by_ext_port.get(ext_port)
        if mapping is None:
            return InboundResult(ok=False, five_tuple=None,
                                 drop_reason=DropReason.NO_MAPPING)
        if (mapping.dst_ip, mapping.dst_port) != (src_ip, src_port):
            return InboundResult(ok=False, five_tuple=None,
                                 drop_reason=DropReason.PEER_MISMATCH)
        if generation != mapping.generation:
            return InboundResult(ok=False, five_tuple=None,
                                 drop_reason=DropReason.STALE_GENERATION)
        return InboundResult(
            ok=True,
            five_tuple=FiveTuple(
                protocol=PROTOCOL,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=mapping.int_ip,
                dst_port=mapping.int_port,
            ),
            drop_reason=None,
        )

    # -- internals -----------------------------------------------------------

    def _free_ports(self) -> list:
        used = set(self._by_ext_port)
        quarantined = set(self._quarantined_until)
        return [p for p in self._pool
                if p not in used and p not in quarantined]

    def _rewritten_out(self, mapping: _Mapping, dst_ip: str,
                       dst_port: int) -> FiveTuple:
        return FiveTuple(
            protocol=PROTOCOL,
            src_ip=self._public_ip,
            src_port=mapping.ext_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )

    @staticmethod
    def _validate_packet(int_ip, int_port, dst_ip, dst_port, prefix=""):
        p = f"{prefix}." if prefix else ""
        int_ip = _require_ip(f"{p}int_ip", int_ip)
        int_port = _require_port(f"{p}int_port", int_port)
        dst_ip = _require_ip(f"{p}dst_ip", dst_ip)
        dst_port = _require_port(f"{p}dst_port", dst_port)
        return (int_ip, int_port, dst_ip, dst_port)
