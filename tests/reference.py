"""Independent dict-based reference model for the NAT contract.

This module is written directly from the task contract and is used by the
differential test. It must NOT import or call ``nat_sim``; expected values
are computed here with plain dicts/lists only.
"""


class RefNat:
    """Plain-dict model of the address-dependent NAT contract."""

    def __init__(self, public_ip, pool, timeout, quarantine):
        self.public_ip = public_ip
        self.pool = sorted(pool)
        self.timeout = timeout
        self.quarantine = quarantine
        self.now = 0
        self.maps = {}          # key4 -> [ext_port, gen, expires_at]
        self.quar = {}          # ext_port -> free_at
        self.gen = {p: 0 for p in self.pool}

    def _free(self):
        used = {v[0] for v in self.maps.values()}
        return [p for p in self.pool
                if p not in used and p not in self.quar]

    def advance(self, dt):
        self.now += dt
        for key in [k for k, v in self.maps.items() if v[2] <= self.now]:
            port = self.maps.pop(key)[0]
            self.quar[port] = self.now + self.quarantine
        for port in [p for p, t in self.quar.items() if t <= self.now]:
            del self.quar[port]

    def outbound(self, ip, port, dip, dport):
        """Returns (ok, ext_port, gen, created)."""
        key = (ip, port, dip, dport)
        if key in self.maps:
            self.maps[key][2] = self.now + self.timeout
            v = self.maps[key]
            return (True, v[0], v[1], False)
        free = self._free()
        if not free:
            return (False, None, None, False)
        ext = free[0]
        self.gen[ext] += 1
        self.maps[key] = [ext, self.gen[ext], self.now + self.timeout]
        return (True, ext, self.gen[ext], True)

    def inbound(self, sip, sport, ext_port, gen):
        """Returns 'ok' or a drop-reason string."""
        target = None
        for key, v in self.maps.items():
            if v[0] == ext_port:
                target = (key, v)
                break
        if target is None:
            return "no_mapping"
        (ip, port, dip, dport), (ext, g, _exp) = target
        if (dip, dport) != (sip, sport):
            return "peer_mismatch"
        if gen != g:
            return "stale_generation"
        return "ok"
