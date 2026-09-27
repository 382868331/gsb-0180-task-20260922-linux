"""地址依赖 NAT 核心：合成 UDP 状态库，不发任何网络包。

时间模型
--------
显式整数时钟：``advance(seconds)`` 推进虚拟时间；每次公开调用先按当前
时钟做 housekeeping（过期映射回收、隔离端口到期释放），再处理本次请求。
映射在 ``now >= expires_at`` 时过期（边界即死）；隔离端口在
``now >= released_at + quarantine`` 时可复用。

原子性
------
``allocate_many`` 先完成全部校验与容量规划（纯函数，不改状态），
全部可满足才一次性提交；容量不足抛 PortExhaustionError（全池扫描，
证明无解）或 SearchBudgetExhaustedError（预算耗尽，未证明无解），
此时 NAT 状态与调用前完全一致——不存在部分分配。
"""

from __future__ import annotations

from dataclasses import dataclass

from ._validate import check_int
from .errors import (
    PortExhaustionError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    DropReason,
    Endpoint,
    Mapping,
    NATConfig,
    Packet,
    TranslationResult,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]


@dataclass(slots=True)
class _Record:
    """内部可变映射记录；对外只暴露不可变 Mapping 快照。"""

    internal: Endpoint
    remote: Endpoint
    external_port: int
    generation: int
    created_at: int
    last_seen: int
    expires_at: int

    def snapshot(self, key: Key) -> Mapping:
        return Mapping(
            key=key,
            internal=self.internal,
            remote=self.remote,
            external_port=self.external_port,
            generation=self.generation,
            created_at=self.created_at,
            last_seen=self.last_seen,
            expires_at=self.expires_at,
        )


class AddressDependentNAT:
    """地址依赖（address-dependent）映射与过滤的 UDP NAT 模拟器。

    - 出站 key = (内网IP, 内网端口, 目的IP, 目的端口)；同一内网端点访问
      不同目的会产生不同映射、不同外端口。
    - 公网 IP 固定；外端口从有限池选最小空闲者。
    - 入站只接受来自映射所记录对端的包（地址依赖过滤）。
    - 每条映射携带单调递增的 generation；包携带的 generation 不一致
      （且非 0）即判为迟到包并丢弃。
    """

    def __init__(self, config: NATConfig) -> None:
        if not isinstance(config, NATConfig):
            raise ValidationError(
                f"config must be NATConfig, got {type(config).__name__}"
            )
        self._config = config
        self._now = 0
        self._mappings: dict[Key, _Record] = {}
        self._port_to_key: dict[int, Key] = {}
        # 隔离中的端口：port -> 释放时刻（进入隔离的时刻）。
        self._quarantine: dict[int, int] = {}
        self._next_generation = 1

    # ------------------------------------------------------------------ #
    # 只读属性                                                            #
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> NATConfig:
        return self._config

    @property
    def now(self) -> int:
        """当前虚拟时钟（整数时间单位）。"""
        return self._now

    # ------------------------------------------------------------------ #
    # 内部：时钟与 housekeeping                                           #
    # ------------------------------------------------------------------ #

    def _check_clock(self, now: int) -> None:
        if now < self._now:
            raise ValidationError(
                f"clock cannot move backwards: now={now} < current={self._now}"
            )

    def _expired_keys_at(self, now: int) -> list[Key]:
        """纯函数：在时刻 now 会过期的 key 列表（不修改状态）。"""
        return [k for k, r in self._mappings.items() if now >= r.expires_at]

    def _housekeeping(self, now: int) -> list[Key]:
        """提交时刻 now 的过期回收与隔离到期释放，返回本次过期的 key（升序）。"""
        expired = sorted(self._expired_keys_at(now))
        for key in expired:
            rec = self._mappings.pop(key)
            del self._port_to_key[rec.external_port]
            self._quarantine[rec.external_port] = now
        q_done = [p for p, t in self._quarantine.items()
                  if now >= t + self._config.quarantine]
        for p in q_done:
            del self._quarantine[p]
        self._now = now
        return expired

    def _plan_ports(self, count: int, now: int) -> list[int]:
        """纯函数：为 count 个新映射规划最小空闲端口（不修改状态）。

        按端口升序检查，最多检查 search_budget 个：
        - 找齐 -> 返回端口列表；
        - 检查满 budget 仍未齐 -> SearchBudgetExhaustedError（未证明无解）；
        - 全池查完仍不够 -> PortExhaustionError（证明无解）。
        """
        expired = set(self._expired_keys_at(now))
        used = {
            rec.external_port
            for key, rec in self._mappings.items()
            if key not in expired
        }
        quarantined = {
            p for p, t in self._quarantine.items()
            if now < t + self._config.quarantine
        }
        chosen: list[int] = []
        inspected = 0
        budget = self._config.search_budget
        assert budget is not None  # NATConfig 保证非 None
        for port in self._config.external_ports:
            if len(chosen) == count:
                break
            if inspected >= budget:
                raise SearchBudgetExhaustedError(
                    budget=budget, inspected=inspected,
                    needed=count, found=len(chosen),
                )
            inspected += 1
            if port in used or port in quarantined:
                continue
            chosen.append(port)
        if len(chosen) < count:
            raise PortExhaustionError(
                needed=count, available=len(chosen),
                pool_size=len(self._config.external_ports),
            )
        return chosen

    def _check_expiry_overflow(self, now: int) -> None:
        if now > MAX_TIME - self._config.lifetime:
            raise ValidationError(
                f"now={now} + lifetime={self._config.lifetime} exceeds "
                f"MAX_TIME={MAX_TIME}"
            )

    # ------------------------------------------------------------------ #
    # 出站分配                                                            #
    # ------------------------------------------------------------------ #

    def allocate(self, internal: Endpoint, remote: Endpoint,
                 *, at: int | None = None) -> AllocationResult:
        """分配（或复用）单条出站映射。批量语义见 allocate_many。"""
        return self.allocate_many([AllocationRequest(internal, remote)], at=at)[0]

    def allocate_many(self, requests, *, at: int | None = None
                      ) -> list[AllocationResult]:
        """批量出站分配：要么全部成功，要么整体回滚（状态不变）。

        已存在活跃映射的 key 直接复用（不占新端口）；同批重复 key 属于
        非法输入，抛 ValidationError。
        """
        now = self._resolve_at(at)
        # ---- 阶段 1：全部输入校验（任何状态变更之前） ----
        if isinstance(requests, (str, bytes)) or not hasattr(requests, "__iter__"):
            raise ValidationError(
                f"requests must be an iterable of AllocationRequest, "
                f"got {type(requests).__name__}"
            )
        reqs = list(requests)
        if len(reqs) > MAX_BATCH_REQUESTS:
            raise ValidationError(
                f"batch size {len(reqs)} exceeds "
                f"MAX_BATCH_REQUESTS={MAX_BATCH_REQUESTS}"
            )
        for i, r in enumerate(reqs):
            if not isinstance(r, AllocationRequest):
                raise ValidationError(
                    f"requests[{i}] must be AllocationRequest, "
                    f"got {type(r).__name__}"
                )
        keys = [r.key for r in reqs]
        if len(set(keys)) != len(keys):
            raise ValidationError("duplicate keys within one batch")
        self._check_clock(now)
        self._check_expiry_overflow(now)

        # ---- 阶段 2：纯函数容量规划（不改状态） ----
        expired = set(self._expired_keys_at(now))
        live_keys = set(self._mappings) - expired
        new_keys = [k for k in keys if k not in live_keys]
        ports = self._plan_ports(len(new_keys), now)

        # ---- 阶段 3：一次性提交 ----
        self._housekeeping(now)
        port_iter = iter(ports)
        results: list[AllocationResult] = []
        for req in reqs:
            key = req.key
            rec = self._mappings.get(key)
            if rec is not None:
                results.append(AllocationResult(
                    key=key, mapping=rec.snapshot(key), created=False))
                continue
            port = next(port_iter)
            rec = _Record(
                internal=req.internal,
                remote=req.remote,
                external_port=port,
                generation=self._next_generation,
                created_at=now,
                last_seen=now,
                expires_at=now + self._config.lifetime,
            )
            self._next_generation += 1
            self._mappings[key] = rec
            self._port_to_key[port] = key
            results.append(AllocationResult(
                key=key, mapping=rec.snapshot(key), created=True))
        return results

    # ------------------------------------------------------------------ #
    # 包改写                                                              #
    # ------------------------------------------------------------------ #

    def translate_outbound(self, packet: Packet, *, at: int | None = None
                           ) -> TranslationResult:
        """出站：内网 -> 公网。不隐式建映射；无映射即丢弃（NO_MAPPING）。

        内部回转（hairpin）：若目的 IP 就是本 NAT 的公网 IP，则在完成
        出站改写后不离开 NAT，直接以改写后的包继续走入站腿——要求
        目的外端口命中另一条活跃映射，且改写后的源端点 == 该映射记录的
        对端（不绕过地址依赖过滤）。包携带的 generation 是发送方对
        *自己* 映射的观测，只在出站腿校验；入站腿按 generation=0 处理，
        由实时映射查找（过期即 NO_MAPPING）与对端过滤保证不投递给
        错误的内部设备。任一检查失败即丢弃。
        """
        now = self._resolve_at(at)
        self._validate_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)
        key = (packet.src.ip, packet.src.port, packet.dst.ip, packet.dst.port)
        rec = self._mappings.get(key)
        if rec is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None)
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION, rec.snapshot(key))
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        hairpin_src = Endpoint(self._config.public_ip, rec.external_port)
        if packet.dst.ip == self._config.public_ip:
            # 内部回转：源已改写为 (公网IP, 本映射外端口)，继续入站腿；
            # generation 只属发送方自己的映射，入站腿按 0（不参与校验）。
            return self._inbound_leg(
                hairpin_src, packet.dst, 0, now)
        rewritten = udp_five_tuple(hairpin_src, packet.dst)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    def translate_inbound(self, packet: Packet, *, at: int | None = None
                          ) -> TranslationResult:
        """入站：公网 -> 内网。必须命中映射且源端点 == 映射对端。"""
        now = self._resolve_at(at)
        self._validate_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)
        if packet.dst.ip != self._config.public_ip:
            return TranslationResult(False, None, DropReason.DEST_MISMATCH, None)
        return self._inbound_leg(packet.src, packet.dst, packet.generation, now)

    def _inbound_leg(self, src: Endpoint, dst: Endpoint, generation: int,
                     now: int) -> TranslationResult:
        """入站腿（公网 -> 内网）的共享实现，也用于内部回转的第二段。

        dst.ip 必须为公网 IP（调用方保证）。命中映射后做 generation
        迟到校验与对端过滤，全部通过才改写目的为内网端点并刷新映射。
        """
        key = self._port_to_key.get(dst.port)
        if key is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None)
        rec = self._mappings[key]
        if generation != 0 and generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION, rec.snapshot(key))
        if (src.ip, src.port) != (rec.remote.ip, rec.remote.port):
            return TranslationResult(
                False, None, DropReason.PEER_MISMATCH, rec.snapshot(key))
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(src, rec.internal)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    # ------------------------------------------------------------------ #
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    def release(self, key: Key, *, at: int | None = None) -> bool:
        """显式释放一条映射；端口进入隔离。映射不存在返回 False（无变更）。"""
        now = self._resolve_at(at)
        self._validate_key(key)
        self._check_clock(now)
        self._housekeeping(now)
        rec = self._mappings.pop(key, None)
        if rec is None:
            return False
        del self._port_to_key[rec.external_port]
        self._quarantine[rec.external_port] = now
        return True

    def advance(self, seconds: int) -> list[Key]:
        """显式推进虚拟时钟，返回本次过期的映射 key 列表。"""
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        return self._housekeeping(target)

    # ------------------------------------------------------------------ #
    # 只读快照                                                            #
    # ------------------------------------------------------------------ #

    def get_mapping(self, key: Key) -> Mapping | None:
        """按 key 查活跃映射快照；不存在或已过期返回 None。"""
        self._validate_key(key)
        rec = self._mappings.get(key)
        if rec is None or self._now >= rec.expires_at:
            return None
        return rec.snapshot(key)

    def snapshot_mappings(self) -> list[Mapping]:
        """当前活跃映射快照，按 key 排序（确定性输出）。"""
        return [
            rec.snapshot(key)
            for key, rec in sorted(self._mappings.items())
            if self._now < rec.expires_at
        ]

    def quarantined_ports(self) -> dict[int, int]:
        """隔离中的端口 -> 进入隔离的时刻。"""
        return dict(self._quarantine)

    def stats(self) -> dict[str, int]:
        """计数快照：活跃映射数 / 占用端口 / 隔离端口 / 空闲端口 / 时钟。"""
        live = sum(1 for r in self._mappings.values()
                   if self._now < r.expires_at)
        pool = len(self._config.external_ports)
        return {
            "now": self._now,
            "live_mappings": live,
            "ports_in_use": len(self._port_to_key),
            "ports_quarantined": len(self._quarantine),
            "ports_free": pool - len(self._port_to_key) - len(self._quarantine),
            "pool_size": pool,
        }

    # ------------------------------------------------------------------ #
    # 内部：校验辅助                                                      #
    # ------------------------------------------------------------------ #

    def _resolve_at(self, at: int | None) -> int:
        if at is None:
            return self._now
        return check_int(at, "at", minimum=0, maximum=MAX_TIME)

    @staticmethod
    def _validate_packet(packet: Packet) -> None:
        if not isinstance(packet, Packet):
            raise ValidationError(
                f"packet must be Packet, got {type(packet).__name__}"
            )

    @staticmethod
    def _validate_key(key: object) -> None:
        if not (isinstance(key, tuple) and len(key) == 4):
            raise ValidationError(
                f"key must be (ip, port, ip, port) tuple, got {key!r}"
            )
        from ._validate import check_ipv4, check_port
        check_ipv4(key[0], "key[0] (internal ip)")
        check_port(key[1], "key[1] (internal port)")
        check_ipv4(key[2], "key[2] (remote ip)")
        check_port(key[3], "key[3] (remote port)")
