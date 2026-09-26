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
    ErrorPacket,
    ErrorTranslationResult,
    Endpoint,
    Mapping,
    NATConfig,
    Packet,
    TranslationResult,
    FiveTuple,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]
_PROTOCOL_ICMP = 1


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
        # 曾占用各公网端口的世代标记（含已过期/已释放），用于区分
        # “引用的是端口复用前的旧连接”与“从未有过的引用”。
        self._port_generations: dict[int, set[int]] = {}

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
            self._port_generations.setdefault(port, set()).add(rec.generation)
            results.append(AllocationResult(
                key=key, mapping=rec.snapshot(key), created=True))
        return results

    # ------------------------------------------------------------------ #
    # 包改写                                                              #
    # ------------------------------------------------------------------ #

    def translate_outbound(self, packet: Packet, *, at: int | None = None
                           ) -> TranslationResult:
        """出站：内网 -> 公网。不隐式建映射；无映射即丢弃（NO_MAPPING）。"""
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
        rewritten = udp_five_tuple(
            Endpoint(self._config.public_ip, rec.external_port), packet.dst)
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
        key = self._port_to_key.get(packet.dst.port)
        if key is None:
            return TranslationResult(False, None, DropReason.NO_MAPPING, None)
        rec = self._mappings[key]
        if packet.generation != 0 and packet.generation != rec.generation:
            return TranslationResult(
                False, None, DropReason.STALE_GENERATION, rec.snapshot(key))
        if (packet.src.ip, packet.src.port) != (rec.remote.ip, rec.remote.port):
            return TranslationResult(
                False, None, DropReason.PEER_MISMATCH, rec.snapshot(key))
        self._check_expiry_overflow(now)
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        rewritten = udp_five_tuple(packet.src, rec.internal)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    # ------------------------------------------------------------------ #
    # 差错报文反向定位                                                    #
    # ------------------------------------------------------------------ #

    def translate_error(self, packet: ErrorPacket,
                        *, at: int | None = None) -> ErrorTranslationResult:
        """差错报文入口：按被引用的原 UDP 五元组做反向映射。

        仅处理题面明确给出的合成结构（见 ErrorPacket），不实现完整网络
        协议栈、不真实发包。匹配必须同时满足：

        1. 外层目的 == 本 NAT 公网 IP（DEST_MISMATCH）；
        2. 引用协议 == UDP 17（QUOTE_NOT_UDP）；
        3. 引用源端点 == 外层目的端点（公网 IP + 外端口一致），
           引用的远端/端口结构可解析（QUOTE_MALFORMED）；
        4. 该外端口当前仍有有效映射，且记录的对端 == 引用远端，
           外层源也必须来自该对端（NO_MAPPING / PEER_MISMATCH）；
        5. 包携带 generation（非 0）时必须等于映射当前世代标记
           （STALE_GENERATION，排除端口复用后的旧引用）。

        命中后返回改写后的外层目标（ICMP, protocol=1，发往内部端点）、
        引用的 UDP 五元组与采用映射 ID（即世代标记）。差错报文不创建
        映射、不刷新 last_seen/expires_at。

        generation=0 表示入口未携带世代标记；此时若公网端口已被完全
        相同的五元组复用，本库不承诺识别旧引用（见 README 限制）。
        """
        now = self._resolve_at(at)
        self._validate_error_packet(packet)
        self._check_clock(now)
        self._housekeeping(now)

        def drop(reason: DropReason, mapping: Mapping | None = None
                 ) -> ErrorTranslationResult:
            return ErrorTranslationResult(False, None, None, None,
                                          reason, mapping)

        if packet.outer_dst.ip != self._config.public_ip:
            return drop(DropReason.DEST_MISMATCH)
        if packet.quoted_protocol != 17:
            return drop(DropReason.QUOTE_NOT_UDP)
        # 引用的必须是“NAT 重写后在公网上观察到的原包”：引用源必须等于
        # 外层目的（同一公网端点），否则方向/结构自相矛盾。
        if (packet.quoted_src.ip, packet.quoted_src.port) != (
                packet.outer_dst.ip, packet.outer_dst.port):
            return drop(DropReason.QUOTE_MALFORMED)

        port = packet.outer_dst.port
        remote_ep = packet.quoted_dst
        key = self._port_to_key.get(port)
        if key is None:
            # 端口当前无有效映射。若曾有同世代映射则是复用前的旧引用。
            if packet.generation != 0 and packet.generation in \
                    self._port_generations.get(port, set()):
                return drop(DropReason.STALE_GENERATION)
            return drop(DropReason.NO_MAPPING)
        rec = self._mappings[key]
        remote_match = (remote_ep.ip, remote_ep.port) == (
            rec.remote.ip, rec.remote.port)
        if not remote_match:
            if packet.generation != 0 and packet.generation in \
                    self._port_generations.get(port, set()):
                return drop(DropReason.STALE_GENERATION, rec.snapshot(key))
            return drop(DropReason.PEER_MISMATCH, rec.snapshot(key))
        # 外层源同样必须来自映射记录的对端（地址依赖）。
        if (packet.outer_src.ip, packet.outer_src.port) != (
                rec.remote.ip, rec.remote.port):
            return drop(DropReason.PEER_MISMATCH, rec.snapshot(key))
        if packet.generation != 0 and packet.generation != rec.generation:
            return drop(DropReason.STALE_GENERATION, rec.snapshot(key))

        quoted = FiveTuple(
            protocol=17,
            src_ip=packet.quoted_src.ip, src_port=packet.quoted_src.port,
            dst_ip=packet.quoted_dst.ip, dst_port=packet.quoted_dst.port,
        )
        outer_target = FiveTuple(
            protocol=_PROTOCOL_ICMP,
            src_ip=packet.outer_src.ip, src_port=packet.outer_src.port,
            dst_ip=rec.internal.ip, dst_port=rec.internal.port,
        )
        # 注意：不更新 last_seen / expires_at —— 差错报文不延长寿命。
        return ErrorTranslationResult(
            True, outer_target, quoted, rec.generation, None,
            rec.snapshot(key))

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

    def port_generations(self) -> dict[int, tuple[int, ...]]:
        """每个公网端口曾占用的世代标记（含已过期/已释放映射）。

        供测试 oracle 对照状态；差错入口据此识别端口复用前的旧引用。
        """
        return {p: tuple(sorted(gs))
                for p, gs in self._port_generations.items()}

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
    def _validate_error_packet(packet: object) -> None:
        if not isinstance(packet, ErrorPacket):
            raise ValidationError(
                f"packet must be ErrorPacket, got {type(packet).__name__}"
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
