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
    Direction,
    DropReason,
    Endpoint,
    Fragment,
    FragmentGroupView,
    FragmentResult,
    FragmentStatus,
    Mapping,
    NATConfig,
    Packet,
    RewrittenFragment,
    TranslationResult,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]
FragKey = tuple[str, str, str, int, int]


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


@dataclass(slots=True)
class _FragGroup:
    """一个分片数据报的重组状态（内部可变）。

    frags: offset -> payload（已暂存的分片，含首片到达前与之后）。
    首片到达后冻结映射世代（generation/map_key/rewrite 端点），
    后续片一律按冻结世代改写；映射换代即整组拒绝。
    """

    created_at: int
    last_seen: int
    frags: dict[int, bytes]
    mf: dict[int, bool]
    buffered_bytes: int
    final_end: int | None = None
    have_first: bool = False
    map_key: Key | None = None
    generation: int = 0
    rewrite_src: Endpoint | None = None
    rewrite_dst: Endpoint | None = None

    def is_complete(self) -> bool:
        """final_end 已知且 [0, final_end) 被分片区间完全覆盖。"""
        if self.final_end is None or not self.have_first:
            return False
        covered = 0
        for start, end in sorted(
            (off, off + len(pl)) for off, pl in self.frags.items()
        ):
            if start > covered:
                return False
            covered = max(covered, end)
            if covered >= self.final_end:
                return True
        return False


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
        self._frag_groups: dict[FragKey, _FragGroup] = {}
        self._frag_cached_bytes = 0

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
        self._expire_frag_groups(now)
        self._now = now
        return expired

    def _expire_frag_groups(self, now: int) -> None:
        """释放逻辑超时的分片组（now >= last_seen + fragment_timeout）。"""
        timeout = self._config.fragment_timeout
        dead = [k for k, g in self._frag_groups.items()
                if now >= g.last_seen + timeout]
        for k in dead:
            self._drop_frag_group(k)

    def _drop_frag_group(self, key: FragKey) -> None:
        group = self._frag_groups.pop(key, None)
        if group is not None:
            self._frag_cached_bytes -= group.buffered_bytes

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
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # 分片重组                                                            #
    # ------------------------------------------------------------------ #

    def process_fragment(self, fragment: Fragment, *, at: int | None = None
                         ) -> FragmentResult:
        """处理一个 IP 分片。

        同一数据报由 (direction, src_ip, dst_ip, protocol, datagram_id)
        关联。首片（offset=0，含 UDP 端口）到达时建立/复用映射并冻结其
        世代，随后改写本片与全部暂存片；非首片先到只能暂存。重叠区字节
        不一致整组拒绝；完全重复片幂等。数据报到齐、拒绝或逻辑超时后
        释放关联，datagram_id 可安全复用。
        """
        now = self._resolve_at(at)
        if not isinstance(fragment, Fragment):
            raise ValidationError(
                f"fragment must be Fragment, got {type(fragment).__name__}"
            )
        self._check_clock(now)
        self._check_expiry_overflow(now)
        self._housekeeping(now)
        fkey: FragKey = (fragment.direction.value, fragment.src_ip,
                         fragment.dst_ip, fragment.protocol,
                         fragment.datagram_id)
        group = self._frag_groups.get(fkey)
        if group is None:
            group = _FragGroup(created_at=now, last_seen=now,
                               frags={}, mf={}, buffered_bytes=0)
            self._frag_groups[fkey] = group
        group.last_seen = now

        # 冻结世代校验：首片已建立关联后，映射换代（过期/释放/重建）
        # 即整组拒绝，防止 ID 复用串包。
        if group.have_first:
            rec = self._mappings.get(group.map_key)
            if rec is None or rec.generation != group.generation:
                self._drop_frag_group(fkey)
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.STALE_GENERATION)

        # 完全重复片：幂等，无任何状态变更。
        if (group.frags.get(fragment.offset) == fragment.payload
                and fragment.offset in group.frags):
            return FragmentResult(FragmentStatus.DUPLICATE, (), None)

        # 重叠区字节一致性：不一致整组拒绝。
        end = fragment.end
        for off, pl in group.frags.items():
            lo = max(off, fragment.offset)
            hi = min(off + len(pl), end)
            if lo < hi and pl[lo - off:hi - off] != fragment.payload[
                    lo - fragment.offset:hi - fragment.offset]:
                self._drop_frag_group(fkey)
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.OVERLAP_CONFLICT)

        # 总长度一致性：MF=0 片确定 final_end，冲突即拒绝。
        if not fragment.more_fragments:
            if group.final_end is not None and group.final_end != end:
                self._drop_frag_group(fkey)
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.OVERLAP_CONFLICT)
            if any(off + len(pl) > end for off, pl in group.frags.items()):
                self._drop_frag_group(fkey)
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.OVERLAP_CONFLICT)
        if group.final_end is not None and end > group.final_end:
            self._drop_frag_group(fkey)
            return FragmentResult(FragmentStatus.DROPPED, (),
                                  DropReason.OVERLAP_CONFLICT)

        # 上限：总长度 / 片数 / 全局缓存字节。
        if end > self._config.max_datagram_size:
            self._drop_frag_group(fkey)
            return FragmentResult(FragmentStatus.DROPPED, (),
                                  DropReason.DATAGRAM_TOO_LARGE)
        if len(group.frags) + 1 > self._config.max_fragments:
            self._drop_frag_group(fkey)
            return FragmentResult(FragmentStatus.DROPPED, (),
                                  DropReason.TOO_MANY_FRAGMENTS)
        if (self._frag_cached_bytes + len(fragment.payload)
                > self._config.max_cached_bytes):
            self._drop_frag_group(fkey)
            return FragmentResult(FragmentStatus.DROPPED, (),
                                  DropReason.CACHE_FULL)

        # 首片：建立/复用映射并冻结世代；失败（含端口耗尽异常）整组释放。
        if not group.have_first and fragment.offset == 0:
            try:
                result = self._bind_first_fragment(group, fragment, now)
            except Exception:
                self._drop_frag_group(fkey)
                raise
            if result is not None:
                self._drop_frag_group(fkey)
                return result

        # 提交本片。
        group.frags[fragment.offset] = fragment.payload
        group.mf[fragment.offset] = fragment.more_fragments
        group.buffered_bytes += len(fragment.payload)
        self._frag_cached_bytes += len(fragment.payload)
        if not fragment.more_fragments:
            group.final_end = end

        if not group.have_first:
            # 非首片先到：只能暂存，不能凭 datagram_id 猜连接。
            return FragmentResult(FragmentStatus.BUFFERED, (), None)

        # 首片已到：改写发出。首片本次到达时连带吐出全部暂存片。
        rec = self._mappings[group.map_key]
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        offsets = (sorted(group.frags) if fragment.offset == 0
                   else [fragment.offset])
        emitted = tuple(self._rewrite(group, fkey[4], off) for off in offsets)
        if group.is_complete():
            self._drop_frag_group(fkey)
            return FragmentResult(FragmentStatus.COMPLETE, emitted, None)
        return FragmentResult(FragmentStatus.FORWARDED, emitted, None)

    def _bind_first_fragment(self, group: _FragGroup, fragment: Fragment,
                             now: int) -> FragmentResult | None:
        """首片到达：建立/查找映射并冻结世代。返回 None 表示成功。"""
        cfg = self._config
        if fragment.direction is Direction.OUTBOUND:
            key: Key = (fragment.src_ip, fragment.src_port,
                        fragment.dst_ip, fragment.dst_port)
            rec = self._mappings.get(key)
            if rec is None and fragment.generation != 0:
                # 携带世代的包对着不存在的映射：迟到包，不隐式建映射。
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.STALE_GENERATION)
            if rec is None:
                port = self._plan_ports(1, now)[0]
                rec = _Record(
                    internal=Endpoint(fragment.src_ip, fragment.src_port),
                    remote=Endpoint(fragment.dst_ip, fragment.dst_port),
                    external_port=port,
                    generation=self._next_generation,
                    created_at=now,
                    last_seen=now,
                    expires_at=now + cfg.lifetime,
                )
                self._next_generation += 1
                self._mappings[key] = rec
                self._port_to_key[port] = key
            if fragment.generation != 0 and fragment.generation != rec.generation:
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.STALE_GENERATION)
            group.map_key = key
            group.rewrite_src = Endpoint(cfg.public_ip, rec.external_port)
            group.rewrite_dst = Endpoint(fragment.dst_ip, fragment.dst_port)
        else:
            if fragment.dst_ip != cfg.public_ip:
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.DEST_MISMATCH)
            key = self._port_to_key.get(fragment.dst_port)
            if key is None:
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.NO_MAPPING)
            rec = self._mappings[key]
            if fragment.generation != 0 and fragment.generation != rec.generation:
                return FragmentResult(FragmentStatus.DROPPED, (),
                                      DropReason.STALE_GENERATION)
            group.map_key = key
            group.rewrite_src = rec.remote
            group.rewrite_dst = rec.internal
        group.have_first = True
        group.generation = rec.generation
        return None

    @staticmethod
    def _rewrite(group: _FragGroup, datagram_id: int,
                 offset: int) -> RewrittenFragment:
        assert group.rewrite_src is not None and group.rewrite_dst is not None
        return RewrittenFragment(
            five_tuple=udp_five_tuple(group.rewrite_src, group.rewrite_dst),
            datagram_id=datagram_id,
            offset=offset,
            more_fragments=group.mf[offset],
            payload=group.frags[offset],
        )

    def fragment_groups(self) -> list[FragmentGroupView]:
        """当前暂存中的分片组快照，按 key 排序（确定性输出）。"""
        return [
            FragmentGroupView(
                key=key,
                buffered_bytes=g.buffered_bytes,
                fragment_count=len(g.frags),
                have_first=g.have_first,
                last_seen=g.last_seen,
            )
            for key, g in sorted(self._frag_groups.items())
        ]

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
            "fragment_groups": len(self._frag_groups),
            "fragment_cached_bytes": self._frag_cached_bytes,
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
