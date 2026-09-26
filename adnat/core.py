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
    FragmentResult,
    FragmentationConfig,
    Mapping,
    NATConfig,
    Packet,
    TranslationResult,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]
# 片组关联键：方向 + 源/目的地址 + 协议 + 数据报 ID（无端口号）。
FragKey = tuple[Direction, str, str, int, int]


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
    """重组中的一个片组（内部可变状态）。

    frozen_* 字段在首片（offset=0）处理时冻结：同一数据报的后续片
    一律使用冻结的映射世代做改写，不跟随映射的后续变化。
    """

    created_at: int
    fragments: dict[int, bytes]          # offset -> payload
    byte_count: int
    total: int | None                    # 见到最后一片后确定的重组总长
    frozen_mapping_key: Key | None = None
    frozen_generation: int = 0
    frozen_src: Endpoint | None = None   # 改写后的源端点（首片含端口）
    frozen_dst: Endpoint | None = None   # 改写后的目的端点


class AddressDependentNAT:
    """地址依赖（address-dependent）映射与过滤的 UDP NAT 模拟器。

    - 出站 key = (内网IP, 内网端口, 目的IP, 目的端口)；同一内网端点访问
      不同目的会产生不同映射、不同外端口。
    - 公网 IP 固定；外端口从有限池选最小空闲者。
    - 入站只接受来自映射所记录对端的包（地址依赖过滤）。
    - 每条映射携带单调递增的 generation；包携带的 generation 不一致
      （且非 0）即判为迟到包并丢弃。
    """

    def __init__(self, config: NATConfig,
                 fragmentation: FragmentationConfig | None = None) -> None:
        if not isinstance(config, NATConfig):
            raise ValidationError(
                f"config must be NATConfig, got {type(config).__name__}"
            )
        if fragmentation is None:
            fragmentation = FragmentationConfig()
        if not isinstance(fragmentation, FragmentationConfig):
            raise ValidationError(
                f"fragmentation must be FragmentationConfig, "
                f"got {type(fragmentation).__name__}"
            )
        self._config = config
        self._frag_config = fragmentation
        self._now = 0
        self._mappings: dict[Key, _Record] = {}
        self._port_to_key: dict[int, Key] = {}
        # 隔离中的端口：port -> 释放时刻（进入隔离的时刻）。
        self._quarantine: dict[int, int] = {}
        self._next_generation = 1
        # 重组中的片组：FragKey -> _FragGroup。
        self._frag_groups: dict[FragKey, _FragGroup] = {}
        self._frag_cached_bytes = 0

    # ------------------------------------------------------------------ #
    # 只读属性                                                            #
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> NATConfig:
        return self._config

    @property
    def fragmentation(self) -> FragmentationConfig:
        return self._frag_config

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
        self._expire_fragment_groups(now)
        self._now = now
        return expired

    def _expire_fragment_groups(self, now: int) -> None:
        """释放逻辑超时的片组（now >= created_at + timeout，边界即死）。"""
        timeout = self._frag_config.fragment_timeout
        dead = [k for k, g in self._frag_groups.items()
                if now >= g.created_at + timeout]
        for key in dead:
            self._drop_group(key)

    def _drop_group(self, key: FragKey) -> None:
        group = self._frag_groups.pop(key, None)
        if group is not None:
            self._frag_cached_bytes -= group.byte_count

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
    # 分片重组                                                            #
    # ------------------------------------------------------------------ #

    def process_fragment(self, fragment: Fragment, *, at: int | None = None
                         ) -> FragmentResult:
        """处理一个分片：暂存、冲突检测、齐全后整体改写并释放关联。

        - 同一数据报由 (direction, src_ip, dst_ip, protocol, datagram_id)
          关联；非首片没有端口，只暂存，绝不凭数据报 ID 猜测连接。
        - 首片到达时建立/命中映射并冻结改写与世代；后续片使用冻结世代，
          映射已过期或世代已变（如端口被复用）即整组拒绝并释放。
        - 重叠区域字节不一致（或与已知总长矛盾）整组拒绝；完全重复片幂等。
        - 总长度 / 片数 / 全实例缓存字节 / 逻辑超时均有上限，超限整组拒绝。
        """
        now = self._resolve_at(at)
        if not isinstance(fragment, Fragment):
            raise ValidationError(
                f"fragment must be Fragment, got {type(fragment).__name__}"
            )
        self._check_clock(now)
        self._housekeeping(now)

        key: FragKey = (fragment.direction, fragment.src_ip, fragment.dst_ip,
                        fragment.protocol, fragment.datagram_id)
        group = self._frag_groups.get(key)
        if group is None:
            group = _FragGroup(created_at=now, fragments={},
                               byte_count=0, total=None)
            self._frag_groups[key] = group

        # ---- 完全重复片：幂等，不改变状态 ----
        existing = group.fragments.get(fragment.offset)
        if existing is not None and existing == fragment.payload:
            return FragmentResult(True, False, None, None, None)

        # ---- 重叠冲突：任何重叠区域字节不一致 -> 整组拒绝 ----
        if self._conflicts(group, fragment):
            return self._reject_group(
                key, DropReason.FRAGMENT_OVERLAP_CONFLICT)

        # ---- 总长上限 ----
        if not fragment.more_fragments:
            total = fragment.end
            if group.total is not None and group.total != total:
                return self._reject_group(
                    key, DropReason.FRAGMENT_OVERLAP_CONFLICT)
            if total > self._frag_config.max_datagram_size:
                return self._reject_group(key, DropReason.FRAGMENT_TOO_LONG)
            group.total = total
        if group.total is not None and fragment.end > group.total:
            return self._reject_group(
                key, DropReason.FRAGMENT_OVERLAP_CONFLICT)

        # ---- 片数与缓存字节上限 ----
        if len(group.fragments) + 1 > self._frag_config.max_fragments:
            return self._reject_group(key, DropReason.FRAGMENT_TOO_MANY)
        if (self._frag_cached_bytes + len(fragment.payload)
                > self._frag_config.max_cached_bytes):
            return self._reject_group(key, DropReason.FRAGMENT_CACHE_FULL)

        # ---- 首片：建立/命中映射并冻结改写（失败则不留部分状态） ----
        if fragment.offset == 0 and group.frozen_mapping_key is None:
            failure = self._freeze_translation(group, fragment, now)
            if failure is not None:
                return self._reject_group(key, failure)

        # ---- 提交暂存 ----
        group.fragments[fragment.offset] = bytes(fragment.payload)
        group.byte_count += len(fragment.payload)
        self._frag_cached_bytes += len(fragment.payload)

        # ---- 后续片：校验冻结世代仍然有效（映射过期/复用即拒绝） ----
        if group.frozen_mapping_key is not None:
            rec = self._mappings.get(group.frozen_mapping_key)
            if (rec is None or rec.generation != group.frozen_generation
                    or now >= rec.expires_at):
                return self._reject_group(key, DropReason.STALE_GENERATION)

        # ---- 齐全：整体改写并释放关联（同 ID 可安全复用） ----
        if group.total is not None and self._is_complete(group):
            rewritten = self._rewrite_group(group, fragment)
            self._drop_group(key)
            mapping = self._mapping_snapshot(group.frozen_mapping_key)
            return FragmentResult(True, True, rewritten, None, mapping)
        return FragmentResult(True, False, None, None, None)

    @staticmethod
    def _conflicts(group: _FragGroup, fragment: Fragment) -> bool:
        """新片与已暂存片的重叠区域是否存在字节不一致。"""
        start, end = fragment.offset, fragment.end
        for off, payload in group.fragments.items():
            o_start, o_end = off, off + len(payload)
            lo, hi = max(start, o_start), min(end, o_end)
            if lo >= hi:
                continue
            if (fragment.payload[lo - start:hi - start]
                    != payload[lo - o_start:hi - o_start]):
                return True
        return False

    def _freeze_translation(self, group: _FragGroup, fragment: Fragment,
                            now: int) -> DropReason | None:
        """首片到达：确定映射并冻结改写。返回 None 表示成功。"""
        assert fragment.src_port is not None and fragment.dst_port is not None
        if fragment.direction is Direction.OUTBOUND:
            mkey: Key = (fragment.src_ip, fragment.src_port,
                         fragment.dst_ip, fragment.dst_port)
            rec = self._mappings.get(mkey)
            if rec is None:
                # 首片可隐式建立映射；容量不足时异常向上抛，
                # 由调用方清理片组，保证不留部分状态。
                try:
                    self.allocate_many([AllocationRequest(
                        Endpoint(fragment.src_ip, fragment.src_port),
                        Endpoint(fragment.dst_ip, fragment.dst_port),
                    )], at=now)
                except Exception:
                    self._frag_groups.pop(
                        (fragment.direction, fragment.src_ip,
                         fragment.dst_ip, fragment.protocol,
                         fragment.datagram_id), None)
                    raise
                rec = self._mappings[mkey]
            group.frozen_mapping_key = mkey
            group.frozen_generation = rec.generation
            group.frozen_src = Endpoint(self._config.public_ip,
                                        rec.external_port)
            group.frozen_dst = Endpoint(fragment.dst_ip, fragment.dst_port)
            rec.last_seen = now
            rec.expires_at = now + self._config.lifetime
            return None
        # 入站：目的必须是本 NAT 公网 IP，目的端口命中映射，源 == 对端。
        if fragment.dst_ip != self._config.public_ip:
            return DropReason.DEST_MISMATCH
        mkey = self._port_to_key.get(fragment.dst_port)
        if mkey is None:
            return DropReason.NO_MAPPING
        rec = self._mappings[mkey]
        if (fragment.src_ip, fragment.src_port) != (rec.remote.ip,
                                                    rec.remote.port):
            return DropReason.PEER_MISMATCH
        group.frozen_mapping_key = mkey
        group.frozen_generation = rec.generation
        group.frozen_src = Endpoint(fragment.src_ip, fragment.src_port)
        group.frozen_dst = rec.internal
        rec.last_seen = now
        rec.expires_at = now + self._config.lifetime
        return None

    @staticmethod
    def _is_complete(group: _FragGroup) -> bool:
        """已暂存片是否无缝覆盖 [0, total)。"""
        assert group.total is not None
        covered = 0
        for off in sorted(group.fragments):
            if off > covered:
                return False
            covered = max(covered, off + len(group.fragments[off]))
        return covered >= group.total

    @staticmethod
    def _rewrite_group(group: _FragGroup,
                       fragment: Fragment) -> tuple[Fragment, ...]:
        """按偏移升序输出改写后的全部片（首片含冻结端口）。"""
        assert group.frozen_src is not None and group.frozen_dst is not None
        out: list[Fragment] = []
        for off in sorted(group.fragments):
            payload = group.fragments[off]
            is_last = group.total is not None and off + len(payload) == group.total
            out.append(Fragment(
                direction=fragment.direction,
                src_ip=group.frozen_src.ip,
                dst_ip=group.frozen_dst.ip,
                protocol=17,
                datagram_id=fragment.datagram_id,
                offset=off,
                more_fragments=not is_last,
                payload=payload,
                src_port=group.frozen_src.port if off == 0 else None,
                dst_port=group.frozen_dst.port if off == 0 else None,
            ))
        return tuple(out)

    def _reject_group(self, key: FragKey, reason: DropReason) -> FragmentResult:
        """整组拒绝并释放关联，避免 ID 复用串包。"""
        self._drop_group(key)
        return FragmentResult(False, False, None, reason, None)

    def _mapping_snapshot(self, key: Key | None) -> Mapping | None:
        if key is None:
            return None
        rec = self._mappings.get(key)
        if rec is None:
            return None
        return rec.snapshot(key)

    def fragment_stats(self) -> dict[str, int]:
        """分片重组计数快照：在组数 / 全实例缓存字节。"""
        return {
            "fragment_groups": len(self._frag_groups),
            "fragment_cached_bytes": self._frag_cached_bytes,
        }

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
