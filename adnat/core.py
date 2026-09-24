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

复制与接管
----------
映射的创建（allocate 新建）、刷新（成功的 translate_*）、释放
（release）各自追加一条 JournalRecord：全局连续序号 seq（从 1 开始）
+ 当前栅栏世代 fence（初始 1）。过期不进日志——它是 (expires_at,
时钟) 的纯函数，备用在记录携带的 at 时刻做同样的 housekeeping 即可
收敛；因此过期端口的隔离起点定为 expires_at（逻辑死亡时刻），与
housekeeping 何时发现过期无关。

备用实例（AddressDependentNAT.standby）只读，通过 apply_record 按序
重放：重复记录（序号已应用且内容完全一致）幂等；缺口、内容/状态
冲突、旧栅栏世代的记录都在任何状态变更之前拒绝。备用追平指定序号
后可 promote 到更高的栅栏世代接管；接管后 seq 与映射 generation
连续不断，旧主携带旧栅栏的记录一律被拒绝（StaleFenceError）。
"""

from __future__ import annotations

from dataclasses import dataclass

from ._validate import check_int
from .errors import (
    JournalConflictError,
    JournalGapError,
    NotCaughtUpError,
    PortExhaustionError,
    RoleError,
    SearchBudgetExhaustedError,
    StaleFenceError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    ApplyOutcome,
    DropReason,
    Endpoint,
    JournalKind,
    JournalRecord,
    Mapping,
    NATConfig,
    Packet,
    TranslationResult,
    udp_five_tuple,
)

Key = tuple[str, int, str, int]

_ROLE_PRIMARY = "primary"
_ROLE_STANDBY = "standby"


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
        # 隔离中的端口：port -> 隔离起始时刻（过期=expires_at，释放=释放时刻）。
        self._quarantine: dict[int, int] = {}
        self._next_generation = 1
        # 复制与接管：角色、栅栏世代、有序记录（seq 从 1 连续递增）。
        self._role = _ROLE_PRIMARY
        self._fence = 1
        self._journal: list[JournalRecord] = []

    @classmethod
    def standby(cls, config: NATConfig) -> "AddressDependentNAT":
        """创建备用实例：只读 + apply_record 重放；promote 后才可本地写入。"""
        inst = cls(config)
        inst._role = _ROLE_STANDBY
        return inst

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

    @property
    def role(self) -> str:
        """实例角色："primary" 或 "standby"。"""
        return self._role

    @property
    def fence(self) -> int:
        """当前栅栏世代（初始 1；promote 后严格递增）。"""
        return self._fence

    @property
    def last_seq(self) -> int:
        """已写/已应用的最大记录序号（0 = 日志为空）。"""
        return len(self._journal)

    def journal(self) -> tuple[JournalRecord, ...]:
        """有序记录快照（按 seq 升序，不可变元组）。"""
        return tuple(self._journal)

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
        """提交时刻 now 的过期回收与隔离到期释放，返回本次过期的 key（升序）。

        过期映射的端口自 expires_at（逻辑死亡时刻）起隔离，而非
        housekeeping 发现过期的时刻——这样备用重放在记录时刻做同样的
        housekeeping 即可与主逐状态收敛（过期不进日志的前提）。
        """
        expired = sorted(self._expired_keys_at(now))
        for key in expired:
            rec = self._mappings.pop(key)
            del self._port_to_key[rec.external_port]
            self._quarantine[rec.external_port] = rec.expires_at
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
    # 内部：角色守卫与有序记录                                              #
    # ------------------------------------------------------------------ #

    def _require_primary(self, op: str) -> None:
        if self._role != _ROLE_PRIMARY:
            raise RoleError(
                f"{op}: standby instance is read-only "
                f"(apply records via apply_record, or promote first)"
            )

    def _emit(self, kind: JournalKind, key: Key, now: int,
              external_port: int, generation: int,
              expires_at: int | None) -> None:
        """追加一条有序记录（仅在提交点调用，提交本身不会失败）。"""
        self._journal.append(JournalRecord(
            seq=len(self._journal) + 1,
            fence=self._fence,
            kind=kind,
            key=key,
            at=now,
            external_port=external_port,
            generation=generation,
            expires_at=expires_at,
        ))

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

        已存在活跃映射的 key 直接复用（不占新端口，不产生记录）；
        同批重复 key 属于非法输入，抛 ValidationError。每个新建映射
        追加一条 CREATE 记录。
        """
        self._require_primary("allocate_many")
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
            self._emit(JournalKind.CREATE, key, now, port,
                       rec.generation, rec.expires_at)
            results.append(AllocationResult(
                key=key, mapping=rec.snapshot(key), created=True))
        return results

    # ------------------------------------------------------------------ #
    # 包改写                                                              #
    # ------------------------------------------------------------------ #

    def translate_outbound(self, packet: Packet, *, at: int | None = None
                           ) -> TranslationResult:
        """出站：内网 -> 公网。不隐式建映射；无映射即丢弃（NO_MAPPING）。

        成功改写追加一条 REFRESH 记录。
        """
        self._require_primary("translate_outbound")
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
        self._emit(JournalKind.REFRESH, key, now, rec.external_port,
                   rec.generation, rec.expires_at)
        rewritten = udp_five_tuple(
            Endpoint(self._config.public_ip, rec.external_port), packet.dst)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    def translate_inbound(self, packet: Packet, *, at: int | None = None
                          ) -> TranslationResult:
        """入站：公网 -> 内网。必须命中映射且源端点 == 映射对端。

        成功改写追加一条 REFRESH 记录。
        """
        self._require_primary("translate_inbound")
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
        self._emit(JournalKind.REFRESH, key, now, rec.external_port,
                   rec.generation, rec.expires_at)
        rewritten = udp_five_tuple(packet.src, rec.internal)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    # ------------------------------------------------------------------ #
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    def release(self, key: Key, *, at: int | None = None) -> bool:
        """显式释放一条映射；端口进入隔离并追加 RELEASE 记录。

        映射不存在返回 False（无变更，不产生记录）。
        """
        self._require_primary("release")
        now = self._resolve_at(at)
        self._validate_key(key)
        self._check_clock(now)
        self._housekeeping(now)
        rec = self._mappings.pop(key, None)
        if rec is None:
            return False
        del self._port_to_key[rec.external_port]
        self._quarantine[rec.external_port] = now
        self._emit(JournalKind.RELEASE, key, now, rec.external_port,
                   rec.generation, None)
        return True

    def advance(self, seconds: int) -> list[Key]:
        """显式推进虚拟时钟，返回本次过期的映射 key 列表。

        过期不进日志（它是 expires_at 与时钟的纯函数，备用重放时在
        记录时刻做同样的 housekeeping 即可收敛）。
        """
        self._require_primary("advance")
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        return self._housekeeping(target)

    # ------------------------------------------------------------------ #
    # 复制与接管                                                          #
    # ------------------------------------------------------------------ #

    def apply_record(self, record: JournalRecord) -> ApplyOutcome:
        """按序应用一条有序记录（备用重放；接管后的主同样可用来校验外来记录）。

        - 重复记录（seq 已应用且内容完全一致）：幂等返回 DUPLICATE；
        - seq 缺口：JournalGapError；
        - 同 seq 内容不同 / 与当前状态冲突：JournalConflictError；
        - 记录栅栏低于当前栅栏（旧主写入）：StaleFenceError。

        所有拒绝都发生在任何状态变更之前；单条记录的应用是原子的。
        """
        if not isinstance(record, JournalRecord):
            raise ValidationError(
                f"record must be JournalRecord, got {type(record).__name__}"
            )
        last = len(self._journal)
        if record.seq <= last:
            if self._journal[record.seq - 1] == record:
                return ApplyOutcome.DUPLICATE
            raise JournalConflictError(
                f"seq={record.seq} already applied with different content"
            )
        if record.seq > last + 1:
            raise JournalGapError(expected=last + 1, got=record.seq)
        if record.fence < self._fence:
            raise StaleFenceError(record.seq, record.fence, self._fence)
        if record.fence > self._fence:
            raise JournalConflictError(
                f"record fence={record.fence} exceeds current "
                f"fence={self._fence} (promote first)"
            )
        now = record.at
        if now < self._now:
            raise JournalConflictError(
                f"record.at={now} moves clock backwards (now={self._now})"
            )
        key = record.key
        q = self._config.quarantine
        # ---- 纯函数预校验：按 housekeeping 后的视图检查，不改状态 ----
        expired = set(self._expired_keys_at(now))
        live = set(self._mappings) - expired
        owned = {r.external_port for k, r in self._mappings.items()
                 if k not in expired}
        quar = {p for p, t in self._quarantine.items() if now < t + q}
        quar |= {self._mappings[k].external_port for k in expired
                 if now < self._mappings[k].expires_at + q}
        kind = record.kind
        if kind is JournalKind.CREATE:
            if key in live:
                raise JournalConflictError(
                    f"CREATE for already-live key {key!r}"
                )
            if record.external_port not in self._config.external_ports:
                raise JournalConflictError(
                    f"CREATE port {record.external_port} not in "
                    f"configured pool"
                )
            if record.external_port in owned:
                raise JournalConflictError(
                    f"CREATE port {record.external_port} already owned"
                )
            if record.external_port in quar:
                raise JournalConflictError(
                    f"CREATE port {record.external_port} still "
                    f"quarantined at now={now}"
                )
        elif kind is JournalKind.REFRESH:
            rec = self._mappings.get(key)
            if rec is None or key not in live:
                raise JournalConflictError(
                    f"REFRESH for unknown/expired key {key!r}"
                )
            if rec.generation != record.generation:
                raise JournalConflictError(
                    f"REFRESH generation mismatch for {key!r}: "
                    f"record={record.generation} current={rec.generation}"
                )
            if rec.external_port != record.external_port:
                raise JournalConflictError(
                    f"REFRESH port mismatch for {key!r}: "
                    f"record={record.external_port} "
                    f"current={rec.external_port}"
                )
        else:  # RELEASE
            rec = self._mappings.get(key)
            if rec is None or key not in live:
                raise JournalConflictError(
                    f"RELEASE for unknown/expired key {key!r}"
                )
            if rec.external_port != record.external_port:
                raise JournalConflictError(
                    f"RELEASE port mismatch for {key!r}: "
                    f"record={record.external_port} "
                    f"current={rec.external_port}"
                )
            if rec.generation != record.generation:
                raise JournalConflictError(
                    f"RELEASE generation mismatch for {key!r}: "
                    f"record={record.generation} current={rec.generation}"
                )
        # ---- 提交：housekeeping + 应用 + 追加日志（预校验后不会失败） ----
        self._housekeeping(now)
        if kind is JournalKind.CREATE:
            assert record.expires_at is not None  # JournalRecord 保证
            rec = _Record(
                internal=Endpoint(key[0], key[1]),
                remote=Endpoint(key[2], key[3]),
                external_port=record.external_port,
                generation=record.generation,
                created_at=now,
                last_seen=now,
                expires_at=record.expires_at,
            )
            self._mappings[key] = rec
            self._port_to_key[rec.external_port] = key
            if record.generation >= self._next_generation:
                self._next_generation = record.generation + 1
        elif kind is JournalKind.REFRESH:
            rec = self._mappings[key]
            rec.last_seen = now
            rec.expires_at = record.expires_at
        else:  # RELEASE
            rec = self._mappings.pop(key)
            del self._port_to_key[rec.external_port]
            self._quarantine[rec.external_port] = now
        self._journal.append(record)
        return ApplyOutcome.APPLIED

    def promote(self, through_seq: int, new_fence: int | None = None) -> None:
        """备用接管：追平 through_seq 后以更高栅栏世代升为主。

        仅备用实例可调用；要求 last_seq >= through_seq（已追平指定序号），
        且 new_fence 严格大于当前栅栏（缺省为当前栅栏 + 1）。接管后
        角色变为 primary，日志、seq 与映射 generation 计数全部保留并
        连续；旧主携带旧栅栏的记录将被 apply_record 拒绝。
        """
        if self._role != _ROLE_STANDBY:
            raise RoleError(
                f"promote: role={self._role!r} is not standby"
            )
        check_int(through_seq, "through_seq", minimum=0, maximum=MAX_TIME)
        if new_fence is None:
            new_fence = self._fence + 1
        else:
            check_int(new_fence, "new_fence", minimum=1, maximum=MAX_TIME)
        if new_fence > MAX_TIME:
            raise ValidationError(
                f"new_fence={new_fence} exceeds MAX_TIME={MAX_TIME}"
            )
        if new_fence <= self._fence:
            raise ValidationError(
                f"new_fence={new_fence} must be higher than current "
                f"fence={self._fence}"
            )
        if self.last_seq < through_seq:
            raise NotCaughtUpError(through_seq, self.last_seq)
        self._role = _ROLE_PRIMARY
        self._fence = new_fence

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
        """隔离中的端口 -> 隔离起始时刻（过期=expires_at，释放=释放时刻）。"""
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
