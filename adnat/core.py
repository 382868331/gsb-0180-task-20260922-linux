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

from ._validate import check_int, check_mapping_key
from .errors import (
    CatchupIncompleteError,
    FencedError,
    PortExhaustionError,
    ReplicationGapError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    ApplyResult,
    ApplyStatus,
    DropReason,
    Endpoint,
    FenceToken,
    JournalRecord,
    Mapping,
    NATConfig,
    Packet,
    RecordKind,
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
    epoch: int = 1

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

    复制与栅栏（本次迭代）
    ----------------------
    - 主实例（role="primary"，默认）的每次创建/刷新/释放都向追加式
      日志写入一条有序 JournalRecord（seq 从 1 连续递增，带 epoch）。
    - 备用实例（role="standby"）通过 apply_record 按序应用记录：
      seq 必须恰好为已应用序号 + 1；重复投递同一记录幂等跳过，
      缺前序记录（跳号）抛 ReplicationGapError，两者状态都不变。
    - 备用追平指定序号后可 promote(after_seq, new_epoch) 接管为新主；
      新 epoch 必须严格大于日志中见过的最大 epoch。旧主调用 fence()
      后其一切写入抛 FencedError；未接管的备用写入同样被拒绝。

    日志语义边界：housekeeping 的隐式过期回收不写日志（它只由时钟
    推进派生），因此日志只记录显式创建、成功包改写刷新、显式释放；
    备用 apply 时会把时钟推进到记录时刻，过期回收由同一时钟自然派生。
    """

    def __init__(self, config: NATConfig, *, role: str = "primary",
                 epoch: int = 1) -> None:
        if not isinstance(config, NATConfig):
            raise ValidationError(
                f"config must be NATConfig, got {type(config).__name__}"
            )
        if role not in ("primary", "standby"):
            raise ValidationError(
                f"role must be 'primary' or 'standby', got {role!r}"
            )
        check_int(epoch, "epoch", minimum=1, maximum=MAX_TIME)
        self._config = config
        self._role = role
        self._epoch = epoch
        self._fenced = False
        self._now = 0
        self._mappings: dict[Key, _Record] = {}
        self._port_to_key: dict[int, Key] = {}
        # 隔离中的端口：port -> 释放时刻（进入隔离的时刻）。
        self._quarantine: dict[int, int] = {}
        self._next_generation = 1
        # 追加式有序日志：seq -> JournalRecord（seq 从 1 连续）。
        self._journal: dict[int, JournalRecord] = {}
        # 日志中出现过的最大栅栏世代（接管时要求新世代严格大于它）。
        self._max_epoch_seen = epoch

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
        """当前角色："primary"（可写）或 "standby"（只读，接管前）。"""
        return self._role

    @property
    def epoch(self) -> int:
        """当前栅栏世代（成为主时写入日志的世代号）。"""
        return self._epoch

    @property
    def is_fenced(self) -> bool:
        """旧主是否已被栅栏（True 时一切写入抛 FencedError）。"""
        return self._fenced

    @property
    def last_seq(self) -> int:
        """日志中最后一条记录序号（空日志为 0）。备用即已应用序号。"""
        return len(self._journal)

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

        过期映射的隔离时间戳取其 expires_at（死亡时刻）而非观测时刻：
        隔离区间由映射自身状态决定，与何时观测无关——主备重放同一
        日志时得到相同的隔离边界。显式 release 的时间戳仍是释放时刻。
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
        self._require_primary_write()
        self._check_expiry_overflow(now)

        # ---- 阶段 2：纯函数容量规划（不改状态） ----
        expired = set(self._expired_keys_at(now))
        live_keys = set(self._mappings) - expired
        new_keys = [k for k in keys if k not in live_keys]
        ports = self._plan_ports(len(new_keys), now)

        # ---- 阶段 3：一次性提交（状态 + 日志同批落地） ----
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
            generation = self._next_generation
            expires_at = now + self._config.lifetime
            rec = _Record(
                internal=req.internal,
                remote=req.remote,
                external_port=port,
                generation=generation,
                created_at=now,
                last_seen=now,
                expires_at=expires_at,
                epoch=self._epoch,
            )
            self._next_generation += 1
            self._mappings[key] = rec
            self._port_to_key[port] = key
            self._append_record(JournalRecord(
                seq=self._journal_next_seq(),
                epoch=self._epoch,
                kind=RecordKind.CREATE,
                key=key, at=now, port=port,
                generation=generation, expires_at=expires_at,
            ))
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
        self._require_primary_write()
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
        self._append_record(JournalRecord(
            seq=self._journal_next_seq(),
            epoch=self._epoch,
            kind=RecordKind.REFRESH,
            key=key, at=now, expires_at=rec.expires_at,
        ))
        rewritten = udp_five_tuple(
            Endpoint(self._config.public_ip, rec.external_port), packet.dst)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    def translate_inbound(self, packet: Packet, *, at: int | None = None
                          ) -> TranslationResult:
        """入站：公网 -> 内网。必须命中映射且源端点 == 映射对端。"""
        now = self._resolve_at(at)
        self._validate_packet(packet)
        self._check_clock(now)
        self._require_primary_write()
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
        self._append_record(JournalRecord(
            seq=self._journal_next_seq(),
            epoch=self._epoch,
            kind=RecordKind.REFRESH,
            key=key, at=now, expires_at=rec.expires_at,
        ))
        rewritten = udp_five_tuple(packet.src, rec.internal)
        return TranslationResult(True, rewritten, None, rec.snapshot(key))

    # ------------------------------------------------------------------ #
    # 生命周期                                                            #
    # ------------------------------------------------------------------ #

    def release(self, key: Key, *, at: int | None = None) -> bool:
        """显式释放一条映射；端口进入隔离。映射不存在返回 False（无变更）。"""
        now = self._resolve_at(at)
        self._validate_key(key)
        self._check_clock(now)
        self._require_primary_write()
        self._housekeeping(now)
        rec = self._mappings.pop(key, None)
        if rec is None:
            return False
        del self._port_to_key[rec.external_port]
        self._quarantine[rec.external_port] = now
        self._append_record(JournalRecord(
            seq=self._journal_next_seq(),
            epoch=self._epoch,
            kind=RecordKind.RELEASE,
            key=key, at=now,
        ))
        return True

    def advance(self, seconds: int) -> list[Key]:
        """显式推进虚拟时钟，返回本次过期的映射 key 列表。

        仅主实例可调用（备用时钟由 apply_record 推进；旧主被栅栏后
        一切状态变更均被拒绝）。
        """
        check_int(seconds, "seconds", minimum=0, maximum=MAX_TIME)
        self._require_primary_write()
        target = self._now + seconds
        if target > MAX_TIME:
            raise ValidationError(
                f"advance({seconds}) overflows MAX_TIME={MAX_TIME}"
            )
        return self._housekeeping(target)

    # ------------------------------------------------------------------ #
    # 复制：有序日志                                                      #
    # ------------------------------------------------------------------ #

    def _journal_next_seq(self) -> int:
        return len(self._journal) + 1

    def _append_record(self, record: JournalRecord) -> None:
        self._journal[record.seq] = record
        if record.epoch > self._max_epoch_seen:
            self._max_epoch_seen = record.epoch

    def _require_primary_write(self) -> None:
        """写入门禁：只有未被栅栏的主实例可改变状态。"""
        if self._role != "primary":
            raise FencedError(self._role, self._epoch)
        if self._fenced:
            raise FencedError(self._role, self._epoch,
                              required_epoch=self._max_epoch_seen)

    def journal(self, *, since: int = 0) -> list[JournalRecord]:
        """返回 seq > since 的日志记录（按 seq 升序）。

        since 为调用方已追平的序号；传 0 取全量。日志只增不改，
        重复读取同一区间结果一致（幂等）。
        """
        check_int(since, "since", minimum=0, maximum=MAX_TIME)
        if since > len(self._journal):
            raise ValidationError(
                f"since={since} beyond journal length {len(self._journal)}"
            )
        return [self._journal[s] for s in range(since + 1, len(self._journal) + 1)]

    def apply_record(self, record: JournalRecord) -> ApplyResult:
        """备用按序应用一条日志记录。

        - record.seq == 已应用序号 + 1：应用并推进时钟到 record.at；
        - record.seq <= 已应用序号：与已应用记录完全一致则幂等跳过
          （DUPLICATE，无变更），内容不一致抛 ValidationError；
        - record.seq > 已应用序号 + 1：缺前序记录，抛
          ReplicationGapError，状态不变。

        仅备用实例可调用；主实例调用抛 FencedError。
        """
        if self._role != "standby":
            raise FencedError(self._role, self._epoch)
        if not isinstance(record, JournalRecord):
            raise ValidationError(
                f"record must be JournalRecord, got {type(record).__name__}"
            )
        applied = len(self._journal)
        if record.seq <= applied:
            existing = self._journal[record.seq]
            if existing != record:
                raise ValidationError(
                    f"record seq={record.seq} conflicts with applied record "
                    f"{existing!r}: duplicate apply must be identical"
                )
            return ApplyResult(ApplyStatus.DUPLICATE, record.seq, record.kind)
        if record.seq > applied + 1:
            raise ReplicationGapError(expected=applied + 1, got=record.seq)
        if record.at < self._now:
            raise ValidationError(
                f"record.at={record.at} < standby clock now={self._now} "
                f"(log time must be non-decreasing)"
            )
        self._apply_fresh(record)
        return ApplyResult(ApplyStatus.APPLIED, record.seq, record.kind)

    def _apply_fresh(self, record: JournalRecord) -> None:
        """应用一条新的（seq == applied+1）记录。调用前已完成格式校验。

        先以纯函数做"日志与本地状态一致性"校验（不改动任何状态），
        全部通过才提交 housekeeping + 记录效果；校验失败抛
        ValidationError，备用状态与调用前完全一致。
        """
        now = record.at
        key = record.key
        live = {k for k, r in self._mappings.items() if now < r.expires_at}
        used_ports = {self._mappings[k].external_port for k in live}
        hot_quarantine = {
            p for p, t in self._quarantine.items()
            if now < t + self._config.quarantine
        }
        if record.kind is RecordKind.CREATE:
            if key in live:
                raise ValidationError(
                    f"CREATE seq={record.seq}: key {key!r} already has a live "
                    f"mapping on standby (log inconsistent with state)"
                )
            if record.port in used_ports:
                raise ValidationError(
                    f"CREATE seq={record.seq}: port {record.port} already in "
                    f"use on standby (log inconsistent with state)"
                )
            if record.port in hot_quarantine:
                raise ValidationError(
                    f"CREATE seq={record.seq}: port {record.port} still "
                    f"quarantined on standby (log inconsistent with state)"
                )
        else:
            if key not in live:
                raise ValidationError(
                    f"{record.kind.name} seq={record.seq}: no live mapping for "
                    f"{key!r} on standby (log inconsistent with state)"
                )
        # ---- 校验通过，提交 ----
        self._housekeeping(now)
        if record.kind is RecordKind.CREATE:
            rec = _Record(
                internal=Endpoint(key[0], key[1]),
                remote=Endpoint(key[2], key[3]),
                external_port=record.port,
                generation=record.generation,
                created_at=now,
                last_seen=now,
                expires_at=record.expires_at,
                epoch=record.epoch,
            )
            self._mappings[key] = rec
            self._port_to_key[record.port] = key
            if record.generation >= self._next_generation:
                self._next_generation = record.generation + 1
        elif record.kind is RecordKind.REFRESH:
            rec = self._mappings[key]
            rec.last_seen = now
            rec.expires_at = record.expires_at
        else:  # RELEASE
            rec = self._mappings.pop(key)
            del self._port_to_key[rec.external_port]
            self._quarantine[rec.external_port] = now
        self._append_record(record)

    # ------------------------------------------------------------------ #
    # 栅栏接管                                                            #
    # ------------------------------------------------------------------ #

    def promote(self, *, after_seq: int, new_epoch: int) -> FenceToken:
        """备用追平 after_seq 后以更高栅栏世代接管为新主。

        - 仅备用实例可调用；主实例调用抛 FencedError。
        - 已应用序号 < after_seq 抛 CatchupIncompleteError（未追平，
          不允许接管），状态不变。
        - new_epoch 必须严格大于日志中见过的最大世代，否则
          ValidationError（无法栅栏旧主）。
        成功后本实例变为可写主，返回 FenceToken（可交给旧主 fence()）。
        """
        if self._role != "standby":
            raise FencedError(self._role, self._epoch)
        check_int(after_seq, "after_seq", minimum=0, maximum=MAX_TIME)
        check_int(new_epoch, "new_epoch", minimum=1, maximum=MAX_TIME)
        applied = len(self._journal)
        if applied < after_seq:
            raise CatchupIncompleteError(after_seq=after_seq, applied_seq=applied)
        if new_epoch <= self._max_epoch_seen:
            raise ValidationError(
                f"new_epoch={new_epoch} must be > max epoch seen in log "
                f"({self._max_epoch_seen}); cannot fence the old primary"
            )
        self._role = "primary"
        self._epoch = new_epoch
        self._max_epoch_seen = new_epoch
        self._fenced = False   # 新世代严格高于一切已知栅栏，接管即生效
        return FenceToken(epoch=new_epoch, after_seq=applied)

    def fence(self, token: FenceToken) -> None:
        """旧主接收接管凭证：若 token.epoch 更高则栅栏自身（幂等）。

        栅栏后一切写入（allocate/translate/release/advance）抛
        FencedError；只读接口不受影响。token.epoch 不高于当前已知
        最大世代时抛 ValidationError（凭证过旧，状态不变）。
        """
        if not isinstance(token, FenceToken):
            raise ValidationError(
                f"token must be FenceToken, got {type(token).__name__}"
            )
        if token.epoch <= self._max_epoch_seen and not self._fenced:
            raise ValidationError(
                f"fence token epoch={token.epoch} not newer than known max "
                f"epoch {self._max_epoch_seen}; refusing to fence"
            )
        if token.epoch > self._max_epoch_seen:
            self._max_epoch_seen = token.epoch
        self._fenced = True

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
        """计数快照：活跃映射数 / 占用端口 / 隔离端口 / 空闲端口 / 时钟 /
        当前世代 / 日志序号。"""
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
            "epoch": self._epoch,
            "last_seq": len(self._journal),
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
        check_mapping_key(key, "key")
