"""复制与接管测试：有序记录、备用按序重放、幂等重复、缺口/冲突拒绝、
栅栏接管与旧主写入拒绝。

所有期望值均手工推算（推算过程见 drive_primary 注释与各用例），
不调用被测实现生成期望值；最后的随机重放是一致性交叉核对
（主实例产生记录、独立的重放路径重建状态，双方逐状态比对）。
"""

from __future__ import annotations

import dataclasses
import random
import unittest

from adnat import (
    AddressDependentNAT,
    AllocationRequest,
    ApplyOutcome,
    DropReason,
    Endpoint,
    JournalConflictError,
    JournalGapError,
    JournalKind,
    JournalRecord,
    NATConfig,
    NATError,
    NotCaughtUpError,
    Packet,
    PortExhaustionError,
    ReplicationError,
    RoleError,
    StaleFenceError,
    ValidationError,
)

PUB = "203.0.113.7"
A = Endpoint("10.0.0.8", 40000)
B = Endpoint("10.0.0.9", 40000)
C = Endpoint("10.0.0.10", 40000)
D = Endpoint("10.0.0.11", 40000)
R1 = Endpoint("198.51.100.10", 53)
R2 = Endpoint("198.51.100.11", 53)
KEY_A_R1 = (A.ip, A.port, R1.ip, R1.port)
KEY_A_R2 = (A.ip, A.port, R2.ip, R2.port)
KEY_B_R1 = (B.ip, B.port, R1.ip, R1.port)
KEY_C_R1 = (C.ip, C.port, R1.ip, R1.port)
KEY_D_R1 = (D.ip, D.port, R1.ip, R1.port)

POOL = (6001, 6002, 6003)


def make_primary() -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=POOL, lifetime=10, quarantine=5))


def make_standby() -> AddressDependentNAT:
    return AddressDependentNAT.standby(NATConfig(
        public_ip=PUB, external_ports=POOL, lifetime=10, quarantine=5))


def drive_primary() -> AddressDependentNAT:
    """手算脚本（lifetime=10, quarantine=5），产生 5 条记录：

    t=0  allocate(A,R1) -> rec1 CREATE  6001 gen1 expires=10
    t=0  allocate(A,R2) -> rec2 CREATE  6002 gen2 expires=10
    t=5  translate(A->R1, gen=1) -> rec3 REFRESH 6001 gen1 expires=15
    t=5  release(KEY_A_R2) -> rec4 RELEASE 6002 gen2；6002 隔离至 t=10
    t=15 housekeeping：KEY_A_R1 到期（expires=15），6001 自 15 起隔离；
         6002 隔离结束（15 >= 5+5）
    t=15 allocate(B,R1) -> 6001 隔离中，最小空闲 6002
         -> rec5 CREATE 6002 gen3 expires=25
    """
    nat = make_primary()
    nat.allocate(A, R1)
    nat.allocate(A, R2)
    nat.advance(5)
    nat.translate_outbound(Packet(src=A, dst=R1, generation=1))
    nat.release(KEY_A_R2)
    nat.advance(10)
    nat.allocate(B, R1)
    return nat


def replayed_standby() -> tuple[AddressDependentNAT, AddressDependentNAT]:
    """驱动主实例并把全部记录重放到新备用，返回 (primary, standby)。"""
    primary = drive_primary()
    standby = make_standby()
    for rec in primary.journal():
        outcome = standby.apply_record(rec)
        assert outcome is ApplyOutcome.APPLIED
    return primary, standby


class TestJournalEmission(unittest.TestCase):
    """创建/刷新/释放生成有序记录；复用、advance、失败批量不产生记录。"""

    def test_create_refresh_release_records(self):
        nat = drive_primary()
        recs = nat.journal()
        self.assertEqual(len(recs), 5)
        self.assertEqual(nat.last_seq, 5)
        # rec1: CREATE KEY_A_R1 @0 port 6001 gen1 expires 10
        self.assertEqual(
            (recs[0].seq, recs[0].fence, recs[0].kind, recs[0].key,
             recs[0].at, recs[0].external_port, recs[0].generation,
             recs[0].expires_at),
            (1, 1, JournalKind.CREATE, KEY_A_R1, 0, 6001, 1, 10))
        # rec2: CREATE KEY_A_R2 @0 port 6002 gen2 expires 10
        self.assertEqual(
            (recs[1].seq, recs[1].kind, recs[1].key, recs[1].at,
             recs[1].external_port, recs[1].generation, recs[1].expires_at),
            (2, JournalKind.CREATE, KEY_A_R2, 0, 6002, 2, 10))
        # rec3: REFRESH KEY_A_R1 @5 port 6001 gen1 expires 15
        self.assertEqual(
            (recs[2].seq, recs[2].kind, recs[2].key, recs[2].at,
             recs[2].external_port, recs[2].generation, recs[2].expires_at),
            (3, JournalKind.REFRESH, KEY_A_R1, 5, 6001, 1, 15))
        # rec4: RELEASE KEY_A_R2 @5 port 6002 gen2 expires None
        self.assertEqual(
            (recs[3].seq, recs[3].kind, recs[3].key, recs[3].at,
             recs[3].external_port, recs[3].generation, recs[3].expires_at),
            (4, JournalKind.RELEASE, KEY_A_R2, 5, 6002, 2, None))
        # rec5: CREATE KEY_B_R1 @15 port 6002 gen3 expires 25
        self.assertEqual(
            (recs[4].seq, recs[4].kind, recs[4].key, recs[4].at,
             recs[4].external_port, recs[4].generation, recs[4].expires_at),
            (5, JournalKind.CREATE, KEY_B_R1, 15, 6002, 3, 25))
        # 全部记录携带当前栅栏世代 1，seq 连续。
        self.assertEqual([r.fence for r in recs], [1] * 5)
        self.assertEqual([r.seq for r in recs], [1, 2, 3, 4, 5])

    def test_no_record_for_reuse_advance_drop_and_rollback(self):
        nat = make_primary()
        nat.allocate(A, R1)                       # rec1
        reused = nat.allocate(A, R1)              # 复用：无记录
        self.assertFalse(reused.created)
        nat.advance(3)                            # 纯时钟：无记录
        dropped = nat.translate_outbound(Packet(src=B, dst=R1))
        self.assertIs(dropped.reason, DropReason.NO_MAPPING)  # 丢弃：无记录
        self.assertEqual(nat.last_seq, 1)
        # 容量不足整体回滚：池 3 口占 1，申请 3 个新 key -> 无解，日志不变。
        before = nat.journal()
        with self.assertRaises(PortExhaustionError):
            nat.allocate_many([
                AllocationRequest(B, R1),
                AllocationRequest(C, R1),
                AllocationRequest(D, R1),
            ])
        self.assertEqual(nat.journal(), before)
        self.assertEqual(nat.last_seq, 1)


class TestStandbyReplay(unittest.TestCase):
    """备用按序应用记录，重放后与主逐状态一致（手算期望值）。"""

    def test_replay_matches_primary(self):
        primary, standby = replayed_standby()
        # 日志逐条相等（冻结数据类全字段相等）。
        self.assertEqual(standby.journal(), primary.journal())
        self.assertEqual(standby.last_seq, 5)
        self.assertEqual(standby.now, 15)
        # 手算最终状态：只剩 KEY_B_R1（6002, gen3, created=15, expires=25）。
        snap = standby.snapshot_mappings()
        self.assertEqual(len(snap), 1)
        m = snap[0]
        self.assertEqual(
            (m.key, m.external_port, m.generation, m.created_at,
             m.last_seen, m.expires_at),
            (KEY_B_R1, 6002, 3, 15, 15, 25))
        # 6001 自 expires_at=15 起隔离（quarantine=5，t=20 解除）。
        self.assertEqual(standby.quarantined_ports(), {6001: 15})
        # 与主实例公开状态一致。
        self.assertEqual(standby.snapshot_mappings(),
                         primary.snapshot_mappings())
        self.assertEqual(standby.quarantined_ports(),
                         primary.quarantined_ports())

    def test_duplicate_is_idempotent(self):
        primary = drive_primary()
        recs = primary.journal()
        standby = make_standby()
        self.assertIs(standby.apply_record(recs[0]), ApplyOutcome.APPLIED)
        before = (standby.snapshot_mappings(), standby.quarantined_ports(),
                  standby.now, standby.last_seq)
        # 同一条记录再次应用：幂等，状态完全不变。
        self.assertIs(standby.apply_record(recs[0]), ApplyOutcome.DUPLICATE)
        after = (standby.snapshot_mappings(), standby.quarantined_ports(),
                 standby.now, standby.last_seq)
        self.assertEqual(before, after)
        for rec in recs[1:]:
            self.assertIs(standby.apply_record(rec), ApplyOutcome.APPLIED)
        # 乱序重发中间的旧记录同样幂等。
        self.assertIs(standby.apply_record(recs[2]), ApplyOutcome.DUPLICATE)
        self.assertIs(standby.apply_record(recs[0]), ApplyOutcome.DUPLICATE)
        self.assertEqual(standby.last_seq, 5)
        self.assertEqual(standby.journal(), primary.journal())

    def test_gap_rejected_state_unchanged(self):
        primary = drive_primary()
        recs = primary.journal()
        standby = make_standby()
        self.assertIs(standby.apply_record(recs[0]), ApplyOutcome.APPLIED)
        before = (standby.snapshot_mappings(), standby.quarantined_ports(),
                  standby.now, standby.last_seq, standby.journal())
        # 跳过 seq=2 直接应用 seq=3 -> 缺口，状态不变。
        with self.assertRaises(JournalGapError) as ctx:
            standby.apply_record(recs[2])
        err = ctx.exception
        self.assertIsInstance(err, ReplicationError)
        self.assertIsInstance(err, NATError)
        self.assertEqual((err.expected, err.got), (2, 3))
        after = (standby.snapshot_mappings(), standby.quarantined_ports(),
                 standby.now, standby.last_seq, standby.journal())
        self.assertEqual(before, after)

    def test_same_seq_different_content_conflict(self):
        primary = drive_primary()
        rec1 = primary.journal()[0]
        standby = make_standby()
        standby.apply_record(rec1)
        forged = dataclasses.replace(rec1, external_port=6003)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged)
        self.assertEqual(standby.last_seq, 1)

    def test_state_conflicts_rejected_before_mutation(self):
        primary = drive_primary()
        recs = primary.journal()

        # 刷新未知映射。
        standby = make_standby()
        forged_refresh = dataclasses.replace(recs[2], seq=1)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_refresh)
        self.assertEqual(standby.last_seq, 0)

        # 释放未知映射。
        standby = make_standby()
        standby.apply_record(recs[0])
        forged_release = dataclasses.replace(recs[3], seq=2)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_release)
        self.assertEqual(standby.last_seq, 1)

        # CREATE 端口已被占用。
        standby = make_standby()
        standby.apply_record(recs[0])           # 6001 被 KEY_A_R1 占用
        forged_port = dataclasses.replace(recs[1], external_port=6001)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_port)
        self.assertEqual(standby.last_seq, 1)

        # CREATE 端口不在配置池内。
        forged_pool = dataclasses.replace(recs[1], external_port=6999)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_pool)
        self.assertEqual(standby.last_seq, 1)

        # CREATE 端口仍在隔离：重放 rec1..rec4 后 t=5，6002 隔离至 t=10；
        # 伪造一条 t=7 的 CREATE 6002 -> 冲突。
        standby = make_standby()
        for rec in recs[:4]:
            standby.apply_record(rec)
        self.assertEqual(standby.quarantined_ports(), {6002: 5})
        forged_quar = dataclasses.replace(recs[4], at=7, expires_at=17)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_quar)
        self.assertEqual(standby.last_seq, 4)

        # 记录时刻早于当前时钟 -> 冲突。
        forged_clock = dataclasses.replace(recs[4], at=3, expires_at=13)
        with self.assertRaises(JournalConflictError):
            standby.apply_record(forged_clock)
        self.assertEqual(standby.last_seq, 4)
        self.assertEqual(standby.now, 5)


class TestPromoteTakeover(unittest.TestCase):
    """追平指定序号后以更高栅栏接管；接管后拒绝旧主写入，分配连续。"""

    def test_takeover_rejects_old_primary_and_continues(self):
        primary, standby = replayed_standby()
        # 追平 seq=5，以更高栅栏 2 接管。
        standby.promote(through_seq=5, new_fence=2)
        self.assertEqual(standby.role, "primary")
        self.assertEqual(standby.fence, 2)

        # 旧主（fence=1）继续写入：t=15 时 6001 隔离、6002 被 B 占用，
        # 只能拿 6003 -> rec6' CREATE KEY_C_R1 6003 gen4 expires=25。
        old_res = primary.allocate(C, R1)
        self.assertEqual(old_res.mapping.external_port, 6003)
        old_rec = primary.journal()[-1]
        self.assertEqual((old_rec.seq, old_rec.fence), (6, 1))

        # 新主拒绝旧主记录：StaleFenceError，状态不变。
        before = (standby.snapshot_mappings(), standby.quarantined_ports(),
                  standby.last_seq)
        with self.assertRaises(StaleFenceError) as ctx:
            standby.apply_record(old_rec)
        err = ctx.exception
        self.assertEqual((err.seq, err.record_fence, err.current_fence),
                         (6, 1, 2))
        after = (standby.snapshot_mappings(), standby.quarantined_ports(),
                 standby.last_seq)
        self.assertEqual(before, after)

        # 接管后继续分配：seq / generation 连续，栅栏为 2。
        new_res = standby.allocate(D, R1)
        self.assertEqual(new_res.mapping.external_port, 6003)   # 最小空闲
        self.assertEqual(new_res.mapping.generation, 4)         # 延续，不重置
        new_rec = standby.journal()[-1]
        self.assertEqual((new_rec.seq, new_rec.fence), (6, 2))
        self.assertEqual(new_rec.key, KEY_D_R1)
        self.assertEqual(new_rec.expires_at, 25)

        # 旧主同序号记录再次流入：内容不同 -> 冲突拒绝（仍是旧主写入）。
        with self.assertRaises(JournalConflictError):
            standby.apply_record(old_rec)
        self.assertEqual(standby.last_seq, 6)

    def test_promote_requires_caught_up(self):
        primary = drive_primary()
        recs = primary.journal()
        standby = make_standby()
        for rec in recs[:4]:                    # 只追平到 seq=4
            standby.apply_record(rec)
        with self.assertRaises(NotCaughtUpError) as ctx:
            standby.promote(through_seq=5, new_fence=2)
        err = ctx.exception
        self.assertEqual((err.through_seq, err.applied_seq), (5, 4))
        # 接管失败不改变角色与栅栏。
        self.assertEqual(standby.role, "standby")
        self.assertEqual(standby.fence, 1)
        # 补齐记录后可以接管。
        standby.apply_record(recs[4])
        standby.promote(through_seq=5, new_fence=2)
        self.assertEqual(standby.role, "primary")
        self.assertEqual(standby.fence, 2)

    def test_promote_fence_must_be_higher(self):
        standby = make_standby()
        for bad_fence in (1, 0, -3):
            with self.assertRaises(ValidationError, msg=f"fence={bad_fence}"):
                standby.promote(through_seq=0, new_fence=bad_fence)
        for bad_seq in (-1, 1.5, True, float("nan")):
            with self.assertRaises(ValidationError, msg=f"seq={bad_seq!r}"):
                standby.promote(through_seq=bad_seq)
        with self.assertRaises(ValidationError):
            standby.promote(through_seq=0, new_fence=True)
        # 缺省 new_fence = 当前栅栏 + 1。
        standby.promote(through_seq=0)
        self.assertEqual(standby.fence, 2)
        self.assertEqual(standby.role, "primary")

    def test_promote_on_primary_rejected(self):
        nat = drive_primary()
        with self.assertRaises(RoleError):
            nat.promote(through_seq=0)


class TestStandbyRole(unittest.TestCase):
    """备用实例只读：本地写入一律拒绝，只读接口可用。"""

    def test_standby_rejects_local_writes(self):
        standby = make_standby()
        with self.assertRaises(RoleError):
            standby.allocate(A, R1)
        with self.assertRaises(RoleError):
            standby.allocate_many([AllocationRequest(A, R1)])
        with self.assertRaises(RoleError):
            standby.translate_outbound(Packet(src=A, dst=R1))
        with self.assertRaises(RoleError):
            standby.translate_inbound(
                Packet(src=R1, dst=Endpoint(PUB, 6001)))
        with self.assertRaises(RoleError):
            standby.release(KEY_A_R1)
        with self.assertRaises(RoleError):
            standby.advance(1)
        # 拒绝写入后状态不变。
        self.assertEqual(standby.snapshot_mappings(), [])
        self.assertEqual(standby.now, 0)
        self.assertEqual(standby.last_seq, 0)

    def test_standby_readonly_views(self):
        standby = make_standby()
        self.assertEqual(standby.role, "standby")
        self.assertEqual(standby.fence, 1)
        self.assertEqual(standby.last_seq, 0)
        self.assertEqual(standby.journal(), ())
        self.assertEqual(standby.snapshot_mappings(), [])
        self.assertEqual(standby.quarantined_ports(), {})
        self.assertIsNone(standby.get_mapping(KEY_A_R1))
        self.assertEqual(standby.stats()["live_mappings"], 0)


class TestJournalRecordValidation(unittest.TestCase):
    """记录本身是严格校验的冻结值对象；非法输入在任何变更前拒绝。"""

    def _valid(self, **over):
        fields = dict(seq=1, fence=1, kind=JournalKind.CREATE, key=KEY_A_R1,
                      at=0, external_port=6001, generation=1, expires_at=10)
        fields.update(over)
        return JournalRecord(**fields)

    def test_field_validation(self):
        self._valid()  # 基准合法
        for bad in (0, -1, True, 1.5, float("nan")):
            with self.assertRaises(ValidationError, msg=f"seq={bad!r}"):
                self._valid(seq=bad)
            with self.assertRaises(ValidationError, msg=f"fence={bad!r}"):
                self._valid(fence=bad)
        with self.assertRaises(ValidationError):
            self._valid(kind="create")
        with self.assertRaises(ValidationError):
            self._valid(key=("10.0.0.8", 40000, "198.51.100.10"))
        with self.assertRaises(ValidationError):
            self._valid(key=("10.0.0.01", 40000, "198.51.100.10", 53))
        with self.assertRaises(ValidationError):
            self._valid(at=-1)
        with self.assertRaises(ValidationError):
            self._valid(external_port=0)
        with self.assertRaises(ValidationError):
            self._valid(generation=0)
        # CREATE/REFRESH 必须带 expires_at 且 > at；RELEASE 必须为 None。
        with self.assertRaises(ValidationError):
            self._valid(expires_at=None)
        with self.assertRaises(ValidationError):
            self._valid(at=10, expires_at=10)
        with self.assertRaises(ValidationError):
            self._valid(kind=JournalKind.RELEASE, expires_at=10)
        self._valid(kind=JournalKind.RELEASE, expires_at=None)  # 合法

    def test_apply_rejects_non_record(self):
        standby = make_standby()
        for bad in ("rec", 1, None, (1, 2, 3)):
            with self.assertRaises(ValidationError, msg=f"record={bad!r}"):
                standby.apply_record(bad)
        self.assertEqual(standby.last_seq, 0)


class TestDeterministicReplayCrossCheck(unittest.TestCase):
    """随机操作交叉核对：主实例产生记录，备用重放，逐状态一致。

    这是主（旧代码路径产生日志）与重放（新代码路径重建状态）两条
    独立路径之间的一致性核对，种子固定可复现。
    """

    def test_random_ops_replay_consistent(self):
        rng = random.Random(20260924)
        ports = tuple(range(7001, 7009))        # 8 口
        internals = [Endpoint(f"10.2.0.{i}", 5000) for i in (1, 2, 3)]
        remotes = [Endpoint("198.51.100.1", 53), Endpoint("198.51.100.2", 443)]
        keys = [(i, r) for i in internals for r in remotes]   # 6 个 key
        cfg = NATConfig(public_ip=PUB, external_ports=ports,
                        lifetime=5, quarantine=0)
        primary = AddressDependentNAT(cfg)
        standby = AddressDependentNAT.standby(cfg)
        known_gen: dict[tuple, int] = {}

        def drain():
            for rec in primary.journal()[standby.last_seq:]:
                self.assertIs(standby.apply_record(rec), ApplyOutcome.APPLIED)

        for _ in range(300):
            roll = rng.random()
            internal, remote = rng.choice(keys)
            key = (internal.ip, internal.port, remote.ip, remote.port)
            if roll < 0.50:                     # 分配
                res = primary.allocate(internal, remote)
                known_gen[key] = res.mapping.generation
            elif roll < 0.75:                   # 出站包（可能刷新）
                gen = known_gen.get(key, 0)
                primary.translate_outbound(Packet(
                    src=internal, dst=remote,
                    generation=gen if rng.random() < 0.5 else 0))
            elif roll < 0.90:                   # 释放
                primary.release(key)
            else:                               # 推进时钟
                primary.advance(rng.randint(0, 3))
            drain()
        # 用一个同步事件对齐两侧时钟（advance 不产生记录）。
        sync = primary.allocate(Endpoint("10.2.0.9", 5000), remotes[0])
        drain()
        self.assertEqual(standby.now, primary.now)
        self.assertEqual(standby.journal(), primary.journal())
        self.assertEqual(standby.snapshot_mappings(),
                         primary.snapshot_mappings())
        self.assertEqual(standby.quarantined_ports(),
                         primary.quarantined_ports())
        # 接管后分配与主继续分配产生相同映射（端口/generation 连续一致）。
        standby.promote(through_seq=standby.last_seq)
        fresh = Endpoint("10.2.0.10", 5000)
        p_new = primary.allocate(fresh, remotes[0])
        s_new = standby.allocate(fresh, remotes[0])
        self.assertEqual(s_new.mapping.external_port,
                         p_new.mapping.external_port)
        self.assertEqual(s_new.mapping.generation, p_new.mapping.generation)
        self.assertEqual(standby.journal()[-1].fence, 2)
        self.assertEqual(sync.created, True)


if __name__ == "__main__":
    unittest.main()
