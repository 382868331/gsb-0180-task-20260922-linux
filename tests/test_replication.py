"""复制与栅栏接管契约测试：手工计算期望值，不依赖被测实现生成。

覆盖题面验收点：
- 创建/刷新/释放生成有序记录（seq 连续、内容精确）
- 备用按序应用；重复投递幂等；缺口拒绝且状态不变
- 备用追平指定序号后以更高栅栏世代接管；接管后继续分配
- 旧主被栅栏后一切写入拒绝；未接管备用写入拒绝
"""

from __future__ import annotations

import unittest

from adnat import (
    AddressDependentNAT,
    ApplyStatus,
    CatchupIncompleteError,
    DropReason,
    Endpoint,
    FenceToken,
    FencedError,
    JournalRecord,
    NATConfig,
    NATError,
    Packet,
    RecordKind,
    ReplicationGapError,
    ValidationError,
)

PUB = "203.0.113.7"
A = Endpoint("10.0.0.8", 40000)
B = Endpoint("10.0.0.9", 40001)
R1 = Endpoint("198.51.100.10", 53)
R2 = Endpoint("198.51.100.11", 53)
KEY1 = (A.ip, A.port, R1.ip, R1.port)
KEY2 = (A.ip, A.port, R2.ip, R2.port)
KEYB = (B.ip, B.port, R1.ip, R1.port)


def make_primary(ports=(6001, 6002, 6003), lifetime=10, quarantine=5,
                 epoch=1) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine,
    ), epoch=epoch)


def make_standby(ports=(6001, 6002, 6003), lifetime=10, quarantine=5
                 ) -> AddressDependentNAT:
    return AddressDependentNAT(NATConfig(
        public_ip=PUB, external_ports=ports,
        lifetime=lifetime, quarantine=quarantine,
    ), role="standby")


def pkt(src: Endpoint, dst: Endpoint, gen: int = 0) -> Packet:
    return Packet(src=src, dst=dst, generation=gen, payload=b"x")


class TestJournalGeneration(unittest.TestCase):
    """主实例的创建/刷新/释放产生精确的有序记录。"""

    def test_create_refresh_release_records(self):
        nat = make_primary()
        nat.allocate(A, R1)                       # t=0: CREATE seq=1
        nat.allocate(A, R2)                       # t=0: CREATE seq=2
        nat.translate_outbound(pkt(A, R1, gen=1), at=3)   # REFRESH seq=3
        nat.release(KEY2, at=4)                   # RELEASE seq=4

        log = nat.journal()
        self.assertEqual([r.seq for r in log], [1, 2, 3, 4])
        self.assertEqual([r.kind for r in log], [
            RecordKind.CREATE, RecordKind.CREATE,
            RecordKind.REFRESH, RecordKind.RELEASE,
        ])
        self.assertTrue(all(r.epoch == 1 for r in log))
        # CREATE #1：端口 6001（最小空闲）、generation 1、expires_at=0+10。
        self.assertEqual(log[0], JournalRecord(
            seq=1, epoch=1, kind=RecordKind.CREATE, key=KEY1, at=0,
            port=6001, generation=1, expires_at=10))
        # CREATE #2：同 key 不同目的 -> 新映射、新端口、新 generation。
        self.assertEqual(log[1], JournalRecord(
            seq=2, epoch=1, kind=RecordKind.CREATE, key=KEY2, at=0,
            port=6002, generation=2, expires_at=10))
        # REFRESH #3：t=3 成功改写，expires_at=3+10=13。
        self.assertEqual(log[2], JournalRecord(
            seq=3, epoch=1, kind=RecordKind.REFRESH, key=KEY1, at=3,
            expires_at=13))
        # RELEASE #4：t=4 显式释放。
        self.assertEqual(log[3], JournalRecord(
            seq=4, epoch=1, kind=RecordKind.RELEASE, key=KEY2, at=4))
        self.assertEqual(nat.last_seq, 4)

    def test_no_record_for_reuse_drop_or_failed_release(self):
        nat = make_primary()
        nat.allocate(A, R1)                       # seq=1
        nat.allocate(A, R1)                       # 复用：无记录
        nat.translate_outbound(pkt(A, R2))        # 无映射丢弃：无记录
        nat.release(KEY2)                         # 不存在：无记录
        nat.advance(3)                            # 时钟推进：无记录
        self.assertEqual(len(nat.journal()), 1)
        # 过期回收是派生事件，不写日志。
        nat.advance(10)                           # t=13 >= 10：映射过期
        self.assertEqual(len(nat.journal()), 1)

    def test_journal_since_is_incremental_and_idempotent(self):
        nat = make_primary()
        nat.allocate(A, R1)
        nat.allocate(A, R2)
        first = nat.journal(since=0)
        again = nat.journal(since=0)
        self.assertEqual(first, again)            # 重复读取一致（幂等）
        self.assertEqual(len(first), 2)
        rest = nat.journal(since=1)
        self.assertEqual([r.seq for r in rest], [2])
        self.assertEqual(nat.journal(since=2), [])
        with self.assertRaises(ValidationError):
            nat.journal(since=3)                  # 越过日志末尾
        with self.assertRaises(ValidationError):
            nat.journal(since=-1)


class TestStandbyApply(unittest.TestCase):
    """备用按序应用；重复幂等；缺口拒绝；失败不留半更新状态。"""

    def _primary_log(self):
        nat = make_primary()
        nat.allocate(A, R1)                       # seq=1 CREATE 6001 gen1
        nat.allocate(A, R2)                       # seq=2 CREATE 6002 gen2
        nat.translate_outbound(pkt(A, R1, gen=1), at=3)  # seq=3 REFRESH
        nat.release(KEY2, at=4)                   # seq=4 RELEASE
        return nat

    def test_apply_in_order_replays_state(self):
        primary = self._primary_log()
        standby = make_standby()
        for rec in primary.journal():
            res = standby.apply_record(rec)
            self.assertIs(res.status, ApplyStatus.APPLIED)
            self.assertEqual(res.seq, rec.seq)
        # 重放后与主实例状态一致（手工核对关键点）。
        self.assertEqual(standby.now, 4)
        self.assertEqual(standby.last_seq, 4)
        m1 = standby.get_mapping(KEY1)
        self.assertIsNotNone(m1)
        self.assertEqual((m1.external_port, m1.generation, m1.expires_at),
                         (6001, 1, 13))
        self.assertIsNone(standby.get_mapping(KEY2))     # 已释放
        self.assertEqual(standby.quarantined_ports(), {6002: 4})
        self.assertEqual(standby.snapshot_mappings(), primary.snapshot_mappings())
        self.assertEqual(standby.stats(), primary.stats())

    def test_duplicate_apply_is_idempotent(self):
        primary = self._primary_log()
        standby = make_standby()
        log = primary.journal()
        for rec in log:
            standby.apply_record(rec)
        before = (standby.snapshot_mappings(), standby.stats(),
                  standby.quarantined_ports())
        # 重放整条日志：全部判 DUPLICATE，状态不变。
        for rec in log:
            res = standby.apply_record(rec)
            self.assertIs(res.status, ApplyStatus.DUPLICATE)
        after = (standby.snapshot_mappings(), standby.stats(),
                 standby.quarantined_ports())
        self.assertEqual(before, after)
        self.assertEqual(standby.last_seq, 4)

    def test_conflicting_duplicate_rejected(self):
        primary = self._primary_log()
        standby = make_standby()
        rec1 = primary.journal()[0]
        standby.apply_record(rec1)
        # 同 seq 不同内容：不是合法重复，拒绝且状态不变。
        forged = JournalRecord(
            seq=1, epoch=1, kind=RecordKind.CREATE, key=KEY1, at=0,
            port=6002, generation=1, expires_at=10)
        before = standby.snapshot_mappings()
        with self.assertRaises(ValidationError):
            standby.apply_record(forged)
        self.assertEqual(standby.snapshot_mappings(), before)
        self.assertEqual(standby.last_seq, 1)

    def test_gap_rejected_without_mutation(self):
        primary = self._primary_log()
        standby = make_standby()
        log = primary.journal()
        standby.apply_record(log[0])              # seq=1
        before = (standby.snapshot_mappings(), standby.stats(), standby.now)
        with self.assertRaises(ReplicationGapError) as ctx:
            standby.apply_record(log[2])          # 跳到 seq=3，缺 seq=2
        err = ctx.exception
        self.assertIsInstance(err, NATError)
        self.assertEqual((err.expected, err.got), (2, 3))
        after = (standby.snapshot_mappings(), standby.stats(), standby.now)
        self.assertEqual(before, after)           # 状态与调用前一致
        # 补上缺口后可以继续。
        standby.apply_record(log[1])
        standby.apply_record(log[2])
        self.assertEqual(standby.last_seq, 3)

    def test_standby_writes_rejected(self):
        standby = make_standby()
        for op in (
            lambda: standby.allocate(A, R1),
            lambda: standby.translate_outbound(pkt(A, R1)),
            lambda: standby.translate_inbound(pkt(R1, Endpoint(PUB, 6001))),
            lambda: standby.release(KEY1),
            lambda: standby.advance(1),
        ):
            with self.assertRaises(FencedError):
                op()
        # 只读接口仍可用。
        self.assertEqual(standby.snapshot_mappings(), [])
        self.assertEqual(standby.stats()["live_mappings"], 0)

    def test_apply_on_primary_rejected(self):
        nat = make_primary()
        nat.allocate(A, R1)
        rec = nat.journal()[0]
        with self.assertRaises(FencedError):
            nat.apply_record(rec)

    def test_apply_validates_record_type_and_time(self):
        standby = make_standby()
        with self.assertRaises(ValidationError):
            standby.apply_record("not a record")
        # 时钟回退的记录拒绝（at < standby.now），状态不变。
        r1 = JournalRecord(seq=1, epoch=1, kind=RecordKind.CREATE,
                           key=KEY1, at=5, port=6001, generation=1,
                           expires_at=15)
        standby.apply_record(r1)
        r2 = JournalRecord(seq=2, epoch=1, kind=RecordKind.REFRESH,
                           key=KEY1, at=2, expires_at=12)
        before = (standby.snapshot_mappings(), standby.now)
        with self.assertRaises(ValidationError):
            standby.apply_record(r2)
        self.assertEqual((standby.snapshot_mappings(), standby.now), before)

    def test_apply_inconsistent_log_rejected_without_mutation(self):
        # 释放一条从未创建的映射：日志与状态不一致，拒绝且状态不变。
        standby = make_standby()
        bogus = JournalRecord(seq=1, epoch=1, kind=RecordKind.RELEASE,
                              key=KEY1, at=0)
        with self.assertRaises(ValidationError):
            standby.apply_record(bogus)
        self.assertEqual(standby.last_seq, 0)
        self.assertEqual(standby.now, 0)
        self.assertEqual(standby.snapshot_mappings(), [])


class TestPromoteAndFence(unittest.TestCase):
    """追平指定序号才能接管；更高栅栏世代；旧主写入被拒。"""

    def _primary_with_log(self):
        primary = make_primary()
        primary.allocate(A, R1)                   # seq=1
        primary.allocate(A, R2)                   # seq=2
        return primary

    def test_promote_requires_catchup(self):
        primary = self._primary_with_log()
        standby = make_standby()
        standby.apply_record(primary.journal()[0])       # 只追到 seq=1
        with self.assertRaises(CatchupIncompleteError) as ctx:
            standby.promote(after_seq=2, new_epoch=2)
        err = ctx.exception
        self.assertIsInstance(err, NATError)
        self.assertEqual((err.after_seq, err.applied_seq), (2, 1))
        self.assertEqual(standby.role, "standby")        # 未接管
        # 追平后接管成功。
        standby.apply_record(primary.journal()[1])
        token = standby.promote(after_seq=2, new_epoch=2)
        self.assertEqual(token, FenceToken(epoch=2, after_seq=2))
        self.assertEqual(standby.role, "primary")
        self.assertEqual(standby.epoch, 2)

    def test_promote_requires_higher_epoch(self):
        primary = self._primary_with_log()
        standby = make_standby()
        for rec in primary.journal():
            standby.apply_record(rec)
        with self.assertRaises(ValidationError):
            standby.promote(after_seq=2, new_epoch=1)    # 不高于日志世代
        self.assertEqual(standby.role, "standby")
        with self.assertRaises(ValidationError):
            standby.promote(after_seq=2, new_epoch=True)
        with self.assertRaises(ValidationError):
            standby.promote(after_seq=-1, new_epoch=2)

    def test_promote_on_primary_rejected(self):
        nat = self._primary_with_log()
        with self.assertRaises(FencedError):
            nat.promote(after_seq=2, new_epoch=2)

    def test_allocation_continues_after_takeover(self):
        primary = self._primary_with_log()
        standby = make_standby()
        for rec in primary.journal():
            standby.apply_record(rec)
        token = standby.promote(after_seq=2, new_epoch=2)
        self.assertEqual(token.after_seq, 2)
        # 接管后继续分配：端口/generation/seq 全部连续递增。
        r = standby.allocate(B, R1)
        self.assertTrue(r.created)
        self.assertEqual(r.mapping.external_port, 6003)  # 最小空闲
        self.assertEqual(r.mapping.generation, 3)        # 接续主实例代号
        new_records = standby.journal(since=2)
        self.assertEqual(len(new_records), 1)
        self.assertEqual(new_records[0], JournalRecord(
            seq=3, epoch=2, kind=RecordKind.CREATE, key=KEYB, at=0,
            port=6003, generation=3, expires_at=10))
        # 新主可正常推进时钟与释放。
        standby.advance(1)
        self.assertTrue(standby.release(KEYB))

    def test_fenced_old_primary_rejects_writes(self):
        primary = self._primary_with_log()
        standby = make_standby()
        for rec in primary.journal():
            standby.apply_record(rec)
        token = standby.promote(after_seq=2, new_epoch=2)

        primary.fence(token)
        self.assertTrue(primary.is_fenced)
        for op in (
            lambda: primary.allocate(B, R1),
            lambda: primary.translate_outbound(pkt(A, R1, gen=1)),
            lambda: primary.translate_inbound(
                pkt(R1, Endpoint(PUB, 6001), gen=1)),
            lambda: primary.release(KEY1),
            lambda: primary.advance(1),
        ):
            with self.assertRaises(FencedError) as ctx:
                op()
            self.assertIsInstance(ctx.exception, NATError)
        # 状态未被写入触动：两条映射都还在，时钟未动。
        self.assertEqual(primary.now, 0)
        self.assertEqual(len(primary.snapshot_mappings()), 2)
        # 只读接口不受影响。
        self.assertIsNotNone(primary.get_mapping(KEY1))
        self.assertEqual(len(primary.journal()), 2)

    def test_fence_is_idempotent_and_stale_token_rejected(self):
        primary = self._primary_with_log()
        standby = make_standby()
        for rec in primary.journal():
            standby.apply_record(rec)
        token = standby.promote(after_seq=2, new_epoch=2)

        with self.assertRaises(ValidationError):
            primary.fence(FenceToken(epoch=1, after_seq=2))  # 不更高
        self.assertFalse(primary.is_fenced)
        with self.assertRaises(ValidationError):
            primary.fence("not a token")
        primary.fence(token)
        primary.fence(token)                                # 幂等
        self.assertTrue(primary.is_fenced)
        # 已栅栏后更旧的凭证不再报错（保持栅栏，幂等语义）。
        primary.fence(FenceToken(epoch=1, after_seq=0))
        self.assertTrue(primary.is_fenced)

    def test_second_takeover_uses_even_higher_epoch(self):
        # 第一次接管后新主再产生记录；第二个备用重放全程并以
        # 更高世代再次接管。
        ports = (6001, 6002, 6003, 6004)
        p1 = make_primary(ports=ports)
        p1.allocate(A, R1)                # seq=1
        p1.allocate(A, R2)                # seq=2
        s1 = make_standby(ports=ports)
        for rec in p1.journal():
            s1.apply_record(rec)
        t1 = s1.promote(after_seq=2, new_epoch=2)
        p1.fence(t1)
        s1.allocate(B, R1)                # seq=3, epoch=2

        s2 = make_standby(ports=ports)
        for rec in s1.journal():
            s2.apply_record(rec)
        with self.assertRaises(ValidationError):
            s2.promote(after_seq=3, new_epoch=2)   # 必须严格更高
        t2 = s2.promote(after_seq=3, new_epoch=3)
        s1.fence(t2)
        with self.assertRaises(FencedError):
            s1.allocate(A, R1)
        r = s2.allocate(Endpoint("10.0.0.10", 40002), R1)
        self.assertEqual(r.mapping.external_port, 6004)
        self.assertEqual(r.mapping.generation, 4)
        self.assertEqual(s2.journal()[-1].epoch, 3)
        self.assertEqual(s2.journal()[-1].seq, 4)


class TestJournalRecordValidation(unittest.TestCase):
    """记录结构本身的输入校验：非法字段在构造时即拒绝。"""

    def test_field_validation(self):
        base = dict(seq=1, epoch=1, kind=RecordKind.CREATE, key=KEY1,
                    at=0, port=6001, generation=1, expires_at=10)
        good = JournalRecord(**base)
        self.assertEqual(good.seq, 1)
        for bad in (
            dict(base, seq=0), dict(base, seq=True), dict(base, seq=1.5),
            dict(base, epoch=0), dict(base, epoch=float("nan")),
            dict(base, kind="create"), dict(base, at=-1),
            dict(base, key=("10.0.0.8", 40000, "198.51.100.10")),
            dict(base, port=0), dict(base, port=65536),
            dict(base, generation=0), dict(base, expires_at=-1),
        ):
            with self.assertRaises(ValidationError, msg=str(bad)):
                JournalRecord(**bad)

    def test_kind_specific_fields(self):
        # CREATE 缺字段。
        with self.assertRaises(ValidationError):
            JournalRecord(seq=1, epoch=1, kind=RecordKind.CREATE,
                          key=KEY1, at=0)
        # REFRESH 必须带 expires_at 且不带 port/generation。
        with self.assertRaises(ValidationError):
            JournalRecord(seq=1, epoch=1, kind=RecordKind.REFRESH,
                          key=KEY1, at=0)
        with self.assertRaises(ValidationError):
            JournalRecord(seq=1, epoch=1, kind=RecordKind.REFRESH,
                          key=KEY1, at=0, port=6001, expires_at=10)
        # RELEASE 不得带负载字段。
        with self.assertRaises(ValidationError):
            JournalRecord(seq=1, epoch=1, kind=RecordKind.RELEASE,
                          key=KEY1, at=0, port=6001)
        ok = JournalRecord(seq=1, epoch=1, kind=RecordKind.RELEASE,
                           key=KEY1, at=0)
        self.assertIsNone(ok.port)

    def test_role_and_epoch_constructor_validation(self):
        cfg = NATConfig(public_ip=PUB, external_ports=(6001,))
        with self.assertRaises(ValidationError):
            AddressDependentNAT(cfg, role="master")
        with self.assertRaises(ValidationError):
            AddressDependentNAT(cfg, epoch=0)
        with self.assertRaises(ValidationError):
            AddressDependentNAT(cfg, epoch=True)
        nat = AddressDependentNAT(cfg, role="standby", epoch=7)
        self.assertEqual((nat.role, nat.epoch), ("standby", 7))


if __name__ == "__main__":
    unittest.main()
