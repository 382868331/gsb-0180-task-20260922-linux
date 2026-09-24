"""错误语义：所有公开接口抛出的异常层级。

层级::

    NATError
    ├── ValidationError            非法输入（类型/取值/NaN/Infinity/bool 整数等）
    ├── PortExhaustionError        全池扫描后容量不足（证明无解）
    ├── SearchBudgetExhaustedError 搜索预算耗尽（与证明无解分开）
    └── ReplicationError           复制/接管相关错误的公共基类
        ├── RoleError              角色不允许该操作（备用本地写入 / 主上 promote）
        ├── JournalGapError        记录序号缺口（必须按序应用）
        ├── JournalConflictError   记录与已应用历史或当前状态冲突
        ├── StaleFenceError        记录来自旧栅栏世代（旧主写入，接管后拒绝）
        └── NotCaughtUpError       备用未追平指定序号即请求接管

所有异常消息均带字段名与实收值，便于定位。
"""

from __future__ import annotations


class NATError(Exception):
    """本库所有异常的公共基类。"""


class ValidationError(NATError, ValueError):
    """非法输入：类型不符、取值越界、NaN/Infinity、bool 充当整数等。

    在任何状态变更之前抛出；抛出时 NAT 状态保持不变。
    """


class PortExhaustionError(NATError):
    """容量不足且已证明无解：扫描了整个端口池仍凑不齐所需空闲端口。

    属性:
        needed:    本次需要的新端口数。
        available: 当前（含时间推进后的过期回收）可用端口数。
        pool_size: 端口池总大小。
    """

    def __init__(self, needed: int, available: int, pool_size: int) -> None:
        self.needed = needed
        self.available = available
        self.pool_size = pool_size
        super().__init__(
            f"port pool exhausted: needed={needed} available={available} "
            f"pool_size={pool_size} (full scan proves infeasible)"
        )


class SearchBudgetExhaustedError(NATError):
    """搜索预算耗尽： inspected 端口数达到 search_budget 仍未凑齐所需端口。

    与 PortExhaustionError 分开：此时并未扫描全池，不能断定无解，
    只是预算内找不到。调大 search_budget 后可能成功。

    属性:
        budget:    生效的搜索预算（最多检查的端口数）。
        inspected: 实际检查过的端口数（== budget）。
        needed:    本次需要的新端口数。
        found:     预算内找到的空闲端口数。
    """

    def __init__(self, budget: int, inspected: int, needed: int, found: int) -> None:
        self.budget = budget
        self.inspected = inspected
        self.needed = needed
        self.found = found
        super().__init__(
            f"port search budget exhausted: budget={budget} inspected={inspected} "
            f"needed={needed} found={found} (pool not fully scanned; "
            f"infeasibility NOT proven)"
        )


class ReplicationError(NATError):
    """复制/接管相关错误的公共基类。抛出时 NAT 状态保持不变。"""


class RoleError(ReplicationError):
    """角色不允许该操作：备用实例执行本地写入，或对主实例调用 promote。"""


class JournalGapError(ReplicationError):
    """记录序号缺口：期望 expected，实收 got。记录必须按 seq 逐条应用。

    属性:
        expected: 下一条应应用的序号（last_seq + 1）。
        got:      实收记录的序号。
    """

    def __init__(self, expected: int, got: int) -> None:
        self.expected = expected
        self.got = got
        super().__init__(
            f"journal gap: expected seq={expected}, got seq={got} "
            f"(records must be applied in order)"
        )


class JournalConflictError(ReplicationError):
    """记录与已应用历史或当前状态冲突。

    包括：同一 seq 内容不同的"重复"记录、刷新/释放未知映射、
    创建端口被占用或仍在隔离、记录时刻早于当前时钟等。
    """


class StaleFenceError(ReplicationError):
    """记录来自旧栅栏世代（旧主写入）：record_fence < 当前栅栏，拒绝应用。

    属性:
        seq:           实收记录的序号。
        record_fence:  记录携带的栅栏世代。
        current_fence: 本实例当前栅栏世代。
    """

    def __init__(self, seq: int, record_fence: int, current_fence: int) -> None:
        self.seq = seq
        self.record_fence = record_fence
        self.current_fence = current_fence
        super().__init__(
            f"stale fence: record seq={seq} fence={record_fence} < "
            f"current fence={current_fence} (old primary write rejected)"
        )


class NotCaughtUpError(ReplicationError):
    """备用尚未追平指定序号，拒绝接管。

    属性:
        through_seq: 调用方要求追平的序号。
        applied_seq: 备用实际已应用的最大序号（last_seq）。
    """

    def __init__(self, through_seq: int, applied_seq: int) -> None:
        self.through_seq = through_seq
        self.applied_seq = applied_seq
        super().__init__(
            f"not caught up: required through_seq={through_seq} but "
            f"applied_seq={applied_seq} (apply missing records first)"
        )
