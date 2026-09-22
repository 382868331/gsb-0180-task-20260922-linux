"""错误语义：所有公开接口抛出的异常层级。

层级::

    NATError
    ├── ValidationError            非法输入（类型/取值/NaN/Infinity/bool 整数等）
    ├── PortExhaustionError        全池扫描后容量不足（证明无解）
    └── SearchBudgetExhaustedError 搜索预算耗尽（与证明无解分开）

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
