"""错误语义：所有公开接口抛出的异常层级。

层级::

    NATError
    ├── ValidationError            非法输入（类型/取值/NaN/Infinity/bool 整数等）
    ├── QuotaExceededError         租户活跃映射配额不足（与端口容量分开）
    ├── PortExhaustionError        全池（子池）扫描后容量不足（证明无解）
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


class QuotaExceededError(NATError):
    """租户活跃映射配额不足：候选时刻过期回收后，活跃数 + 本批新建数超限。

    与端口容量无关：即使该租户子池里还有空闲端口，配额不足也单独报这个错，
    绝不伪装成 PortExhaustionError / SearchBudgetExhaustedError。

    属性:
        tenant_id: 触顶的租户 ID。
        active:    候选时刻过期回收后该租户的活跃映射数。
        new:       本批拟为该租户新建的映射数（复用不计数）。
        limit:     该租户的最大活跃映射数。
    """

    def __init__(self, tenant_id: str, active: int, new: int, limit: int) -> None:
        self.tenant_id = tenant_id
        self.active = active
        self.new = new
        self.limit = limit
        super().__init__(
            f"tenant {tenant_id!r} active-mapping quota exceeded: "
            f"active={active} new={new} limit={limit}"
        )


class PortExhaustionError(NATError):
    """容量不足且已证明无解：扫描了整个（租户子）池仍凑不齐所需空闲端口。

    属性:
        needed:    本次需要的新端口数。
        available: 当前（含时间推进后的过期回收）可用端口数。
        pool_size: （租户子）池总大小。
        tenant:    所属租户 ID；旧接口下为默认租户。
    """

    def __init__(self, needed: int, available: int, pool_size: int,
                 tenant: str | None = None) -> None:
        self.needed = needed
        self.available = available
        self.pool_size = pool_size
        self.tenant = tenant
        super().__init__(
            f"port pool exhausted for tenant {tenant!r}: needed={needed} "
            f"available={available} pool_size={pool_size} "
            f"(full scan proves infeasible)"
        )


class SearchBudgetExhaustedError(NATError):
    """搜索预算耗尽： inspected 端口数达到 search_budget 仍未凑齐所需端口。

    与 PortExhaustionError 分开：此时并未扫描全（子）池，不能断定无解，
    只是预算内找不到。调大 search_budget 后可能成功。跨租户批量中每个
    租户独立计一次预算（各自扫描自己的子池）。

    属性:
        budget:    生效的搜索预算（最多检查的端口数）。
        inspected: 实际检查过的端口数（== budget）。
        needed:    本次需要的新端口数。
        found:     预算内找到的空闲端口数。
        tenant:    所属租户 ID；旧接口下为默认租户。
    """

    def __init__(self, budget: int, inspected: int, needed: int, found: int,
                 tenant: str | None = None) -> None:
        self.budget = budget
        self.inspected = inspected
        self.needed = needed
        self.found = found
        self.tenant = tenant
        super().__init__(
            f"port search budget exhausted for tenant {tenant!r}: "
            f"budget={budget} inspected={inspected} needed={needed} "
            f"found={found} (pool not fully scanned; infeasibility NOT proven)"
        )
