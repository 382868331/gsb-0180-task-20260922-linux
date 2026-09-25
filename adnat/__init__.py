"""adnat —— 地址依赖 NAT 端点生命周期的合成 UDP 状态库（离线，不发包）。

公开接口见 README.md；核心类为 AddressDependentNAT。多租户扩展见
``NATConfig(tenants=...)``、``TenantConfig`` 与
``AddressDependentNAT.allocate_across_tenants``。
"""

from .core import DEFAULT_TENANT_ID, AddressDependentNAT
from .errors import (
    NATError,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_POOL_SIZE,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    DropReason,
    Endpoint,
    FiveTuple,
    Mapping,
    NATConfig,
    Packet,
    TenantAllocationRequest,
    TenantConfig,
    TranslationResult,
)

__all__ = [
    "AddressDependentNAT",
    "DEFAULT_TENANT_ID",
    "NATError",
    "ValidationError",
    "PortExhaustionError",
    "SearchBudgetExhaustedError",
    "QuotaExceededError",
    "Endpoint",
    "FiveTuple",
    "Packet",
    "Mapping",
    "AllocationRequest",
    "TenantAllocationRequest",
    "AllocationResult",
    "TranslationResult",
    "DropReason",
    "NATConfig",
    "TenantConfig",
    "MAX_TIME",
    "MAX_BATCH_REQUESTS",
    "MAX_POOL_SIZE",
]

__version__ = "1.1.0"
