"""adnat —— 多租户地址依赖 NAT 端点生命周期的合成 UDP 状态库（离线，不发包）。

公开接口见 README.md；核心类为 AddressDependentNAT。
"""

from .core import AddressDependentNAT
from .errors import (
    NATError,
    PortExhaustionError,
    QuotaExceededError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    DEFAULT_TENANT,
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
    TenantConfig,
    TenantRequest,
    TranslationResult,
)

__all__ = [
    "AddressDependentNAT",
    "NATError",
    "ValidationError",
    "QuotaExceededError",
    "PortExhaustionError",
    "SearchBudgetExhaustedError",
    "Endpoint",
    "FiveTuple",
    "Packet",
    "Mapping",
    "AllocationRequest",
    "TenantRequest",
    "AllocationResult",
    "TranslationResult",
    "DropReason",
    "NATConfig",
    "TenantConfig",
    "DEFAULT_TENANT",
    "MAX_TIME",
    "MAX_BATCH_REQUESTS",
    "MAX_POOL_SIZE",
]

__version__ = "2.0.0"
