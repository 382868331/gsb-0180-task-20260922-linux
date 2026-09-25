"""adnat —— 地址依赖 NAT 端点生命周期的合成 UDP 状态库（离线，不发包）。

公开接口见 README.md；核心类为 AddressDependentNAT。
"""

from .core import AddressDependentNAT
from .errors import (
    NATError,
    PortExhaustionError,
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
    HairpinResult,
    Mapping,
    NATConfig,
    Packet,
    TranslationResult,
)

__all__ = [
    "AddressDependentNAT",
    "NATError",
    "ValidationError",
    "PortExhaustionError",
    "SearchBudgetExhaustedError",
    "Endpoint",
    "FiveTuple",
    "Packet",
    "Mapping",
    "AllocationRequest",
    "AllocationResult",
    "TranslationResult",
    "HairpinResult",
    "DropReason",
    "NATConfig",
    "MAX_TIME",
    "MAX_BATCH_REQUESTS",
    "MAX_POOL_SIZE",
]

__version__ = "1.1.0"
