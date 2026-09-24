"""adnat —— 地址依赖 NAT 端点生命周期的合成 UDP 状态库（离线，不发包）。

公开接口见 README.md；核心类为 AddressDependentNAT。
"""

from .core import AddressDependentNAT
from .errors import (
    CatchupIncompleteError,
    FencedError,
    NATError,
    PortExhaustionError,
    ReplicationGapError,
    SearchBudgetExhaustedError,
    ValidationError,
)
from .model import (
    MAX_BATCH_REQUESTS,
    MAX_POOL_SIZE,
    MAX_TIME,
    AllocationRequest,
    AllocationResult,
    ApplyResult,
    ApplyStatus,
    DropReason,
    Endpoint,
    FenceToken,
    FiveTuple,
    JournalRecord,
    Mapping,
    NATConfig,
    Packet,
    RecordKind,
    TranslationResult,
)

__all__ = [
    "AddressDependentNAT",
    "NATError",
    "ValidationError",
    "PortExhaustionError",
    "SearchBudgetExhaustedError",
    "ReplicationGapError",
    "CatchupIncompleteError",
    "FencedError",
    "Endpoint",
    "FiveTuple",
    "Packet",
    "Mapping",
    "AllocationRequest",
    "AllocationResult",
    "TranslationResult",
    "DropReason",
    "NATConfig",
    "JournalRecord",
    "RecordKind",
    "ApplyResult",
    "ApplyStatus",
    "FenceToken",
    "MAX_TIME",
    "MAX_BATCH_REQUESTS",
    "MAX_POOL_SIZE",
]

__version__ = "1.1.0"
