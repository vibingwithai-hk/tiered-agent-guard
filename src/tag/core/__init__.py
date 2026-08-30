"""Core models, interfaces, and exceptions for TAG."""

from tag.core.enums import (
    ToolTier,
    Verdict,
    RiskLevel,
    TicketStatus,
    UserRole,
)
from tag.core.contracts import (
    CallerContext,
    ToolExecutionRequest,
    GatekeeperDecision,
    ApprovalCard,
    ExecutionResult,
    utc_now,
)
from tag.core.exceptions import (
    TAGException,
    SecurityValidationError,
    SuspensionException,
    ApprovalExpiredError,
    ApprovalTamperedError,
    CircuitBreakerTrippedError,
    UnauthorizedError,
)
from tag.core.state_store import (
    StateStore,
    InMemoryTicketStore,
)

__all__ = [
    "ToolTier",
    "Verdict",
    "RiskLevel",
    "TicketStatus",
    "UserRole",
    "CallerContext",
    "ToolExecutionRequest",
    "GatekeeperDecision",
    "ApprovalCard",
    "ExecutionResult",
    "utc_now",
    "TAGException",
    "SecurityValidationError",
    "SuspensionException",
    "ApprovalExpiredError",
    "ApprovalTamperedError",
    "CircuitBreakerTrippedError",
    "UnauthorizedError",
    "StateStore",
    "InMemoryTicketStore",
]
