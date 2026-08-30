"""Tiered Agent Guard (TAG): A lightweight security middleware prototype for AI Agents (Practice Project)."""

from tag.core.enums import (
    RiskLevel,
    TicketStatus,
    ToolTier,
    UserRole,
    Verdict,
)
from tag.core.contracts import (
    ApprovalCard,
    CallerContext,
    ExecutionResult,
    GatekeeperDecision,
    ToolExecutionRequest,
    utc_now,
)
from tag.core.exceptions import (
    ApprovalExpiredError,
    ApprovalTamperedError,
    CircuitBreakerTrippedError,
    SecurityValidationError,
    SuspensionException,
    TAGException,
    UnauthorizedError,
)
from tag.core.state_store import (
    InMemoryTicketStore,
    StateStore,
)
from tag.validators.injection_guard import InjectionGuard
from tag.validators.schema_guard import (
    SchemaContractValidator,
    ValidationResult,
)
from tag.gatekeeper.audit import (
    AuditEntry,
    AuditTrail,
    hash_payload,
)
from tag.gatekeeper.circuit_breaker import CircuitBreaker
from tag.gatekeeper.policy import (
    PolicyEnforcer,
    PolicyRegistry,
    ToolPolicy,
)
from tag.suspension.crypto import (
    CryptoSigner,
    canonical_json,
)
from tag.suspension.controller import SuspensionController
from tag.interceptor import (
    TAGRuntime,
    get_default_runtime,
    guard,
)

__version__ = "0.1.0"

__all__ = [
    # Core Enums
    "ToolTier",
    "Verdict",
    "RiskLevel",
    "TicketStatus",
    "UserRole",
    # Contracts
    "CallerContext",
    "ToolExecutionRequest",
    "GatekeeperDecision",
    "ApprovalCard",
    "ExecutionResult",
    "utc_now",
    # Exceptions
    "TAGException",
    "SecurityValidationError",
    "SuspensionException",
    "ApprovalExpiredError",
    "ApprovalTamperedError",
    "CircuitBreakerTrippedError",
    "UnauthorizedError",
    # State Store
    "StateStore",
    "InMemoryTicketStore",
    # Validators
    "InjectionGuard",
    "SchemaContractValidator",
    "ValidationResult",
    # Gatekeeper
    "AuditTrail",
    "AuditEntry",
    "hash_payload",
    "CircuitBreaker",
    "PolicyRegistry",
    "PolicyEnforcer",
    "ToolPolicy",
    # Suspension
    "CryptoSigner",
    "canonical_json",
    "SuspensionController",
    # Interceptor & Runtime
    "TAGRuntime",
    "get_default_runtime",
    "guard",
]
