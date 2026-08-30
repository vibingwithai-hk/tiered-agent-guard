"""Core Enums for Tiered Agent Guard (TAG).

Defines tool tier classifications, policy verdicts, risk levels, and ticket lifecycle statuses.
"""

from enum import Enum


class ToolTier(str, Enum):
    """Execution tiers determining safety and governance level."""
    L1_READ_ONLY = "L1_READ_ONLY"             # Pure idempotent read; auto-execute
    L2_STATE_CHANGING = "L2_STATE_CHANGING"   # Reversible/low-risk state mutation; audit & rate-check
    L3_CRITICAL = "L3_CRITICAL"               # Irreversible/destructive/financial mutation; Zero-Trust suspension


class Verdict(str, Enum):
    """Gatekeeper evaluation outcome."""
    PERMITTED = "PERMITTED"
    SUSPENDED_PENDING_APPROVAL = "SUSPENDED_PENDING_APPROVAL"
    REJECTED_VALIDATION_FAILED = "REJECTED_VALIDATION_FAILED"
    REJECTED_POLICY_VIOLATION = "REJECTED_POLICY_VIOLATION"
    REJECTED_CIRCUIT_BROKEN = "REJECTED_CIRCUIT_BROKEN"


class RiskLevel(str, Enum):
    """Risk severity classification for human approval card."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    FATAL = "FATAL"


class TicketStatus(str, Enum):
    """Status lifecycle of a suspended L3 execution ticket."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class UserRole(str, Enum):
    """Role-based access levels for agent invocation contexts."""
    ANONYMOUS = "ANONYMOUS"
    AGENT = "AGENT"
    STANDARD_USER = "AGENT"  # Alias for compatibility
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"
