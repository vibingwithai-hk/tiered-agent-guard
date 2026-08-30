"""Pydantic data contracts for Tiered Agent Guard (TAG).

Strict type contracts for request payloads, gatekeeper decisions, and approval cards.
"""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4
from pydantic import BaseModel, Field, ConfigDict

from tag.core.enums import ToolTier, Verdict, RiskLevel, TicketStatus, UserRole


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CallerContext(BaseModel):
    """Execution context representing the agent session and user permissions."""
    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(..., description="Unique identifier for the calling agent")
    user_role: UserRole = Field(default=UserRole.STANDARD_USER, description="RBAC level of caller")
    session_id: str = Field(..., description="Cross-turn persistent session ID")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Custom context attributes")


class ToolExecutionRequest(BaseModel):
    """Input contract emitted by the LLM reasoning core or agent loop."""
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str = Field(..., description="Session identifier")
    timestamp: datetime = Field(default_factory=utc_now)
    tool_name: str = Field(..., description="Target tool identifier")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Raw arguments from LLM")
    caller_context: CallerContext = Field(..., description="Originating execution context")


class GatekeeperDecision(BaseModel):
    """Decision event emitted by the policy gatekeeper."""
    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str = Field(..., description="Associated ToolExecutionRequest ID")
    assigned_tier: ToolTier = Field(..., description="Assigned governance tier")
    verdict: Verdict = Field(..., description="Execution verdict")
    reason: str = Field(..., description="Human-readable decision explanation")
    audit_hash: str = Field(..., description="Cryptographic integrity hash")
    ticket_id: Optional[str] = Field(default=None, description="Suspension ticket ID if L3")


class ApprovalCard(BaseModel):
    """Schema for Human-In-The-Loop suspension card."""
    ticket_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str = Field(...)
    session_id: str = Field(...)
    tool_name: str = Field(...)
    risk_level: RiskLevel = Field(default=RiskLevel.HIGH)
    impact_summary: str = Field(..., description="Summary of side-effects")
    arguments: dict[str, Any] = Field(..., description="Exact arguments to be executed")
    expires_at: datetime = Field(..., description="Expiry deadline (UTC)")
    status: TicketStatus = Field(default=TicketStatus.PENDING)
    audit_hash: str = Field(..., description="HMAC-SHA256 of canonical arguments")
    operator_id: Optional[str] = Field(default=None)
    feedback: Optional[str] = Field(default=None, description="Human rejection reason or note")


class ExecutionResult(BaseModel):
    """Standardized response from tool execution."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    audit_hash: Optional[str] = None
    ticket_id: Optional[str] = None
