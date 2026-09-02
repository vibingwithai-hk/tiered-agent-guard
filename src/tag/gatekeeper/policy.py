"""Policy Enforcer and Tool Registry for Tiered Agent Guard."""

from typing import Any, Callable, Optional, Type
from pydantic import BaseModel, ConfigDict

from tag.core.contracts import CallerContext, GatekeeperDecision, ToolExecutionRequest
from tag.core.enums import RiskLevel, ToolTier, UserRole, Verdict
from tag.core.exceptions import CircuitBreakerTrippedError, UnauthorizedError
from tag.gatekeeper.audit import AuditTrail, hash_payload
from tag.gatekeeper.circuit_breaker import CircuitBreaker


ROLE_HIERARCHY = {
    UserRole.ANONYMOUS: 0,
    UserRole.AGENT: 1,
    UserRole.OPERATOR: 2,
    UserRole.ADMIN: 3,
}

DEFAULT_TIER_MIN_ROLES = {
    ToolTier.L1_READ_ONLY: UserRole.ANONYMOUS,
    ToolTier.L2_STATE_CHANGING: UserRole.AGENT,
    ToolTier.L3_CRITICAL: UserRole.AGENT,
}

DEFAULT_TIER_RISK = {
    ToolTier.L1_READ_ONLY: RiskLevel.LOW,
    ToolTier.L2_STATE_CHANGING: RiskLevel.MEDIUM,
    ToolTier.L3_CRITICAL: RiskLevel.HIGH,
}


class ToolPolicy(BaseModel):
    """Configuration contract for a registered tool."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    tier: ToolTier
    min_role: UserRole
    risk_level: RiskLevel
    impact_summary: str
    schema_model: Optional[Type[BaseModel]] = None
    handler: Optional[Callable[..., Any]] = None


class PolicyRegistry:
    """Registry maintaining metadata and governance policies for tools."""

    def __init__(self) -> None:
        self._policies: dict[str, ToolPolicy] = {}

    def register(
        self,
        name: str,
        tier: ToolTier,
        min_role: Optional[UserRole] = None,
        risk_level: Optional[RiskLevel] = None,
        impact_summary: Optional[str] = None,
        schema_model: Optional[Type[BaseModel]] = None,
        handler: Optional[Callable[..., Any]] = None,
    ) -> ToolPolicy:
        """Register a tool and its policy constraints."""
        policy = ToolPolicy(
            name=name,
            tier=tier,
            min_role=min_role or DEFAULT_TIER_MIN_ROLES[tier],
            risk_level=risk_level or DEFAULT_TIER_RISK[tier],
            impact_summary=impact_summary or f"Execution of {name} under tier {tier.value}",
            schema_model=schema_model,
            handler=handler,
        )
        self._policies[name] = policy
        return policy

    def get(self, name: str) -> Optional[ToolPolicy]:
        return self._policies.get(name)

    def contains(self, name: str) -> bool:
        return name in self._policies


class PolicyEnforcer:
    """Evaluates requests against RBAC, Tier classification, and Circuit Breakers."""

    def __init__(
        self,
        registry: PolicyRegistry,
        circuit_breaker: CircuitBreaker,
        audit_trail: AuditTrail,
    ) -> None:
        self.registry = registry
        self.circuit_breaker = circuit_breaker
        self.audit_trail = audit_trail

    def evaluate(self, request: ToolExecutionRequest) -> GatekeeperDecision:
        """Evaluate a tool execution request and emit a GatekeeperDecision."""
        policy = self.registry.get(request.tool_name)
        if not policy:
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=ToolTier.L3_CRITICAL,
                verdict=Verdict.REJECTED_POLICY_VIOLATION,
                reason=f"Tool '{request.tool_name}' is not registered in TAG policy registry",
                audit_hash=hash_payload(request.arguments),
            )
            self.audit_trail.record_event(
                request_id=request.request_id,
                session_id=request.session_id,
                tool_name=request.tool_name,
                tier=ToolTier.L3_CRITICAL,
                verdict=Verdict.REJECTED_POLICY_VIOLATION,
                arguments=request.arguments,
                metadata={"reason": decision.reason},
            )
            return decision

        # 1. Circuit Breaker Check
        try:
            self.circuit_breaker.check_and_increment(request.session_id, policy.tier)
        except CircuitBreakerTrippedError as e:
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=policy.tier,
                verdict=Verdict.REJECTED_CIRCUIT_BROKEN,
                reason=str(e),
                audit_hash=hash_payload(request.arguments),
            )
            self.audit_trail.record_event(
                request_id=request.request_id,
                session_id=request.session_id,
                tool_name=request.tool_name,
                tier=policy.tier,
                verdict=Verdict.REJECTED_CIRCUIT_BROKEN,
                arguments=request.arguments,
                metadata={"reason": str(e)},
            )
            return decision

        # 2. RBAC Role Evaluation
        caller_role_level = ROLE_HIERARCHY.get(request.caller_context.user_role, 0)
        required_role_level = ROLE_HIERARCHY.get(policy.min_role, 0)
        if caller_role_level < required_role_level:
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=policy.tier,
                verdict=Verdict.REJECTED_POLICY_VIOLATION,
                reason=(
                    f"Insufficient permissions: UserRole.{request.caller_context.user_role.value} "
                    f"does not satisfy minimum required UserRole.{policy.min_role.value}"
                ),
                audit_hash=hash_payload(request.arguments),
            )
            self.audit_trail.record_event(
                request_id=request.request_id,
                session_id=request.session_id,
                tool_name=request.tool_name,
                tier=policy.tier,
                verdict=Verdict.REJECTED_POLICY_VIOLATION,
                arguments=request.arguments,
                metadata={"reason": decision.reason},
            )
            return decision

        # 3. Tier-based Decision
        audit_hash = hash_payload(request.arguments)
        if policy.tier == ToolTier.L1_READ_ONLY:
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=ToolTier.L1_READ_ONLY,
                verdict=Verdict.PERMITTED,
                reason="L1 Read-Only: Auto-approved for execution",
                audit_hash=audit_hash,
            )
        elif policy.tier == ToolTier.L2_STATE_CHANGING:
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=ToolTier.L2_STATE_CHANGING,
                verdict=Verdict.PERMITTED,
                reason="L2 State-Changing: Verified caller context; audit logged",
                audit_hash=audit_hash,
            )
        else:  # L3_CRITICAL
            decision = GatekeeperDecision(
                request_id=request.request_id,
                assigned_tier=ToolTier.L3_CRITICAL,
                verdict=Verdict.SUSPENDED_PENDING_APPROVAL,
                reason="L3 Critical: Zero-trust interception; human sign-off required",
                audit_hash=audit_hash,
            )

        self.audit_trail.record_event(
            request_id=request.request_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            tier=policy.tier,
            verdict=decision.verdict,
            arguments=request.arguments,
            metadata={"impact": policy.impact_summary, "risk": policy.risk_level.value},
        )
        return decision
