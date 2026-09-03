"""TAG Interceptor and Core Runtime.

Provides the primary interface for registering, guarding, executing, and resuming tool calls.
"""

import asyncio
import functools
import inspect
import time
from typing import Any, Callable, Coroutine, Optional, Type
from pydantic import BaseModel

from tag.core.contracts import (
    ApprovalCard,
    CallerContext,
    ExecutionResult,
    GatekeeperDecision,
    ToolExecutionRequest,
)
from tag.core.enums import RiskLevel, TicketStatus, ToolTier, UserRole, Verdict
from tag.core.exceptions import (
    ApprovalExpiredError,
    ApprovalTamperedError,
    CircuitBreakerTrippedError,
    SecurityValidationError,
    SuspensionException,
    UnauthorizedError,
)
from tag.core.state_store import InMemoryTicketStore, StateStore
from tag.gatekeeper.audit import AuditTrail
from tag.gatekeeper.circuit_breaker import CircuitBreaker
from tag.gatekeeper.policy import DEFAULT_TIER_MIN_ROLES, PolicyEnforcer, PolicyRegistry, ToolPolicy
from tag.suspension.controller import SuspensionController
from tag.suspension.crypto import CryptoSigner
from tag.validators.schema_guard import SchemaContractValidator


class TAGRuntime:
    """The central runtime engine orchestrating validation, gatekeeping, and suspension."""

    def __init__(
        self,
        store: Optional[StateStore] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        signer: Optional[CryptoSigner] = None,
        on_suspended_event: Optional[Callable[[ApprovalCard], Any]] = None,
    ) -> None:
        self.store = store or InMemoryTicketStore()
        self.registry = PolicyRegistry()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.audit_trail = AuditTrail()
        self.signer = signer or CryptoSigner()
        self.suspension = SuspensionController(
            store=self.store,
            signer=self.signer,
            on_suspended_event=on_suspended_event,
        )
        self.gatekeeper = PolicyEnforcer(
            registry=self.registry,
            circuit_breaker=self.circuit_breaker,
            audit_trail=self.audit_trail,
        )

    def register_tool(
        self,
        name: str,
        tier: ToolTier,
        min_role: Optional[UserRole] = None,
        risk_level: Optional[RiskLevel] = None,
        impact_summary: Optional[str] = None,
        schema_model: Optional[Type[BaseModel]] = None,
        handler: Optional[Callable[..., Any]] = None,
    ) -> ToolPolicy:
        """Register a tool with policy constraints and optional handler."""
        return self.registry.register(
            name=name,
            tier=tier,
            min_role=min_role,
            risk_level=risk_level,
            impact_summary=impact_summary,
            schema_model=schema_model,
            handler=handler,
        )

    async def execute_tool(
        self,
        request: ToolExecutionRequest,
        handler: Optional[Callable[..., Any]] = None,
        raise_on_suspension: bool = False,
    ) -> ExecutionResult:
        """Execute a tool request through the TAG pipeline."""
        start_time = time.perf_counter()
        policy = self.registry.get(request.tool_name)

        target_handler = handler or (policy.handler if policy else None)

        # 1. Schema & Injection Validation
        validation_result = SchemaContractValidator.validate(
            tool_name=request.tool_name,
            arguments=request.arguments,
            schema=policy.schema_model if policy else None,
            raise_on_error=False,
        )

        if not validation_result.is_valid:
            self.audit_trail.record_event(
                request_id=request.request_id,
                session_id=request.session_id,
                tool_name=request.tool_name,
                tier=policy.tier if policy else ToolTier.L3_CRITICAL,
                verdict=Verdict.REJECTED_VALIDATION_FAILED,
                arguments=request.arguments,
                metadata={"violations": validation_result.violations},
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=validation_result.correction_prompt,
                execution_time_ms=elapsed,
            )

        # 2. Gatekeeper Policy Evaluation
        decision = self.gatekeeper.evaluate(request)

        if decision.verdict in (
            Verdict.REJECTED_POLICY_VIOLATION,
            Verdict.REJECTED_CIRCUIT_BROKEN,
        ):
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=decision.reason,
                execution_time_ms=elapsed,
            )

        # 3. L3 Suspension Interception
        if decision.verdict == Verdict.SUSPENDED_PENDING_APPROVAL:
            card = await self.suspension.create_ticket(
                request=request,
                impact_summary=policy.impact_summary if policy else "Critical operation",
                risk_level=policy.risk_level if policy else RiskLevel.HIGH,
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0

            if raise_on_suspension:
                raise SuspensionException(ticket_id=card.ticket_id, approval_card=card)

            return ExecutionResult(
                success=False,
                error=f"SUSPENDED: Execution awaiting human sign-off (TicketID: {card.ticket_id})",
                ticket_id=card.ticket_id,
                audit_hash=card.audit_hash,
                execution_time_ms=elapsed,
            )

        # 4. Authorized Execution (L1 or L2)
        if not target_handler:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=f"No executable handler registered for tool '{request.tool_name}'",
                execution_time_ms=elapsed,
            )

        try:
            if inspect.iscoroutinefunction(target_handler):
                data = await target_handler(**validation_result.validated_data)
            else:
                data = target_handler(**validation_result.validated_data)

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=True,
                data=data,
                execution_time_ms=elapsed,
                audit_hash=decision.audit_hash,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=f"Actuator execution failed: {str(e)}",
                execution_time_ms=elapsed,
            )

    async def resume_ticket(
        self,
        ticket_id: str,
        approved: bool,
        operator_id: str,
        feedback: Optional[str] = None,
        verify_arguments: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
    ) -> ExecutionResult:
        """Resolve a suspended ticket and execute if approved."""
        start_time = time.perf_counter()
        card = await self.suspension.resolve_ticket(
            ticket_id=ticket_id,
            approved=approved,
            operator_id=operator_id,
            feedback=feedback,
            verify_arguments=verify_arguments,
        )

        if not approved:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            self.audit_trail.record_event(
                request_id=card.request_id,
                session_id=card.session_id,
                tool_name=card.tool_name,
                tier=ToolTier.L3_CRITICAL,
                verdict=Verdict.REJECTED_POLICY_VIOLATION,
                arguments=card.arguments,
                metadata={"operator_id": operator_id, "feedback": card.feedback},
            )
            return ExecutionResult(
                success=False,
                error=f"Operation rejected by operator {operator_id}: {card.feedback}",
                ticket_id=ticket_id,
                execution_time_ms=elapsed,
            )

        # Approved: execute actuator
        policy = self.registry.get(card.tool_name)
        target_handler = handler or (policy.handler if policy else None)
        if not target_handler:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=f"No executable handler registered for tool '{card.tool_name}'",
                ticket_id=ticket_id,
                execution_time_ms=elapsed,
            )

        try:
            if inspect.iscoroutinefunction(target_handler):
                data = await target_handler(**card.arguments)
            else:
                data = target_handler(**card.arguments)

            elapsed = (time.perf_counter() - start_time) * 1000.0
            self.audit_trail.record_event(
                request_id=card.request_id,
                session_id=card.session_id,
                tool_name=card.tool_name,
                tier=ToolTier.L3_CRITICAL,
                verdict=Verdict.PERMITTED,
                arguments=card.arguments,
                metadata={"operator_id": operator_id, "feedback": card.feedback},
            )
            return ExecutionResult(
                success=True,
                data=data,
                ticket_id=ticket_id,
                audit_hash=card.audit_hash,
                execution_time_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                success=False,
                error=f"Actuator execution failed post-approval: {str(e)}",
                ticket_id=ticket_id,
                execution_time_ms=elapsed,
            )

    async def get_ticket(self, ticket_id: str) -> Optional[ApprovalCard]:
        """Retrieve an approval card by ticket ID."""
        return await self.store.get_ticket(ticket_id)


# Global default runtime instance
_default_runtime = TAGRuntime()


def get_default_runtime() -> TAGRuntime:
    return _default_runtime


def guard(
    tier: ToolTier,
    name: Optional[str] = None,
    min_role: Optional[UserRole] = None,
    risk_level: Optional[RiskLevel] = None,
    impact_summary: Optional[str] = None,
    schema_model: Optional[Type[BaseModel]] = None,
    runtime: Optional[TAGRuntime] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to register and wrap a tool function with TAG security boundaries."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        rt = runtime or _default_runtime
        tool_name = name or fn.__name__

        rt.register_tool(
            name=tool_name,
            tier=tier,
            min_role=min_role,
            risk_level=risk_level,
            impact_summary=impact_summary or fn.__doc__ or f"Execution of {tool_name}",
            schema_model=schema_model,
            handler=fn,
        )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # If wrapped function called directly with caller_context kwarg
            caller_context = kwargs.pop("_caller_context", None)
            if not caller_context:
                # Default practice context: standard agent invoking tools
                caller_context = CallerContext(
                    agent_id="practice_agent",
                    user_role=UserRole.AGENT,
                    session_id="practice_session",
                )

            req = ToolExecutionRequest(
                session_id=caller_context.session_id,
                tool_name=tool_name,
                arguments=kwargs,
                caller_context=caller_context,
            )

            result = await rt.execute_tool(req, handler=fn, raise_on_suspension=True)
            if not result.success:
                raise RuntimeError(result.error)
            return result.data

        wrapper.__tool_name__ = tool_name  # type: ignore
        wrapper.__tool_tier__ = tier  # type: ignore
        return wrapper

    return decorator
