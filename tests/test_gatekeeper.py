"""Unit tests for PolicyEnforcer, CircuitBreaker, and AuditTrail."""

import pytest
from tag.core.contracts import CallerContext, ToolExecutionRequest
from tag.core.enums import RiskLevel, ToolTier, UserRole, Verdict
from tag.core.exceptions import CircuitBreakerTrippedError
from tag.gatekeeper.audit import AuditTrail
from tag.gatekeeper.circuit_breaker import CircuitBreaker
from tag.gatekeeper.policy import PolicyEnforcer, PolicyRegistry


@pytest.fixture
def setup_gatekeeper():
    registry = PolicyRegistry()
    registry.register(
        name="read_data",
        tier=ToolTier.L1_READ_ONLY,
        min_role=UserRole.ANONYMOUS,
        impact_summary="Read data safely",
    )
    registry.register(
        name="write_draft",
        tier=ToolTier.L2_STATE_CHANGING,
        min_role=UserRole.STANDARD_USER,
        impact_summary="Save draft",
    )
    registry.register(
        name="delete_database",
        tier=ToolTier.L3_CRITICAL,
        min_role=UserRole.OPERATOR,
        impact_summary="Purge database",
        risk_level=RiskLevel.FATAL,
    )
    cb = CircuitBreaker(max_calls_per_session=5, max_critical_calls_per_session=2)
    audit = AuditTrail()
    enforcer = PolicyEnforcer(registry=registry, circuit_breaker=cb, audit_trail=audit)
    return enforcer, cb, audit


def test_l1_read_only_permitted(setup_gatekeeper):
    enforcer, _, audit = setup_gatekeeper
    req = ToolExecutionRequest(
        session_id="sess_1",
        tool_name="read_data",
        arguments={"id": "123"},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.ANONYMOUS, session_id="sess_1"
        ),
    )
    decision = enforcer.evaluate(req)
    assert decision.verdict == Verdict.PERMITTED
    assert decision.assigned_tier == ToolTier.L1_READ_ONLY
    assert len(audit.entries) == 1


def test_l2_state_write_permitted_with_role(setup_gatekeeper):
    enforcer, _, audit = setup_gatekeeper
    req = ToolExecutionRequest(
        session_id="sess_1",
        tool_name="write_draft",
        arguments={"title": "Draft 1"},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.STANDARD_USER, session_id="sess_1"
        ),
    )
    decision = enforcer.evaluate(req)
    assert decision.verdict == Verdict.PERMITTED
    assert decision.assigned_tier == ToolTier.L2_STATE_CHANGING


def test_l3_critical_suspended(setup_gatekeeper):
    enforcer, _, audit = setup_gatekeeper
    req = ToolExecutionRequest(
        session_id="sess_1",
        tool_name="delete_database",
        arguments={"target": "prod"},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.OPERATOR, session_id="sess_1"
        ),
    )
    decision = enforcer.evaluate(req)
    assert decision.verdict == Verdict.SUSPENDED_PENDING_APPROVAL
    assert decision.assigned_tier == ToolTier.L3_CRITICAL


def test_rbac_insufficient_role(setup_gatekeeper):
    enforcer, _, audit = setup_gatekeeper
    # Anonymous calling L2 (requires STANDARD_USER)
    req = ToolExecutionRequest(
        session_id="sess_1",
        tool_name="write_draft",
        arguments={"title": "Hack"},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.ANONYMOUS, session_id="sess_1"
        ),
    )
    decision = enforcer.evaluate(req)
    assert decision.verdict == Verdict.REJECTED_POLICY_VIOLATION
    assert "Insufficient permissions" in decision.reason


def test_circuit_breaker_tripped(setup_gatekeeper):
    enforcer, cb, _ = setup_gatekeeper
    session_id = "looping_agent_session"

    ctx = CallerContext(
        agent_id="agent_loop", user_role=UserRole.OPERATOR, session_id=session_id
    )

    # Calling L3 more than max_critical_calls (2)
    req = ToolExecutionRequest(
        session_id=session_id,
        tool_name="delete_database",
        arguments={"dry_run": True},
        caller_context=ctx,
    )

    # 1st call
    d1 = enforcer.evaluate(req)
    assert d1.verdict == Verdict.SUSPENDED_PENDING_APPROVAL

    # 2nd call
    d2 = enforcer.evaluate(req)
    assert d2.verdict == Verdict.SUSPENDED_PENDING_APPROVAL

    # 3rd call -> trips critical limit (max 2)
    d3 = enforcer.evaluate(req)
    assert d3.verdict == Verdict.REJECTED_CIRCUIT_BROKEN
    assert "Circuit breaker tripped" in d3.reason


def test_audit_trail_cryptographic_chain(setup_gatekeeper):
    enforcer, _, audit = setup_gatekeeper
    ctx = CallerContext(
        agent_id="agent_test", user_role=UserRole.STANDARD_USER, session_id="sess_audit"
    )

    for i in range(5):
        req = ToolExecutionRequest(
            session_id="sess_audit",
            tool_name="read_data",
            arguments={"query_idx": i},
            caller_context=ctx,
        )
        enforcer.evaluate(req)

    # Verify chain integrity
    is_valid, err = audit.verify_integrity()
    assert is_valid is True
    assert err is None
    assert len(audit.entries) == 5

    # Tamper with an entry in the middle
    audit._entries[2].tool_name = "tampered_tool"
    is_valid_tampered, err_tampered = audit.verify_integrity()
    assert is_valid_tampered is False
    assert "Tampered entry" in err_tampered
