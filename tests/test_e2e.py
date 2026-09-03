"""End-to-end integration tests for TAGRuntime and guard decorator."""

import pytest
from pydantic import BaseModel, Field

from tag.core.contracts import CallerContext, ToolExecutionRequest
from tag.core.enums import RiskLevel, ToolTier, UserRole
from tag.core.exceptions import SuspensionException
from tag.interceptor import TAGRuntime, guard


class PaymentSchema(BaseModel):
    recipient: str = Field(..., min_length=3)
    amount: float = Field(..., gt=0)


class SearchSchema(BaseModel):
    query: str


@pytest.fixture
def runtime():
    rt = TAGRuntime()

    # L1: Search
    def search_handler(query: str):
        return [f"Result for {query}"]

    # L2: Audit log
    def save_log(message: str):
        return f"Saved: {message}"

    # L3: Payment
    def execute_payment(recipient: str, amount: float):
        return {"status": "PAID", "recipient": recipient, "amount": amount}

    rt.register_tool(
        name="search",
        tier=ToolTier.L1_READ_ONLY,
        schema_model=SearchSchema,
        handler=search_handler,
    )
    rt.register_tool(
        name="save_log",
        tier=ToolTier.L2_STATE_CHANGING,
        min_role=UserRole.STANDARD_USER,
        handler=save_log,
    )
    rt.register_tool(
        name="pay",
        tier=ToolTier.L3_CRITICAL,
        min_role=UserRole.OPERATOR,
        risk_level=RiskLevel.FATAL,
        impact_summary="Transfer real monetary funds",
        schema_model=PaymentSchema,
        handler=execute_payment,
    )
    return rt


@pytest.mark.asyncio
async def test_e2e_l1_pass_through(runtime):
    req = ToolExecutionRequest(
        session_id="agent_sess_1",
        tool_name="search",
        arguments={"query": "Autonomous Agents"},
        caller_context=CallerContext(
            agent_id="researcher", user_role=UserRole.ANONYMOUS, session_id="agent_sess_1"
        ),
    )
    res = await runtime.execute_tool(req)
    assert res.success is True
    assert res.data == ["Result for Autonomous Agents"]
    assert res.execution_time_ms < 50.0  # Typically < 1-2ms


@pytest.mark.asyncio
async def test_e2e_l2_audit_trail(runtime):
    req = ToolExecutionRequest(
        session_id="agent_sess_1",
        tool_name="save_log",
        arguments={"message": "Checkpoint reached"},
        caller_context=CallerContext(
            agent_id="worker", user_role=UserRole.STANDARD_USER, session_id="agent_sess_1"
        ),
    )
    res = await runtime.execute_tool(req)
    assert res.success is True
    assert res.data == "Saved: Checkpoint reached"
    assert len(runtime.audit_trail.entries) >= 1


@pytest.mark.asyncio
async def test_e2e_l3_suspension_and_resume(runtime):
    ctx = CallerContext(
        agent_id="finance_bot", user_role=UserRole.OPERATOR, session_id="sess_fin"
    )
    req = ToolExecutionRequest(
        session_id="sess_fin",
        tool_name="pay",
        arguments={"recipient": "Supplier Inc", "amount": 5000.0},
        caller_context=ctx,
    )

    # 1. Execution is intercepted and suspended
    res = await runtime.execute_tool(req)
    assert res.success is False
    assert "SUSPENDED" in res.error
    assert res.ticket_id is not None
    ticket_id = res.ticket_id

    # 2. Human Operator signs off
    resumed = await runtime.resume_ticket(
        ticket_id=ticket_id,
        approved=True,
        operator_id="cfo_sarah",
        feedback="Approved high-value payment to verified supplier",
    )
    assert resumed.success is True
    assert resumed.data["status"] == "PAID"
    assert resumed.data["amount"] == 5000.0


@pytest.mark.asyncio
async def test_e2e_malicious_injection_and_self_correction(runtime):
    ctx = CallerContext(
        agent_id="bot_1", user_role=UserRole.STANDARD_USER, session_id="sess_bot"
    )

    # Malicious injection in query
    bad_req = ToolExecutionRequest(
        session_id="sess_bot",
        tool_name="search",
        arguments={"query": "test; rm -rf /"},
        caller_context=ctx,
    )
    bad_res = await runtime.execute_tool(bad_req)
    assert bad_res.success is False
    assert "SYSTEM INTERCEPT" in bad_res.error
    assert "destructive removal" in bad_res.error.lower() or "rm" in bad_res.error

    # Agent receives correction prompt and self-corrects:
    clean_req = ToolExecutionRequest(
        session_id="sess_bot",
        tool_name="search",
        arguments={"query": "test_clean_search"},
        caller_context=ctx,
    )
    clean_res = await runtime.execute_tool(clean_req)
    assert clean_res.success is True
    assert clean_res.data == ["Result for test_clean_search"]


@pytest.mark.asyncio
async def test_guard_decorator():
    rt = TAGRuntime()

    @guard(tier=ToolTier.L1_READ_ONLY, runtime=rt)
    def calculate_tax(amount: float) -> float:
        return amount * 0.1

    res = await calculate_tax(amount=100.0)
    assert res == 10.0

    @guard(tier=ToolTier.L3_CRITICAL, runtime=rt, impact_summary="Wipe server logs")
    def wipe_logs() -> str:
        return "wiped"

    # 1. Practice default call to L3 triggers SuspensionException directly
    with pytest.raises(SuspensionException) as exc_info:
        await wipe_logs()
    assert exc_info.value.ticket_id is not None

    # 2. Unauthenticated call with ANONYMOUS role fails with RBAC error
    anon_ctx = CallerContext(
        agent_id="unauth_caller",
        user_role=UserRole.ANONYMOUS,
        session_id="anon_session",
    )
    with pytest.raises(RuntimeError) as exc_rbac:
        await wipe_logs(_caller_context=anon_ctx)
    assert "Insufficient permissions" in str(exc_rbac.value)
