"""Unit and integration tests for LangGraph Human-in-the-loop and TAG tool governance.

Runs 100% locally and in-memory with zero external API dependencies or subscription costs.
"""

from typing import Annotated, Any, TypedDict
import pytest

from pydantic import BaseModel, Field
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

from tag import (
    CallerContext,
    RiskLevel,
    SuspensionException,
    TAGRuntime,
    ToolTier,
    UserRole,
    guard,
)


# --- Schemas & States ---

class ActionState(TypedDict):
    messages: Annotated[list, add_messages]
    action_type: str
    amount: float
    approved: bool


class PaymentSchema(BaseModel):
    recipient: str = Field(..., min_length=3)
    amount: float = Field(..., gt=0)


# --- Test 1: Native LangGraph interrupt() approval flow ---

def test_langgraph_native_interrupt_approval():
    def planner_node(state: ActionState) -> dict[str, Any]:
        return {
            "action_type": "WIRE_TRANSFER",
            "amount": 2500.0,
            "messages": [AIMessage(content="Prepared $2,500 wire transfer.")],
        }

    def approval_node(state: ActionState) -> dict[str, Any]:
        decision = interrupt({
            "action": state["action_type"],
            "amount": state["amount"],
            "prompt": "Approve this transaction?",
        })
        return {"approved": decision.get("approved", False)}

    def actuator_node(state: ActionState) -> dict[str, Any]:
        if state.get("approved"):
            return {"messages": [AIMessage(content="Transfer executed successfully.")]}
        return {"messages": [AIMessage(content="Transfer cancelled.")]}

    builder = StateGraph(ActionState)
    builder.add_node("planner", planner_node)
    builder.add_node("approval", approval_node)
    builder.add_node("actuator", actuator_node)

    builder.add_edge(START, "planner")
    builder.add_edge("planner", "approval")
    builder.add_edge("approval", "actuator")
    builder.add_edge("actuator", END)

    memory = MemorySaver()
    graph = builder.compile(checkpointer=memory)

    config = {"configurable": {"thread_id": "test_thread_approve"}}
    initial_input = {
        "messages": [HumanMessage(content="Send $2,500")],
        "action_type": "",
        "amount": 0.0,
        "approved": False,
    }

    # Step 1: Run until interrupt
    list(graph.stream(initial_input, config))
    state_paused = graph.get_state(config)

    assert state_paused.next == ("approval",)
    assert len(state_paused.tasks) > 0
    assert len(state_paused.tasks[0].interrupts) > 0
    interrupt_val = state_paused.tasks[0].interrupts[0].value
    assert interrupt_val["amount"] == 2500.0
    assert interrupt_val["action"] == "WIRE_TRANSFER"

    # Step 2: Resume with approval
    resume_cmd = Command(resume={"approved": True})
    list(graph.stream(resume_cmd, config))

    final_state = graph.get_state(config)
    assert final_state.next == ()
    assert final_state.values["approved"] is True
    assert final_state.values["messages"][-1].content == "Transfer executed successfully."


# --- Test 2: Native LangGraph interrupt() rejection flow ---

def test_langgraph_native_interrupt_rejection():
    def planner_node(state: ActionState) -> dict[str, Any]:
        return {
            "action_type": "DELETE_DATABASE",
            "amount": 0.0,
            "messages": [AIMessage(content="Attempting database deletion.")],
        }

    def approval_node(state: ActionState) -> dict[str, Any]:
        decision = interrupt({"prompt": "Confirm dangerous action?"})
        return {"approved": decision.get("approved", False)}

    def actuator_node(state: ActionState) -> dict[str, Any]:
        if state.get("approved"):
            return {"messages": [AIMessage(content="Database deleted.")]}
        return {"messages": [AIMessage(content="Action aborted by operator.")]}

    builder = StateGraph(ActionState)
    builder.add_node("planner", planner_node)
    builder.add_node("approval", approval_node)
    builder.add_node("actuator", actuator_node)

    builder.add_edge(START, "planner")
    builder.add_edge("planner", "approval")
    builder.add_edge("approval", "actuator")
    builder.add_edge("actuator", END)

    memory = MemorySaver()
    graph = builder.compile(checkpointer=memory)

    config = {"configurable": {"thread_id": "test_thread_reject"}}
    initial_input = {
        "messages": [HumanMessage(content="Drop DB")],
        "action_type": "",
        "amount": 0.0,
        "approved": False,
    }

    list(graph.stream(initial_input, config))
    state_paused = graph.get_state(config)
    assert state_paused.next == ("approval",)

    # Resume with rejection
    resume_cmd = Command(resume={"approved": False})
    list(graph.stream(resume_cmd, config))

    final_state = graph.get_state(config)
    assert final_state.next == ()
    assert final_state.values["approved"] is False
    assert final_state.values["messages"][-1].content == "Action aborted by operator."


# --- Test 3: TAG Guard as Actuator Boundary inside LangGraph Tool Node ---

@pytest.mark.asyncio
async def test_langgraph_with_tag_actuator_boundary():
    runtime = TAGRuntime()

    @guard(
        tier=ToolTier.L3_CRITICAL,
        runtime=runtime,
        impact_summary="Irreversible treasury settlement",
        schema_model=PaymentSchema,
    )
    def settle_payment(recipient: str, amount: float) -> dict[str, Any]:
        return {"status": "SETTLED", "recipient": recipient, "amount": amount}

    class ToolState(TypedDict):
        recipient: str
        amount: float
        result: dict[str, Any]
        error: str

    async def tool_node(state: ToolState) -> dict[str, Any]:
        try:
            res = await settle_payment(recipient=state["recipient"], amount=state["amount"])
            return {"result": res, "error": ""}
        except SuspensionException as ex:
            return {"result": {}, "error": f"SUSPENDED:{ex.ticket_id}"}

    builder = StateGraph(ToolState)
    builder.add_node("tool_node", tool_node)
    builder.add_edge(START, "tool_node")
    builder.add_edge("tool_node", END)

    graph = builder.compile()

    state = await graph.ainvoke({
        "recipient": "Vendor A",
        "amount": 999.0,
        "result": {},
        "error": "",
    })

    # The tool node must catch the SuspensionException from TAG
    assert state["error"].startswith("SUSPENDED:")
    ticket_id = state["error"].split(":")[1]

    # Verify ticket exists in TAG registry and can be reviewed
    ticket = await runtime.get_ticket(ticket_id)
    assert ticket is not None
    assert ticket.tool_name == "settle_payment"
    assert ticket.arguments == {"recipient": "Vendor A", "amount": 999.0}
    assert ticket.status.value == "PENDING"


# --- Test 4: TAG Resumption after Operator Approval ---

@pytest.mark.asyncio
async def test_langgraph_with_tag_resume_after_approval():
    runtime = TAGRuntime()

    @guard(
        tier=ToolTier.L3_CRITICAL,
        runtime=runtime,
        impact_summary="Treasury fund transfer",
        schema_model=PaymentSchema,
    )
    def wire_funds(recipient: str, amount: float) -> dict[str, Any]:
        return {"status": "SUCCESS", "recipient": recipient, "amount": amount}

    # First invocation: suspended
    ticket_id = None
    try:
        await wire_funds(recipient="Supplier Corp", amount=12000.0)
    except SuspensionException as ex:
        ticket_id = ex.ticket_id

    assert ticket_id is not None

    # Operator approves the ticket via TAG runtime
    resumed_result = await runtime.resume_ticket(
        ticket_id=ticket_id,
        approved=True,
        operator_id="security_officer_bob",
        feedback="Verified supplier contract #8841",
    )

    assert resumed_result.success is True
    assert resumed_result.data == {
        "status": "SUCCESS",
        "recipient": "Supplier Corp",
        "amount": 12000.0,
    }
