"""Demonstration of LangGraph Human-in-the-loop and TAG integration.

Runs 100% locally and offline without requiring any paid API keys or subscriptions.
Demonstrates:
  1. Native LangGraph interrupt() with MemorySaver checkpointer.
  2. TAG @guard as a defense-in-depth actuator boundary inside a LangGraph tool node.
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Annotated, Any, TypedDict

# Ensure src in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydantic import BaseModel, Field

# LangChain & LangGraph imports (free, in-process)
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

# TAG imports
from tag import SuspensionException, ToolTier, guard, get_default_runtime


# --- Part 1: Native LangGraph Human-In-The-Loop Demo ---

class NativeGraphState(TypedDict):
    messages: Annotated[list, add_messages]
    action_type: str
    amount: float
    approved: bool


def mock_planner_node(state: NativeGraphState) -> dict[str, Any]:
    """Simulates an LLM agent planning an action."""
    return {
        "action_type": "WIRE_TRANSFER",
        "amount": 5000.0,
        "messages": [AIMessage(content="Planned wire transfer: $5,000 to Supplier.")],
    }


def human_approval_node(state: NativeGraphState) -> dict[str, Any]:
    """Suspends the graph using native LangGraph interrupt() awaiting operator resume."""
    decision = interrupt({
        "prompt": "Approve $5,000 wire transfer?",
        "action": state["action_type"],
        "amount": state["amount"],
    })
    return {"approved": decision.get("approved", False)}


def actuator_node(state: NativeGraphState) -> dict[str, Any]:
    """Executes the action only if approved by the human operator."""
    if state.get("approved"):
        return {
            "messages": [
                AIMessage(content="Actuator executed: $5,000 successfully transferred.")
            ]
        }
    return {
        "messages": [
            AIMessage(content="Actuator aborted: Transfer rejected by operator.")
        ]
    }


def build_native_langgraph():
    builder = StateGraph(NativeGraphState)
    builder.add_node("planner", mock_planner_node)
    builder.add_node("human_approval", human_approval_node)
    builder.add_node("actuator", actuator_node)

    builder.add_edge(START, "planner")
    builder.add_edge("planner", "human_approval")
    builder.add_edge("human_approval", "actuator")
    builder.add_edge("actuator", END)

    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


# --- Part 2: TAG Guardrail Inside LangGraph Tool Calling ---

class WireTransferSchema(BaseModel):
    recipient: str = Field(..., min_length=3)
    amount: float = Field(..., gt=0)


@guard(
    tier=ToolTier.L3_CRITICAL,
    impact_summary="Irreversibly transfers funds from treasury",
    schema_model=WireTransferSchema,
)
def protected_transfer(recipient: str, amount: float) -> dict[str, Any]:
    """Target actuator guarded by TAG."""
    return {"status": "SETTLED", "recipient": recipient, "amount": amount}


class TagGraphState(TypedDict):
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    error: str


async def tag_tool_node(state: TagGraphState) -> dict[str, Any]:
    """LangGraph node invoking an actuator protected by TAG @guard."""
    try:
        data = await protected_transfer(**state["arguments"])
        return {"result": data, "error": ""}
    except SuspensionException as e:
        return {
            "result": {},
            "error": f"TAG_INTERCEPTED: Ticket ID {e.ticket_id}",
        }


def build_tag_langgraph():
    builder = StateGraph(TagGraphState)
    builder.add_node("tool_executor", tag_tool_node)
    builder.add_edge(START, "tool_executor")
    builder.add_edge("tool_executor", END)
    return builder.compile()


# --- CLI Execution ---

async def run_demo(auto_approve: bool = False):
    print("\n" + "=" * 70)
    print("      LANGGRAPH & TAG INTEGRATION SHOWCASE (OFFLINE & FREE)")
    print("=" * 70 + "\n")

    # --- Section 1: Native LangGraph interrupt() ---
    print("[1] Native LangGraph interrupt() Flow")
    print("    Building StateGraph with MemorySaver checkpointer...")
    native_graph = build_native_langgraph()
    thread_config = {"configurable": {"thread_id": "langgraph_demo_thread_1"}}

    print("    Step A: Running graph until interrupt...")
    initial_input = {
        "messages": [HumanMessage(content="Please send $5,000 to Supplier")],
        "action_type": "",
        "amount": 0.0,
        "approved": False,
    }

    events = list(native_graph.stream(initial_input, thread_config))
    state_after_pause = native_graph.get_state(thread_config)
    next_node = state_after_pause.next
    interrupt_payload = state_after_pause.tasks[0].interrupts[0].value

    print(f"    Graph paused successfully. Waiting on node: {next_node}")
    print(f"    Interrupt Payload: {interrupt_payload}")

    decision = True
    if not auto_approve:
        user_input = input("    Operator Action: Approve transfer? [y/N]: ").strip().lower()
        decision = user_input in ("y", "yes")

    print(f"    Operator Decision: {'APPROVED' if decision else 'REJECTED'}")
    print("    Step B: Resuming graph execution with Command(resume=...)...")
    resume_command = Command(resume={"approved": decision})
    resume_events = list(native_graph.stream(resume_command, thread_config))

    final_state = native_graph.get_state(thread_config)
    print(f"    Outcome: {final_state.values['messages'][-1].content}")
    print("-" * 70 + "\n")

    # --- Section 2: TAG Actuator Guard Inside LangGraph ---
    print("[2] TAG @guard as Actuator Boundary inside LangGraph Node")
    print("    Simulating LangGraph tool node invoking an L3 critical tool...")
    tag_graph = build_tag_langgraph()

    input_payload = {
        "tool_name": "protected_transfer",
        "arguments": {"recipient": "Supplier Corp", "amount": 5000.0},
        "result": {},
        "error": "",
    }

    result_state = await tag_graph.ainvoke(input_payload)
    print(f"    Node Execution Output: {result_state['error']}")
    print("    Demonstration: Even if the graph developer forgets to add an interrupt node,")
    print("                   TAG catches the call at the actuator level and halts execution.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LangGraph & TAG Integration Showcase")
    parser.add_argument("--auto", action="store_true", help="Run in automated non-interactive mode")
    args = parser.parse_args()

    asyncio.run(run_demo(auto_approve=args.auto))
