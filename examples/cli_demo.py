"""Deterministic Interactive CLI Demonstration for Tiered Agent Guard (TAG).

Showcases Track A (L1), Track B (L2), Track C (L3 Suspension & HITL),
Track D (Injection Intercept & Self-Correction), and Track E (Circuit Breaker).
"""

import argparse
import asyncio
import sys
from pathlib import Path
from pydantic import BaseModel, Field

# Ensure src in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tag.core.contracts import CallerContext, ToolExecutionRequest
from tag.core.enums import RiskLevel, ToolTier, UserRole
from tag.gatekeeper.circuit_breaker import CircuitBreaker
from tag.interceptor import TAGRuntime


# ANSI Terminal Colors
BOLD = "\033[1m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"


# Schemas for demo tools
class BalanceQuerySchema(BaseModel):
    account_id: str


class UpdateProfileSchema(BaseModel):
    display_name: str
    email_notifications: bool = True


class TransferFundsSchema(BaseModel):
    destination_iban: str = Field(..., min_length=8)
    amount_usd: float = Field(..., gt=0)
    note: str = ""


class ExportLogsSchema(BaseModel):
    output_path: str


# Concrete Actuators
def get_account_balance(account_id: str):
    return {"account_id": account_id, "balance_usd": 142500.75, "currency": "USD"}


def update_profile(display_name: str, email_notifications: bool):
    return {"updated": True, "display_name": display_name, "notifications": email_notifications}


def transfer_funds(destination_iban: str, amount_usd: float, note: str = ""):
    return {
        "status": "SETTLED",
        "tx_id": "TX-984210948",
        "destination": destination_iban,
        "amount": amount_usd,
        "note": note,
    }


def export_logs(output_path: str):
    return {"exported_to": output_path, "bytes_written": 4096}


async def main(non_interactive: bool = False, reject_l3: bool = False):
    print("\n" + "=" * 76)
    print(f"{BOLD}{CYAN}      TIERED AGENT GUARD (TAG) — ARCHITECTURAL SHOWCASE DEMO{RESET}")
    print(f"{DIM}      Zero-Trust Autonomous Security Middleware for AI Agents{RESET}")
    print("=" * 76 + "\n")

    # Initialize Runtime with CircuitBreaker (threshold = 3 for demo)
    cb = CircuitBreaker(max_calls_per_session=10, max_critical_calls_per_session=2)
    runtime = TAGRuntime(circuit_breaker=cb)

    # Register tools
    runtime.register_tool(
        name="get_account_balance",
        tier=ToolTier.L1_READ_ONLY,
        impact_summary="Queries account ledger without side effects",
        schema_model=BalanceQuerySchema,
        handler=get_account_balance,
    )
    runtime.register_tool(
        name="update_profile",
        tier=ToolTier.L2_STATE_CHANGING,
        min_role=UserRole.STANDARD_USER,
        impact_summary="Updates user profile preferences and logs audit entry",
        schema_model=UpdateProfileSchema,
        handler=update_profile,
    )
    runtime.register_tool(
        name="transfer_funds",
        tier=ToolTier.L3_CRITICAL,
        min_role=UserRole.OPERATOR,
        risk_level=RiskLevel.FATAL,
        impact_summary="Irreversibly transfers real monetary assets out of treasury",
        schema_model=TransferFundsSchema,
        handler=transfer_funds,
    )
    runtime.register_tool(
        name="export_logs",
        tier=ToolTier.L2_STATE_CHANGING,
        min_role=UserRole.STANDARD_USER,
        impact_summary="Dumps system audit logs to local disk",
        schema_model=ExportLogsSchema,
        handler=export_logs,
    )

    session_id = "agent_session_alpha"
    operator_ctx = CallerContext(
        agent_id="autonomous_trader_v1",
        user_role=UserRole.OPERATOR,
        session_id=session_id,
    )

    # =========================================================================
    # TRACK A: L1 Read-Only (Safe Pass-Through)
    # =========================================================================
    print(f"{BOLD}▶ TRACK A: L1 Read-Only Pass-Through{RESET}")
    print(f"  Agent intent: Query treasury account balance.")
    req_a = ToolExecutionRequest(
        session_id=session_id,
        tool_name="get_account_balance",
        arguments={"account_id": "TREASURY-01"},
        caller_context=operator_ctx,
    )
    res_a = await runtime.execute_tool(req_a)
    print(f"  [{GREEN}PASS-THROUGH{RESET}] Tier: {ToolTier.L1_READ_ONLY.value}")
    print(f"  Execution Time: {BOLD}{res_a.execution_time_ms:.3f} ms{RESET}")
    print(f"  Payload Returned: {res_a.data}")
    print("-" * 76 + "\n")

    # =========================================================================
    # TRACK B: L2 State-Changing (Audit Trail & Policy Check)
    # =========================================================================
    print(f"{BOLD}▶ TRACK B: L2 State-Changing Action{RESET}")
    print(f"  Agent intent: Update operator notification preferences.")
    req_b = ToolExecutionRequest(
        session_id=session_id,
        tool_name="update_profile",
        arguments={"display_name": "QuantDesk-1", "email_notifications": True},
        caller_context=operator_ctx,
    )
    res_b = await runtime.execute_tool(req_b)
    print(f"  [{BLUE}AUDITED & EXECUTED{RESET}] Tier: {ToolTier.L2_STATE_CHANGING.value}")
    print(f"  Execution Time: {BOLD}{res_b.execution_time_ms:.3f} ms{RESET}")
    print(f"  Audit Hash: {DIM}{res_b.audit_hash[:20]}...{RESET}")
    print(f"  Payload Returned: {res_b.data}")
    print("-" * 76 + "\n")

    # =========================================================================
    # TRACK C: L3 Critical Action (Zero-Trust Suspension & Human Sign-off)
    # =========================================================================
    print(f"{BOLD}▶ TRACK C: L3 Critical Action Interception (Zero-Trust Suspension){RESET}")
    print(f"  Agent intent: Initiate wire transfer of $50,000 USD to external counterparty.")
    req_c = ToolExecutionRequest(
        session_id=session_id,
        tool_name="transfer_funds",
        arguments={
            "destination_iban": "CH93-0000-1111-2222-3333",
            "amount_usd": 50000.0,
            "note": "Liquidity rebalance to Vault",
        },
        caller_context=operator_ctx,
    )
    res_c = await runtime.execute_tool(req_c)
    ticket_id = res_c.ticket_id

    card = await runtime.suspension.get_ticket(ticket_id)
    print(f"  [{YELLOW}SUSPENDED{RESET}] Zero-Trust Interception Triggered!")
    print(f"""  ┌─────────────────── APPROVAL SUSPENSION CARD ───────────────────┐
  │ Ticket ID:       {card.ticket_id}
  │ Tool:            {card.tool_name}
  │ Risk Level:      {RED}{card.risk_level.value}{RESET}
  │ Impact:          {card.impact_summary}
  │ Expiry (TTL):    {card.expires_at.strftime('%H:%M:%S UTC')}
  │ HMAC Signature:  {DIM}{card.audit_hash[:28]}...{RESET}
  │ Arguments:       {card.arguments}
  └─────────────────────────────────────────────────────────────────┘""")

    decision_approved = True
    if not non_interactive:
        prompt = input(f"  {BOLD}Operator Action: Approve execution? [y/N]: {RESET}").strip().lower()
        decision_approved = prompt in ("y", "yes")
    elif reject_l3:
        decision_approved = False

    print(f"  Operator Decision: {'APPROVED' if decision_approved else 'REJECTED'}")
    res_c_resumed = await runtime.resume_ticket(
        ticket_id=ticket_id,
        approved=decision_approved,
        operator_id="human_supervisor_01",
        feedback="Verified destination counterparty and treasury allocation",
    )

    if res_c_resumed.success:
        print(f"  [{GREEN}RESUMED & SETTLED{RESET}] Actuator Executed Successfully!")
        print(f"  Settlement Details: {res_c_resumed.data}")
    else:
        print(f"  [{RED}ABORTED{RESET}] {res_c_resumed.error}")
    print("-" * 76 + "\n")

    # =========================================================================
    # TRACK D: Injection Attack & Self-Correction Feedback Loop
    # =========================================================================
    print(f"{BOLD}▶ TRACK D: Security Parameter Injection & Self-Correction Loop{RESET}")
    print(f"  Malicious prompt injected via agent context: 'export logs to /var/log; rm -rf /'")
    req_d_bad = ToolExecutionRequest(
        session_id=session_id,
        tool_name="export_logs",
        arguments={"output_path": "/var/log/audit.log; rm -rf /"},
        caller_context=operator_ctx,
    )
    res_d_bad = await runtime.execute_tool(req_d_bad)
    print(f"  [{RED}SECURITY INTERCEPT{RESET}] Malicious payload blocked by InjectionGuard!")
    print(f"{DIM}{res_d_bad.error}{RESET}\n")

    print(f"  {BOLD}Simulating Agent Self-Correction:{RESET}")
    print(f"  Agent parses diagnostic prompt, sanitizes path to 'exports/safe_audit.log', and retries...")
    req_d_clean = ToolExecutionRequest(
        session_id=session_id,
        tool_name="export_logs",
        arguments={"output_path": "exports/safe_audit.log"},
        caller_context=operator_ctx,
    )
    res_d_clean = await runtime.execute_tool(req_d_clean)
    print(f"  [{GREEN}RE-EXECUTION SUCCESS{RESET}] Cleaned Arguments Passed: {res_d_clean.data}")
    print("-" * 76 + "\n")

    # =========================================================================
    # TRACK E: Circuit Breaker Tripping (Preventing Infinite Tool Loops)
    # =========================================================================
    print(f"{BOLD}▶ TRACK E: Circuit Breaker Tripping (Runaway Agent Mitigation){RESET}")
    print(f"  Simulating a confused agent executing repeated critical calls in loop...")

    loop_session = "infinite_loop_session"
    loop_ctx = CallerContext(
        agent_id="confused_agent",
        user_role=UserRole.OPERATOR,
        session_id=loop_session,
    )
    req_loop = ToolExecutionRequest(
        session_id=loop_session,
        tool_name="transfer_funds",
        arguments={"destination_iban": "CH93-0000-1111-2222-3333", "amount_usd": 10.0},
        caller_context=loop_ctx,
    )

    for call_idx in range(1, 4):
        res_loop = await runtime.execute_tool(req_loop)
        if res_loop.success or "SUSPENDED" in (res_loop.error or ""):
            print(f"  Call #{call_idx}: Intercepted as normal ({YELLOW}L3 Suspended{RESET})")
        else:
            print(f"  Call #{call_idx}: [{MAGENTA}CIRCUIT BREAKER TRIPPED{RESET}] {res_loop.error}")
            break

    print("-" * 76 + "\n")

    # =========================================================================
    # Cryptographic Audit Trail Verification
    # =========================================================================
    print(f"{BOLD}▶ CRYPTOGRAPHIC AUDIT LOG INTEGRITY VERIFICATION{RESET}")
    is_valid, err = runtime.audit_trail.verify_integrity()
    entries = runtime.audit_trail.entries
    print(f"  Total Audited Events: {len(entries)}")
    print(f"  Chain Status: {'✅ VALID & UNTAMPERED' if is_valid else '❌ CORRUPTED'}")
    if entries:
        print(f"  Genesis Hash: {DIM}{entries[0].previous_hash[:20]}...{RESET}")
        print(f"  Latest Hash:  {DIM}{entries[-1].entry_hash[:20]}...{RESET}")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TAG Deterministic CLI Demo")
    parser.add_argument("--auto", action="store_true", help="Run in automated non-interactive mode")
    parser.add_argument("--reject-l3", action="store_true", help="Simulate human operator rejecting L3")
    args = parser.parse_args()

    asyncio.run(main(non_interactive=args.auto, reject_l3=args.reject_l3))
