# Tiered Agent Guard (TAG)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)](#test-suite)
[![Type](https://img.shields.io/badge/Type-Practice_Prototype-lightgrey.svg)](#scope-limitations--non-goals)

> **A lightweight security middleware and execution gatekeeper prototype for Autonomous AI Agents.**
> 
> *Developed as a practice project to explore safety boundaries, state machines, and Human-in-the-Loop (HITL) interception patterns.*
> 
> *Note on Terminology: Tiers here (L1–L3) denote tool risk classes, not agent-loop layers or Berkeley Table-Augmented Generation.*

---

## Problem Formulation & Motivation

Autonomous AI Agents (ReAct, Plan-and-Solve, Tool-calling agents) are empowered with direct access to system actuators—databases, shell environments, APIs, and financial payment rails. In production, unconstrained tool execution introduces real operational liabilities:

1. **Excessive Agency (OWASP LLM06)**: An agent experiencing prompt injection or reasoning drift can emit destructive commands (e.g., `DROP TABLE`, unauthorized wire transfers, or cascading state updates).
2. **Schema & Argument Drift**: LLMs frequently emit malformed, out-of-spec JSON types or omitted required fields, causing uncaught runtime exceptions and actuator panics.
3. **Runaway Loops & Budget Burning**: An agent trapped in a reasoning thrashing cycle can trigger expensive external tools dozens of times in seconds.

**Tiered Agent Guard (TAG)** addresses this by decoupling **Action Governance** from **Agent Orchestration**. It functions as a lightweight, pre-flight gatekeeper that categorizes tools into three deterministic tiers, audits arguments, enforces session circuit breakers, and coordinates **Human-In-The-Loop (HITL) Suspension**.

---

## Three-Tier Governance Matrix

| Tier | Classification | Semantic Purpose | Policy Strategy | Overhead (In-Process) | Typical Use-cases |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **L1** | `L1_READ_ONLY` | Pure idempotent queries; zero side-effects. | **Auto-Approve Pass-Through** | ~0.08 ms ($80\,\mu\text{s}$) | Read DB, vector search, status lookup |
| **L2** | `L2_STATE_CHANGING` | Reversible, low-risk state mutations. | **RBAC Check + Audit Log** | ~0.18 ms ($176\,\mu\text{s}$) | Draft comment, update tag, set preference |
| **L3** | `L3_CRITICAL` | Irreversible, destructive, or financial operations. | **HITL Suspension & Approval** | Human review time (TTL-bounded) | Wire transfer, delete schema, server reboot |

*(Note: In-process Python overhead is negligible compared to network model roundtrips; demonstrates that local gatekeeping will not become the system latency bottleneck).*

---

## Scope, Limitations & Non-Goals

To ensure clear engineering boundaries, the following limitations are explicitly documented:

0. **Practice & Learning Purpose**:
   * This project is a personal practice implementation and prototype created to study agent execution governance and defense-in-depth patterns. It is not an enterprise-certified security product.
1. **Regex Filter vs. Sandbox Isolation**:
   * `InjectionGuard` is a first-pass, cheap regex heuristic for obvious command-chaining operators (`&&`, `;`, `|`, `$(...)`) and path traversal (`../`). Known bypasses exist; it does **not** replace kernel-level virtualization or containers (Docker, gVisor, Firecracker) for untrusted code execution.
2. **Reasoning vs. Action Containment**:
   * TAG does **not** fix or solve LLM hallucinations during internal thought processes. Its objective is strictly **blast radius containment**: preventing hallucinated decisions from causing unauthorized mutations in backend actuators.
3. **Decorator Call-Site Dependency**:
   * The `@guard` decorator enforces policy at the entrypoint of wrapped Python functions. If a caller invokes an unwrapped function directly, no gatekeeping occurs (unlike network-level proxy firewalls or database-level row/role permissions).
4. **Human Bottleneck on L3**:
   * Suspending L3 tools introduces human latency into an otherwise automated workflow. If operators are unavailable, tickets will expire based on their TTL (default 10 minutes) and safely abort.
5. **Single-Process vs. Distributed Scale**:
   * The built-in `InMemoryTicketStore` is designed for single-process workers, CLI tools, and testing. For distributed multi-instance services, you must provide an implementation of the `StateStore` protocol backed by a shared persistence layer (e.g., Redis or PostgreSQL).

---

## Architectural Rationale: Why Not Just Use LangChain / LangGraph?

A common question is: *"LangGraph already provides `interrupt()` for human-in-the-loop. Why build a dedicated guard?"*

| Dimension | LangGraph `interrupt()` | Tiered Agent Guard (TAG) |
| :--- | :--- | :--- |
| **Architectural Layer** | **Application / Orchestration Layer**<br>(Tied to specific graph workflow) | **Call-Site Middleware**<br>(Decorator attached directly to actuator functions) |
| **Framework Lock-in** | Locked into LangChain ecosystem; breaks if switching to raw OpenAI/Anthropic SDK or DSPy | **Framework-Agnostic**; pure Python + Pydantic, portable to any codebase |
| **Enforcement Point** | "Inside-the-loop": Handled within agent graph logic | **Tool Entrypoint**: Gates wrapped functions; but like any decorator, unwrapped functions have no protection |
| **State Verification** | Standard state serialization | **HMAC-SHA256 Digest**: Simple payload integrity check to detect accidental alteration while ticket is pending review |
| **Runaway Protection** | Manual node logic | Built-in sliding-window session **Circuit Breakers** |

---

## Quick Start

### Installation

```bash
git clone https://github.com/vibingwithai-hk/tiered-agent-guard.git
cd tiered-agent-guard
pip install -e .
```

### 1. Using the `@guard` Decorator

```python
import asyncio
from pydantic import BaseModel, Field
from tag import guard, ToolTier, RiskLevel, SuspensionException

# 1. Define input contract
class TransferSchema(BaseModel):
    recipient_iban: str = Field(..., min_length=8)
    amount_usd: float = Field(..., gt=0)

# 2. Guard an L3 critical actuator
@guard(
    tier=ToolTier.L3_CRITICAL,
    risk_level=RiskLevel.FATAL,
    impact_summary="Sends funds to external counterparty",
    schema_model=TransferSchema
)
def execute_wire_transfer(recipient_iban: str, amount_usd: float):
    return {"status": "SETTLED", "recipient": recipient_iban, "amount": amount_usd}

async def main():
    try:
        # Default practice caller triggers L3 Human-In-The-Loop suspension
        await execute_wire_transfer(recipient_iban="CH930000111122223333", amount_usd=500.0)
    except SuspensionException as e:
        print(f"Operation Suspended! Ticket ID: {e.ticket_id}")
        # Next: Human operator signs off via CLI or TAGRuntime.resume_ticket()

asyncio.run(main())
```

### 2. Run the Interactive CLI Demo

Run the 5-track deterministic showcase in your terminal:

```bash
python examples/cli_demo.py
```

Or run automated non-interactive mode:

```bash
python examples/cli_demo.py --auto
```

### 3. Run LangGraph Showcase (100% Offline, Zero API Fees)

Demonstrates native LangGraph `interrupt()` flow and TAG `@guard` defense-in-depth:

```bash
python examples/langgraph_demo.py --auto
```

### 4. Run Test Suite (25 Tests)

```bash
pytest tests/ -v
```

---

## Repository Structure

```text
tiered-agent-guard/
├── README.md                      # Architecture, benchmarks, and limitations
├── pyproject.toml                 # Package definition & build config
├── requirements.txt               # Minimal runtime dependencies (pydantic>=2.0)
├── src/
│   └── tag/
│       ├── __init__.py            # Clean public API
│       ├── interceptor.py         # TAGRuntime and @guard decorator
│       ├── core/
│       │   ├── contracts.py       # Pydantic schemas (ToolExecutionRequest, ApprovalCard)
│       │   ├── enums.py           # ToolTier (L1, L2, L3), Verdict, RiskLevel
│       │   ├── exceptions.py      # SecurityValidationError, SuspensionException
│       │   └── state_store.py     # StateStore Protocol & InMemoryTicketStore (TTL)
│       ├── validators/
│       │   ├── injection_guard.py # Static pattern defense (Shell, Path, SQL)
│       │   └── schema_guard.py    # Schema validation & self-correction synthesis
│       ├── gatekeeper/
│       │   ├── audit.py           # Tamper-evident SHA-256 hash-chaining log
│       │   ├── circuit_breaker.py # Sliding-window session loop breaker
│       │   └── policy.py          # RBAC & Tiered decision enforcer
│       └── suspension/
│           ├── controller.py      # Suspension & Resume lifecycle manager
│           └── crypto.py          # HMAC-SHA256 anti-tampering signer
├── examples/
│   ├── cli_demo.py                # 5-track interactive terminal demo
│   ├── langgraph_demo.py          # Zero-cost LangGraph & TAG integration showcase
│   └── mock_agent.py              # Autonomous Agent integration example
├── benchmarks/
│   └── latency_bench.py           # Microsecond precision benchmark
└── tests/
    ├── test_validator.py          # Schema & injection attack tests
    ├── test_gatekeeper.py         # Policy, RBAC, and circuit breaker tests
    ├── test_suspension.py         # Suspension, TTL expiry, and tampering tests
    ├── test_e2e.py                # End-to-end integration & @guard tests
    └── test_langgraph.py          # LangGraph interrupt and TAG actuator defense tests
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
