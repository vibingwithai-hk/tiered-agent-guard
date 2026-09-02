"""Unit tests for SuspensionController, CryptoSigner, and StateStore."""

import asyncio
from datetime import timedelta
import pytest

from tag.core.contracts import CallerContext, ToolExecutionRequest, utc_now
from tag.core.enums import RiskLevel, TicketStatus, UserRole
from tag.core.exceptions import ApprovalExpiredError, ApprovalTamperedError
from tag.core.state_store import InMemoryTicketStore
from tag.suspension.controller import SuspensionController
from tag.suspension.crypto import CryptoSigner


@pytest.fixture
def setup_suspension():
    store = InMemoryTicketStore()
    signer = CryptoSigner(secret_key=b"super_secret_test_key_32bytes_!!")
    controller = SuspensionController(store=store, signer=signer, default_ttl_seconds=2)
    return controller, store, signer


@pytest.mark.asyncio
async def test_ticket_creation_and_approval(setup_suspension):
    controller, store, _ = setup_suspension
    req = ToolExecutionRequest(
        session_id="session_test",
        tool_name="transfer_funds",
        arguments={"to": "Alice", "amount": 1000},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.OPERATOR, session_id="session_test"
        ),
    )

    card = await controller.create_ticket(
        request=req,
        impact_summary="Transfer $1000 to Alice",
        risk_level=RiskLevel.HIGH,
    )

    assert card.status == TicketStatus.PENDING
    assert card.audit_hash != ""

    # Human approves with verified arguments
    resolved = await controller.resolve_ticket(
        ticket_id=card.ticket_id,
        approved=True,
        operator_id="operator_bob",
        feedback="Verified destination account",
        verify_arguments={"to": "Alice", "amount": 1000},
    )

    assert resolved.status == TicketStatus.APPROVED
    assert resolved.operator_id == "operator_bob"


@pytest.mark.asyncio
async def test_tampering_rejection(setup_suspension):
    controller, _, _ = setup_suspension
    req = ToolExecutionRequest(
        session_id="session_test",
        tool_name="transfer_funds",
        arguments={"to": "Alice", "amount": 1000},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.OPERATOR, session_id="session_test"
        ),
    )

    card = await controller.create_ticket(
        request=req,
        impact_summary="Transfer $1000 to Alice",
    )

    # Malicious actor tries to approve while quietly changing amount to $99999
    with pytest.raises(ApprovalTamperedError):
        await controller.resolve_ticket(
            ticket_id=card.ticket_id,
            approved=True,
            operator_id="attacker",
            verify_arguments={"to": "Alice", "amount": 99999},  # Tampered!
        )


@pytest.mark.asyncio
async def test_ttl_expiration(setup_suspension):
    controller, _, _ = setup_suspension
    req = ToolExecutionRequest(
        session_id="session_test",
        tool_name="restart_server",
        arguments={"graceful": False},
        caller_context=CallerContext(
            agent_id="agent_1", user_role=UserRole.OPERATOR, session_id="session_test"
        ),
    )

    # Short 0.1s TTL
    card = await controller.create_ticket(
        request=req,
        impact_summary="Immediate restart",
        ttl_seconds=0,  # Expire immediately
    )

    # Artificially shift expires_at to the past
    card.expires_at = utc_now() - timedelta(seconds=5)
    await controller.store.save_ticket(card)

    with pytest.raises(ApprovalExpiredError):
        await controller.resolve_ticket(
            ticket_id=card.ticket_id,
            approved=True,
            operator_id="admin",
        )
