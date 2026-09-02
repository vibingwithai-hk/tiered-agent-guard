"""Suspension & Resume Controller for Human-in-the-loop (HITL) approval lifecycle."""

from datetime import timedelta
from typing import Any, Callable, Coroutine, Optional
from uuid import uuid4

from tag.core.contracts import ApprovalCard, ToolExecutionRequest, utc_now
from tag.core.enums import RiskLevel, TicketStatus
from tag.core.exceptions import ApprovalExpiredError, ApprovalTamperedError
from tag.core.state_store import StateStore
from tag.suspension.crypto import CryptoSigner


class SuspensionController:
    """Manages the creation, persistence, verification, and resolution of approval tickets."""

    def __init__(
        self,
        store: StateStore,
        signer: Optional[CryptoSigner] = None,
        default_ttl_seconds: int = 600,
        on_suspended_event: Optional[Callable[[ApprovalCard], Any]] = None,
    ) -> None:
        self.store = store
        self.signer = signer or CryptoSigner()
        self.default_ttl_seconds = default_ttl_seconds
        self.on_suspended_event = on_suspended_event

    async def create_ticket(
        self,
        request: ToolExecutionRequest,
        impact_summary: str,
        risk_level: RiskLevel = RiskLevel.HIGH,
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalCard:
        """Create and persist a new suspended approval ticket."""
        ttl = ttl_seconds or self.default_ttl_seconds
        expires_at = utc_now() + timedelta(seconds=ttl)
        ticket_id = str(uuid4())

        audit_hash = self.signer.generate_token(
            request_id=request.request_id,
            session_id=request.session_id,
            arguments=request.arguments,
        )

        card = ApprovalCard(
            ticket_id=ticket_id,
            request_id=request.request_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            risk_level=risk_level,
            impact_summary=impact_summary,
            arguments=request.arguments,
            expires_at=expires_at,
            status=TicketStatus.PENDING,
            audit_hash=audit_hash,
        )

        await self.store.save_ticket(card)

        if self.on_suspended_event:
            result = self.on_suspended_event(card)
            if isinstance(result, Coroutine):
                await result

        return card

    async def get_ticket(self, ticket_id: str) -> Optional[ApprovalCard]:
        """Fetch ticket by ID."""
        return await self.store.get_ticket(ticket_id)

    async def resolve_ticket(
        self,
        ticket_id: str,
        approved: bool,
        operator_id: str,
        feedback: Optional[str] = None,
        verify_arguments: Optional[dict[str, Any]] = None,
    ) -> ApprovalCard:
        """Resolve a pending ticket with operator decision and tampering check."""
        ticket = await self.store.get_ticket(ticket_id)
        if not ticket:
            raise KeyError(f"Ticket '{ticket_id}' not found")

        if ticket.status == TicketStatus.EXPIRED:
            raise ApprovalExpiredError(f"Ticket '{ticket_id}' has expired and cannot be resolved")

        if ticket.status != TicketStatus.PENDING:
            raise ValueError(f"Ticket '{ticket_id}' is already {ticket.status.value}")

        # Check payload tampering if arguments provided at resolution
        if verify_arguments is not None:
            self.signer.verify_token(
                request_id=ticket.request_id,
                session_id=ticket.session_id,
                arguments=verify_arguments,
                expected_token=ticket.audit_hash,
                raise_on_mismatch=True,
            )

        new_status = TicketStatus.APPROVED if approved else TicketStatus.REJECTED
        updated = await self.store.update_ticket_status(
            ticket_id=ticket_id,
            status=new_status,
            operator_id=operator_id,
            feedback=feedback or ("Approved by operator" if approved else "Rejected by operator"),
        )
        return updated
