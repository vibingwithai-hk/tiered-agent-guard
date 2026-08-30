"""State store abstraction and in-memory implementation with TTL management."""

import asyncio
from datetime import datetime, timezone
from typing import Optional, Protocol, runtime_checkable

from tag.core.contracts import ApprovalCard, utc_now
from tag.core.enums import TicketStatus
from tag.core.exceptions import ApprovalExpiredError


@runtime_checkable
class StateStore(Protocol):
    """Protocol defining the interface for storing and retrieving approval tickets."""

    async def save_ticket(self, card: ApprovalCard) -> None:
        """Persist an approval card."""
        ...

    async def get_ticket(self, ticket_id: str) -> Optional[ApprovalCard]:
        """Retrieve ticket by ID, evaluating TTL."""
        ...

    async def update_ticket_status(
        self,
        ticket_id: str,
        status: TicketStatus,
        operator_id: Optional[str] = None,
        feedback: Optional[str] = None,
    ) -> ApprovalCard:
        """Update status of a ticket."""
        ...

    async def cleanup_expired(self) -> int:
        """Mark expired tickets and return count."""
        ...


class InMemoryTicketStore:
    """Thread-safe, asynchronous in-memory ticket store with TTL enforcement."""

    def __init__(self) -> None:
        self._tickets: dict[str, ApprovalCard] = {}
        self._lock = asyncio.Lock()

    async def save_ticket(self, card: ApprovalCard) -> None:
        async with self._lock:
            self._tickets[card.ticket_id] = card

    async def get_ticket(self, ticket_id: str) -> Optional[ApprovalCard]:
        async with self._lock:
            ticket = self._tickets.get(ticket_id)
            if not ticket:
                return None

            # Check TTL
            now = utc_now()
            if ticket.status == TicketStatus.PENDING and now > ticket.expires_at:
                ticket.status = TicketStatus.EXPIRED
                ticket.feedback = f"Ticket expired at {ticket.expires_at.isoformat()} (evaluated at {now.isoformat()})"

            return ticket

    async def update_ticket_status(
        self,
        ticket_id: str,
        status: TicketStatus,
        operator_id: Optional[str] = None,
        feedback: Optional[str] = None,
    ) -> ApprovalCard:
        async with self._lock:
            ticket = self._tickets.get(ticket_id)
            if not ticket:
                raise KeyError(f"Ticket {ticket_id} not found")

            now = utc_now()
            if ticket.status == TicketStatus.PENDING and now > ticket.expires_at:
                ticket.status = TicketStatus.EXPIRED
                ticket.feedback = "Operation rejected: TTL expired before approval"
                raise ApprovalExpiredError(f"Ticket {ticket_id} has expired (TTL exceeded)")

            ticket.status = status
            if operator_id:
                ticket.operator_id = operator_id
            if feedback:
                ticket.feedback = feedback

            return ticket

    async def cleanup_expired(self) -> int:
        async with self._lock:
            now = utc_now()
            expired_count = 0
            for ticket in self._tickets.values():
                if ticket.status == TicketStatus.PENDING and now > ticket.expires_at:
                    ticket.status = TicketStatus.EXPIRED
                    ticket.feedback = "Auto-expired during sweep"
                    expired_count += 1
            return expired_count

    def clear(self) -> None:
        self._tickets.clear()
