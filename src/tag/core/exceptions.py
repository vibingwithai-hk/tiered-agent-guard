"""TAG Exception hierarchy."""

from typing import Any, Optional


class TAGException(Exception):
    """Base exception for all Tiered Agent Guard errors."""
    pass


class SecurityValidationError(TAGException):
    """Raised when parameter schema validation or injection audit fails."""

    def __init__(
        self,
        message: str,
        errors: list[str],
        correction_prompt: str,
        tool_name: Optional[str] = None,
    ):
        super().__init__(message)
        self.errors = errors
        self.correction_prompt = correction_prompt
        self.tool_name = tool_name


class SuspensionException(TAGException):
    """Raised when an L3 tool execution is suspended awaiting human sign-off."""

    def __init__(self, ticket_id: str, approval_card: Any):
        super().__init__(f"Execution suspended awaiting human approval. Ticket ID: {ticket_id}")
        self.ticket_id = ticket_id
        self.approval_card = approval_card


class ApprovalExpiredError(TAGException):
    """Raised when a ticket is approved or accessed after its TTL has expired."""
    pass


class ApprovalTamperedError(TAGException):
    """Raised when an approval token signature does not match or payload was altered."""
    pass


class CircuitBreakerTrippedError(TAGException):
    """Raised when session call budget or rate threshold is exceeded."""

    def __init__(self, session_id: str, call_count: int, threshold: int):
        super().__init__(
            f"Circuit breaker tripped for session {session_id}: {call_count} calls exceeded threshold {threshold}"
        )
        self.session_id = session_id
        self.call_count = call_count
        self.threshold = threshold


class UnauthorizedError(TAGException):
    """Raised when caller context has insufficient role for the target tier."""
    pass
