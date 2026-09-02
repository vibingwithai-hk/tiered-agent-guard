"""Circuit Breaker for preventing agent budget burn and infinite tool call loops."""

import time
from collections import defaultdict
from typing import Optional

from tag.core.enums import ToolTier
from tag.core.exceptions import CircuitBreakerTrippedError


class CircuitBreaker:
    """Monitors tool execution frequency per session and trips if thresholds are exceeded."""

    def __init__(
        self,
        max_calls_per_session: int = 50,
        max_critical_calls_per_session: int = 5,
        max_rate_per_minute: int = 30,
    ) -> None:
        self.max_calls_per_session = max_calls_per_session
        self.max_critical_calls_per_session = max_critical_calls_per_session
        self.max_rate_per_minute = max_rate_per_minute

        self._session_total_calls: dict[str, int] = defaultdict(int)
        self._session_critical_calls: dict[str, int] = defaultdict(int)
        self._session_call_timestamps: dict[str, list[float]] = defaultdict(list)
        self._tripped_sessions: set[str] = set()

    def is_tripped(self, session_id: str) -> bool:
        return session_id in self._tripped_sessions

    def check_and_increment(self, session_id: str, tier: ToolTier) -> None:
        """Evaluate session limits and record execution attempt.

        Raises:
            CircuitBreakerTrippedError: If any safety threshold is breached.
        """
        if session_id in self._tripped_sessions:
            raise CircuitBreakerTrippedError(
                session_id=session_id,
                call_count=self._session_total_calls[session_id],
                threshold=self.max_calls_per_session,
            )

        now = time.monotonic()

        # 1. Check rate limit (sliding window 60s)
        window = [ts for ts in self._session_call_timestamps[session_id] if now - ts < 60.0]
        if len(window) >= self.max_rate_per_minute:
            self._tripped_sessions.add(session_id)
            raise CircuitBreakerTrippedError(
                session_id=session_id,
                call_count=len(window),
                threshold=self.max_rate_per_minute,
            )

        # 2. Check total session calls
        total_calls = self._session_total_calls[session_id] + 1
        if total_calls > self.max_calls_per_session:
            self._tripped_sessions.add(session_id)
            raise CircuitBreakerTrippedError(
                session_id=session_id,
                call_count=total_calls,
                threshold=self.max_calls_per_session,
            )

        # 3. Check critical calls limit (L3)
        if tier == ToolTier.L3_CRITICAL:
            crit_calls = self._session_critical_calls[session_id] + 1
            if crit_calls > self.max_critical_calls_per_session:
                self._tripped_sessions.add(session_id)
                raise CircuitBreakerTrippedError(
                    session_id=session_id,
                    call_count=crit_calls,
                    threshold=self.max_critical_calls_per_session,
                )
            self._session_critical_calls[session_id] = crit_calls

        # Commit increments
        self._session_total_calls[session_id] = total_calls
        window.append(now)
        self._session_call_timestamps[session_id] = window

    def reset_session(self, session_id: str) -> None:
        """Reset counters for a given session."""
        self._session_total_calls.pop(session_id, None)
        self._session_critical_calls.pop(session_id, None)
        self._session_call_timestamps.pop(session_id, None)
        self._tripped_sessions.discard(session_id)
