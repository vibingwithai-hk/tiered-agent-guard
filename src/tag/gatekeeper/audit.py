"""Tamper-evident audit logging for tool executions using cryptographic hash-chaining."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field

from tag.core.contracts import utc_now
from tag.core.enums import ToolTier, Verdict


def hash_payload(data: Any) -> str:
    """Deterministic SHA-256 digest of arbitrary payload."""
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditEntry(BaseModel):
    """Immutable audit record within the tamper-evident chain."""
    sequence_id: int
    timestamp: datetime = Field(default_factory=utc_now)
    request_id: str
    session_id: str
    tool_name: str
    tier: ToolTier
    verdict: Verdict
    arguments_hash: str
    previous_hash: str
    entry_hash: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditTrail:
    """Append-only, cryptographically verifiable audit log."""

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def record_event(
        self,
        request_id: str,
        session_id: str,
        tool_name: str,
        tier: ToolTier,
        verdict: Verdict,
        arguments: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        """Append a new event and compute chained hash."""
        seq_id = len(self._entries) + 1
        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        args_hash = hash_payload(arguments)
        now = utc_now()

        # Compute tamper-evident hash
        hash_content = f"{seq_id}|{now.isoformat()}|{request_id}|{session_id}|{tool_name}|{tier.value}|{verdict.value}|{args_hash}|{prev_hash}"
        entry_hash = hashlib.sha256(hash_content.encode("utf-8")).hexdigest()

        entry = AuditEntry(
            sequence_id=seq_id,
            timestamp=now,
            request_id=request_id,
            session_id=session_id,
            tool_name=tool_name,
            tier=tier,
            verdict=verdict,
            arguments_hash=args_hash,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            metadata=metadata or {},
        )
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify the entire chain from genesis to head."""
        prev_hash = self.GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.previous_hash != prev_hash:
                return False, f"Broken chain link at sequence {entry.sequence_id}: expected {prev_hash}, got {entry.previous_hash}"

            hash_content = f"{entry.sequence_id}|{entry.timestamp.isoformat()}|{entry.request_id}|{entry.session_id}|{entry.tool_name}|{entry.tier.value}|{entry.verdict.value}|{entry.arguments_hash}|{entry.previous_hash}"
            expected_hash = hashlib.sha256(hash_content.encode("utf-8")).hexdigest()
            if entry.entry_hash != expected_hash:
                return False, f"Tampered entry at sequence {entry.sequence_id}: content does not match hash"

            prev_hash = entry.entry_hash

        return True, None
