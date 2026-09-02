"""Cryptographic integrity module for human approval tokens."""

import hmac
import hashlib
import json
import secrets
from typing import Any, Optional

from tag.core.exceptions import ApprovalTamperedError


def canonical_json(data: Any) -> str:
    """Serialize data to a deterministic, compact JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


class CryptoSigner:
    """HMAC-SHA256 signer ensuring payload integrity between suspension and approval."""

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._secret_key = secret_key or secrets.token_bytes(32)

    def generate_token(self, request_id: str, session_id: str, arguments: dict[str, Any]) -> str:
        """Generate a cryptographic HMAC-SHA256 signature for the tool arguments."""
        message = f"{request_id}:{session_id}:{canonical_json(arguments)}".encode("utf-8")
        return hmac.new(self._secret_key, message, hashlib.sha256).hexdigest()

    def verify_token(
        self,
        request_id: str,
        session_id: str,
        arguments: dict[str, Any],
        expected_token: str,
        raise_on_mismatch: bool = True,
    ) -> bool:
        """Verify that the payload has not been modified or tampered with."""
        actual_token = self.generate_token(request_id, session_id, arguments)
        is_valid = hmac.compare_digest(actual_token, expected_token)

        if not is_valid and raise_on_mismatch:
            raise ApprovalTamperedError(
                f"HMAC signature mismatch! Arguments were tampered with between suspension and approval."
            )
        return is_valid
