"""Injection Guard: Static heuristic and pattern inspection against malicious payloads.

Protects actuators from Shell Command Hijacking, Path Traversal, and SQL injection in tool arguments.
"""

import re
from typing import Any, Optional


class InjectionGuard:
    """Zero-trust pattern inspector for tool call arguments."""

    # Shell command chaining and dangerous executable sequences
    COMMAND_INJECTION_PATTERNS = [
        (re.compile(r"[;&|`$]\s*(rm|mkfs|dd|chmod|chown|kill|bash|sh|curl|wget|python|nc|eval)\b", re.IGNORECASE),
         "Shell command chaining or destructive binary execution attempt"),
        (re.compile(r"\$\(.*?\)|`.*?`", re.IGNORECASE),
         "Subshell / Command substitution attempt"),
        (re.compile(r"\b(curl|wget)\s+.*?\s*\|\s*(sh|bash)", re.IGNORECASE),
         "Remote script piping to shell execution"),
        (re.compile(r"\brm\s+-(rf|fr|r)\b", re.IGNORECASE),
         "Recursive destructive removal flag detected"),
        (re.compile(r"\b(chmod\s+777|sudo\s+)", re.IGNORECASE),
         "Privilege escalation or insecure permission modification detected"),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
         "Directory traversal (../ or ..\\) detected"),
        (re.compile(r"^/(etc/(passwd|shadow)|root|proc/)", re.IGNORECASE),
         "Restricted system directory path access detected"),
    ]

    # Destructive SQL patterns
    SQL_INJECTION_PATTERNS = [
        (re.compile(r"\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT)\b", re.IGNORECASE),
         "SQL UNION-based exfiltration detected"),
        (re.compile(r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b", re.IGNORECASE),
         "Destructive SQL DDL statement detected"),
        (re.compile(r"(--|/\*|\*/)\s*$", re.IGNORECASE),
         "SQL comment truncation detected"),
    ]

    @classmethod
    def inspect_value(cls, key: str, value: Any) -> list[str]:
        """Inspect a single key-value pair for injection indicators."""
        violations: list[str] = []
        if isinstance(value, str):
            # Check Command Injection
            for pattern, reason in cls.COMMAND_INJECTION_PATTERNS:
                if pattern.search(value):
                    violations.append(f"Field '{key}' failed security audit: {reason} [Match: '{value[:40]}...']")

            # Check Path Traversal
            for pattern, reason in cls.PATH_TRAVERSAL_PATTERNS:
                if pattern.search(value):
                    violations.append(f"Field '{key}' failed security audit: {reason} [Match: '{value[:40]}...']")

            # Check SQL Injection
            for pattern, reason in cls.SQL_INJECTION_PATTERNS:
                if pattern.search(value):
                    violations.append(f"Field '{key}' failed security audit: {reason} [Match: '{value[:40]}...']")

        elif isinstance(value, dict):
            for sub_key, sub_val in value.items():
                violations.extend(cls.inspect_value(f"{key}.{sub_key}", sub_val))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                violations.extend(cls.inspect_value(f"{key}[{i}]", item))

        return violations

    @classmethod
    def audit_arguments(cls, arguments: dict[str, Any]) -> list[str]:
        """Audit all fields in an argument dictionary."""
        violations: list[str] = []
        for key, val in arguments.items():
            violations.extend(cls.inspect_value(key, val))
        return violations
