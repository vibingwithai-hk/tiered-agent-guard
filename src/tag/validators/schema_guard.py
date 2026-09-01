"""Schema Contract Validator for Tool Arguments.

Enforces strict Pydantic type models and sanitizes inputs via InjectionGuard.
Generates structured LLM self-correction prompts on failure.
"""

from typing import Any, Optional, Type
from pydantic import BaseModel, ValidationError

from tag.core.exceptions import SecurityValidationError
from tag.validators.injection_guard import InjectionGuard


class ValidationResult(BaseModel):
    """Encapsulates outcome of schema and injection validation."""
    is_valid: bool
    validated_data: dict[str, Any]
    violations: list[str]
    correction_prompt: Optional[str] = None


class SchemaContractValidator:
    """Validates raw tool arguments against strict schemas and injection checks."""

    @classmethod
    def validate(
        cls,
        tool_name: str,
        arguments: dict[str, Any],
        schema: Optional[Type[BaseModel]] = None,
        raise_on_error: bool = False,
    ) -> ValidationResult:
        """Validate arguments against schema and security policies.

        Args:
            tool_name: Target tool name.
            arguments: Raw arguments dict from LLM.
            schema: Optional Pydantic model class.
            raise_on_error: Whether to raise SecurityValidationError on violation.

        Returns:
            ValidationResult with sanitized data or correction guidance.
        """
        violations: list[str] = []
        validated_data: dict[str, Any] = arguments.copy()

        # Step 1: Zero-trust Injection Audit
        injection_violations = InjectionGuard.audit_arguments(arguments)
        if injection_violations:
            violations.extend(injection_violations)

        # Step 2: Strict Pydantic Schema Validation (if schema provided)
        if schema and issubclass(schema, BaseModel):
            try:
                model_instance = schema.model_validate(arguments)
                validated_data = model_instance.model_dump()
            except ValidationError as e:
                for err in e.errors():
                    field_loc = " -> ".join(str(p) for p in err.get("loc", []))
                    err_msg = err.get("msg", "Invalid value")
                    violations.append(f"Schema mismatch on '{field_loc}': {err_msg}")

        # Step 3: Synthesis of LLM Self-Correction Prompt
        if violations:
            correction_prompt = cls._build_correction_prompt(tool_name, arguments, violations, schema)
            if raise_on_error:
                raise SecurityValidationError(
                    message=f"Validation failed for tool '{tool_name}' with {len(violations)} violations",
                    errors=violations,
                    correction_prompt=correction_prompt,
                    tool_name=tool_name,
                )
            return ValidationResult(
                is_valid=False,
                validated_data={},
                violations=violations,
                correction_prompt=correction_prompt,
            )

        return ValidationResult(
            is_valid=True,
            validated_data=validated_data,
            violations=[],
            correction_prompt=None,
        )

    @classmethod
    def _build_correction_prompt(
        cls,
        tool_name: str,
        arguments: dict[str, Any],
        violations: list[str],
        schema: Optional[Type[BaseModel]],
    ) -> str:
        """Constructs an actionable diagnostic prompt for the LLM's next reasoning loop."""
        schema_info = ""
        if schema and hasattr(schema, "model_json_schema"):
            schema_info = f"\nExpected JSON Schema:\n{schema.model_json_schema()}"

        bullets = "\n".join(f"- {v}" for v in violations)
        return (
            f"[SYSTEM INTERCEPT: Tool Call '{tool_name}' Rejected]\n"
            f"The arguments provided failed security and contract validation:\n"
            f"{bullets}\n\n"
            f"Rejected Payload: {arguments}{schema_info}\n\n"
            f"Instructions for Agent: Please rectify the parameter schema, strip malicious "
            f"metacharacters or commands, and re-emit ToolCallRequest with compliant types."
        )
