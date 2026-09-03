"""Mock Autonomous Agent showcasing integration with TAG."""

import asyncio
import sys
from pathlib import Path
from typing import Any

# Ensure src in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tag.core.contracts import CallerContext, ExecutionResult, ToolExecutionRequest
from tag.core.enums import UserRole
from tag.interceptor import TAGRuntime


class MockAutonomousAgent:
    """Simulates an Autonomous AI Agent loop with perception, tool selection, and reflection."""

    def __init__(self, agent_id: str, role: UserRole, runtime: TAGRuntime) -> None:
        self.agent_id = agent_id
        self.role = role
        self.runtime = runtime
        self.session_id = f"session_{agent_id}"

    async def execute_action(self, tool_name: str, arguments: dict[str, Any]) -> ExecutionResult:
        """Emits a ToolExecutionRequest into the TAG runtime."""
        context = CallerContext(
            agent_id=self.agent_id,
            user_role=self.role,
            session_id=self.session_id,
        )
        req = ToolExecutionRequest(
            session_id=self.session_id,
            tool_name=tool_name,
            arguments=arguments,
            caller_context=context,
        )
        return await self.runtime.execute_tool(req)
