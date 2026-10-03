from chatbot.agent import run_agent, _current_tool_gate, _max_agent_depth
from typing import Optional

def create_subagent(user_message: str) -> str:
    """Run a child agent for the given task.

    The child inherits the caller's tool gate, but cannot create
    another subagent.
    """
    parent_gate = _current_tool_gate.get()
    parent_depth = _max_agent_depth.get()
    def child_gate(name: str, args: dict) -> Optional[str]:
        if name == "create_subagent" and parent_depth <= 0:
            return "Tool rejected: Maximum subagent depth reached."

        if parent_gate is not None:
            return parent_gate(name, args)

        return None

    result, _ = run_agent(user_message, tool_gate=child_gate, max_depth=parent_depth - 1)

    return result