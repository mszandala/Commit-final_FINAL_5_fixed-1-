from chatbot.agent import run_agent, _current_tool_gate
from typing import Optional

def create_subagent(user_message: str) -> str:
    """Run a child agent for the given task.

    The child inherits the caller's tool gate, but cannot create
    another subagent.
    """
    parent_gate = _current_tool_gate.get()

    def child_gate(name: str, args: dict) -> Optional[str]:
        if name == "create_subagent":
            return "Tool rejected: subagents cannot create further subagents."

        if parent_gate is not None:
            return parent_gate(name, args)

        return None

    result, _ = run_agent(user_message, tool_gate=child_gate)

    return result