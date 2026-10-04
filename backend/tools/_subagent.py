from audit import logger as audit
from chatbot.agent import run_agent, _current_tool_gate, _max_agent_depth
from typing import Optional

DEPTH_REASON = "Maximum subagent depth reached"


def create_subagent(user_message: str) -> str:
    """Run a child agent for the given task.

    The child inherits the caller's tool gate, but cannot create
    another subagent.
    """
    parent_gate = _current_tool_gate.get()
    parent_depth = _max_agent_depth.get()
    def child_gate(name: str, args: dict) -> Optional[str]:
        if name == "create_subagent" and parent_depth <= 0:
            # Odmowa ma być widoczna w logach i w czacie jak każda inna decyzja warstwy bezpieczeństwa.
            call = {"tool": name, "args": args, "allowed": False, "stage": "subagent_depth", "reason": DEPTH_REASON}
            calls = getattr(parent_gate, "calls", None)
            if isinstance(calls, list):
                calls.append(call)
            audit.record("tool_call", "security", tool=name, allowed=False, args=args, stage="subagent_depth",
                         reason=DEPTH_REASON)
            return f"Tool rejected: {DEPTH_REASON}."

        if parent_gate is not None:
            return parent_gate(name, args)

        return None

    result, _ = run_agent(user_message, tool_gate=child_gate, max_depth=parent_depth - 1)

    return result