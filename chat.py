import ast
import json
import os
from pathlib import Path
from typing import Optional

import ollama

MODEL = "gemma4:12b"

BASE_DIR    = Path("./files")
MAX_HISTORY    = 12
MAX_TOOL_STEPS = 10

BASE_DIR.mkdir(exist_ok=True)

def _safe_path(name: str) -> Path:
    path = (BASE_DIR / name).resolve()
    if not str(path).startswith(str(BASE_DIR.resolve())):
        raise ValueError(f"Unsafe path: {name}")
    return path


def read_file(filename: str, start_line: int = 0, end_line: Optional[int] = None) -> str:
    """Read lines from a file in the files/ directory.

    Args:
        filename: Name of the file to read.
        start_line: First line to return (0-indexed, default 0).
        end_line: Last line to return inclusive (default: end of file).

    Returns:
        The requested lines as a string, or an error message.
    """
    path = _safe_path(filename)
    if not path.exists():
        return f"File not found: {filename}"
    lines = path.read_text(encoding="utf-8").splitlines(True)
    if end_line is None or end_line >= len(lines):
        end_line = len(lines)
    return "".join(lines[start_line : end_line])


def list_files() -> str:
    """List all files in the files/ directory, including subdirectories.

    Returns:
        Newline-separated list of relative file paths.
    """
    names = sorted(
        str(p.relative_to(BASE_DIR)).replace("\\", "/")
        for p in BASE_DIR.rglob("*")
        if p.is_file()
    )
    return "\n".join(names) if names else "(no files)"


def write_file(filename: str, content: str, mode: str = "write") -> str:
    """Write or append content to a file in the files/ directory.

    Args:
        filename: Name of the file to write.
        content: Text to write.
        mode: 'write' to overwrite, 'append' to add to the end.

    Returns:
        'Saved' on success, or an error message.
    """
    if mode not in ("write", "append"):
        return f"Invalid mode '{mode}'. Use 'write' or 'append'."
    path = _safe_path(filename)
    with open(path, "w" if mode == "write" else "a", encoding="utf-8") as f:
        f.write(content)
    return "Saved"



TOOLS = [read_file, list_files, write_file]

TOOL_MAP = {fn.__name__: fn for fn in TOOLS}

SYSTEM = (
    "You are a helpful coding assistant. "
    "You have file tools available. Use them whenever the user asks about files or code. "
    "You have a total of 10 tool calls per message. if that's not enough, tell it directly. "
    "Be concise."
)


def run_tool(name: str, args: dict) -> str:
    fn = TOOL_MAP.get(name)
    if fn is None:
        return f"Unknown tool: {name}"
    try:
        result = fn(**args)
        return str(result)
    except Exception as e:
        return f"Tool error: {e}"


def chat() -> None:
    messages: list[dict] = [{"role": "system", "content": SYSTEM}]

    print(f"Chat ready (model: {MODEL}). Type 'quit' to exit.\n")

    while True:
        try:
            user = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if user.lower() == "quit":
            break
        if not user:
            continue

        messages.append({"role": "user", "content": user})

        for step in range(MAX_TOOL_STEPS):
            try:
                response = ollama.chat(
                    model=MODEL,
                    messages=messages,
                    tools=TOOLS,
                )
            except ollama.ResponseError as e:
                print(f"\n[Response error: {e}]\n")
                messages.pop()
                break

            msg = response.message

            if not msg.tool_calls:
                print(f"\nAssistant: {msg.content}\n")
                messages.append({"role": "assistant", "content": msg.content})
                break

            messages.append(msg)

            for tc in msg.tool_calls:
                name = tc.function.name
                args = dict(tc.function.arguments)
                result = run_tool(name, args)
                print(f"  [tool: {name}({args})] → {str(result)[:120]}")
                messages.append({
                    "role": "tool",
                    "content": result,
                })

        else:
            messages.append({"role": "user", "content": "Please give your final answer now."})
            response = ollama.chat(model=MODEL, messages=messages)
            msg = response.message
            print(f"\nAssistant: {msg.content}\n")
            messages.append({"role": "assistant", "content": msg.content})

if __name__ == "__main__":
    try:
        chat()
    except Exception as e:
        import traceback
        print(f"\nCRASH: {type(e).__name__}: {e}")
        traceback.print_exc()

    input("\nPress ENTER to close...")