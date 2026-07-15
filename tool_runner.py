"""Launch one whitelisted Cros tool in its own Windows console."""

from __future__ import annotations

import os
import sys

from app_catalog import TOOL_KEYS


def run(category: str, tool_id: str) -> None:
    if category == "terminal" and tool_id == "main":
        import osint_tool
        osint_tool.main()
        return

    key = f"{category}:{tool_id}"
    if key not in TOOL_KEYS:
        raise ValueError("Unknown or unavailable tool selection")

    if category in {"osint", "advanced"}:
        import osint_tool
        osint_tool.enable_terminal_colors()
        osint_tool.pause = lambda: None
        actions = osint_tool.MAIN_ACTIONS if category == "osint" else osint_tool.ADVANCED_ACTIONS
        action = actions.get(tool_id)
    elif category == "security":
        import security_tools
        security_tools.pause = lambda: None
        action = security_tools.SECURITY_ACTIONS.get(tool_id)
    else:
        action = None

    if action is None:
        raise ValueError("The selected tool is not registered")
    action()


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: tool_runner.py <category> <tool-id>")
        return 2
    category, tool_id = sys.argv[1].strip().lower(), sys.argv[2].strip()
    os.system(f"title Cros // {category.upper()} {tool_id}")
    try:
        run(category, tool_id)
    except KeyboardInterrupt:
        print("\nTool cancelled.")
    except Exception as exc:
        print(f"\nTool error: {exc}")
    try:
        input("\nPress Enter to close this tool window...")
    except (EOFError, KeyboardInterrupt):
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

