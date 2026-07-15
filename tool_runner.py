"""Launch one whitelisted Cros tool in its own Windows console."""

from __future__ import annotations

import os
import sys

from app_catalog import TOOL_KEYS


def show_embedded_link(url: str, *_args, **_kwargs) -> bool:
    print(f"\nExternal research link (copy when needed):\n{url}\n", flush=True)
    return True


def run(category: str, tool_id: str) -> None:
    if category == "terminal" and tool_id == "main":
        import osint_tool
        if os.environ.get("CROS_EMBEDDED") == "1":
            osint_tool.webbrowser.open = show_embedded_link
        osint_tool.main()
        return

    key = f"{category}:{tool_id}"
    if key not in TOOL_KEYS:
        raise ValueError("Unknown or unavailable tool selection")

    if category in {"osint", "advanced"}:
        import osint_tool
        osint_tool.enable_terminal_colors()
        osint_tool.pause = lambda: None
        if os.environ.get("CROS_EMBEDDED") == "1":
            osint_tool.webbrowser.open = show_embedded_link
        actions = osint_tool.MAIN_ACTIONS if category == "osint" else osint_tool.ADVANCED_ACTIONS
        action = actions.get(tool_id)
    elif category == "security":
        import security_tools
        security_tools.pause = lambda: None
        if os.environ.get("CROS_EMBEDDED") == "1":
            security_tools.webbrowser.open = show_embedded_link
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
    embedded = os.environ.get("CROS_EMBEDDED") == "1"
    if not embedded:
        os.system(f"title Cros // {category.upper()} {tool_id}")
    exit_code = 0
    try:
        run(category, tool_id)
    except KeyboardInterrupt:
        print("\nTool cancelled.")
        exit_code = 130
    except Exception as exc:
        print(f"\nTool error: {exc}")
        exit_code = 1
    if not embedded:
        try:
            input("\nPress Enter to close this tool window...")
        except (EOFError, KeyboardInterrupt):
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
