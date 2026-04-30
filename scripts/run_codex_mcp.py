#!/usr/bin/env python3
"""
Codex plugin launcher for TTDObjectsPy.

This script makes the bundled MCP server clone-path independent:
- It resolves the repo root from this file's location
- It adds `src/` to sys.path so local sources are importable
- It bootstraps Python dependencies on first run if needed
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"


def _add_local_paths() -> None:
    repo = str(REPO_ROOT)
    src = str(SRC_ROOT)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    if src not in sys.path:
        sys.path.insert(0, src)


def _ensure_dependencies() -> None:
    try:
        import mcp  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-e", str(REPO_ROOT)],
        cwd=str(REPO_ROOT),
    )


def main() -> None:
    _add_local_paths()
    _ensure_dependencies()
    _add_local_paths()

    from ttdobjectspy.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
