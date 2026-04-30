#!/usr/bin/env python
"""
Entry point for TTD MCP Server.

Usage:
    python run_server.py
"""
import sys
from pathlib import Path

# Add src to path for ttdobjectspy
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Add project root to path for ttd_mcp_server
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ttdobjectspy.server import main

if __name__ == "__main__":
    main()
