#!/usr/bin/env python3
"""
TTD-Binary Ninja Unified Bridge

A comprehensive bridge that combines TTD and Binary Ninja MCP servers
for AI-assisted reverse engineering with full coverage.

This module can be used in two ways:
1. As a standalone MCP server that orchestrates both TTD and Binary Ninja
2. As a library for direct integration

Key Features:
- Map TTD execution to Binary Ninja functions
- Annotate Binary Ninja with runtime values from TTD
- Track code coverage and highlight in Binary Ninja
- Cross-reference memory accesses with data references
- Trace function parameters and return values
"""

from __future__ import annotations

import sys
import json
import asyncio
import aiohttp
from pathlib import Path
from typing import Optional, Dict, List, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp.server.fastmcp import FastMCP

from ttdobjectspy.ttd_types import Position, EventType, EventMask
from ttdobjectspy.engine import ReplayEngine
from ttdobjectspy.cursor import Cursor, RegisterState
from ttdobjectspy.bindings import TTDError, TTDNotInitializedError


# =============================================================================
# Configuration
# =============================================================================

BINJA_MCP_HOST = "localhost"
BINJA_MCP_PORT = 9009  # Default Binary Ninja MCP port


# =============================================================================
# Binary Ninja MCP Client
# =============================================================================

class BinjaMCPClient:
    """
    Client for calling Binary Ninja MCP server.
    
    Makes HTTP requests to the Binary Ninja MCP server to access
    its analysis capabilities.
    """
    
    def __init__(self, host: str = BINJA_MCP_HOST, port: int = BINJA_MCP_PORT):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self._connected = False
    
    async def check_connection(self) -> bool:
        """Check if Binary Ninja MCP is available."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/status", timeout=2) as resp:
                    self._connected = resp.status == 200
                    return self._connected
        except Exception:
            self._connected = False
            return False
    
    def is_connected(self) -> bool:
        """Return cached connection status."""
        return self._connected
    
    async def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """
        Call a Binary Ninja MCP tool.
        
        Args:
            tool_name: Name of the tool (e.g., "decompile_function")
            **kwargs: Tool arguments
        
        Returns:
            Tool result dictionary
        """
        if not self._connected:
            if not await self.check_connection():
                return {"error": "Binary Ninja MCP not connected"}
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"tool": tool_name, "arguments": kwargs}
                async with session.post(
                    f"{self.base_url}/call",
                    json=payload,
                    timeout=30
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return {"error": f"HTTP {resp.status}"}
        except Exception as e:
            return {"error": str(e)}
    
    # Convenience methods for common operations
    
    async def get_binary_info(self) -> Dict[str, Any]:
        """Get information about the loaded binary."""
        return await self.call_tool("get_binary_info")
    
    async def function_at(self, address: str) -> Optional[str]:
        """Get function name at address."""
        result = await self.call_tool("function_at", address=address)
        if "error" not in result:
            return result.get("function_name")
        return None
    
    async def decompile_function(self, name: str) -> Optional[str]:
        """Decompile a function by name."""
        result = await self.call_tool("decompile_function", name=name)
        if "error" not in result:
            return result.get("decompiled")
        return None
    
    async def get_function_callers(self, name: str) -> List[str]:
        """Get functions that call this function."""
        result = await self.call_tool("get_function_callers", name=name)
        if "error" not in result:
            return result.get("callers", [])
        return []
    
    async def get_function_callees(self, name: str) -> List[str]:
        """Get functions called by this function."""
        result = await self.call_tool("get_function_callees", name=name)
        if "error" not in result:
            return result.get("callees", [])
        return []
    
    async def set_comment(self, address: str, comment: str) -> bool:
        """Set a comment at an address."""
        result = await self.call_tool("set_comment", address=address, comment=comment)
        return "error" not in result
    
    async def set_function_comment(self, function_name: str, comment: str) -> bool:
        """Set a comment for a function."""
        result = await self.call_tool("set_function_comment", 
                                       function_name=function_name, 
                                       comment=comment)
        return "error" not in result
    
    async def rename_function(self, old_name: str, new_name: str) -> bool:
        """Rename a function."""
        result = await self.call_tool("rename_function", 
                                       old_name=old_name, 
                                       new_name=new_name)
        return "error" not in result
    
    async def get_xrefs_to(self, address: str) -> List[Dict]:
        """Get cross-references to an address."""
        result = await self.call_tool("get_xrefs_to", address=address)
        if "error" not in result:
            return result.get("xrefs", [])
        return []
    
    async def list_functions(self, limit: int = 100, offset: int = 0) -> List[str]:
        """List functions in the binary."""
        result = await self.call_tool("list_methods", limit=limit, offset=offset)
        if "error" not in result:
            return result.get("functions", [])
        return []
    
    async def search_functions(self, query: str) -> List[str]:
        """Search for functions by name pattern."""
        result = await self.call_tool("search_functions_by_name", query=query)
        if "error" not in result:
            return result.get("functions", [])
        return []
    
    async def get_function_vars(self, name: str) -> Dict[str, Any]:
        """Get function variables."""
        return await self.call_tool("get_function_vars", name=name)
    
    async def get_high_level_overview(self, name: str) -> Dict[str, Any]:
        """Get high-level overview of a function."""
        return await self.call_tool("get_high_level_overview", name=name)


# =============================================================================
# Synchronous Wrapper for Binary Ninja Client
# =============================================================================

class BinjaMCPClientSync:
    """
    Synchronous wrapper around BinjaMCPClient.
    
    Runs async operations in an event loop for use in sync contexts.
    """
    
    def __init__(self, host: str = BINJA_MCP_HOST, port: int = BINJA_MCP_PORT):
        self._async_client = BinjaMCPClient(host, port)
        self._loop = None
    
    def _get_loop(self):
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop
    
    def _run(self, coro):
        return self._get_loop().run_until_complete(coro)
    
    def check_connection(self) -> bool:
        return self._run(self._async_client.check_connection())
    
    def is_connected(self) -> bool:
        return self._async_client.is_connected()
    
    def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        return self._run(self._async_client.call_tool(tool_name, **kwargs))
    
    def get_binary_info(self) -> Dict[str, Any]:
        return self._run(self._async_client.get_binary_info())
    
    def function_at(self, address: str) -> Optional[str]:
        return self._run(self._async_client.function_at(address))
    
    def decompile_function(self, name: str) -> Optional[str]:
        return self._run(self._async_client.decompile_function(name))
    
    def get_function_callers(self, name: str) -> List[str]:
        return self._run(self._async_client.get_function_callers(name))
    
    def get_function_callees(self, name: str) -> List[str]:
        return self._run(self._async_client.get_function_callees(name))
    
    def set_comment(self, address: str, comment: str) -> bool:
        return self._run(self._async_client.set_comment(address, comment))
    
    def set_function_comment(self, function_name: str, comment: str) -> bool:
        return self._run(self._async_client.set_function_comment(function_name, comment))
    
    def rename_function(self, old_name: str, new_name: str) -> bool:
        return self._run(self._async_client.rename_function(old_name, new_name))
    
    def get_xrefs_to(self, address: str) -> List[Dict]:
        return self._run(self._async_client.get_xrefs_to(address))
    
    def list_functions(self, limit: int = 100, offset: int = 0) -> List[str]:
        return self._run(self._async_client.list_functions(limit, offset))
    
    def search_functions(self, query: str) -> List[str]:
        return self._run(self._async_client.search_functions(query))
    
    def get_function_vars(self, name: str) -> Dict[str, Any]:
        return self._run(self._async_client.get_function_vars(name))
    
    def get_high_level_overview(self, name: str) -> Dict[str, Any]:
        return self._run(self._async_client.get_high_level_overview(name))


# =============================================================================
# Unified Bridge State
# =============================================================================

@dataclass
class CoverageData:
    """Code coverage tracking."""
    addresses: Dict[int, int] = field(default_factory=dict)  # addr -> hit count
    functions: Dict[str, Set[int]] = field(default_factory=dict)  # func -> positions
    total_instructions: int = 0
    
    def record_hit(self, address: int, position: int = 0):
        self.addresses[address] = self.addresses.get(address, 0) + 1
        self.total_instructions += 1
    
    def get_unique_count(self) -> int:
        return len(self.addresses)
    
    def get_top_addresses(self, n: int = 20) -> List[Tuple[int, int]]:
        return sorted(self.addresses.items(), key=lambda x: -x[1])[:n]
    
    def was_executed(self, address: int) -> bool:
        return address in self.addresses
    
    def get_hit_count(self, address: int) -> int:
        return self.addresses.get(address, 0)


@dataclass 
class FunctionCallRecord:
    """Record of a function call."""
    position: str
    address: int
    function_name: Optional[str]
    parameters: Dict[str, int]  # Register values
    return_value: Optional[int] = None
    return_position: Optional[str] = None


@dataclass
class MemoryAccessRecord:
    """Record of a memory access."""
    position: str
    instruction_address: int
    access_address: int
    access_size: int
    access_type: str  # "read", "write", "execute"
    value: Optional[int] = None


class UnifiedBridge:
    """
    Unified bridge combining TTD and Binary Ninja capabilities.
    
    This class manages the state and operations for combined analysis.
    """
    
    def __init__(self):
        self.ttd_engine: Optional[ReplayEngine] = None
        self.ttd_cursor: Optional[Cursor] = None
        self.binja_client = BinjaMCPClientSync()
        
        self.coverage = CoverageData()
        self.function_calls: List[FunctionCallRecord] = []
        self.memory_accesses: List[MemoryAccessRecord] = []
        
        self._address_to_function: Dict[int, str] = {}  # Cache
    
    def load_ttd_trace(self, trace_path: str) -> bool:
        """Load a TTD trace."""
        if self.ttd_cursor:
            self.ttd_cursor.close()
            self.ttd_cursor = None
        
        if self.ttd_engine:
            self.ttd_engine.close()
        
        self.ttd_engine = ReplayEngine()
        self.ttd_engine.initialize(trace_path)
        self.ttd_cursor = self.ttd_engine.new_cursor()
        
        # Clear cached data
        self.coverage = CoverageData()
        self.function_calls.clear()
        self.memory_accesses.clear()
        self._address_to_function.clear()
        
        return True
    
    def check_binja_connection(self) -> bool:
        """Check if Binary Ninja MCP is available."""
        return self.binja_client.check_connection()
    
    def get_function_at_address(self, address: int) -> Optional[str]:
        """Get Binary Ninja function name at address (with caching)."""
        if address in self._address_to_function:
            return self._address_to_function[address]
        
        if not self.binja_client.is_connected():
            return None
        
        func_name = self.binja_client.function_at(f"0x{address:x}")
        if func_name:
            self._address_to_function[address] = func_name
        
        return func_name
    
    def get_current_context(self) -> Dict[str, Any]:
        """Get combined TTD + Binary Ninja context."""
        if not self.ttd_cursor:
            return {"error": "No TTD trace loaded"}
        
        pc = int(self.ttd_cursor.program_counter)
        regs = self.ttd_cursor.get_registers()
        
        context = {
            "position": self.ttd_cursor.position.to_string(),
            "address": f"0x{pc:x}",
            "registers": regs.to_dict(),
        }
        
        # Add Binary Ninja info if available
        if self.binja_client.is_connected():
            func_name = self.get_function_at_address(pc)
            if func_name:
                context["function"] = func_name
                
                # Get decompiled code
                decompiled = self.binja_client.decompile_function(func_name)
                if decompiled:
                    context["decompiled"] = decompiled
        
        return context
    
    def collect_coverage(self, max_steps: int = 10000) -> CoverageData:
        """Collect code coverage by replaying through trace."""
        if not self.ttd_cursor or not self.ttd_engine:
            raise TTDNotInitializedError("No TTD trace loaded")
        
        # Start from beginning
        self.ttd_cursor.set_position(self.ttd_engine.first_position)
        self.coverage = CoverageData()
        
        steps = 0
        while steps < max_steps:
            pc = int(self.ttd_cursor.program_counter)
            pos = self.ttd_cursor.position
            self.coverage.record_hit(pc, pos.sequence)
            
            result = self.ttd_cursor.step_forward(1)
            steps += 1
            
            if result.stop_reason != EventType.STEP_COUNT:
                break
        
        return self.coverage
    
    def map_coverage_to_functions(self) -> Dict[str, int]:
        """Map coverage data to Binary Ninja functions."""
        if not self.binja_client.is_connected():
            return {}
        
        function_hits: Dict[str, int] = {}
        
        for addr, hits in self.coverage.addresses.items():
            func_name = self.get_function_at_address(addr)
            if func_name:
                function_hits[func_name] = function_hits.get(func_name, 0) + hits
        
        return function_hits
    
    def annotate_coverage_in_binja(self) -> int:
        """Add coverage comments to Binary Ninja."""
        if not self.binja_client.is_connected():
            return 0
        
        annotated = 0
        for addr, hits in self.coverage.get_top_addresses(100):
            comment = f"[TTD] Executed {hits} times"
            if self.binja_client.set_comment(f"0x{addr:x}", comment):
                annotated += 1
        
        return annotated
    
    def trace_function_calls(self, function_address: int, max_calls: int = 50) -> List[FunctionCallRecord]:
        """Trace all calls to a function."""
        if not self.ttd_cursor or not self.ttd_engine:
            raise TTDNotInitializedError("No TTD trace loaded")
        
        original_pos = self.ttd_cursor.position
        self.ttd_cursor.set_position(self.ttd_engine.first_position)
        
        # Get function name if available
        func_name = self.get_function_at_address(function_address)
        
        # Add execute watchpoint
        self.ttd_cursor.add_memory_watchpoint(function_address, 1, access_type="execute")
        
        calls = []
        try:
            while len(calls) < max_calls:
                result = self.ttd_cursor.replay_forward()
                
                if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                    regs = self.ttd_cursor.get_registers()
                    
                    call = FunctionCallRecord(
                        position=self.ttd_cursor.position.to_string(),
                        address=function_address,
                        function_name=func_name,
                        parameters={
                            "rcx": regs.rcx,
                            "rdx": regs.rdx,
                            "r8": regs.r8,
                            "r9": regs.r9,
                        }
                    )
                    calls.append(call)
                    self.ttd_cursor.step_forward(1)
                else:
                    break
        finally:
            self.ttd_cursor.remove_memory_watchpoint(function_address, 1, access_type="execute")
            self.ttd_cursor.set_position(original_pos)
        
        self.function_calls.extend(calls)
        return calls
    
    def annotate_function_with_calls(self, function_name: str) -> bool:
        """Annotate a function in Binary Ninja with TTD call data."""
        if not self.binja_client.is_connected():
            return False
        
        # Find calls to this function
        relevant_calls = [c for c in self.function_calls if c.function_name == function_name]
        
        if not relevant_calls:
            return False
        
        # Build comment
        lines = [f"[TTD] Called {len(relevant_calls)} times:"]
        for i, call in enumerate(relevant_calls[:10]):
            lines.append(f"  Call {i+1} @ {call.position}:")
            lines.append(f"    RCX={call.parameters['rcx']:#x}")
            lines.append(f"    RDX={call.parameters['rdx']:#x}")
            lines.append(f"    R8={call.parameters['r8']:#x}")
            lines.append(f"    R9={call.parameters['r9']:#x}")
        
        if len(relevant_calls) > 10:
            lines.append(f"  ... and {len(relevant_calls) - 10} more calls")
        
        comment = "\n".join(lines)
        return self.binja_client.set_function_comment(function_name, comment)
    
    def find_uncovered_functions(self) -> List[str]:
        """Find functions that were NOT executed in TTD trace."""
        if not self.binja_client.is_connected():
            return []
        
        all_functions = self.binja_client.list_functions(limit=1000)
        covered_functions = set(self.map_coverage_to_functions().keys())
        
        return [f for f in all_functions if f not in covered_functions]
    
    def close(self):
        """Clean up resources."""
        if self.ttd_cursor:
            self.ttd_cursor.close()
            self.ttd_cursor = None
        
        if self.ttd_engine:
            self.ttd_engine.close()
            self.ttd_engine = None


# =============================================================================
# Global Bridge Instance
# =============================================================================

_bridge = UnifiedBridge()


def get_bridge() -> UnifiedBridge:
    """Get the global bridge instance."""
    return _bridge


# =============================================================================
# MCP Server
# =============================================================================

mcp = FastMCP("ttd-binja-unified")


# -----------------------------------------------------------------------------
# Connection & Status Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_status() -> dict:
    """
    Get status of both TTD and Binary Ninja connections.
    
    Returns connection status, loaded trace info, and loaded binary info.
    """
    bridge = get_bridge()
    
    result = {
        "ttd": {
            "connected": bridge.ttd_engine is not None and bridge.ttd_engine.is_initialized,
        },
        "binary_ninja": {
            "connected": bridge.check_binja_connection(),
        },
        "coverage": {
            "unique_addresses": bridge.coverage.get_unique_count(),
            "total_instructions": bridge.coverage.total_instructions,
        }
    }
    
    if bridge.ttd_engine and bridge.ttd_engine.is_initialized:
        result["ttd"]["trace_path"] = str(bridge.ttd_engine.trace_path)
        result["ttd"]["thread_count"] = bridge.ttd_engine.thread_count
        result["ttd"]["module_count"] = bridge.ttd_engine.module_count
        if bridge.ttd_cursor:
            result["ttd"]["position"] = bridge.ttd_cursor.position.to_string()
            result["ttd"]["program_counter"] = f"0x{int(bridge.ttd_cursor.program_counter):x}"
    
    if result["binary_ninja"]["connected"]:
        binja_info = bridge.binja_client.get_binary_info()
        if "error" not in binja_info:
            result["binary_ninja"]["info"] = binja_info
    
    return {"status": "success", **result}


@mcp.tool()
def unified_load_trace(trace_path: str) -> dict:
    """
    Load a TTD trace file.
    
    Args:
        trace_path: Path to TTD trace (.run, .ttd, .idx)
    
    Returns:
        Trace information and connection status
    """
    try:
        bridge = get_bridge()
        bridge.load_ttd_trace(trace_path)
        
        return {
            "status": "success",
            "trace_path": trace_path,
            "first_position": bridge.ttd_engine.first_position.to_string(),
            "last_position": bridge.ttd_engine.last_position.to_string(),
            "thread_count": bridge.ttd_engine.thread_count,
            "module_count": bridge.ttd_engine.module_count,
            "binary_ninja_connected": bridge.check_binja_connection(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Context & Navigation Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_get_context() -> dict:
    """
    Get combined execution context from TTD and Binary Ninja.
    
    Returns current position, registers, and if Binary Ninja is connected:
    - Function name at current address
    - Decompiled code
    """
    try:
        bridge = get_bridge()
        return {"status": "success", **bridge.get_current_context()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_goto_position(position: str) -> dict:
    """
    Go to a specific TTD position and get context.
    
    Args:
        position: TTD position in "seq:steps" format
    """
    try:
        bridge = get_bridge()
        if not bridge.ttd_cursor:
            return {"status": "error", "error": "No trace loaded"}
        
        bridge.ttd_cursor.set_position(Position.from_string(position))
        return {"status": "success", **bridge.get_current_context()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_goto_address(address: str, direction: str = "forward") -> dict:
    """
    Navigate to when an address was executed.
    
    Args:
        address: Code address (hex string)
        direction: "forward" or "backward"
    
    Returns:
        Context at the position where address was executed
    """
    try:
        bridge = get_bridge()
        if not bridge.ttd_cursor:
            return {"status": "error", "error": "No trace loaded"}
        
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        bridge.ttd_cursor.add_memory_watchpoint(addr, 1, access_type="execute")
        try:
            if direction == "backward":
                result = bridge.ttd_cursor.replay_backward()
            else:
                result = bridge.ttd_cursor.replay_forward()
            
            if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                return {
                    "status": "success",
                    "found": True,
                    **bridge.get_current_context()
                }
            else:
                return {
                    "status": "success",
                    "found": False,
                    "stop_reason": result.stop_reason.name,
                }
        finally:
            bridge.ttd_cursor.remove_memory_watchpoint(addr, 1, access_type="execute")
            
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_goto_function(function_name: str, direction: str = "forward") -> dict:
    """
    Navigate to when a function was called.
    
    Uses Binary Ninja to resolve function address, then finds execution in TTD.
    
    Args:
        function_name: Name of function
        direction: "forward" or "backward"
    """
    try:
        bridge = get_bridge()
        
        if not bridge.binja_client.is_connected():
            return {"status": "error", "error": "Binary Ninja not connected"}
        
        # Search for function
        functions = bridge.binja_client.search_functions(function_name)
        if not functions:
            return {"status": "error", "error": f"Function '{function_name}' not found"}
        
        # Get function info to find address
        overview = bridge.binja_client.get_high_level_overview(functions[0])
        if "error" in overview or "start_address" not in overview:
            return {"status": "error", "error": "Could not get function address"}
        
        func_addr = overview["start_address"]
        return unified_goto_address(func_addr, direction)
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Coverage Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_collect_coverage(max_steps: int = 10000) -> dict:
    """
    Collect code coverage by replaying through the TTD trace.
    
    Args:
        max_steps: Maximum steps to replay
    
    Returns:
        Coverage statistics and top executed addresses
    """
    try:
        bridge = get_bridge()
        coverage = bridge.collect_coverage(max_steps)
        
        result = {
            "status": "success",
            "unique_addresses": coverage.get_unique_count(),
            "total_instructions": coverage.total_instructions,
            "top_addresses": [
                {"address": f"0x{addr:x}", "hits": hits}
                for addr, hits in coverage.get_top_addresses(20)
            ]
        }
        
        # Map to functions if Binary Ninja connected
        if bridge.binja_client.is_connected():
            func_coverage = bridge.map_coverage_to_functions()
            result["functions_hit"] = len(func_coverage)
            result["top_functions"] = [
                {"function": name, "hits": hits}
                for name, hits in sorted(func_coverage.items(), key=lambda x: -x[1])[:20]
            ]
        
        return result
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_get_uncovered_functions() -> dict:
    """
    Get list of functions that were NOT executed in the TTD trace.
    
    Useful for finding dead code or unexplored paths.
    """
    try:
        bridge = get_bridge()
        
        if not bridge.binja_client.is_connected():
            return {"status": "error", "error": "Binary Ninja not connected"}
        
        uncovered = bridge.find_uncovered_functions()
        
        return {
            "status": "success",
            "uncovered_count": len(uncovered),
            "uncovered_functions": uncovered[:100],  # Limit to first 100
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_annotate_coverage() -> dict:
    """
    Add coverage annotations to Binary Ninja.
    
    Adds comments to frequently executed addresses showing hit counts.
    """
    try:
        bridge = get_bridge()
        
        if not bridge.binja_client.is_connected():
            return {"status": "error", "error": "Binary Ninja not connected"}
        
        count = bridge.annotate_coverage_in_binja()
        
        return {
            "status": "success",
            "annotations_added": count,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Function Analysis Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_trace_function(function_address: str, max_calls: int = 50) -> dict:
    """
    Trace all calls to a function in the TTD trace.
    
    Records parameter values for each call.
    
    Args:
        function_address: Address of function (hex string)
        max_calls: Maximum calls to record
    """
    try:
        bridge = get_bridge()
        addr = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
        
        calls = bridge.trace_function_calls(addr, max_calls)
        
        return {
            "status": "success",
            "function_address": f"0x{addr:x}",
            "function_name": calls[0].function_name if calls else None,
            "call_count": len(calls),
            "calls": [
                {
                    "position": c.position,
                    "rcx": f"0x{c.parameters['rcx']:x}",
                    "rdx": f"0x{c.parameters['rdx']:x}",
                    "r8": f"0x{c.parameters['r8']:x}",
                    "r9": f"0x{c.parameters['r9']:x}",
                }
                for c in calls
            ]
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_annotate_function(function_name: str) -> dict:
    """
    Annotate a function in Binary Ninja with TTD runtime data.
    
    Adds comments showing call counts and parameter values.
    
    Args:
        function_name: Name of function to annotate
    """
    try:
        bridge = get_bridge()
        
        if not bridge.binja_client.is_connected():
            return {"status": "error", "error": "Binary Ninja not connected"}
        
        success = bridge.annotate_function_with_calls(function_name)
        
        return {
            "status": "success" if success else "error",
            "function": function_name,
            "annotated": success,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool() 
def unified_decompile_at_position() -> dict:
    """
    Get decompiled code for function at current TTD position.
    
    Combines TTD execution context with Binary Ninja decompilation.
    """
    try:
        bridge = get_bridge()
        
        if not bridge.ttd_cursor:
            return {"status": "error", "error": "No trace loaded"}
        
        if not bridge.binja_client.is_connected():
            return {"status": "error", "error": "Binary Ninja not connected"}
        
        pc = int(bridge.ttd_cursor.program_counter)
        func_name = bridge.get_function_at_address(pc)
        
        if not func_name:
            return {
                "status": "error",
                "error": f"No function at address 0x{pc:x}",
                "address": f"0x{pc:x}",
            }
        
        decompiled = bridge.binja_client.decompile_function(func_name)
        
        return {
            "status": "success",
            "position": bridge.ttd_cursor.position.to_string(),
            "address": f"0x{pc:x}",
            "function": func_name,
            "decompiled": decompiled,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Memory Analysis Tools
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_trace_memory(address: str, size: int = 8, access_type: str = "read_write", max_accesses: int = 100) -> dict:
    """
    Find all accesses to a memory address in the TTD trace.
    
    Args:
        address: Memory address (hex string)
        size: Size of memory region
        access_type: "read", "write", or "read_write"
        max_accesses: Maximum accesses to record
    """
    try:
        bridge = get_bridge()
        if not bridge.ttd_cursor or not bridge.ttd_engine:
            return {"status": "error", "error": "No trace loaded"}
        
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        original_pos = bridge.ttd_cursor.position
        bridge.ttd_cursor.set_position(bridge.ttd_engine.first_position)
        
        bridge.ttd_cursor.add_memory_watchpoint(addr, size, access_type=access_type)
        
        accesses = []
        try:
            while len(accesses) < max_accesses:
                result = bridge.ttd_cursor.replay_forward()
                
                if result.stop_reason == EventType.MEMORY_WATCHPOINT and result.memory_watchpoint:
                    pc = int(bridge.ttd_cursor.program_counter)
                    
                    access = {
                        "position": bridge.ttd_cursor.position.to_string(),
                        "instruction_address": f"0x{pc:x}",
                        "access_type": str(result.memory_watchpoint.access_type),
                    }
                    
                    # Add function name if Binary Ninja connected
                    if bridge.binja_client.is_connected():
                        func_name = bridge.get_function_at_address(pc)
                        if func_name:
                            access["function"] = func_name
                    
                    accesses.append(access)
                    bridge.ttd_cursor.step_forward(1)
                else:
                    break
                    
        finally:
            bridge.ttd_cursor.remove_memory_watchpoint(addr, size, access_type=access_type)
            bridge.ttd_cursor.set_position(original_pos)
        
        return {
            "status": "success",
            "address": f"0x{addr:x}",
            "size": size,
            "access_type": access_type,
            "access_count": len(accesses),
            "accesses": accesses,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_find_data_source(address: str, size: int = 8) -> dict:
    """
    Find where data at an address originated from.
    
    Traces backward to find the write that set the current value.
    
    Args:
        address: Memory address (hex string)
        size: Size of data
    """
    try:
        bridge = get_bridge()
        if not bridge.ttd_cursor:
            return {"status": "error", "error": "No trace loaded"}
        
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Get current value
        if size == 8:
            current_value = bridge.ttd_cursor.read_pointer(addr)
        else:
            current_value = bridge.ttd_cursor.read_uint32(addr)
        
        # Find last write
        bridge.ttd_cursor.add_memory_watchpoint(addr, size, access_type="write")
        
        try:
            result = bridge.ttd_cursor.replay_backward()
            
            if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                pc = int(bridge.ttd_cursor.program_counter)
                
                source = {
                    "position": bridge.ttd_cursor.position.to_string(),
                    "instruction_address": f"0x{pc:x}",
                }
                
                if bridge.binja_client.is_connected():
                    func_name = bridge.get_function_at_address(pc)
                    if func_name:
                        source["function"] = func_name
                
                return {
                    "status": "success",
                    "address": f"0x{addr:x}",
                    "current_value": f"0x{current_value:x}",
                    "source": source,
                }
            else:
                return {
                    "status": "success",
                    "address": f"0x{addr:x}",
                    "current_value": f"0x{current_value:x}",
                    "source": None,
                    "note": "No write found (value may be from initial state)",
                }
                
        finally:
            bridge.ttd_cursor.remove_memory_watchpoint(addr, size, access_type="write")
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Combined Analysis Workflows
# -----------------------------------------------------------------------------

@mcp.tool()
def unified_analyze_function_behavior(function_name: str, max_calls: int = 20) -> dict:
    """
    Comprehensive analysis of a function combining static and dynamic data.
    
    Gets:
    - Decompiled code from Binary Ninja
    - All calls from TTD trace with parameters
    - Call graph information
    
    Args:
        function_name: Name of function to analyze
        max_calls: Maximum TTD calls to trace
    """
    try:
        bridge = get_bridge()
        
        result = {
            "status": "success",
            "function": function_name,
            "static_analysis": {},
            "dynamic_analysis": {},
        }
        
        # Static analysis from Binary Ninja
        if bridge.binja_client.is_connected():
            # Decompile
            decompiled = bridge.binja_client.decompile_function(function_name)
            if decompiled:
                result["static_analysis"]["decompiled"] = decompiled
            
            # Get callers/callees
            callers = bridge.binja_client.get_function_callers(function_name)
            callees = bridge.binja_client.get_function_callees(function_name)
            result["static_analysis"]["callers"] = callers
            result["static_analysis"]["callees"] = callees
            
            # Get variables
            vars_info = bridge.binja_client.get_function_vars(function_name)
            if "error" not in vars_info:
                result["static_analysis"]["variables"] = vars_info
            
            # Get overview
            overview = bridge.binja_client.get_high_level_overview(function_name)
            if "error" not in overview:
                result["static_analysis"]["overview"] = overview
                
                # Use address for dynamic analysis
                if "start_address" in overview:
                    func_addr = int(overview["start_address"], 16) if isinstance(overview["start_address"], str) else overview["start_address"]
                    
                    # Dynamic analysis from TTD
                    if bridge.ttd_cursor:
                        calls = bridge.trace_function_calls(func_addr, max_calls)
                        result["dynamic_analysis"]["call_count"] = len(calls)
                        result["dynamic_analysis"]["calls"] = [
                            {
                                "position": c.position,
                                "parameters": {k: f"0x{v:x}" for k, v in c.parameters.items()}
                            }
                            for c in calls
                        ]
        
        return result
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def unified_full_analysis_report() -> dict:
    """
    Generate a comprehensive analysis report combining TTD and Binary Ninja data.
    
    Includes:
    - Trace summary
    - Binary summary
    - Code coverage statistics
    - Top executed functions
    - Uncovered code
    """
    try:
        bridge = get_bridge()
        
        report = {
            "status": "success",
            "ttd_summary": {},
            "binja_summary": {},
            "coverage_summary": {},
            "recommendations": [],
        }
        
        # TTD summary
        if bridge.ttd_engine and bridge.ttd_engine.is_initialized:
            report["ttd_summary"] = {
                "trace_path": str(bridge.ttd_engine.trace_path),
                "first_position": bridge.ttd_engine.first_position.to_string(),
                "last_position": bridge.ttd_engine.last_position.to_string(),
                "thread_count": bridge.ttd_engine.thread_count,
                "module_count": bridge.ttd_engine.module_count,
            }
        
        # Binary Ninja summary
        if bridge.binja_client.is_connected():
            binja_info = bridge.binja_client.get_binary_info()
            if "error" not in binja_info:
                report["binja_summary"] = binja_info
        
        # Coverage summary
        if bridge.coverage.get_unique_count() > 0:
            report["coverage_summary"] = {
                "unique_addresses": bridge.coverage.get_unique_count(),
                "total_instructions": bridge.coverage.total_instructions,
                "top_addresses": [
                    {"address": f"0x{addr:x}", "hits": hits}
                    for addr, hits in bridge.coverage.get_top_addresses(10)
                ],
            }
            
            # Function coverage
            if bridge.binja_client.is_connected():
                func_coverage = bridge.map_coverage_to_functions()
                report["coverage_summary"]["functions_executed"] = len(func_coverage)
                report["coverage_summary"]["top_functions"] = [
                    {"function": name, "hits": hits}
                    for name, hits in sorted(func_coverage.items(), key=lambda x: -x[1])[:10]
                ]
                
                # Recommendations
                uncovered = bridge.find_uncovered_functions()
                if uncovered:
                    report["recommendations"].append({
                        "type": "uncovered_code",
                        "message": f"{len(uncovered)} functions were not executed",
                        "examples": uncovered[:5],
                    })
        else:
            report["recommendations"].append({
                "type": "collect_coverage",
                "message": "Run unified_collect_coverage() to gather execution data",
            })
        
        return report
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Run the Unified TTD-Binary Ninja MCP server."""
    print("TTD-Binary Ninja Unified Bridge MCP Server starting...", file=sys.stderr)
    print("This server combines TTD traces with Binary Ninja analysis.", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
