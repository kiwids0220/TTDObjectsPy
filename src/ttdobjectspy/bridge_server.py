#!/usr/bin/env python3
"""
TTD-Binary Ninja Bridge MCP Server

Bridges Time Travel Debugging (TTD) with Binary Ninja for comprehensive
reverse engineering coverage. Combines static analysis from Binary Ninja
with dynamic execution data from TTD traces.

Features:
- Map TTD execution positions to Binary Ninja functions
- Get decompiled code at current TTD position
- Track code coverage from TTD traces
- Cross-reference runtime values with static analysis
- Find functions that access specific memory

Usage:
    python run_bridge_server.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Dict, List, Set, Any
from dataclasses import dataclass, field

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp.server.fastmcp import FastMCP

from ttdobjectspy.ttd_types import Position, EventType
from ttdobjectspy.engine import ReplayEngine
from ttdobjectspy.bindings import TTDError, TTDNotInitializedError

# =============================================================================
# Global State
# =============================================================================

_ttd_engine: Optional[ReplayEngine] = None
_ttd_cursor = None
_binja_connected = False
_coverage_data: Dict[int, int] = {}  # address -> hit count
_function_coverage: Dict[str, Set[int]] = {}  # function name -> set of positions


@dataclass
class ExecutionContext:
    """Combined TTD + Binary Ninja execution context."""
    position: str
    address: int
    function_name: Optional[str] = None
    function_start: Optional[int] = None
    decompiled: Optional[str] = None
    registers: Dict[str, str] = field(default_factory=dict)
    stack: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "address": f"0x{self.address:x}",
            "function": {
                "name": self.function_name,
                "start": f"0x{self.function_start:x}" if self.function_start else None,
            },
            "decompiled": self.decompiled,
            "registers": self.registers,
            "stack": self.stack,
        }


# =============================================================================
# MCP Server Setup
# =============================================================================

mcp = FastMCP("ttd-binja-bridge")


# =============================================================================
# TTD Engine Helpers
# =============================================================================

def get_ttd_engine() -> ReplayEngine:
    """Get or create TTD engine."""
    global _ttd_engine
    if _ttd_engine is None:
        _ttd_engine = ReplayEngine()
    return _ttd_engine


def get_ttd_cursor():
    """Get active TTD cursor."""
    global _ttd_cursor
    engine = get_ttd_engine()
    
    if not engine.is_initialized:
        raise TTDNotInitializedError("No TTD trace loaded. Use bridge_load_trace first.")
    
    if _ttd_cursor is None:
        _ttd_cursor = engine.new_cursor()
    
    return _ttd_cursor


# =============================================================================
# Binary Ninja Helpers (via MCP calls to binja server)
# =============================================================================

async def call_binja_tool(tool_name: str, **kwargs) -> dict:
    """
    Call a Binary Ninja MCP tool.
    
    This is a placeholder - in production, this would make actual MCP calls
    to the Binary Ninja server. For now, we'll simulate or make direct calls.
    """
    # TODO: Implement actual MCP client calls to Binary Ninja server
    # For now, return a placeholder
    return {"status": "not_connected", "error": "Binary Ninja MCP not connected"}


def get_binja_function_at(address: int) -> Optional[dict]:
    """Get Binary Ninja function info at address (placeholder)."""
    # This would call binary_ninja_mcp:function_at
    return None


def get_binja_decompile(function_name: str) -> Optional[str]:
    """Get decompiled code from Binary Ninja (placeholder)."""
    # This would call binary_ninja_mcp:decompile_function
    return None


# =============================================================================
# Bridge Tools - Trace Management
# =============================================================================

@mcp.tool()
def bridge_load_trace(trace_path: str, binary_path: str = "") -> dict:
    """
    Load a TTD trace and optionally associate with a Binary Ninja binary.
    
    Args:
        trace_path: Path to TTD trace file (.run, .ttd, .idx)
        binary_path: Optional path to the binary for Binary Ninja analysis
    
    Returns:
        Combined trace and binary information
    """
    global _ttd_cursor, _coverage_data, _function_coverage
    
    try:
        # Reset state
        if _ttd_cursor is not None:
            _ttd_cursor.close()
            _ttd_cursor = None
        _coverage_data.clear()
        _function_coverage.clear()
        
        engine = get_ttd_engine()
        
        if engine.is_initialized:
            engine.close()
            global _ttd_engine
            _ttd_engine = ReplayEngine()
            engine = _ttd_engine
        
        engine.initialize(trace_path)
        
        result = {
            "status": "success",
            "ttd": {
                "trace_path": trace_path,
                "first_position": engine.first_position.to_string(),
                "last_position": engine.last_position.to_string(),
                "thread_count": engine.thread_count,
                "module_count": engine.module_count,
                "peb_address": f"0x{int(engine.peb_address):x}",
            },
            "binary_ninja": {
                "connected": False,
                "binary_path": binary_path if binary_path else None,
            }
        }
        
        # TODO: Connect to Binary Ninja MCP and load binary
        if binary_path:
            # await call_binja_tool("select_binary", view=binary_path)
            pass
        
        return result
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_get_status() -> dict:
    """
    Get current status of TTD and Binary Ninja connections.
    """
    try:
        engine = get_ttd_engine()
        
        ttd_status = {
            "connected": engine.is_initialized,
            "trace_path": str(engine.trace_path) if engine.trace_path else None,
        }
        
        if engine.is_initialized:
            cursor = get_ttd_cursor()
            ttd_status["position"] = cursor.position.to_string()
            ttd_status["program_counter"] = f"0x{int(cursor.program_counter):x}"
        
        return {
            "status": "success",
            "ttd": ttd_status,
            "binary_ninja": {
                "connected": _binja_connected,
            },
            "coverage": {
                "addresses_hit": len(_coverage_data),
                "functions_hit": len(_function_coverage),
            }
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Execution Context
# =============================================================================

@mcp.tool()
def bridge_get_context() -> dict:
    """
    Get combined execution context from TTD and Binary Ninja.
    
    Returns current position, registers, and if available:
    - Function name and decompiled code from Binary Ninja
    - Stack contents
    """
    try:
        cursor = get_ttd_cursor()
        
        pc = int(cursor.program_counter)
        regs = cursor.get_registers()
        
        context = ExecutionContext(
            position=cursor.position.to_string(),
            address=pc,
            registers=regs.to_dict(),
        )
        
        # Get stack
        rsp = int(cursor.stack_pointer)
        stack_entries = []
        for i in range(8):
            addr = rsp + (i * 8)
            value = cursor.read_pointer(addr)
            stack_entries.append({
                "offset": f"+0x{i*8:x}",
                "address": f"0x{addr:x}",
                "value": f"0x{value:016x}",
            })
        context.stack = stack_entries
        
        # TODO: Get Binary Ninja info
        # func_info = get_binja_function_at(pc)
        # if func_info:
        #     context.function_name = func_info.get("name")
        #     context.function_start = func_info.get("start")
        #     context.decompiled = get_binja_decompile(context.function_name)
        
        return {
            "status": "success",
            **context.to_dict()
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_get_context_at(position: str) -> dict:
    """
    Get execution context at a specific TTD position.
    
    Args:
        position: TTD position in "seq:steps" format
    """
    try:
        cursor = get_ttd_cursor()
        original_pos = cursor.position
        
        # Set to requested position
        cursor.set_position(Position.from_string(position))
        
        # Get context
        result = bridge_get_context()
        
        # Restore position
        cursor.set_position(original_pos)
        
        return result
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Code Coverage
# =============================================================================

@mcp.tool()
def bridge_collect_coverage(max_steps: int = 10000) -> dict:
    """
    Collect code coverage by replaying through the trace.
    
    Runs through the trace and records all unique instruction addresses.
    
    Args:
        max_steps: Maximum steps to replay (0 = entire trace)
    
    Returns:
        Coverage statistics
    """
    global _coverage_data
    
    try:
        cursor = get_ttd_cursor()
        engine = get_ttd_engine()
        
        # Start from beginning
        cursor.set_position(engine.first_position)
        
        _coverage_data.clear()
        steps_taken = 0
        
        # Replay and collect addresses
        while steps_taken < max_steps or max_steps == 0:
            pc = int(cursor.program_counter)
            _coverage_data[pc] = _coverage_data.get(pc, 0) + 1
            
            result = cursor.step_forward(1)
            steps_taken += 1
            
            if result.stop_reason != EventType.STEP_COUNT:
                break
        
        return {
            "status": "success",
            "steps_taken": steps_taken,
            "unique_addresses": len(_coverage_data),
            "total_instructions": sum(_coverage_data.values()),
            "top_addresses": [
                {"address": f"0x{addr:x}", "hits": hits}
                for addr, hits in sorted(_coverage_data.items(), key=lambda x: -x[1])[:20]
            ]
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_get_coverage_for_function(function_name: str) -> dict:
    """
    Get coverage data for a specific function.
    
    Args:
        function_name: Name of function to check coverage for
    
    Returns:
        Coverage information for the function
    """
    try:
        # TODO: Get function bounds from Binary Ninja
        # func_info = await call_binja_tool("get_function_info", name=function_name)
        
        return {
            "status": "error",
            "error": "Binary Ninja integration not yet implemented"
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_was_address_executed(address: str) -> dict:
    """
    Check if a specific address was executed in the trace.
    
    Args:
        address: Address to check (hex string)
    
    Returns:
        Execution status and hit count
    """
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        hits = _coverage_data.get(addr, 0)
        
        return {
            "status": "success",
            "address": f"0x{addr:x}",
            "executed": hits > 0,
            "hit_count": hits,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Navigation
# =============================================================================

@mcp.tool()
def bridge_goto_address(address: str, direction: str = "forward") -> dict:
    """
    Navigate to when a specific address was executed.
    
    Args:
        address: Code address to find (hex string)
        direction: "forward" from current position or "backward"
    
    Returns:
        Position where address was executed
    """
    try:
        cursor = get_ttd_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Add execute watchpoint
        cursor.add_memory_watchpoint(addr, 1, access_type="execute")
        
        try:
            if direction == "backward":
                result = cursor.replay_backward()
            else:
                result = cursor.replay_forward()
            
            if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                return {
                    "status": "success",
                    "found": True,
                    "position": cursor.position.to_string(),
                    "address": f"0x{int(cursor.program_counter):x}",
                }
            else:
                return {
                    "status": "success",
                    "found": False,
                    "stop_reason": str(result.stop_reason),
                }
        finally:
            cursor.remove_memory_watchpoint(addr, 1, access_type="execute")
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_goto_function(function_name: str, direction: str = "forward") -> dict:
    """
    Navigate to when a specific function was called.
    
    Args:
        function_name: Name of function to find
        direction: "forward" from current position or "backward"
    
    Returns:
        Position where function was entered
    """
    try:
        # TODO: Get function address from Binary Ninja
        # func_info = await call_binja_tool("get_function_info", name=function_name)
        # if func_info and "start" in func_info:
        #     return bridge_goto_address(func_info["start"], direction)
        
        return {
            "status": "error",
            "error": "Binary Ninja integration not yet implemented"
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Memory Analysis
# =============================================================================

@mcp.tool()
def bridge_trace_memory_access(address: str, size: int = 8, access_type: str = "read_write") -> dict:
    """
    Find all accesses to a memory address throughout the trace.
    
    Args:
        address: Memory address to trace
        size: Size of memory region
        access_type: "read", "write", or "read_write"
    
    Returns:
        List of positions where memory was accessed
    """
    try:
        cursor = get_ttd_cursor()
        engine = get_ttd_engine()
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Save original position
        original_pos = cursor.position
        
        # Start from beginning
        cursor.set_position(engine.first_position)
        
        # Add watchpoint
        cursor.add_memory_watchpoint(addr, size, access_type=access_type)
        
        accesses = []
        try:
            while True:
                result = cursor.replay_forward()
                
                if result.stop_reason == EventType.MEMORY_WATCHPOINT and result.memory_watchpoint:
                    accesses.append({
                        "position": cursor.position.to_string(),
                        "address": f"0x{int(cursor.program_counter):x}",
                        "access_type": str(result.memory_watchpoint.access_type),
                        "access_address": str(result.memory_watchpoint.address),
                        "access_size": result.memory_watchpoint.size,
                    })
                    
                    # Continue to next access
                    cursor.step_forward(1)
                else:
                    break
                    
                # Limit results
                if len(accesses) >= 100:
                    break
                    
        finally:
            cursor.remove_memory_watchpoint(addr, size, access_type=access_type)
            cursor.set_position(original_pos)
        
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
def bridge_find_data_origin(address: str, size: int = 8) -> dict:
    """
    Find where a memory value originated from by tracing writes backward.
    
    Args:
        address: Memory address to trace
        size: Size of memory region
    
    Returns:
        Chain of writes leading to current value
    """
    try:
        cursor = get_ttd_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Get current value
        current_value = cursor.read_pointer(addr) if size == 8 else cursor.read_uint32(addr)
        
        # Add write watchpoint
        cursor.add_memory_watchpoint(addr, size, access_type="write")
        
        origin_chain = []
        try:
            result = cursor.replay_backward()
            
            if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                origin_chain.append({
                    "position": cursor.position.to_string(),
                    "address": f"0x{int(cursor.program_counter):x}",
                    "value_after": f"0x{current_value:x}",
                })
                
        finally:
            cursor.remove_memory_watchpoint(addr, size, access_type="write")
        
        return {
            "status": "success",
            "address": f"0x{addr:x}",
            "current_value": f"0x{current_value:x}",
            "origin": origin_chain[0] if origin_chain else None,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Binary Ninja Integration
# =============================================================================

@mcp.tool()
def bridge_decompile_at_position() -> dict:
    """
    Get decompiled code for the function at current TTD position.
    
    Uses Binary Ninja to decompile the function containing the current
    program counter.
    """
    try:
        cursor = get_ttd_cursor()
        pc = int(cursor.program_counter)
        
        # TODO: Call Binary Ninja MCP
        # func_name = await call_binja_tool("function_at", address=hex(pc))
        # if func_name:
        #     decompiled = await call_binja_tool("decompile_function", name=func_name)
        #     return {
        #         "status": "success",
        #         "position": cursor.position.to_string(),
        #         "address": f"0x{pc:x}",
        #         "function": func_name,
        #         "decompiled": decompiled,
        #     }
        
        return {
            "status": "error",
            "error": "Binary Ninja integration not yet implemented. Use the separate Binary Ninja MCP to decompile.",
            "hint": f"The current address is 0x{pc:x}. You can use binary_ninja_mcp:function_at to find the function name, then binary_ninja_mcp:decompile_function to get the code."
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_annotate_with_runtime_values(function_name: str) -> dict:
    """
    Annotate a Binary Ninja function with runtime values from TTD.
    
    Collects actual parameter values, return values, and variable values
    from TTD execution and annotates them in Binary Ninja.
    
    Args:
        function_name: Name of function to annotate
    """
    try:
        # TODO: Implement when Binary Ninja integration is ready
        return {
            "status": "error", 
            "error": "Binary Ninja integration not yet implemented"
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Bridge Tools - Analysis Workflows
# =============================================================================

@mcp.tool()
def bridge_analyze_call(address: str) -> dict:
    """
    Analyze a function call at the given address.
    
    Gets:
    - Function being called
    - Parameter values (from registers/stack)
    - Return value (by stepping to return)
    
    Args:
        address: Address of the CALL instruction
    """
    try:
        cursor = get_ttd_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Go to the address
        cursor.add_memory_watchpoint(addr, 1, access_type="execute")
        try:
            cursor.replay_forward()
        finally:
            cursor.remove_memory_watchpoint(addr, 1, access_type="execute")
        
        # Get registers at call site (parameters in x64 calling convention)
        regs = cursor.get_registers()
        
        call_info = {
            "position": cursor.position.to_string(),
            "call_address": f"0x{int(cursor.program_counter):x}",
            "parameters": {
                "rcx": f"0x{regs.rcx:x}",  # 1st param
                "rdx": f"0x{regs.rdx:x}",  # 2nd param
                "r8": f"0x{regs.r8:x}",    # 3rd param
                "r9": f"0x{regs.r9:x}",    # 4th param
            },
            "stack_params": [],
        }
        
        # Get stack parameters (5th+ parameters)
        rsp = int(cursor.stack_pointer)
        for i in range(4):
            value = cursor.read_pointer(rsp + 0x28 + (i * 8))  # Skip shadow space
            call_info["stack_params"].append(f"0x{value:x}")
        
        return {
            "status": "success",
            **call_info
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def bridge_trace_function_calls(function_address: str, max_calls: int = 50) -> dict:
    """
    Trace all calls to a function throughout execution.
    
    Args:
        function_address: Address of function to trace
        max_calls: Maximum number of calls to record
    
    Returns:
        List of all calls with parameters
    """
    try:
        cursor = get_ttd_cursor()
        engine = get_ttd_engine()
        addr = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
        
        # Save position
        original_pos = cursor.position
        cursor.set_position(engine.first_position)
        
        # Add execute watchpoint at function start
        cursor.add_memory_watchpoint(addr, 1, access_type="execute")
        
        calls = []
        try:
            while len(calls) < max_calls:
                result = cursor.replay_forward()
                
                if result.stop_reason == EventType.MEMORY_WATCHPOINT:
                    regs = cursor.get_registers()
                    calls.append({
                        "position": cursor.position.to_string(),
                        "rcx": f"0x{regs.rcx:x}",
                        "rdx": f"0x{regs.rdx:x}",
                        "r8": f"0x{regs.r8:x}",
                        "r9": f"0x{regs.r9:x}",
                    })
                    cursor.step_forward(1)
                else:
                    break
                    
        finally:
            cursor.remove_memory_watchpoint(addr, 1, access_type="execute")
            cursor.set_position(original_pos)
        
        return {
            "status": "success",
            "function_address": f"0x{addr:x}",
            "call_count": len(calls),
            "calls": calls,
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Run the TTD-Binary Ninja Bridge MCP server."""
    print("TTD-Binary Ninja Bridge MCP Server starting...", file=sys.stderr)
    print("This server bridges TTD traces with Binary Ninja analysis.", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
