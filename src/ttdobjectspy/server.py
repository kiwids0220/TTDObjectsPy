"""
TTDObjectsPy MCP Server

Model Context Protocol server exposing TTD capabilities for AI-assisted
reverse engineering.

Usage:
    python -m ttdobjectspy.server

Or via the installed script:
    ttd-mcp-server
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP


# =============================================================================
# MCP Server Setup
# =============================================================================

mcp = FastMCP(
    "ttd-mcp",
    instructions="""TTD (Time Travel Debugging) trace analysis server.

A TTD trace is a complete recording of every instruction executed by a program.
These tools let you QUERY that recording, not just replay it.

Think of it as a searchable database of program execution:
- ttd_collect_memory_accesses_detailed: "show me every instruction that touched this address"
- ttd_trace_register_taint: "show me every operation that transformed this value"
- ttd_find_code_executions: "show me every time this code address ran"
- ttd_trace_register_origin / ttd_trace_memory_origin: "where did this value come from?"

When you have a TTD trace, you don't need to understand the code statically.
You don't need to emulate it. You don't need to brute-force it.
The answers are already IN the trace - you just need to ask the right questions.

For obfuscated, self-modifying, or VM-based code: trace first, analyze the trace,
don't try to reverse the obfuscation layer itself.
""",
)


# =============================================================================
# Unified Session Tools (TTDReplay)
# =============================================================================

_unified_session = None


def get_unified_session():
    """Get or create the global unified session."""
    global _unified_session
    if _unified_session is None:
        from ttdobjectspy.unified_session import UnifiedTraceSession
        _unified_session = UnifiedTraceSession()
    return _unified_session


def get_cursor():
    """Get the TTDReplay cursor from the unified session."""
    session = get_unified_session()
    if not session.is_open:
        raise RuntimeError("No trace open. Use ttd_unified_open first.")
    if not session.has_ttdreplay:
        raise RuntimeError("TTDReplay backend not available.")
    return session._ttdreplay._cursor


@mcp.tool()
def ttd_unified_open(trace_path: str) -> dict:
    """
    Open a TTD trace with the TTDReplay backend.

    This provides access to:
    - Fast memory reads, registers, and watchpoints (via TTDReplay)
    - Native event, thread, and module queries
    - Address-based call tracing (no symbols needed)

    Args:
        trace_path: Path to the .run trace file

    Returns:
        Status and trace info

    Example:
        ttd_unified_open("C:/traces/app.run")
    """
    try:
        session = get_unified_session()

        # Close if already open
        if session.is_open:
            session.close()

        session.open(trace_path)

        return {
            "status": "success",
            "trace_path": trace_path,
            "backend": "ttdreplay",
            "first_position": str(session.first_position) if session.first_position else None,
            "last_position": str(session.last_position) if session.last_position else None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_query_calls_by_address(
    entry_address: str,
    exits: list,
    max_calls: int = 100,
    expected_module: str = "",
    ghidra_binary_size: int = 0,
    ghidra_checksum: int = 0,
) -> dict:
    """
    Query function calls by address without symbols (address-based TTD.Calls() equivalent).

    Uses execute watchpoints to find all calls to a function entry address,
    capturing parameters (RCX, RDX, R8, R9) and correlating with return values (RAX).

    Use ghidra_get_function_boundaries() to obtain entry_address and exits.
    If the binary is ASLR'd, rebase Ghidra first with ghidra_rebase() using the
    module base from the TTD trace.

    Handles three types of function exits:
    - "ret": Normal RET/RETN/RETF instructions
    - "tail_call": JMP to address outside function (tail call optimization)
    - "indirect_jmp": JMP via register (computed jump, vtable dispatch)

    Args:
        entry_address: Function entry address (hex, e.g. "0x7ff812345678")
        exits: Exit info from ghidra_get_function_boundaries(). Can be:
               - List of address strings: ["0x...", "0x..."] (assumes all are RETs)
               - List of exit objects: [{"address": "0x...", "type": "ret"}, ...]
                 where type is "ret", "tail_call", or "indirect_jmp"
        max_calls: Maximum number of calls to capture
        expected_module: Optional module name to validate (e.g., "kerberos"). If provided,
                        a warning is returned if the address is in a different module.
        ghidra_binary_size: Optional size of binary from ghidra_get_program_info for validation
        ghidra_checksum: Optional PE checksum from ghidra_get_program_info for validation

    Returns:
        Calls with exit_type indicating how the function returned:
        - "ret": Normal return via RET instruction
        - "tail_call": Exited via tail call JMP (RAX is from tail-called function)
        - "indirect_jmp": Exited via indirect jump (RAX may not be meaningful)

    Example workflow:
        1. ghidra_rebase(module_base)
        2. boundaries = ghidra_get_function_boundaries("0x...")
        3. ttd_unified_query_calls_by_address(boundaries.entry_address, boundaries.exits)
    """
    try:
        session = get_unified_session()
        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        entry = int(entry_address, 16)
        # exits parameter is passed directly - it can be list of strings or list of dicts
        # The underlying method handles normalization

        # Check if address is valid and in expected module
        warnings_list = []
        module_info = session.get_module_for_address(entry)
        if module_info is None:
            warnings_list.append(
                f"Entry address {entry_address} does not fall within any loaded module in the TTD trace. "
                f"The address may be incorrect or the binary may not have been rebased. "
                f"Use ghidra_rebase() with the module base from TTD before getting function boundaries."
            )
        else:
            if expected_module:
                actual_module = module_info["name"].lower()
                expected_lower = expected_module.lower()
                if expected_lower not in actual_module and actual_module not in expected_lower:
                    warnings_list.append(
                        f"Entry address {entry_address} is in module '{module_info['name']}' "
                        f"but expected module '{expected_module}'. Make sure Ghidra is loaded with the "
                        f"correct binary and rebased to the TTD runtime address."
                    )

            # Validate binary matches between TTD and Ghidra
            if ghidra_binary_size or ghidra_checksum:
                ttd_size = module_info.get("size", 0)
                ttd_checksum = module_info.get("checksum", 0)

                if ghidra_binary_size and ttd_size and ghidra_binary_size != ttd_size:
                    warnings_list.append(
                        f"Binary SIZE MISMATCH: TTD module size is 0x{ttd_size:x} but Ghidra binary size is 0x{ghidra_binary_size:x}. "
                        f"You may be analyzing a different version of the binary."
                    )

                if ghidra_checksum and ttd_checksum and ghidra_checksum != ttd_checksum:
                    warnings_list.append(
                        f"Binary CHECKSUM MISMATCH: TTD module checksum is 0x{ttd_checksum:x} but Ghidra binary checksum is 0x{ghidra_checksum:x}. "
                        f"You may be analyzing a different version of the binary."
                    )

        # Build ghidra_info dict for internal validation
        ghidra_info = None
        if ghidra_binary_size or ghidra_checksum:
            ghidra_info = {}
            if ghidra_binary_size:
                ghidra_info["size"] = ghidra_binary_size
            if ghidra_checksum:
                ghidra_info["checksum"] = ghidra_checksum

        calls = session.query_calls_by_address(entry, exits, max_calls, expected_module or None, ghidra_info)

        result = {
            "status": "success",
            "entry_address": entry_address,
            "module": module_info["name"] if module_info else None,
            "count": len(calls),
            "calls": [
                {
                    "position_start": str(c.position_start),
                    "position_end": str(c.position_end) if c.position_end else None,
                    "parameters": {
                        "rcx": hex(c.rcx),
                        "rdx": hex(c.rdx),
                        "r8": hex(c.r8),
                        "r9": hex(c.r9),
                    },
                    "return_value": hex(c.rax) if c.rax is not None else None,
                    "rsp": hex(c.rsp),
                    "thread_id": c.thread_id,
                    "exit_address": hex(c.exit_address) if c.exit_address else None,
                    "exit_type": c.exit_type,  # "ret", "tail_call", or "indirect_jmp"
                }
                for c in calls
            ],
        }

        if warnings_list:
            result["warnings"] = warnings_list

        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_query_exceptions(max_results: int = 1000) -> dict:
    """
    Query exception events from the TTDReplay native API.

    Returns all exceptions (first-chance, second-chance) during trace.

    Args:
        max_results: Maximum results to return

    Returns:
        List of exception events with code, address, type, and position

    Example:
        ttd_unified_query_exceptions()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.query_exceptions(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "exception_code": hex(e.exception_code),
                    "exception_address": hex(e.exception_address),
                    "exception_flags": e.exception_flags,
                    "type": e.type,
                    "position": str(e.position),
                    "program_counter": hex(e.program_counter),
                    "thread_id": e.thread_id,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_query_modules(max_results: int = 1000) -> dict:
    """
    Query module load/unload events from the TTDReplay native API.

    Returns all module loads and unloads during trace.

    Args:
        max_results: Maximum results to return

    Returns:
        List of module events with name, address, size, and event type

    Example:
        ttd_unified_query_modules()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.query_modules(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "name": e.name,
                    "path": e.path,
                    "address": hex(e.address),
                    "size": hex(e.size),
                    "checksum": hex(e.checksum),
                    "event_type": e.event_type,
                    "position": str(e.position),
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_query_thread_lifetimes(max_results: int = 1000) -> dict:
    """
    Query thread lifetime info from the TTDReplay native API.

    Returns all threads with their lifetime positions.

    Args:
        max_results: Maximum results to return

    Returns:
        List of thread info with thread IDs and lifetime positions

    Example:
        ttd_unified_query_thread_lifetimes()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        threads = session.query_thread_lifetimes(max_results)

        return {
            "status": "success",
            "count": len(threads),
            "threads": [
                {
                    "thread_id": t.thread_id,
                    "unique_thread_id": t.unique_thread_id,
                    "lifetime_start": str(t.lifetime_start),
                    "lifetime_end": str(t.lifetime_end),
                }
                for t in threads
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_lifetime() -> dict:
    """
    Get trace lifetime.

    Returns the minimum and maximum positions in the trace.

    Returns:
        Lifetime with min and max positions

    Example:
        ttd_unified_get_lifetime()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        lifetime = session.get_lifetime()

        return {
            "status": "success",
            "min_position": str(lifetime.min_position),
            "max_position": str(lifetime.max_position),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_threads(max_results: int = 100) -> dict:
    """
    Get thread info from the TTDReplay native API.

    Returns information about all threads in the trace.

    Args:
        max_results: Maximum results to return

    Returns:
        List of thread info with IDs and lifetime positions

    Example:
        ttd_unified_get_threads()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        threads = session.get_threads(max_results)

        return {
            "status": "success",
            "count": len(threads),
            "threads": [
                {
                    "thread_id": t.thread_id,
                    "unique_thread_id": t.unique_thread_id,
                    "lifetime_start": str(t.lifetime_start),
                    "lifetime_end": str(t.lifetime_end),
                }
                for t in threads
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_status() -> dict:
    """
    Get the status of the unified session.

    Returns:
        Current status including open state, backends, and position
    """
    try:
        session = get_unified_session()

        return {
            "status": "success",
            "is_open": session.is_open,
            "trace_path": session.trace_path,
            "backend": "ttdreplay" if session.has_ttdreplay else None,
            "position": str(session.position) if session.position else None,
            "first_position": str(session.first_position) if session.first_position else None,
            "last_position": str(session.last_position) if session.last_position else None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_close() -> dict:
    """
    Close the unified session.

    Returns:
        Status confirmation
    """
    try:
        global _unified_session
        if _unified_session is not None:
            _unified_session.close()
            _unified_session = None

        return {"status": "success", "message": "Unified session closed"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_position() -> dict:
    """
    Get the current cursor position in the trace.

    Returns:
        Current position (sequence:steps) and program counter
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        pos = session.position
        regs = session.get_registers()

        return {
            "status": "success",
            "position": str(pos) if pos else None,
            "program_counter": hex(regs.get("rip", 0)) if isinstance(regs, dict) else None,
            "stack_pointer": hex(regs.get("rsp", 0)) if isinstance(regs, dict) else None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_goto_start() -> dict:
    """
    Move cursor to the beginning of the trace.

    Returns:
        New position at start of trace
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        first = session.first_position
        if first is None:
            return {"status": "error", "error": "Could not determine first position."}

        session.set_position(str(first))

        return {
            "status": "success",
            "position": str(session.position),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_goto_end() -> dict:
    """
    Move cursor to the end of the trace.

    Returns:
        New position at end of trace
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        last = session.last_position
        if last is None:
            return {"status": "error", "error": "Could not determine last position."}

        session.set_position(str(last))

        return {
            "status": "success",
            "position": str(session.position),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_run_to_address(address: str, backward: bool = False) -> dict:
    """
    Run until a specific code address is executed.

    Sets an execute watchpoint at the address and replays until hit.

    Args:
        address: Code address to stop at (hex, e.g. "0x7ff812345678")
        backward: If True, run backward

    Returns:
        New position when address is hit
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        addr = int(address, 16) if address.startswith("0x") else int(address)

        result = session.run_to_address(addr, backward)

        return {
            "status": "success",
            "position": str(session.position),
            **result.to_dict(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_read_memory(address: str, size: int) -> dict:
    """
    Read memory at the current position using TTDReplay (fast memory access).

    Args:
        address: Memory address in hex (e.g., "0x7ff6abcd1234")
        size: Number of bytes to read (max 4096)

    Returns:
        Memory contents as hex string and ASCII representation

    Example:
        ttd_unified_read_memory("0x7ff6abcd1234", 64)
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        # Parse address
        addr = int(address, 16) if address.startswith("0x") else int(address)
        size = min(size, 4096)

        data = session.read_memory(addr, size)

        # Format as hex with spacing
        hex_str = data.hex()
        formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

        return {
            "status": "success",
            "address": f"0x{addr:x}",
            "size": len(data),
            "hex": formatted,
            "ascii": "".join(chr(b) if 32 <= b < 127 else '.' for b in data),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_registers() -> dict:
    """
    Get all CPU registers at the current position using TTDReplay.

    Returns:
        All general-purpose registers (rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
        r8-r15, rip, rflags)
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        regs = session.get_registers()

        return {
            "status": "success",
            "position": str(session.position) if session.position else None,
            "registers": {k: hex(v) for k, v in regs.items()},
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_register(name: str) -> dict:
    """
    Get a specific register value at the current position.

    Args:
        name: Register name (e.g., "rax", "rcx", "rip", "rsp")

    Returns:
        Register value in hex and decimal
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        value = session.get_register(name)

        return {
            "status": "success",
            "register": name.lower(),
            "value": f"0x{value:x}",
            "decimal": value,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_set_position(position: str) -> dict:
    """
    Set the cursor position in the trace.

    Args:
        position: Position in "seq:steps" hex format (e.g., "64:0" or "1a3:5f")

    Returns:
        New position state
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        session.set_position(position)

        return {
            "status": "success",
            "position": str(session.position),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_step_forward(steps: int = 1) -> dict:
    """
    Step forward by a specific number of steps using TTDReplay.

    Args:
        steps: Number of steps to execute (default: 1)

    Returns:
        New position and execution info
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        result = session.step_forward(steps)

        return {
            "status": "success",
            "position": str(session.position),
            **result,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_step_backward(steps: int = 1) -> dict:
    """
    Step backward by a specific number of steps using TTDReplay.

    Args:
        steps: Number of steps to execute (default: 1)

    Returns:
        New position and execution info
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        result = session.step_backward(steps)

        return {
            "status": "success",
            "position": str(session.position),
            **result,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_replay_forward(max_steps: int = 0) -> dict:
    """
    Replay forward until a watchpoint is hit or step limit reached.

    Use ttd_unified_add_memory_watchpoint to set watchpoints before calling this.

    Args:
        max_steps: Maximum steps to execute (0 = unlimited)

    Returns:
        Stop reason and position details
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        result = session.replay_forward(max_steps)

        # ReplayResult is a dataclass, use to_dict() method
        return {
            "status": "success",
            "position": str(session.position),
            **result.to_dict(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_replay_backward(max_steps: int = 0) -> dict:
    """
    Replay backward until a watchpoint is hit or step limit reached.

    Use ttd_unified_add_memory_watchpoint to set watchpoints before calling this.

    Args:
        max_steps: Maximum steps to execute (0 = unlimited)

    Returns:
        Stop reason and position details
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        result = session.replay_backward(max_steps)

        # ReplayResult is a dataclass, use to_dict() method
        return {
            "status": "success",
            "position": str(session.position),
            **result.to_dict(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_add_memory_watchpoint(
    address: str,
    size: int,
    access_type: str = "write"
) -> dict:
    """
    Add a memory watchpoint for replay operations.

    When replaying, execution will stop when the specified memory is accessed.

    Args:
        address: Memory address to watch (hex)
        size: Size of memory region in bytes
        access_type: "read", "write", "execute", "read_write", or "all"

    Returns:
        Success status

    Example:
        ttd_unified_add_memory_watchpoint("0x7ff6abcd1234", 8, "write")
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        addr = int(address, 16) if address.startswith("0x") else int(address)
        result = session.add_memory_watchpoint(addr, size, access_type)

        return {
            "status": "success" if result else "error",
            "address": f"0x{addr:x}",
            "size": size,
            "access_type": access_type,
            "added": result,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_remove_memory_watchpoint(
    address: str,
    size: int,
    access_type: str = "write"
) -> dict:
    """
    Remove a previously added memory watchpoint.

    Args must match those used when adding the watchpoint.
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        addr = int(address, 16) if address.startswith("0x") else int(address)
        result = session.remove_memory_watchpoint(addr, size, access_type)

        return {
            "status": "success" if result else "error",
            "removed": result,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_clear_watchpoints() -> dict:
    """
    Remove all memory watchpoints.
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        session.clear_watchpoints()

        return {"status": "success", "message": "All watchpoints cleared"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_read_string(
    address: str,
    max_length: int = 256,
    wide: bool = False
) -> dict:
    """
    Read a null-terminated string from memory.

    Args:
        address: String address in hex
        max_length: Maximum characters to read
        wide: If True, read as wide string (UTF-16)

    Returns:
        Decoded string
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        addr = int(address, 16) if address.startswith("0x") else int(address)

        # Read raw bytes and decode
        char_size = 2 if wide else 1
        data = session.read_memory(addr, max_length * char_size)

        # Find null terminator
        if wide:
            # UTF-16 null terminator (00 00)
            result = ""
            for i in range(0, len(data) - 1, 2):
                if data[i] == 0 and data[i + 1] == 0:
                    break
                try:
                    result += data[i:i+2].decode('utf-16-le')
                except:
                    break
            value = result
        else:
            # ASCII null terminator
            null_idx = data.find(b'\x00')
            if null_idx >= 0:
                data = data[:null_idx]
            try:
                value = data.decode('utf-8', errors='replace')
            except:
                value = data.decode('latin-1')

        return {
            "status": "success",
            "address": f"0x{addr:x}",
            "string": value,
            "length": len(value),
            "encoding": "utf-16" if wide else "utf-8",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_stack(depth: int = 16) -> dict:
    """
    Get stack contents at current position.

    Args:
        depth: Number of stack entries (qwords) to read

    Returns:
        Stack pointer and stack values
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        rsp = session.get_register("rsp")
        entries = []

        for i in range(depth):
            addr = rsp + (i * 8)
            try:
                value = session.read_uint64(addr)
                entries.append({
                    "offset": f"+0x{i*8:x}",
                    "address": f"0x{addr:x}",
                    "value": f"0x{value:016x}",
                })
            except:
                break

        return {
            "status": "success",
            "rsp": f"0x{rsp:x}",
            "entries": entries,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_find_memory_write(address: str, size: int = 8) -> dict:
    """
    Find the last instruction that wrote to a memory address.

    This adds a write watchpoint and replays backward to find the write.

    Args:
        address: Memory address in hex
        size: Size of memory region to watch

    Returns:
        Position and details of the write instruction
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        if not session.has_ttdreplay:
            return {"status": "error", "error": "TTDReplay backend not available."}

        addr = int(address, 16) if address.startswith("0x") else int(address)

        # Add write watchpoint
        session.add_memory_watchpoint(addr, size, "write")

        try:
            # Replay backward
            result = session.replay_backward()

            # ReplayResult is a dataclass, use attributes not dict access
            if result.memory_watchpoint:
                return {
                    "status": "success",
                    "found": True,
                    "position": str(session.position),
                    "result": result.to_dict(),
                }
            else:
                return {
                    "status": "success",
                    "found": False,
                    "stop_reason": str(result.stop_reason),
                }
        finally:
            session.remove_memory_watchpoint(addr, size, "write")

    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Advanced Watchpoint Callback Tools (LLM-optimized)
# =============================================================================

@mcp.tool()
def ttd_collect_memory_accesses_detailed(
    address: str,
    size: int = 8,
    access_type: str = "read_write",
    max_hits: int = 50,
    forward: bool = True,
    capture_registers: bool = True,
    capture_stack: bool = True,
    capture_memory: bool = True,
    memory_read_size: int = 64,
    stack_depth: int = 8,
    code_address_min: str = "",
    code_address_max: str = "",
) -> dict:
    """
    [ALTERNATIVE] Collect detailed information about all memory accesses to an address.

    This uses client-side watchpoint iteration with comprehensive context capture.
    It is SLOWER than the PRIMARY methods but provides detailed register/stack/memory
    context at each access point.

    PREFER using ttd_unified_get_memory_reads, ttd_unified_get_memory_writes, or
    ttd_unified_get_memory_executes for faster server-side LINQ filtering when you
    only need basic access information.

    Use this alternative when you need:
    - Full CPU register state at each memory access
    - Stack contents at each access point
    - Memory dump at the watched location for each hit
    - Step-by-step detailed execution context

    Args:
        address: Memory address to monitor (hex, e.g., "0x7ff6abcd1234")
        size: Size of memory region to watch in bytes
        access_type: "read", "write", "execute", "read_write", or "all"
        max_hits: Maximum number of accesses to collect (keep low for large traces)
        forward: If True, search forward from current position; False for backward
        capture_registers: If True, capture all CPU registers at each access
        capture_stack: If True, capture stack values at each access
        capture_memory: If True, read memory content at the watched address
        memory_read_size: Bytes to read at watched address (if capture_memory=True)
        stack_depth: Number of stack entries to capture (if capture_stack=True)
        code_address_min: If set, only include accesses where PC >= this address (hex).
                         Use to filter out ntdll/kernel accesses and show only buffer code.
        code_address_max: If set, only include accesses where PC <= this address (hex).
                         Use to filter out ntdll/kernel accesses and show only buffer code.

    Returns:
        Detailed list of memory accesses, each containing:
        - position: Trace position (sequence:steps)
        - program_counter: Instruction address that accessed memory
        - access_info: Details about the access (address, size, type)
        - registers: Full register state (rax, rbx, rcx, rdx, rsi, rdi, etc.)
        - stack: Stack pointer and top N values
        - memory_at_address: Hex dump of memory at watched location

    Example:
        ttd_collect_memory_accesses_detailed("0x7ff6abcd1234", size=8, access_type="write", max_hits=20)
        # Filter to only buffer code accesses:
        ttd_collect_memory_accesses_detailed("0x7ff6abcd1234", size=8, code_address_min="0xd200000", code_address_max="0xda00000")
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)

        # Parse optional code address filters
        ca_min = None
        ca_max = None
        if code_address_min:
            ca_min = int(code_address_min, 16) if code_address_min.startswith("0x") else int(code_address_min)
        if code_address_max:
            ca_max = int(code_address_max, 16) if code_address_max.startswith("0x") else int(code_address_max)

        hits = cursor.collect_memory_accesses_detailed(
            address=addr,
            size=size,
            access_type=access_type,
            max_hits=max_hits,
            forward=forward,
            read_memory_at_access=capture_memory,
            memory_read_size=memory_read_size,
            capture_registers=capture_registers,
            capture_stack=capture_stack,
            stack_depth=stack_depth,
            code_address_min=ca_min,
            code_address_max=ca_max,
        )

        return {
            "status": "success",
            "query": {
                "address": f"0x{addr:x}",
                "size": size,
                "access_type": access_type,
                "direction": "forward" if forward else "backward",
                "code_address_min": code_address_min or None,
                "code_address_max": code_address_max or None,
            },
            "hit_count": len(hits),
            "hits": hits,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_trace_value_changes_detailed(
    address: str,
    size: int = 8,
    max_changes: int = 30,
    forward: bool = True,
    capture_context: bool = True
) -> dict:
    """
    Track how a memory value changes over time with full execution context.

    This tool monitors writes to a memory location and captures both the
    old and new values, along with the instruction and context that caused
    each change.

    Use this when you need to:
    - Understand how a variable's value evolves
    - Find where a value gets corrupted or modified
    - Track state changes in data structures

    Args:
        address: Memory address to trace (hex)
        size: Size of value in bytes (1, 2, 4, or 8)
        max_changes: Maximum number of value changes to track
        forward: If True, trace forward; False for backward
        capture_context: If True, include registers and stack at each change

    Returns:
        List of value changes, each containing:
        - position: Trace position
        - program_counter: Instruction that wrote the value
        - old_value: Value before the write (hex)
        - new_value: Value after the write (hex)
        - value_changed: Boolean indicating if value actually changed
        - registers: Register state at write (if capture_context=True)
        - stack_top: Top 4 stack values (if capture_context=True)

    Example:
        ttd_trace_value_changes_detailed("0x7ff6abcd1234", size=4, max_changes=10)
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)

        changes = cursor.trace_value_changes_detailed(
            address=addr,
            size=size,
            max_changes=max_changes,
            forward=forward,
            capture_context=capture_context
        )

        return {
            "status": "success",
            "query": {
                "address": f"0x{addr:x}",
                "size": size,
                "direction": "forward" if forward else "backward",
            },
            "change_count": len(changes),
            "changes": changes,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_find_code_executions(
    code_address: str,
    max_hits: int = 50,
    forward: bool = True,
    capture_args: bool = True
) -> dict:
    """
    Find all executions at a specific code address with calling context.

    This tool monitors when a specific instruction address is executed and
    captures the calling convention arguments and return address.

    IMPORTANT: Use this as an alternative to ttd_query_calls() when:
    - The module doesn't have symbols loaded
    - TTD.Calls() returns an error for the function
    - You have a raw address from disassembly or Binary Ninja

    To get the function address:
    - Use ttd_unified_execute("x module!function") to resolve symbol to address
    - Or get the address from Binary Ninja decompilation/disassembly

    Use this when you need to:
    - Analyze all calls to a specific function
    - Understand what arguments are passed to a function
    - Find the callers of a function

    Args:
        code_address: Code address to monitor (hex, e.g., "0x7ff6abcd1234")
        max_hits: Maximum number of executions to collect
        forward: If True, search forward from current position; False for backward
        capture_args: If True, capture x64 calling convention arguments

    Returns:
        List of execution records, each containing:
        - position: Trace position
        - code_address: The monitored address
        - program_counter: Instruction pointer at execution
        - arguments: x64 args (rcx=arg1, rdx=arg2, r8=arg3, r9=arg4)
        - return_address: Return address from stack
        - stack_args: Arguments 5-8 from stack

    Example:
        # Find all executions of a function at a known address
        ttd_find_code_executions("0x7ff6abcd1234", max_hits=20)

        # To find function address first, use: ttd_unified_execute("x ws2_32!connect")
    """
    try:
        cursor = get_cursor()
        addr = int(code_address, 16) if code_address.startswith("0x") else int(code_address)

        hits = cursor.find_code_execution_at_address(
            code_address=addr,
            max_hits=max_hits,
            forward=forward,
            capture_args=capture_args
        )

        return {
            "status": "success",
            "query": {
                "code_address": f"0x{addr:x}",
                "direction": "forward" if forward else "backward",
            },
            "execution_count": len(hits),
            "executions": hits,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_analyze_memory_access_pattern(
    address: str,
    size: int = 8,
    max_samples: int = 100,
    forward: bool = True
) -> dict:
    """
    Analyze the access pattern to a memory location.

    This tool collects memory accesses and provides a summary of the access
    pattern including read/write ratio, unique accessors, and timing distribution.

    Use this for:
    - Understanding how a variable or buffer is used
    - Finding hot spots in memory access
    - Detecting unusual access patterns

    Args:
        address: Memory address to analyze (hex)
        size: Size of memory region
        max_samples: Maximum number of accesses to sample
        forward: Search direction

    Returns:
        Analysis summary including:
        - total_accesses: Number of accesses found
        - access_breakdown: Count by access type (read/write/execute)
        - unique_accessors: List of unique instruction addresses that accessed memory
        - first_access: Details of first access
        - last_access: Details of last access

    Example:
        ttd_analyze_memory_access_pattern("0x7ff6abcd1234", size=8)
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)

        # Collect accesses with minimal context for speed
        hits = cursor.collect_memory_accesses_detailed(
            address=addr,
            size=size,
            access_type="all",
            max_hits=max_samples,
            forward=forward,
            read_memory_at_access=False,
            capture_registers=False,
            capture_stack=False,
            stack_depth=0
        )

        # Analyze the pattern
        access_counts = {"READ": 0, "WRITE": 0, "EXECUTE": 0, "OTHER": 0}
        unique_pcs = set()

        for hit in hits:
            access_type = hit.get("access_info", {}).get("access_type", "OTHER")
            if access_type in access_counts:
                access_counts[access_type] += 1
            else:
                access_counts["OTHER"] += 1

            pc = hit.get("program_counter", "")
            if pc:
                unique_pcs.add(pc)

        return {
            "status": "success",
            "query": {
                "address": f"0x{addr:x}",
                "size": size,
            },
            "analysis": {
                "total_accesses": len(hits),
                "access_breakdown": access_counts,
                "unique_accessor_count": len(unique_pcs),
                "unique_accessors": list(unique_pcs)[:20],  # Limit to first 20
            },
            "first_access": hits[0] if hits else None,
            "last_access": hits[-1] if hits else None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_find_data_source(
    address: str,
    size: int = 8
) -> dict:
    """
    Find where a memory value originated from by tracing backward.

    This tool traces backward from the current position to find the first
    write to a memory location, helping identify the source of a value.

    Use this when you need to:
    - Find where a buffer was populated
    - Trace back to the source of a value
    - Understand data provenance

    Args:
        address: Memory address to trace (hex)
        size: Size of memory region

    Returns:
        Information about the write that set the current value:
        - found: Whether a write was found
        - position: Position where the write occurred
        - program_counter: Instruction that wrote the value
        - value_at_write: The value that was written
        - registers: Register state at the write
        - distance: Number of steps backward to the write
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)

        # Read current value
        try:
            current_data = cursor.query_memory(addr, size)
            current_value = f"0x{int.from_bytes(current_data[:size], 'little'):x}" if current_data else "unknown"
        except Exception:
            current_value = "unknown"

        # Find the write
        saved_pos = cursor.position
        changes = cursor.trace_value_changes_detailed(
            address=addr,
            size=size,
            max_changes=1,
            forward=False,
            capture_context=True
        )

        result = {
            "status": "success",
            "query": {
                "address": f"0x{addr:x}",
                "size": size,
                "current_value": current_value,
                "search_from": saved_pos.to_dict(),
            }
        }

        if changes:
            change = changes[0]
            result["found"] = True
            result["write_info"] = change
        else:
            result["found"] = False
            result["message"] = "No write found before current position"

        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Data Flow Tracing Tools
# =============================================================================

@mcp.tool()
def ttd_trace_register_origin(
    register: str,
    max_steps: int = 10000,
    max_trace_depth: int = 50
) -> dict:
    """
    Track a register value backward to find its origin.

    This tool traces backward through the execution to find where a register's
    current value came from. It follows data flow through:
    - Register-to-register copies (MOV reg, reg)
    - Memory loads (MOV reg, [mem])
    - Immediate values (MOV reg, imm)
    - LEA instructions (address computations)
    - Function return values (CALL)
    - Arithmetic operations

    Uses efficient execution watchpoints for fast backward replay (per TTD
    developer guidance from GitHub issue #332).

    Args:
        register: Register to track (e.g., "rax", "rcx", "r8", "rdx")
        max_steps: Maximum replay steps to execute (default 10000)
        max_trace_depth: Maximum data flow steps to record (default 50)

    Returns:
        Trace result containing:
        - success: Whether tracing completed
        - steps: List of data flow steps showing how value moved
        - origin_found: Whether the ultimate origin was found
        - origin_type: Type of origin ("constant", "memory_read", "function_return", "computed")
        - origin_detail: Details about the origin
        - termination_reason: Why tracing stopped

    Example:
        # Find where RAX got its current value
        ttd_trace_register_origin("rax")

        # Trace RCX (first argument in x64 calling convention)
        ttd_trace_register_origin("rcx", max_steps=5000)
    """
    try:
        cursor = get_cursor()

        result = cursor.trace_register_origin_backward(
            register_name=register,
            max_steps=max_steps,
            max_trace_depth=max_trace_depth
        )

        return {
            "status": "success",
            "query": {
                "register": register,
                "max_steps": max_steps,
                "max_trace_depth": max_trace_depth,
                "from_position": cursor.position.to_dict(),
            },
            **result.to_dict()
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_trace_memory_origin(
    address: str,
    size: int = 8,
    max_steps: int = 10000
) -> dict:
    """
    Track a memory value backward to find what instruction wrote it.

    This tool traces backward to find the instruction that wrote to a memory
    location, and analyzes the data source (register, immediate, or memory).

    Args:
        address: Memory address to track (hex, e.g., "0x7ff6abcd1234")
        size: Size of memory value (1, 2, 4, or 8 bytes)
        max_steps: Maximum replay steps to execute

    Returns:
        Trace result containing:
        - success: Whether a write was found
        - steps: Data flow step showing the write
        - origin_found: True if write was found
        - origin_type: "write_from_register", "write_from_immediate", "write_from_memory"
        - origin_detail: Full instruction that performed the write
        - termination_reason: Why tracing stopped

    Example:
        # Find what wrote to this memory address
        ttd_trace_memory_origin("0x7ff6abcd1234", size=8)

        # Track a 4-byte value
        ttd_trace_memory_origin("0x12345678", size=4)
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if address.startswith("0x") else int(address)

        result = cursor.trace_memory_origin_backward(
            address=addr,
            size=size,
            max_steps=max_steps
        )

        return {
            "status": "success",
            "query": {
                "address": f"0x{addr:x}",
                "size": size,
                "max_steps": max_steps,
                "from_position": cursor.position.to_dict(),
            },
            **result.to_dict()
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_trace_register_taint(
    register: str,
    max_steps: int = 10000,
    max_trace_depth: int = 100,
    track_all_writes: bool = False,
    follow_context_chain: bool = True,
    context_chain_max_depth: int = 20
) -> dict:
    """
    Full taint analysis: track ALL data sources that contribute to a register's value.

    Unlike ttd_trace_register_origin which stops at computed operations (xor, add, etc.),
    this tool follows ALL input operands through arithmetic operations. For example:

    - 'xor r8, rax': Traces BOTH the old r8 value AND rax backward
    - 'add rax, rbx': Traces BOTH rax AND rbx to their origins
    - 'lea rax, [rbx + rcx*4]': Traces BOTH rbx AND rcx

    This enables complete taint tracking to find ALL ultimate origins (constants,
    memory reads, function returns) that contributed to a value, even through
    complex computations.

    Args:
        register: Register to track (e.g., "rax", "rcx", "r8", "rdx")
        max_steps: Maximum replay steps to execute (default 10000)
        max_trace_depth: Maximum taint steps to record (default 100)
        track_all_writes: If True, record ALL instructions that write to tracked
            registers, even if the value doesn't change. For example, 'xor r8, r8'
            when R8 is already 0 will still be recorded. Default False only tracks
            instructions that actually change register values.
        follow_context_chain: If True (default), automatically follow values through
            ntdll CONTEXT save/restore chains during exception handling. When the
            trace hits a memory read in ntdll (e.g., reading from a saved CONTEXT
            structure), it will find who wrote that value, follow through any
            intermediate CONTEXT copies, and continue tracing from user code.
            This is essential for analyzing SEH-based obfuscation where values
            bounce through CONTEXT structures during exception dispatch.
        context_chain_max_depth: Maximum number of CONTEXT copies to follow (default 20).

    Returns:
        Taint trace result containing:
        - success: Whether tracing completed
        - steps: List of taint steps showing instruction flow
        - taint_sources: List of ALL identified origins (constants, memory, etc.)
        - active_taint_set: Registers still being tracked when tracing stopped
        - termination_reason: Why tracing stopped
        - steps_executed: Total steps replayed

    Example:
        # Full taint analysis on RAX
        ttd_trace_register_taint("rax")

        # Trace R8 through XOR operations to find all contributing values
        ttd_trace_register_taint("r8", max_steps=15000)

        # Include all writes even if value unchanged (e.g., xor r8,r8 when r8=0)
        ttd_trace_register_taint("r8", track_all_writes=True)

    Note:
        This is more expensive than ttd_trace_register_origin because it tracks
        multiple registers simultaneously. Use ttd_trace_register_origin for
        simpler cases where you just need the immediate data source.
    """
    try:
        cursor = get_cursor()

        saved_pos = cursor.position

        result = cursor.trace_register_taint_backward(
            register_name=register,
            max_steps=max_steps,
            max_trace_depth=max_trace_depth,
            track_all_writes=track_all_writes
        )

        result_dict = result.to_dict()

        # CONTEXT chain traversal: when the trace stops at an ntdll memory read
        # (a CONTEXT save/restore), automatically follow through the chain to find
        # the actual user-code source. This is critical for SEH-based obfuscation
        # where values bounce through CONTEXT structures during exception dispatch.
        if follow_context_chain and result_dict.get("taint_sources"):
            NTDLL_MIN = 0x7ff000000000  # ntdll/kernel address range
            extra_steps = []
            extra_sources = []
            resolved_sources = []

            for source in result_dict["taint_sources"]:
                src_addr = source.get("instruction_address", 0)
                if isinstance(src_addr, str):
                    try: src_addr = int(src_addr, 16) if src_addr.startswith("0x") else int(src_addr)
                    except: src_addr = 0
                src_type = source.get("source_type", "")

                # Follow ALL memory sources to trace through CONTEXT structures,
                # stack values, and other indirect references
                if src_type != "memory":
                    resolved_sources.append(source)
                    continue

                # This is an ntdll CONTEXT read - follow the chain
                chain_depth = 0
                current_source = source
                found_user_code = False

                while chain_depth < context_chain_max_depth:
                    chain_depth += 1
                    src_pos = current_source.get("position", {})
                    src_pc = current_source.get("instruction_address", 0)
                    src_text = current_source.get("instruction_text", "")

                    # Parse memory address from instruction
                    # The instruction is like "mov rax, [r9+0xf0]" or "mov rax, [rdx]"
                    # We need to compute the actual memory address from registers at that point
                    pos_str = src_pos.get("formatted", "")
                    if not pos_str:
                        resolved_sources.append(current_source)
                        break

                    try:
                        cursor.set_position(pos_str)
                        regs_at_src = cursor.get_registers()

                        # Try to compute memory address from instruction text
                        # Parse patterns like [reg + 0xNN] or [reg]
                        mem_addr = None
                        import re
                        # Match patterns: [reg + 0xNN], [reg + +0xNN], [reg]
                        m = re.search(r'\[(\w+)\s*[+\-]\s*\+?0x([0-9a-fA-F]+)\]', src_text)
                        if m:
                            base_reg = m.group(1).lower()
                            offset = int(m.group(2), 16)
                            if '-' in src_text.split('[')[1].split(']')[0]:
                                offset = -offset
                            base_val = regs_at_src.get(base_reg, 0)
                            mem_addr = (base_val + offset) & 0xFFFFFFFFFFFFFFFF
                        else:
                            m2 = re.search(r'\[(\w+)\]', src_text)
                            if m2:
                                base_reg = m2.group(1).lower()
                                mem_addr = regs_at_src.get(base_reg, 0)

                        if mem_addr is None:
                            resolved_sources.append(current_source)
                            break

                        # Find who wrote to this memory address
                        write_result = cursor.trace_memory_origin_backward(
                            address=mem_addr,
                            size=8,
                            max_steps=max_steps
                        )

                        if not write_result.origin_found:
                            resolved_sources.append(current_source)
                            break

                        write_step = write_result.steps[0] if write_result.steps else None
                        write_pc = write_step.instruction_address if write_step else 0
                        if isinstance(write_pc, str):
                            try: write_pc = int(write_pc, 16) if write_pc.startswith("0x") else int(write_pc)
                            except: write_pc = 0

                        extra_steps.append({
                            "context_chain": True,
                            "depth": chain_depth,
                            "memory_address": f"0x{mem_addr:x}",
                            "written_by": write_step.instruction_text if write_step else "unknown",
                            "written_at": f"0x{write_pc:x}",
                            "position": write_step.position if write_step else None,
                        })

                        if write_pc > 0:  # Found the writer - continue tracing from there
                            # Reached user code! Now taint trace from here
                            if write_step and write_step.position:
                                cursor.set_position(write_step.position)
                                # The writer instruction is like "mov [mem], reg"
                                # The source register holds the value we want to trace
                                src_detail = write_result.origin_detail or ""
                                # Extract source register from "Written by ... mov [x], REG"
                                src_reg_match = re.search(r'Written by.*?:\s*\S+\s+mov\s+\S+,\s+(\w+)', src_detail)
                                if not src_reg_match and write_step:
                                    # Try from instruction text: "mov qword ptr [rcx + 0xf0], rax"
                                    src_reg_match = re.search(r'mov\s+\S+\s+ptr\s+\[.*?\],\s*(\w+)', write_step.instruction_text)
                                if src_reg_match:
                                    src_reg = src_reg_match.group(1).lower()
                                    # Continue taint trace from this register at this position
                                    sub_result = cursor.trace_register_taint_backward(
                                        register_name=src_reg,
                                        max_steps=max_steps,
                                        max_trace_depth=max_trace_depth - len(result_dict.get("steps", [])),
                                        track_all_writes=track_all_writes
                                    )
                                    sub_dict = sub_result.to_dict()
                                    extra_steps.extend(sub_dict.get("steps", []))
                                    extra_sources.extend(sub_dict.get("taint_sources", []))
                                    found_user_code = True
                                    break
                                else:
                                    resolved_sources.append({
                                        "source_type": "memory_write",
                                        "source_detail": write_step.instruction_text if write_step else "unknown",
                                        "instruction_address": write_pc,
                                        "position": write_step.position if write_step else None,
                                        "context_chain_depth": chain_depth,
                                    })
                                    found_user_code = True
                                    break
                        else:
                            # write_pc == 0 - couldn't find writer
                            resolved_sources.append(current_source)
                            break
                    except Exception as e:
                        extra_steps.append({"context_chain_error": str(e), "depth": chain_depth})
                        resolved_sources.append(current_source)
                        break

                if not found_user_code and chain_depth >= context_chain_max_depth:
                    resolved_sources.append({
                        **current_source,
                        "context_chain_note": f"Reached max depth ({context_chain_max_depth})"
                    })

            # Merge results
            if extra_steps or extra_sources:
                result_dict["context_chain_steps"] = extra_steps
                result_dict["taint_sources"] = resolved_sources + extra_sources
                if extra_sources:
                    result_dict["taint_source_count"] = len(result_dict["taint_sources"])

        # Restore position
        cursor.set_position(saved_pos)

        return {
            "status": "success",
            "query": {
                "register": register,
                "max_steps": max_steps,
                "max_trace_depth": max_trace_depth,
                "follow_context_chain": follow_context_chain,
                "from_position": saved_pos.to_dict() if hasattr(saved_pos, 'to_dict') else str(saved_pos),
            },
            **result_dict
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Event Query Tools (Native TTDReplay API)
# =============================================================================

@mcp.tool()
def ttd_unified_get_events(max_results: int = 1000) -> dict:
    """
    Get all events from the TTDReplay native API.

    Returns all trace events (module loads, thread events, exceptions).

    Args:
        max_results: Maximum results to return

    Returns:
        List of events with type, position, thread ID, and description

    Example:
        ttd_unified_get_events(max_results=100)
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_events(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "type": e.type,
                    "position": str(e.position),
                    "thread_id": e.thread_id,
                    "description": e.description,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_exception_events(max_results: int = 100) -> dict:
    """
    Get exception events from the TTDReplay native API.

    Args:
        max_results: Maximum results to return

    Returns:
        List of exception events with code, address, type, and position

    Example:
        ttd_unified_get_exception_events()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_exception_events(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "exception_code": hex(e.exception_code),
                    "exception_address": hex(e.exception_address),
                    "exception_flags": e.exception_flags,
                    "type": e.type,
                    "position": str(e.position),
                    "program_counter": hex(e.program_counter),
                    "thread_id": e.thread_id,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_thread_events(max_results: int = 100) -> dict:
    """
    Get thread create/terminate events from the TTDReplay native API.

    Args:
        max_results: Maximum results to return

    Returns:
        List of thread lifecycle events

    Example:
        ttd_unified_get_thread_events()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_thread_events(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "type": e.event_type,
                    "position": str(e.position),
                    "thread_id": e.thread_id,
                    "unique_thread_id": e.unique_thread_id,
                    "lifetime_start": str(e.lifetime_start) if e.lifetime_start else None,
                    "lifetime_end": str(e.lifetime_end) if e.lifetime_end else None,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_module_events(max_results: int = 100) -> dict:
    """
    Get module load/unload events from the TTDReplay native API.

    Args:
        max_results: Maximum results to return

    Returns:
        List of module events with name, address, size

    Example:
        ttd_unified_get_module_events()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_module_events(max_results)

        return {
            "status": "success",
            "count": len(events),
            "events": [
                {
                    "name": e.name,
                    "event_type": e.event_type,
                    "position": str(e.position),
                    "address": hex(e.address),
                    "size": hex(e.size),
                    "checksum": hex(e.checksum),
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_events_by_type(event_type: str, max_results: int = 100) -> dict:
    """
    Get events filtered by a specific type.

    Args:
        event_type: Event type to filter (e.g., "Exception", "ModuleLoaded",
                   "ModuleUnloaded", "ThreadCreated", "ThreadTerminated")
        max_results: Maximum results to return

    Returns:
        List of events matching the specified type

    Example:
        ttd_unified_get_events_by_type("Exception")
        ttd_unified_get_events_by_type("ModuleLoaded")
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_events_by_type(event_type, max_results)

        return {
            "status": "success",
            "count": len(events),
            "filter": event_type,
            "events": [
                {
                    "type": e.type,
                    "position": str(e.position),
                    "thread_id": e.thread_id,
                    "description": e.description,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_first_events(count: int = 10) -> dict:
    """
    Get the first N events for quick trace overview.

    Args:
        count: Number of events to return

    Returns:
        List of events from the beginning of the trace

    Example:
        ttd_unified_get_first_events(20)
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_first_events(count)

        return {
            "status": "success",
            "count": len(events),
            "position": "first",
            "events": [
                {
                    "type": e.type,
                    "position": str(e.position),
                    "thread_id": e.thread_id,
                    "description": e.description,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_last_events(count: int = 10) -> dict:
    """
    Get the last N events.

    Useful for quickly understanding what happens at the end of a trace,
    including any crashes or final state.

    Args:
        count: Number of events to return

    Returns:
        List of events from the end of the trace

    Example:
        ttd_unified_get_last_events(20)
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        events = session.get_last_events(count)

        return {
            "status": "success",
            "count": len(events),
            "position": "last",
            "events": [
                {
                    "type": e.type,
                    "position": str(e.position),
                    "thread_id": e.thread_id,
                    "description": e.description,
                }
                for e in events
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def ttd_unified_get_event_summary() -> dict:
    """
    Get a summary of event counts by type.

    Provides a quick overview of what types of events occurred in the trace
    and how many of each type. Useful for initial trace triage.

    Returns:
        Formatted summary of event counts

    Example:
        ttd_unified_get_event_summary()
    """
    try:
        session = get_unified_session()

        if not session.is_open:
            return {"status": "error", "error": "No trace open. Use ttd_unified_open first."}

        summary = session.get_event_summary()

        return {
            "status": "success",
            "summary": summary,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# Arithmetic / Constraint Extraction Tools
# =============================================================================

@mcp.tool()
def ttd_find_arithmetic_operations(
    watch_address: str,
    watch_size: int = 32,
    max_hits: int = 500,
    forward: bool = True,
    code_address_min: str = "",
    code_address_max: str = "",
    lookahead_instructions: int = 10,
) -> dict:
    """
    Find arithmetic operations (MUL, IMUL, ADD, SUB, XOR) that use values loaded
    from a watched memory range. This is designed for extracting constraint equations
    from obfuscated binaries.

    For each read of the watched memory range, this tool:
    1. Records which byte(s) were read
    2. Steps forward a few instructions to find the arithmetic operation using that value
    3. Records the operation type, constant operand, and key byte index

    This is particularly useful for binaries that validate a key by computing
    key[i]*const + key[j]*const + ... == 0.

    Args:
        watch_address: Base address of the watched memory (hex, e.g., "0x14089b8e8")
        watch_size: Size of memory region to watch (e.g., 32 for 32-byte key)
        max_hits: Maximum reads to collect
        forward: Search direction
        code_address_min: Filter: only include reads where PC >= this (hex)
        code_address_max: Filter: only include reads where PC <= this (hex)
        lookahead_instructions: How many instructions to look ahead for arithmetic ops

    Returns:
        List of arithmetic operations found, each containing:
        - key_byte_offset: Offset within watched region (e.g., 0 for first byte)
        - key_byte_value: The actual byte value read
        - read_position: Trace position of the read
        - read_pc: PC of the read instruction
        - read_instruction: Disassembly of the read instruction
        - arithmetic_op: The arithmetic operation found (MUL, IMUL, ADD, SUB, etc.)
        - arithmetic_pc: PC of the arithmetic instruction
        - arithmetic_instruction: Disassembly of the arithmetic instruction
        - constant: The constant operand (if immediate)
        - register_operand: The register operand (if register)

    Example:
        ttd_find_arithmetic_operations("0x14089b8e8", watch_size=32,
            code_address_min="0xd200000", code_address_max="0xda00000")
    """
    try:
        cursor = get_cursor()
        base_addr = int(watch_address, 16) if watch_address.startswith("0x") else int(watch_address)

        # Parse optional code address filters
        ca_min = None
        ca_max = None
        if code_address_min:
            ca_min = int(code_address_min, 16) if code_address_min.startswith("0x") else int(code_address_min)
        if code_address_max:
            ca_max = int(code_address_max, 16) if code_address_max.startswith("0x") else int(code_address_max)

        # Import disassembly helper
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register
            disasm = get_disassembly_helper()
        except ImportError:
            return {"status": "error", "error": "Capstone not available"}

        if disasm is None:
            return {"status": "error", "error": "Capstone disassembly helper not available"}

        # Save position
        saved_position = cursor.position

        # Step 1: Collect all reads of the key bytes using watchpoints
        reads = cursor.collect_memory_accesses_detailed(
            address=base_addr,
            size=watch_size,
            access_type="read",
            max_hits=max_hits,
            forward=forward,
            read_memory_at_access=False,
            capture_registers=True,
            capture_stack=False,
            stack_depth=0,
            code_address_min=ca_min,
            code_address_max=ca_max,
        )

        operations = []

        # Step 2: For each read, navigate to that position and look ahead for arithmetic
        for read_hit in reads:
            pos = read_hit.get("position", {})
            pc_str = read_hit.get("program_counter", "0x0")
            pc = int(pc_str, 16) if pc_str.startswith("0x") else int(pc_str)

            # Determine which key byte was accessed
            access_info = read_hit.get("access_info", {})
            access_addr_str = access_info.get("access_address", "0x0")
            access_addr = int(access_addr_str, 16) if access_addr_str.startswith("0x") else int(access_addr_str)
            key_byte_offset = access_addr - base_addr

            # Navigate to this position
            try:
                pos_str = f"{pos['sequence']:x}:{pos['steps']:x}"
                cursor.set_position(pos_str)
            except Exception:
                continue

            # Read the instruction at the read PC
            read_insn_text = ""
            try:
                insn_bytes = cursor.query_memory(pc, 16)
                if insn_bytes:
                    insn = disasm.disassemble_one(insn_bytes, pc)
                    if insn:
                        read_insn_text = str(insn)
            except Exception:
                pass

            # Read the actual key byte value
            key_byte_value = 0
            try:
                key_byte_value = cursor.read_uint8(access_addr)
            except Exception:
                pass

            # Step forward to find arithmetic operations
            arith_found = False
            for step_i in range(lookahead_instructions):
                try:
                    cursor.step_forward(1)
                    step_pc = cursor.program_counter
                    step_insn_bytes = cursor.query_memory(step_pc, 16)
                    if not step_insn_bytes:
                        continue

                    step_insn = disasm.disassemble_one(step_insn_bytes, step_pc)
                    if not step_insn:
                        continue

                    mnemonic = step_insn.mnemonic.lower()

                    # Check for arithmetic operations
                    if mnemonic in ("imul", "mul", "add", "sub", "xor", "or", "and",
                                     "shl", "shr", "sar", "neg", "not", "adc", "sbb"):
                        op_record = {
                            "key_byte_offset": key_byte_offset,
                            "key_byte_value": key_byte_value,
                            "read_position": pos,
                            "read_pc": pc_str,
                            "read_instruction": read_insn_text,
                            "arithmetic_op": mnemonic.upper(),
                            "arithmetic_pc": f"0x{step_pc:x}",
                            "arithmetic_instruction": str(step_insn),
                        }

                        # Extract constant/register operands
                        if step_insn.immediate is not None:
                            op_record["constant"] = step_insn.immediate
                            op_record["constant_hex"] = f"0x{step_insn.immediate:x}"
                        if step_insn.source_reg:
                            op_record["register_operand"] = step_insn.source_reg
                        if step_insn.dest_reg:
                            op_record["dest_register"] = step_insn.dest_reg

                        # For IMUL with 3 operands, capture all
                        if mnemonic == "imul" and step_insn.immediate is not None:
                            op_record["arithmetic_type"] = "imul_reg_reg_imm"
                        elif mnemonic in ("imul", "mul") and step_insn.source_reg:
                            op_record["arithmetic_type"] = f"{mnemonic}_reg_reg"
                        elif step_insn.immediate is not None:
                            op_record["arithmetic_type"] = f"{mnemonic}_reg_imm"
                        elif step_insn.source_reg:
                            op_record["arithmetic_type"] = f"{mnemonic}_reg_reg"
                        elif step_insn.source_mem:
                            op_record["arithmetic_type"] = f"{mnemonic}_reg_mem"

                        # Get register values at this point
                        try:
                            regs = cursor.get_registers()
                            op_record["registers_at_arith"] = {
                                "rax": f"0x{regs.rax:x}",
                                "rcx": f"0x{regs.rcx:x}",
                                "rdx": f"0x{regs.rdx:x}",
                                "r8": f"0x{regs.r8:x}",
                                "r9": f"0x{regs.r9:x}",
                                "r10": f"0x{regs.r10:x}",
                                "r11": f"0x{regs.r11:x}",
                                "r12": f"0x{regs.r12:x}",
                            }
                        except Exception:
                            pass

                        operations.append(op_record)
                        arith_found = True
                        break  # Found the arithmetic op, stop looking ahead

                except Exception:
                    break

        # Restore position
        cursor.set_position(saved_position)

        return {
            "status": "success",
            "query": {
                "watch_address": f"0x{base_addr:x}",
                "watch_size": watch_size,
                "code_address_min": code_address_min or None,
                "code_address_max": code_address_max or None,
            },
            "read_count": len(reads),
            "operation_count": len(operations),
            "operations": operations,
        }
    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def ttd_trace_forward_taint(
    start_position: str = "",
    register: str = "rax",
    max_steps: int = 500,
    stop_on_cmp: bool = True,
    code_address_min: str = "",
    code_address_max: str = "",
) -> dict:
    """
    Trace a register value FORWARD through arithmetic operations until a comparison
    (TEST/CMP) is reached. Records all operations along the way.

    This is useful for understanding how key byte values are combined through
    arithmetic to produce a final check value.

    Args:
        start_position: Starting trace position (hex "seq:steps"). Empty = current position.
        register: Register to track forward (e.g., "rax", "r12")
        max_steps: Maximum instructions to step through
        stop_on_cmp: If True, stop when a TEST or CMP instruction is found
        code_address_min: If set, only track when PC >= this address (hex)
        code_address_max: If set, only track when PC <= this address (hex)

    Returns:
        List of operations performed on the tracked register, including:
        - instruction: Full instruction text
        - pc: Program counter
        - operation: Mnemonic (ADD, SUB, IMUL, etc.)
        - operands: Operand details
        - register_values: Key register values before the operation

    Example:
        ttd_trace_forward_taint(register="rax", max_steps=200, stop_on_cmp=True)
    """
    try:
        cursor = get_cursor()

        # Parse optional filters
        ca_min = None
        ca_max = None
        if code_address_min:
            ca_min = int(code_address_min, 16) if code_address_min.startswith("0x") else int(code_address_min)
        if code_address_max:
            ca_max = int(code_address_max, 16) if code_address_max.startswith("0x") else int(code_address_max)

        # Import disassembly helper
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register
            disasm = get_disassembly_helper()
        except ImportError:
            return {"status": "error", "error": "Capstone not available"}

        if disasm is None:
            return {"status": "error", "error": "Capstone disassembly helper not available"}

        # Set position if specified
        saved_position = cursor.position
        if start_position:
            cursor.set_position(start_position)

        target_reg = normalize_register(register.lower())
        operations = []
        termination_reason = "max_steps_reached"

        for step_i in range(max_steps):
            try:
                pc = cursor.program_counter

                # Check code address filter
                in_range = True
                if ca_min is not None and pc < ca_min:
                    in_range = False
                if ca_max is not None and pc > ca_max:
                    in_range = False

                if in_range:
                    # Read and disassemble
                    insn_bytes = cursor.query_memory(pc, 16)
                    if insn_bytes:
                        insn = disasm.disassemble_one(insn_bytes, pc)
                        if insn:
                            mnemonic = insn.mnemonic.lower()

                            # Check if this is a CMP/TEST (comparison)
                            if stop_on_cmp and mnemonic in ("cmp", "test"):
                                # Record the comparison
                                regs = cursor.get_registers()
                                operations.append({
                                    "step": step_i,
                                    "pc": f"0x{pc:x}",
                                    "instruction": str(insn),
                                    "operation": mnemonic.upper(),
                                    "is_comparison": True,
                                    "registers": {
                                        "rax": f"0x{regs.rax:x}",
                                        "rcx": f"0x{regs.rcx:x}",
                                        "rdx": f"0x{regs.rdx:x}",
                                        "r8": f"0x{regs.r8:x}",
                                        "r9": f"0x{regs.r9:x}",
                                        "r10": f"0x{regs.r10:x}",
                                        "r11": f"0x{regs.r11:x}",
                                        "r12": f"0x{regs.r12:x}",
                                    },
                                })
                                termination_reason = "comparison_found"
                                break

                            # Check if instruction modifies our tracked register
                            modified_reg = disasm.get_modified_register(insn)
                            if modified_reg and normalize_register(modified_reg) == target_reg:
                                regs = cursor.get_registers()
                                op_record = {
                                    "step": step_i,
                                    "pc": f"0x{pc:x}",
                                    "instruction": str(insn),
                                    "operation": mnemonic.upper(),
                                    "is_comparison": False,
                                    "dest_register": insn.dest_reg,
                                    "registers": {
                                        "rax": f"0x{regs.rax:x}",
                                        "rcx": f"0x{regs.rcx:x}",
                                        "rdx": f"0x{regs.rdx:x}",
                                        "r8": f"0x{regs.r8:x}",
                                        "r9": f"0x{regs.r9:x}",
                                        "r10": f"0x{regs.r10:x}",
                                        "r11": f"0x{regs.r11:x}",
                                        "r12": f"0x{regs.r12:x}",
                                    },
                                }
                                if insn.immediate is not None:
                                    op_record["constant"] = insn.immediate
                                    op_record["constant_hex"] = f"0x{insn.immediate:x}"
                                if insn.source_reg:
                                    op_record["source_register"] = insn.source_reg
                                if insn.source_mem:
                                    op_record["source_memory"] = str(insn.source_mem)

                                operations.append(op_record)

                                # If the register was overwritten (not modified), update tracking
                                if mnemonic in ("mov", "movzx", "movsxd", "movsx", "lea"):
                                    # Track the new value source
                                    pass

                # Step forward
                cursor.step_forward(1)

            except Exception as e:
                termination_reason = f"error: {e}"
                break

        # Restore position
        cursor.set_position(saved_position)

        return {
            "status": "success",
            "query": {
                "register": register,
                "max_steps": max_steps,
                "stop_on_cmp": stop_on_cmp,
            },
            "operation_count": len(operations),
            "termination_reason": termination_reason,
            "operations": operations,
        }
    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def ttd_extract_linear_constraints(
    key_address: str,
    key_size: int = 32,
    buffer_base: str = "",
    buffer_size: int = 0x800000,
    max_reads: int = 2000,
    group_by_equation: bool = True,
) -> dict:
    """
    Extract linear constraint equations from a TTD trace by monitoring key byte reads
    and the subsequent arithmetic operations. Designed for challenges where a key is
    validated via linear equations: sum(key[i] * const_i) + constant == 0.

    This tool:
    1. Finds all reads of key bytes (within the buffer code region)
    2. For each read, identifies the IMUL/MUL and ADD/SUB operations
    3. Groups operations into equations (based on proximity in the trace)
    4. Returns coefficients for each equation

    Args:
        key_address: Address of the key bytes (hex)
        key_size: Number of key bytes
        buffer_base: Base address of the code buffer to filter reads (hex).
                    Only reads from this code region are considered.
        buffer_size: Size of code buffer
        max_reads: Maximum key byte reads to collect
        group_by_equation: If True, group operations into equations

    Returns:
        Extracted equations with coefficients for Z3 solving

    Example:
        ttd_extract_linear_constraints("0x14089b8e8", key_size=32,
            buffer_base="0xd200000", buffer_size=0x800000)
    """
    try:
        cursor = get_cursor()
        key_addr = int(key_address, 16) if key_address.startswith("0x") else int(key_address)

        buf_base = None
        buf_end = None
        if buffer_base:
            buf_base = int(buffer_base, 16) if buffer_base.startswith("0x") else int(buffer_base)
            buf_end = buf_base + buffer_size

        # Import disassembly helper
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register
            disasm = get_disassembly_helper()
        except ImportError:
            return {"status": "error", "error": "Capstone not available"}

        if disasm is None:
            return {"status": "error", "error": "Capstone disassembly helper not available"}

        # Save position
        saved_position = cursor.position

        # Step 1: Collect all reads of key bytes from buffer code
        reads = cursor.collect_memory_accesses_detailed(
            address=key_addr,
            size=key_size,
            access_type="read",
            max_hits=max_reads,
            forward=True,
            read_memory_at_access=False,
            capture_registers=False,
            capture_stack=False,
            stack_depth=0,
            code_address_min=buf_base,
            code_address_max=buf_end,
        )

        # Step 2: For each read, step forward to extract arithmetic context
        equation_data = []  # List of (key_byte_index, coefficient, position_seq)

        for read_hit in reads:
            pos = read_hit.get("position", {})
            pc_str = read_hit.get("program_counter", "0x0")

            # Determine which key byte
            access_info = read_hit.get("access_info", {})
            access_addr_str = access_info.get("access_address", "0x0")
            access_addr = int(access_addr_str, 16) if access_addr_str.startswith("0x") else int(access_addr_str)
            key_byte_idx = access_addr - key_addr

            if key_byte_idx < 0 or key_byte_idx >= key_size:
                continue

            # Navigate to this position
            try:
                pos_str = f"{pos['sequence']:x}:{pos['steps']:x}"
                cursor.set_position(pos_str)
            except Exception:
                continue

            # Step forward to find the IMUL and get the constant
            coefficient = None
            arith_op = None

            for _ in range(15):
                try:
                    cursor.step_forward(1)
                    pc = cursor.program_counter
                    insn_bytes = cursor.query_memory(pc, 16)
                    if not insn_bytes:
                        continue
                    insn = disasm.disassemble_one(insn_bytes, pc)
                    if not insn:
                        continue

                    mnemonic = insn.mnemonic.lower()

                    if mnemonic == "imul" and insn.immediate is not None:
                        coefficient = insn.immediate
                        arith_op = "IMUL"
                        break
                    elif mnemonic == "imul" and insn.source_reg:
                        # Two-operand IMUL - the multiplier is in a register
                        reg = normalize_register(insn.source_reg)
                        if reg:
                            regs = cursor.get_registers()
                            coefficient = regs.get(reg)
                        arith_op = "IMUL"
                        break
                    elif mnemonic == "mul":
                        arith_op = "MUL"
                        break

                except Exception:
                    break

            if coefficient is not None:
                equation_data.append({
                    "key_byte_index": key_byte_idx,
                    "coefficient": coefficient,
                    "coefficient_hex": f"0x{coefficient & 0xFFFFFFFF:08x}",
                    "operation": arith_op,
                    "position_sequence": pos.get("sequence", 0),
                })

        # Step 3: Group into equations if requested
        equations = []
        if group_by_equation and equation_data:
            # Group by proximity in trace (same equation = consecutive reads)
            current_eq = {"terms": [], "start_seq": 0}
            prev_seq = 0

            for item in equation_data:
                seq = item["position_sequence"]
                if current_eq["terms"] and (seq - prev_seq > 0x1000):
                    # New equation - big gap in trace
                    equations.append(current_eq)
                    current_eq = {"terms": [], "start_seq": seq}

                current_eq["terms"].append({
                    "key_byte_index": item["key_byte_index"],
                    "coefficient": item["coefficient"],
                    "coefficient_hex": item["coefficient_hex"],
                })
                prev_seq = seq

            if current_eq["terms"]:
                equations.append(current_eq)

        # Restore position
        cursor.set_position(saved_position)

        result = {
            "status": "success",
            "query": {
                "key_address": f"0x{key_addr:x}",
                "key_size": key_size,
                "buffer_base": buffer_base or None,
            },
            "raw_operation_count": len(equation_data),
            "raw_operations": equation_data,
        }

        if group_by_equation:
            result["equation_count"] = len(equations)
            result["equations"] = equations

        return result

    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}


# =============================================================================
# Entry Point
# =============================================================================
# Write-Execute Pattern Query (Self-Modifying Code Analysis)
# =============================================================================

@mcp.tool()
def ttd_query_write_execute_patterns(
    address: str,
    size: int = 8388608,
    max_events: int = 50000
) -> dict:
    """
    Query for write-then-execute (WE) patterns in a memory range.

    This is the TTD equivalent of WinDbg's @$cursession.TTD.Memory(base, base+size, 'WE').
    It finds all locations where code was WRITTEN to memory and then EXECUTED.

    This is the key technique for analyzing self-modifying code: the binary writes
    decoded/decrypted instructions to memory, executes them, then re-encrypts.
    By capturing the write-execute pattern, you recover the actual instructions that
    ran, bypassing all obfuscation.

    For each WE event, returns the instruction bytes that were written and executed,
    along with the position and address. Feed these bytes to Capstone for disassembly
    to recover the deobfuscated instruction stream.

    Args:
        address: Base address of the memory range (hex, e.g., "0xd200000")
        size: Size of memory range to watch (default 8MB for shellcode buffers)
        max_events: Maximum write-execute events to collect

    Returns:
        List of write-execute events with address, positions, and instruction bytes.

    Example:
        ttd_query_write_execute_patterns("0xd200000", size=0x800000)
    """
    try:
        cursor = get_cursor()
        addr = int(address, 16) if isinstance(address, str) else address

        # Collect WRITE events in the range
        session = get_unified_session()
        start_pos = session.first_position
        cursor.set_position(start_pos)
        writes = cursor.collect_memory_accesses_detailed(
            address=addr, size=size, access_type="write",
            max_hits=max_events, forward=True,
            read_memory_at_access=True, memory_read_size=16,
            capture_registers=False, capture_stack=False,
        )

        # Collect EXECUTE events
        session = get_unified_session()
        start_pos = session.first_position
        cursor.set_position(start_pos)
        executes = cursor.collect_memory_accesses_detailed(
            address=addr, size=size, access_type="execute",
            max_hits=max_events, forward=True,
            read_memory_at_access=True, memory_read_size=16,
            capture_registers=False, capture_stack=False,
        )

        # Build write map: address -> list of (position, bytes)
        write_map = {}
        for w in writes:
            w_addr = w.get("access_info", {}).get("access_address", "0x0")
            if isinstance(w_addr, str):
                w_addr = int(w_addr, 16)
            w_pos = w.get("position", {})
            w_size = w.get("access_info", {}).get("access_size", 0)
            w_mem = w.get("memory_at_address", {}).get("hex", "")
            if w_addr not in write_map:
                write_map[w_addr] = []
            write_map[w_addr].append({"position": w_pos, "size": w_size, "memory_hex": w_mem})

        # Correlate: for each execute, find most recent write to same address
        we_events = []
        for e in executes:
            e_addr = e.get("access_info", {}).get("access_address", "0x0")
            if isinstance(e_addr, str):
                e_addr = int(e_addr, 16)
            e_pos = e.get("position", {})
            e_size = e.get("access_info", {}).get("access_size", 0)
            e_mem = e.get("memory_at_address", {}).get("hex", "")

            if e_addr in write_map:
                e_seq = e_pos.get("sequence", 0)
                best_write = None
                for w in write_map[e_addr]:
                    w_seq = w["position"].get("sequence", 0)
                    if w_seq <= e_seq:
                        if best_write is None or w_seq > best_write["position"].get("sequence", 0):
                            best_write = w
                if best_write:
                    # Extract instruction bytes from memory dump
                    # memory_at_address starts at the watched base, not at access_address
                    mem_base = addr
                    byte_offset = (e_addr - mem_base) * 2  # hex chars
                    insn_hex = ""
                    if e_mem and byte_offset >= 0 and byte_offset < len(e_mem):
                        insn_hex = e_mem[byte_offset:byte_offset + e_size * 2]
                    if not insn_hex:
                        # Try from write's memory snapshot
                        w_mem = best_write.get("memory_hex", "")
                        if w_mem and byte_offset >= 0 and byte_offset < len(w_mem):
                            insn_hex = w_mem[byte_offset:byte_offset + e_size * 2]
                    we_events.append({
                        "address": f"0x{e_addr:x}",
                        "execute_position": e_pos,
                        "write_position": best_write["position"],
                        "instruction_bytes": insn_hex,
                        "instruction_size": e_size,
                    })
            if len(we_events) >= max_events:
                break

        # Post-process: read actual instruction bytes at each WE event position
        for ev in we_events:
            if not ev.get("instruction_bytes"):
                try:
                    e_pos = ev["execute_position"]
                    e_addr = int(ev["address"], 16)
                    e_size = ev["instruction_size"]
                    pos_str = f"{e_pos['sequence']:x}:{e_pos['steps']:x}"
                    cursor.set_position(pos_str)
                    mem = cursor.query_memory(e_addr, max(e_size, 16))
                    ev["instruction_bytes"] = mem[:e_size].hex() if mem else ""
                    ev["full_context_bytes"] = mem[:16].hex() if mem else ""
                except Exception:
                    pass

        return {
            "status": "success",
            "query": {"address": address, "size": size},
            "total_writes": len(writes),
            "total_executes": len(executes),
            "write_execute_count": len(we_events),
            "events": we_events[:1000],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================

def main():
    """Run the TTD MCP server."""
    print("TTD MCP Server starting...", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
