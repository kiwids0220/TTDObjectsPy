# TTDObjectsPy MCP Server

Model Context Protocol (MCP) server for **Microsoft Time Travel Debugging (TTD)**. Gives Codex direct access to TTD trace recordings for reverse engineering, malware analysis, vulnerability research, and debugging.

TTDObjectsPy talks directly to `TTDReplay.dll` via ctypes — no WinDbg or debugger engine required.

## Features

- **Full trace navigation** &mdash; step forward/backward, set position, replay to watchpoints
- **Memory & register inspection** &mdash; read memory, registers, and stack at any point in time
- **Function call tracing** &mdash; query all calls to a function address with parameters and return values
- **Data flow / taint analysis** &mdash; trace values backward to their origin, full taint propagation
- **Memory watchpoints** &mdash; watch for reads, writes, or executes on address ranges
- **Event queries** &mdash; exceptions, thread events, module loads/unloads
- **No WinDbg dependency** &mdash; uses TTDReplay.dll native API directly via ctypes vtable bindings

## Requirements

- **Windows 10/11** (x64)
- **Codex** with local plugin support
- TTD trace files (`.run` + `.out`) recorded with WinDbg, TTD.exe, or tttracer

## Installation

### Fresh Windows install

From an extracted release or repository checkout:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\installer\installer.ps1
```

The installer downloads the TTD runtime, installs Python through `winget` when needed,
creates the project venv, installs dependencies, registers the Codex marketplace and MCP
server, and exposes the bundled skill. Restart Codex after installation, then invoke
`$ttd-analysis`.

The bundled `ttd-installer.exe` means Git, Visual Studio, CMake, and preinstalled Python are
not required for the normal installation path.

The legacy helper remains available and delegates to the full installer:

```powershell
.\scripts\install_codex_plugin.ps1
```

### Python environment (optional)

```bash
pip install -e .

# Capstone disassembler for data-flow tracing
pip install -e ".[dataflow]"

# Development tools (pytest, black, ruff, mypy)
pip install -e ".[dev]"
```

If you plan to rebuild the bundled installer, install Visual Studio 2022 Build Tools with the MSVC toolchain, CMake support, and a recent Windows SDK.

## Quick Start

Once installed in Codex, open a conversation and work with TTD traces:

```
Open the trace at C:\traces\malware.run and show me what happened
```

Codex will call the MCP tools automatically. Here's what a typical session looks like:

### 1. Open a trace

```python
# Codex calls: ttd_unified_open("C:/traces/malware.run")
# Returns: first_position, last_position, thread count
```

### 2. Explore events

```python
# ttd_unified_get_event_summary()
# Returns counts: 3 exceptions, 12 thread events, 45 module loads

# ttd_unified_get_module_events()
# Shows every DLL loaded with base address and size

# ttd_unified_get_exception_events()
# Shows crash location, exception code, faulting address
```

### 3. Navigate and inspect

```python
# ttd_unified_set_position("1a3:5f")
# Jump to a specific point in the trace

# ttd_unified_get_registers()
# Read all CPU registers at this position

# ttd_unified_read_memory("0x7ff612340000", 256)
# Read 256 bytes of memory at this moment in time

# ttd_unified_step_forward(10)
# Step 10 instructions forward
```

### 4. Trace function calls

```python
# ttd_unified_query_calls_by_address(
#     entry_address="0x7ffa6e520010",  # WS2_32!send
#     exits=[{"address": "0x7ffa6e520080", "type": "ret"}],
#     max_calls=50
# )
# Returns every call to send() with RCX/RDX/R8/R9 parameters and RAX return value
```

### 5. Data flow analysis

```python
# ttd_trace_register_origin("rcx")
# Traces backward to find where RCX got its current value

# ttd_trace_register_taint("rax")
# Full taint analysis: every data source that contributed to RAX

# ttd_unified_find_memory_write("0x00007ff612345678", 8)
# Find the instruction that last wrote to this address
```

### 6. Watchpoint-based analysis

```python
# ttd_unified_add_memory_watchpoint("0x7ff612340000", 4096, "write")
# Watch for any write to this memory page

# ttd_unified_replay_forward()
# Replay until the watchpoint fires

# ttd_unified_clear_watchpoints()
```

## Example: Crash Root-Cause Analysis

```
User: "Open crash.run and find the root cause of the access violation"

Codex will:
1. Open the trace and find exception events
2. Navigate to the crash position
3. Read registers to see the faulting instruction
4. Trace the bad pointer backward using ttd_trace_register_origin
5. Follow the data flow to identify where the corruption originated
6. Report the root cause with exact positions and instruction context
```

## Example: Malware C2 Protocol Analysis

```
User: "Analyze the network communication in malware.run"

Codex will:
1. Find WS2_32.dll's base address from module events
2. Query all calls to connect(), send(), recv() by address
3. Read the buffer contents at each send/recv call
4. Reconstruct the network protocol from the captured data
5. Identify encryption keys, C2 commands, and exfiltrated data
```

## Tool Reference

| Category | Tools |
|----------|-------|
| **Trace management** | `ttd_unified_open`, `ttd_unified_close`, `ttd_unified_status` |
| **Navigation** | `ttd_unified_set_position`, `ttd_unified_step_forward/backward`, `ttd_unified_replay_forward/backward`, `ttd_unified_run_to_address`, `ttd_unified_goto_start/end` |
| **Inspection** | `ttd_unified_get_registers`, `ttd_unified_get_register`, `ttd_unified_read_memory`, `ttd_unified_read_string`, `ttd_unified_get_stack`, `ttd_unified_get_position` |
| **Call tracing** | `ttd_unified_query_calls_by_address` |
| **Data flow** | `ttd_trace_register_origin`, `ttd_trace_memory_origin`, `ttd_trace_register_taint`, `ttd_find_data_source`, `ttd_unified_find_memory_write` |
| **Memory analysis** | `ttd_collect_memory_accesses_detailed`, `ttd_trace_value_changes_detailed`, `ttd_analyze_memory_access_pattern` |
| **Events** | `ttd_unified_get_event_summary`, `ttd_unified_get_exception_events`, `ttd_unified_get_module_events`, `ttd_unified_get_thread_events` |
| **Watchpoints** | `ttd_unified_add_memory_watchpoint`, `ttd_unified_remove_memory_watchpoint`, `ttd_unified_clear_watchpoints` |

## Recording TTD Traces

Prefer the bundled recorder from this repo:

- **Bundled TTD.exe** &mdash; `C:\Tools\TTDObjectsPy\asset\amd64\ttd\TTD.exe -out C:\traces -launch myapp.exe`
- **WinDbg** &mdash; `File > Start debugging > Launch executable (advanced)` with "Record with Time Travel Debugging" checked
- **Other installs of TTD.exe** &mdash; `TTD.exe -out C:\traces -launch myapp.exe`

If you need the exact capture syntax, run the bundled recorder with no arguments to show its help menu:

```powershell
C:\Tools\TTDObjectsPy\asset\amd64\ttd\TTD.exe
```

Each recording produces a `.run` file (trace data) and `.out` file (index). Both are needed.

## Architecture

```
Codex
        |
        | MCP (stdio)
        v
  TTDObjectsPy MCP Server  (src/ttdobjectspy/server.py)
        |
        | Python ctypes
        v
  TTDReplay.dll            (asset/amd64/ttd/TTDReplay.dll)
        |
        | Native API
        v
  .run trace file
```

The bundled loader prefers the installer-managed layout under `asset/amd64/ttd` and falls back to the legacy flat `asset/` layout if it still exists.

## License

MIT
