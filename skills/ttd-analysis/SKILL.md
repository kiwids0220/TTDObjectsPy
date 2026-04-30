---
name: ttd-analysis
description: Capture and analyze Microsoft Time Travel Debugging (TTD) traces with TTDObjectsPy MCP for malware analysis, CTF challenges, vulnerability research, crash debugging, and general reverse engineering on Windows. Use when asked to record a process, analyze a .run trace, trace API calls, perform taint or data-flow analysis, find what wrote to memory, or investigate any recorded execution.
---

# TTD Trace Capture and Analysis

A TTD trace is a complete recording of every instruction the target executed. The `ttd_*` tools exposed by the bundled TTDObjectsPy MCP server query that recording. Treat the trace as a searchable, time-indexed database of program execution rather than a step debugger.

When a trace exists, prefer querying the trace over statically reasoning about obfuscation, brute-forcing a check, or emulating code. The execution history is already there.

## Mental Model

| Question | Tool |
|----------|------|
| "Show me every instruction that touched this address" | `ttd_collect_memory_accesses_detailed` |
| "Show me every operation that transformed this value" | `ttd_trace_register_taint`, `ttd_trace_forward_taint` |
| "Show me every time this code address ran" | `ttd_find_code_executions` |
| "Where did this value come from?" | `ttd_trace_register_origin`, `ttd_trace_memory_origin` |
| "Who wrote to this address?" | `ttd_unified_find_memory_write` |
| "What calls did this function receive?" | `ttd_unified_query_calls_by_address` |
| "What crashed?" | `ttd_unified_get_exception_events` |
| "What DLLs got loaded and where?" | `ttd_unified_get_module_events`, `ttd_unified_query_modules` |

## Part 1 - Capturing a Trace

The MCP server consumes `.run` files and operates independently of the capture executable.
Capture happens outside the MCP session. If a trace already exists, analysis can proceed even
when `TTD.exe` is unavailable.

### Resolve The Bundled Capture Tool

Never assume the repository is installed at `C:\Tools\TTDObjectsPy`. Resolve its current path
from the registered MCP launcher:

```powershell
$McpConfig = codex mcp get ttdobjectspy --json | ConvertFrom-Json
$McpLauncher = $McpConfig.transport.args |
    Where-Object { [IO.Path]::GetFileName($_) -eq "run_codex_mcp.py" } |
    Select-Object -First 1

if (-not $McpLauncher) {
    throw "TTDObjectsPy MCP launcher is not registered."
}

$RepoRoot = Split-Path -Parent (Split-Path -Parent $McpLauncher)
$TtdExe = Join-Path $RepoRoot "asset\amd64\ttd\TTD.exe"

if (-not (Test-Path -LiteralPath $TtdExe -PathType Leaf)) {
    Write-Warning "Bundled capture executable is missing: $TtdExe"
}
```

Prefer `$TtdExe` when it exists. If capture syntax is unclear, run it with no arguments first
to open the built-in help menu:

```powershell
& $TtdExe
```

Fallbacks only if the bundled copy is missing:

```text
C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\ttd\TTD.exe
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\ttd\TTD.exe
C:\Tools\WinDbg\amd64\ttd\TTD.exe
```

Run as Administrator when attaching to running processes, tracing services, or capturing privileged behavior.

### Capture Modes

| Scenario | Command |
|----------|---------|
| Launch and record a new process | `& $TtdExe -accepteula -out C:\traces -launch program.exe arg1 arg2` |
| Attach to a running process by PID | `& $TtdExe -accepteula -out C:\traces -attach 1234` |
| Record process and child processes | `& $TtdExe -accepteula -out C:\traces -children -launch program.exe` |
| Ring buffer capture | `& $TtdExe -accepteula -out C:\traces -ring -maxfile 2048 -launch program.exe` |
| Stop one active trace | `& $TtdExe -stop <instance_id>` |
| Stop all active traces | `& $TtdExe -stop all` |
| Wait for a process by name | `& $TtdExe -accepteula -out C:\traces -monitor program.exe` |

### Output Files

Each capture produces:

```text
<ProcessName><PID>.run
<ProcessName><PID>.idx
<ProcessName><PID>.out
```

### Capture Workflow

```powershell
mkdir C:\traces
& $TtdExe -accepteula -out C:\traces -launch target.exe
& $TtdExe -stop all
dir C:\traces\*.run
```

Then open the trace with:

```text
ttd_unified_open("C:\\traces\\target1234.run")
```

### Capture Tips

- Use `-ring -maxfile <MB>` for long-running or noisy targets.
- Expect anti-TTD and anti-analysis checks in some malware; capture the bail-out path if the sample exits early.
- Use `-children` for multi-process workflows.
- TTD records crashes in-line; no separate dump is required.

## Part 2 - Always Start Here

Open the trace, then orient:

```text
ttd_unified_open(trace_path)
  -> ttd_unified_status()
  -> ttd_unified_get_event_summary()
  -> ttd_unified_get_module_events()
  -> ttd_unified_get_exception_events()
  -> ttd_unified_get_threads()
```

That five-call opener tells you whether the program crashed, what modules loaded, how many threads exist, and the overall trace lifetime.

## Part 3 - Core Analysis Workflows

### A. Hit-Point Pivot

Use this when you know an interesting code address and want runtime state at each execution:

```text
ttd_find_code_executions(addr)
  -> ttd_unified_set_position(hit_pos)
  -> ttd_unified_get_registers()
  -> ttd_unified_read_memory(@rcx, 16)
  -> ttd_unified_read_string(@rcx)
  -> ttd_unified_step_forward(1)
```

### B. Data-Flow Backward

Use this when you have a suspicious value and need its provenance:

```text
ttd_unified_set_position(suspicious_pos)
  -> ttd_unified_get_registers()
  -> ttd_trace_register_origin("rcx")
  -> ttd_unified_set_position(origin_pos)
  -> ttd_trace_register_taint("rcx")
```

`origin` finds the immediate write. `taint` reconstructs the broader dependency chain.

### C. Memory Surveillance

Use this when you know the interesting memory region:

```text
ttd_collect_memory_accesses_detailed(addr, size)
  -> ttd_unified_set_position(pos)
  -> ttd_unified_get_registers()
  -> ttd_unified_read_memory(addr, size)
```

### D. Function Call Tracing

Use this when you know a function entry address and its exits:

```text
ttd_unified_query_calls_by_address(entry, exits)
  -> ttd_unified_set_position(call_pos)
  -> ttd_unified_get_registers()
  -> ttd_unified_read_string(@rcx)
```

If another toolchain gives you entry and exit addresses, feed them directly into `ttd_unified_query_calls_by_address`.

## Part 4 - Domain Playbooks

### Malware Analysis

Start broad, then narrow:

```text
ttd_unified_get_event_summary()
ttd_unified_get_module_events()
ttd_unified_get_exception_events()
ttd_unified_get_threads()
```

For injection or hollowing, focus on allocator, writer, and execution APIs by address and inspect their arguments and buffers at each call site.

For network reconstruction, find the relevant module base with `ttd_unified_query_modules`, then query `send`, `recv`, or other networking functions by address and dump the pointed-to buffers at call time.

For persistence or config handling, query file, registry, service, or crypto functions by address and inspect parameters and return values at the matching positions.

### CTF Challenges

Do not statically fight packed or obfuscated code if you already have a trace:

```text
ttd_find_code_executions(<cmp_or_jcc_addr>)
  -> ttd_unified_set_position(hit)
  -> ttd_unified_get_registers()
  -> ttd_trace_register_taint("rax")
  -> ttd_find_arithmetic_operations(...)
  -> ttd_extract_linear_constraints(...)
```

For flag buffers or decrypted state, track the writes with `ttd_collect_memory_accesses_detailed` and pivot to the write that populated the interesting region.

For packed or self-modifying code, `ttd_query_write_execute_patterns()` is a strong first query.

### Crash and Vulnerability Analysis

```text
ttd_unified_get_exception_events()
ttd_unified_set_position("<crash_pos>")
ttd_unified_get_registers()
ttd_unified_find_memory_write("<bad_addr>", 8)
ttd_trace_register_taint("rcx")
```

For UAF-style issues, combine object-address memory access collection with allocator or free-function call tracing by address.

## Part 5 - Position Strings

Positions use the `"sequence:steps"` format in hex, for example `"3df:1234"`. If `ttd_unified_set_position` returns `InvalidPosition`, call `ttd_unified_get_position()` or `ttd_unified_status()` to confirm the expected format, then retry with a valid hex pair.

## Part 6 - Windows x64 Calling Convention

- Arguments: `RCX`, `RDX`, `R8`, `R9`
- Return: `RAX`
- Additional args: stack slots starting at `[RSP+0x28]`
- Callee-saved: `RBX`, `RBP`, `RDI`, `RSI`, `R12`-`R15`, `RSP`
- Caller-saved: `RAX`, `RCX`, `RDX`, `R8`-`R11`

Read argument registers at function-entry positions and `RAX` at the matching exit.

## Part 7 - Core Principles

1. Trace first, reason second.
2. Ground truth is the trace.
3. Orient before diving.
4. Prefer queries over stepping.
5. Validate position strings before assuming the trace is wrong.
6. Close the current session with `ttd_unified_close()` before switching traces.

## Tool Quick Reference

### Trace lifecycle

- `ttd_unified_open(trace_path)`
- `ttd_unified_status()`
- `ttd_unified_close()`

### Navigation

- `ttd_unified_set_position(position)`
- `ttd_unified_get_position()`
- `ttd_unified_step_forward(steps)`
- `ttd_unified_step_backward(steps)`
- `ttd_unified_replay_forward(max_steps)`
- `ttd_unified_replay_backward(max_steps)`
- `ttd_unified_run_to_address(address, backward=False)`
- `ttd_unified_goto_start()`
- `ttd_unified_goto_end()`

### Inspection

- `ttd_unified_get_registers()`
- `ttd_unified_get_register(name)`
- `ttd_unified_read_memory(address, size)`
- `ttd_unified_read_string(address, max_length, wide)`
- `ttd_unified_get_stack(depth)`

### Watchpoints

- `ttd_unified_add_memory_watchpoint(address, size, access_type)`
- `ttd_unified_remove_memory_watchpoint(address, size, access_type)`
- `ttd_unified_clear_watchpoints()`

### Function calls

- `ttd_unified_query_calls_by_address(entry_address, exits, max_calls)`

### Memory access analytics

- `ttd_collect_memory_accesses_detailed(address, size)`
- `ttd_unified_find_memory_write(address, size)`
- `ttd_analyze_memory_access_pattern(address, size)`

### Data flow and taint

- `ttd_trace_register_origin(register)`
- `ttd_trace_memory_origin(address, size)`
- `ttd_trace_register_taint(register)`
- `ttd_trace_forward_taint(register)`
- `ttd_find_data_source(address, size)`
- `ttd_trace_value_changes_detailed(address, size)`

### Events

- `ttd_unified_get_event_summary()`
- `ttd_unified_get_events(max_results)`
- `ttd_unified_get_exception_events(max_results)`
- `ttd_unified_get_thread_events(max_results)`
- `ttd_unified_get_module_events(max_results)`
- `ttd_unified_get_events_by_type(event_type, max_results)`
- `ttd_unified_get_first_events(count)`
- `ttd_unified_get_last_events(count)`
- `ttd_unified_get_threads(max_results)`
- `ttd_unified_get_lifetime()`

### Native API event queries

- `ttd_unified_query_exceptions(max_results)`
- `ttd_unified_query_modules(max_results)`
- `ttd_unified_query_thread_lifetimes(max_results)`

### Code execution queries

- `ttd_find_code_executions(address)`

### Solver-oriented helpers

- `ttd_find_arithmetic_operations(...)`
- `ttd_extract_linear_constraints(...)`
- `ttd_query_write_execute_patterns()`
