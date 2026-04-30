"""
Unified TTD Trace Session - TTDReplay-only backend.

This module provides the trace session interface using TTDReplay.dll natively.
All queries (threads, modules, events, exceptions) use the native TTDReplay API.

Usage:
    from ttdobjectspy.unified_session import UnifiedTraceSession

    with UnifiedTraceSession(r"C:\\traces\\app.run") as session:
        # Navigate to a position
        session.set_position("64:0")

        # Use TTDReplay for fast memory/register access
        rax = session.get_register("rax")
        memory = session.read_memory(rax, 64)

        # Query events natively
        exceptions = session.get_exception_events()
        threads = session.get_thread_events()
        modules = session.get_module_events()
"""

from __future__ import annotations

import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Union, TYPE_CHECKING

# Type hints for optional imports
if TYPE_CHECKING:
    from ttdobjectspy.engine import ReplayEngine, Cursor, Position


@dataclass
class TracePosition:
    """Unified position representation."""
    sequence: int
    steps: int

    def __str__(self) -> str:
        return f"{self.sequence:x}:{self.steps:x}"

    @classmethod
    def from_string(cls, s: str) -> "TracePosition":
        """Parse position from 'seq:steps' hex format."""
        parts = s.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid position format: {s}")
        return cls(int(parts[0], 16), int(parts[1], 16))

    @classmethod
    def from_ttdreplay(cls, pos) -> "TracePosition":
        """Create from TTDReplay Position object."""
        return cls(pos.sequence, pos.steps)


@dataclass
class AddressCallEvent:
    """Call event captured via address-based watchpoint replay (no symbols needed)."""
    entry_address: int
    position_start: TracePosition
    position_end: Optional[TracePosition]  # None if return not captured
    rcx: int
    rdx: int
    r8: int
    r9: int
    rsp: int
    rax: Optional[int]  # Return value, None if return not captured
    thread_id: int
    exit_address: Optional[int] = None  # Address where function exited
    exit_type: Optional[str] = None  # "ret", "tail_call", or "indirect_jmp"


@dataclass
class ExceptionEvent:
    """Exception event from TTDReplay native API."""
    exception_code: int
    exception_address: int
    exception_flags: int
    type: str  # "FirstChance" or "SecondChance"
    position: TracePosition
    program_counter: int = 0
    thread_id: int = 0

    @classmethod
    def from_native(cls, event) -> "ExceptionEvent":
        """Create from CTTDExceptionEvent."""
        pos = event.Position.to_python()
        # ExceptionType: 0=FirstChance, 1=SecondChance
        exc_type = "SecondChance" if event.Type == 1 else "FirstChance"
        # Try to get thread info from pointer
        thread_id = 0
        if event.pThreadInfo:
            try:
                from ctypes import cast, POINTER
                from ttdobjectspy.ttd_types import CTTDThreadInfo
                ti = cast(event.pThreadInfo, POINTER(CTTDThreadInfo)).contents
                thread_id = ti.Id
            except Exception:
                pass
        return cls(
            exception_code=event.Code,
            exception_address=event.RecordAddress,
            exception_flags=event.Flags,
            type=exc_type,
            position=TracePosition(pos.sequence, pos.steps),
            program_counter=event.ProgramCounter,
            thread_id=thread_id,
        )


@dataclass
class ModuleEvent:
    """Module load/unload event from TTDReplay native API."""
    name: str
    path: str
    address: int
    size: int
    checksum: int
    timestamp: int
    event_type: str  # "ModuleLoaded" or "ModuleUnloaded"
    position: TracePosition

    @classmethod
    def from_native_loaded(cls, event) -> "ModuleEvent":
        """Create from CTTDModuleLoadedEvent."""
        pos = event.Position.to_python()
        mod = event.pModule.contents
        name = mod.pName[:mod.NameLength] if mod.pName else ""
        return cls(
            name=name,
            path=name,  # TTDReplay only gives us the name
            address=mod.Address,
            size=mod.Size,
            checksum=mod.Checksum,
            timestamp=mod.Timestamp,
            event_type="ModuleLoaded",
            position=TracePosition(pos.sequence, pos.steps),
        )

    @classmethod
    def from_native_unloaded(cls, event) -> "ModuleEvent":
        """Create from CTTDModuleUnloadedEvent."""
        pos = event.Position.to_python()
        mod = event.pModule.contents
        name = mod.pName[:mod.NameLength] if mod.pName else ""
        return cls(
            name=name,
            path=name,
            address=mod.Address,
            size=mod.Size,
            checksum=mod.Checksum,
            timestamp=mod.Timestamp,
            event_type="ModuleUnloaded",
            position=TracePosition(pos.sequence, pos.steps),
        )


@dataclass
class ThreadEvent:
    """Thread create/terminate event from TTDReplay native API."""
    thread_id: int
    unique_thread_id: int
    event_type: str  # "ThreadCreated" or "ThreadTerminated"
    position: TracePosition
    lifetime_start: Optional[TracePosition] = None
    lifetime_end: Optional[TracePosition] = None

    @classmethod
    def from_native_created(cls, event) -> "ThreadEvent":
        """Create from CTTDThreadCreatedEvent."""
        pos = event.Position.to_python()
        ti = event.pThreadInfo.contents
        lifetime = ti.Lifetime.to_python()
        return cls(
            thread_id=ti.Id,
            unique_thread_id=ti.UniqueId,
            event_type="ThreadCreated",
            position=TracePosition(pos.sequence, pos.steps),
            lifetime_start=TracePosition(lifetime.min.sequence, lifetime.min.steps),
            lifetime_end=TracePosition(lifetime.max.sequence, lifetime.max.steps),
        )

    @classmethod
    def from_native_terminated(cls, event) -> "ThreadEvent":
        """Create from CTTDThreadTerminatedEvent."""
        pos = event.Position.to_python()
        ti = event.pThreadInfo.contents
        lifetime = ti.Lifetime.to_python()
        return cls(
            thread_id=ti.Id,
            unique_thread_id=ti.UniqueId,
            event_type="ThreadTerminated",
            position=TracePosition(pos.sequence, pos.steps),
            lifetime_start=TracePosition(lifetime.min.sequence, lifetime.min.steps),
            lifetime_end=TracePosition(lifetime.max.sequence, lifetime.max.steps),
        )


@dataclass
class ThreadInfo:
    """Thread info from TTDReplay native API."""
    thread_id: int
    unique_thread_id: int
    lifetime_start: TracePosition
    lifetime_end: TracePosition

    @classmethod
    def from_native(cls, ti) -> "ThreadInfo":
        """Create from CTTDThreadInfo."""
        lifetime = ti.Lifetime.to_python()
        return cls(
            thread_id=ti.Id,
            unique_thread_id=ti.UniqueId,
            lifetime_start=TracePosition(lifetime.min.sequence, lifetime.min.steps),
            lifetime_end=TracePosition(lifetime.max.sequence, lifetime.max.steps),
        )


@dataclass
class ModuleInfo:
    """Module info from TTDReplay native API."""
    name: str
    address: int
    size: int
    checksum: int
    timestamp: int

    @classmethod
    def from_native(cls, mod) -> "ModuleInfo":
        """Create from CTTDModule."""
        name = mod.pName[:mod.NameLength] if mod.pName else ""
        return cls(
            name=name,
            address=mod.Address,
            size=mod.Size,
            checksum=mod.Checksum,
            timestamp=mod.Timestamp,
        )


@dataclass
class Event:
    """Generic event for unified event listing."""
    type: str
    position: TracePosition
    thread_id: int
    description: str


@dataclass
class Lifetime:
    """Trace lifetime."""
    min_position: TracePosition
    max_position: TracePosition


class TTDReplayBackend:
    """Adapter for TTDReplay.dll (this project) backend."""

    def __init__(self):
        self._engine = None
        self._cursor = None
        self._available = False
        self._error = None
        self._trace_path = None

        # Try to import TTDReplay engine
        try:
            from ttdobjectspy.engine import ReplayEngine
            self._engine_class = ReplayEngine
            self._available = True
        except ImportError as e:
            self._error = f"TTDReplay not available: {e}"

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def error(self) -> Optional[str]:
        return self._error

    @property
    def is_open(self) -> bool:
        return self._engine is not None and self._engine.is_initialized

    def open(self, trace_path: str) -> None:
        """Open a trace file."""
        if not self._available:
            raise RuntimeError(self._error)

        self._engine = self._engine_class()
        self._engine.initialize(trace_path)
        self._cursor = self._engine.new_cursor()
        self._cursor.set_position(self._engine.first_position)
        self._trace_path = trace_path

    def close(self) -> None:
        """Close the trace session."""
        if self._cursor:
            self._cursor.close()
            self._cursor = None
        if self._engine:
            self._engine.close()
            self._engine = None
        self._trace_path = None

    @property
    def position(self) -> Optional[TracePosition]:
        """Get current cursor position."""
        if not self._cursor:
            return None
        pos = self._cursor.position
        return TracePosition(pos.sequence, pos.steps)

    def set_position(self, pos: TracePosition) -> None:
        """Set cursor position."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        from ttdobjectspy.engine import Position
        self._cursor.set_position(Position(pos.sequence, pos.steps))

    @property
    def first_position(self) -> Optional[TracePosition]:
        """Get first position in trace."""
        if not self._engine:
            return None
        pos = self._engine.first_position
        return TracePosition(pos.sequence, pos.steps)

    @property
    def last_position(self) -> Optional[TracePosition]:
        """Get last position in trace."""
        if not self._engine:
            return None
        pos = self._engine.last_position
        return TracePosition(pos.sequence, pos.steps)

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory at current position."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        return self._cursor.query_memory(address, size)

    def read_uint64(self, address: int) -> int:
        """Read a 64-bit integer from memory."""
        data = self.read_memory(address, 8)
        return int.from_bytes(data, 'little')

    def read_uint32(self, address: int) -> int:
        """Read a 32-bit integer from memory."""
        data = self.read_memory(address, 4)
        return int.from_bytes(data, 'little')

    def get_register(self, name: str) -> int:
        """Get a register value at current position."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")

        name = name.lower()
        if name == "rip":
            return self._cursor.program_counter
        elif name == "rsp":
            return self._cursor.stack_pointer
        elif name == "rbp":
            return self._cursor.frame_pointer
        elif name == "rax":
            return self._cursor.return_value
        else:
            # Get from full context
            return self._cursor.get_register(name)

    def get_registers(self) -> Dict[str, int]:
        """Get all general-purpose registers as a dictionary."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        regs = self._cursor.get_registers()
        # Convert RegisterState dataclass to dict
        from dataclasses import asdict
        return asdict(regs)

    def replay_forward(self, max_steps: int = 0) -> dict:
        """Replay forward until watchpoint or limit."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        return self._cursor.replay_forward(max_steps=max_steps)

    def replay_backward(self, max_steps: int = 0) -> dict:
        """Replay backward until watchpoint or limit."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        return self._cursor.replay_backward(max_steps=max_steps)

    def add_memory_watchpoint(self, address: int, size: int,
                              access_type: str = "write") -> bool:
        """Add a memory watchpoint."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        return self._cursor.add_memory_watchpoint(address, size, access_type)

    def remove_memory_watchpoint(self, address: int, size: int,
                                  access_type: str = "write") -> bool:
        """Remove a memory watchpoint."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        return self._cursor.remove_memory_watchpoint(address, size, access_type)

    def clear_watchpoints(self) -> None:
        """Clear all watchpoints."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        self._cursor.clear_watchpoints()

    def step_forward(self, steps: int = 1) -> dict:
        """Step forward by a specific number of steps."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        result = self._cursor.step_forward(steps)
        return result.to_dict()

    def step_backward(self, steps: int = 1) -> dict:
        """Step backward by a specific number of steps."""
        if not self._cursor:
            raise RuntimeError("TTDReplay cursor not open")
        result = self._cursor.step_backward(steps)
        return result.to_dict()

    # =========================================================================
    # Native Event/Thread/Module Queries
    # =========================================================================

    def get_thread_list(self) -> List[ThreadInfo]:
        """Get all threads from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native_threads = self._engine._native.get_thread_list()
        return [ThreadInfo.from_native(t) for t in native_threads]

    def get_module_list(self) -> List[ModuleInfo]:
        """Get unique modules from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native_modules = self._engine._native.get_module_list()
        return [ModuleInfo.from_native(m) for m in native_modules]

    def get_module_instance_list(self) -> List[ModuleEvent]:
        """Get module load/unload instances from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native = self._engine._native

        events = []
        # Module loaded events
        for ev in native.get_module_loaded_event_list():
            events.append(ModuleEvent.from_native_loaded(ev))
        # Module unloaded events
        for ev in native.get_module_unloaded_event_list():
            events.append(ModuleEvent.from_native_unloaded(ev))

        # Sort by position
        events.sort(key=lambda e: (e.position.sequence, e.position.steps))
        return events

    def get_exception_event_list(self) -> List[ExceptionEvent]:
        """Get all exception events from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native_events = self._engine._native.get_exception_event_list()
        return [ExceptionEvent.from_native(e) for e in native_events]

    def get_thread_created_event_list(self) -> List[ThreadEvent]:
        """Get thread creation events from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native_events = self._engine._native.get_thread_created_event_list()
        return [ThreadEvent.from_native_created(e) for e in native_events]

    def get_thread_terminated_event_list(self) -> List[ThreadEvent]:
        """Get thread termination events from the native API."""
        if not self._engine or not self._engine._native:
            raise RuntimeError("TTDReplay engine not open")
        native_events = self._engine._native.get_thread_terminated_event_list()
        return [ThreadEvent.from_native_terminated(e) for e in native_events]


class UnifiedTraceSession:
    """
    TTD trace session using TTDReplay.dll natively.

    Provides a single interface for all trace operations including:
    - Navigation and position management
    - Memory and register access
    - Watchpoints and replay
    - Event, thread, and module queries (via native TTDReplay API)
    """

    def __init__(self, trace_path: Optional[str] = None):
        self._ttdreplay = TTDReplayBackend()
        self._trace_path = None

        if trace_path:
            self.open(trace_path)

    def open(self, trace_path: str, dbgeng_output: bool = False) -> "UnifiedTraceSession":
        """
        Open a TTD trace file.

        Args:
            trace_path: Path to the .run trace file
            dbgeng_output: Ignored (kept for API compatibility)

        Returns:
            self (for method chaining)
        """
        self._trace_path = trace_path

        if self._ttdreplay.is_available:
            self._ttdreplay.open(trace_path)

        return self

    def close(self) -> None:
        """Close the session."""
        if self._ttdreplay.is_open:
            self._ttdreplay.close()
        self._trace_path = None

    @property
    def is_open(self) -> bool:
        """True if session is open."""
        return self._ttdreplay.is_open

    @property
    def trace_path(self) -> Optional[str]:
        return self._trace_path

    @property
    def has_ttdreplay(self) -> bool:
        """True if TTDReplay backend is available and open."""
        return self._ttdreplay.is_open

    # =========================================================================
    # Position Management
    # =========================================================================

    @property
    def position(self) -> Optional[TracePosition]:
        """Get current position."""
        if self._ttdreplay.is_open:
            return self._ttdreplay.position
        return None

    def set_position(self, pos: Union[TracePosition, str]) -> None:
        """Set position."""
        if isinstance(pos, str):
            pos = TracePosition.from_string(pos)

        if self._ttdreplay.is_open:
            self._ttdreplay.set_position(pos)

    @property
    def first_position(self) -> Optional[TracePosition]:
        """Get first position in trace."""
        if self._ttdreplay.is_open:
            return self._ttdreplay.first_position
        return None

    @property
    def last_position(self) -> Optional[TracePosition]:
        """Get last position in trace."""
        if self._ttdreplay.is_open:
            return self._ttdreplay.last_position
        return None

    # =========================================================================
    # Native Event/Thread/Module Queries
    # =========================================================================

    def get_module_for_address(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get module information for an address using native module list.

        Args:
            address: Address to look up

        Returns:
            Dict with module info (name, start, end, size, checksum, timestamp) or None
        """
        if not self._ttdreplay.is_open:
            return None

        try:
            modules = self._ttdreplay.get_module_list()
            for mod in modules:
                if mod.address <= address < mod.address + mod.size:
                    return {
                        "name": Path(mod.name).stem if mod.name else "",
                        "start": mod.address,
                        "end": mod.address + mod.size,
                        "size": mod.size,
                        "checksum": mod.checksum,
                        "timestamp": mod.timestamp,
                    }
            return None
        except Exception:
            return None

    def get_lifetime(self) -> Lifetime:
        """Get trace lifetime."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        first = self._ttdreplay.first_position
        last = self._ttdreplay.last_position
        return Lifetime(min_position=first, max_position=last)

    def get_threads(self, max_rows: int = 100) -> List[ThreadInfo]:
        """Get thread info from the native API."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        threads = self._ttdreplay.get_thread_list()
        return threads[:max_rows]

    def get_exception_events(self, max_rows: int = 100) -> List[ExceptionEvent]:
        """Get exception events from the native API."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        events = self._ttdreplay.get_exception_event_list()
        return events[:max_rows]

    def get_thread_events(self, max_rows: int = 100) -> List[ThreadEvent]:
        """Get thread create/terminate events from the native API."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        created = self._ttdreplay.get_thread_created_event_list()
        terminated = self._ttdreplay.get_thread_terminated_event_list()
        all_events = created + terminated
        all_events.sort(key=lambda e: (e.position.sequence, e.position.steps))
        return all_events[:max_rows]

    def get_module_events(self, max_rows: int = 100) -> List[ModuleEvent]:
        """Get module load/unload events from the native API."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        events = self._ttdreplay.get_module_instance_list()
        return events[:max_rows]

    def get_events(self, max_rows: int = 1000) -> List[Event]:
        """Get all events combined (exceptions + threads + modules)."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")

        events = []

        # Exception events
        for e in self._ttdreplay.get_exception_event_list():
            events.append(Event(
                type="Exception",
                position=e.position,
                thread_id=e.thread_id,
                description=f"Exception 0x{e.exception_code:08x} at 0x{e.program_counter:x}",
            ))

        # Thread events
        for e in self._ttdreplay.get_thread_created_event_list():
            events.append(Event(
                type="ThreadCreated",
                position=e.position,
                thread_id=e.thread_id,
                description=f"Thread {e.thread_id} created (unique_id={e.unique_thread_id})",
            ))
        for e in self._ttdreplay.get_thread_terminated_event_list():
            events.append(Event(
                type="ThreadTerminated",
                position=e.position,
                thread_id=e.thread_id,
                description=f"Thread {e.thread_id} terminated (unique_id={e.unique_thread_id})",
            ))

        # Module events
        for e in self._ttdreplay.get_module_instance_list():
            events.append(Event(
                type=e.event_type,
                position=e.position,
                thread_id=0,
                description=f"{e.event_type}: {e.name} at 0x{e.address:x} (size=0x{e.size:x})",
            ))

        # Sort by position
        events.sort(key=lambda e: (e.position.sequence, e.position.steps))
        return events[:max_rows]

    def get_events_by_type(self, event_type: str, max_rows: int = 100) -> List[Event]:
        """Get events filtered by type."""
        all_events = self.get_events(max_rows=10000)
        filtered = [e for e in all_events if e.type == event_type]
        return filtered[:max_rows]

    def get_first_events(self, count: int = 10) -> List[Event]:
        """Get the first N events."""
        return self.get_events(max_rows=count)

    def get_last_events(self, count: int = 10) -> List[Event]:
        """Get the last N events."""
        all_events = self.get_events(max_rows=10000)
        return all_events[-count:] if len(all_events) > count else all_events

    def get_event_summary(self) -> str:
        """Get a summary of event counts by type."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")

        native = self._ttdreplay._engine._native

        summary_parts = []
        exc_count = native.get_exception_event_count()
        thread_created = native.get_thread_created_event_count()
        thread_terminated = native.get_thread_terminated_event_count()
        mod_loaded = native.get_module_loaded_event_count()
        mod_unloaded = native.get_module_unloaded_event_count()

        summary_parts.append(f"Exception: {exc_count}")
        summary_parts.append(f"ThreadCreated: {thread_created}")
        summary_parts.append(f"ThreadTerminated: {thread_terminated}")
        summary_parts.append(f"ModuleLoaded: {mod_loaded}")
        summary_parts.append(f"ModuleUnloaded: {mod_unloaded}")

        total = exc_count + thread_created + thread_terminated + mod_loaded + mod_unloaded
        summary_parts.append(f"Total: {total}")

        return "\n".join(summary_parts)

    def query_modules(self, max_rows: int = 1000) -> List[ModuleEvent]:
        """Query module load/unload events (alias for get_module_events)."""
        return self.get_module_events(max_rows)

    def query_exceptions(self, max_rows: int = 1000) -> List[ExceptionEvent]:
        """Query exception events (alias for get_exception_events)."""
        return self.get_exception_events(max_rows)

    def query_thread_lifetimes(self, max_rows: int = 1000) -> List[ThreadInfo]:
        """Query thread lifetime info."""
        return self.get_threads(max_rows)

    # =========================================================================
    # Address-based Call Tracing (watchpoint-based, no symbols needed)
    # =========================================================================

    def query_calls_by_address(
        self,
        entry_address: int,
        exit_addresses: List[Any],  # List[int] or List[Dict] with address/type
        max_calls: int = 100,
        expected_module: Optional[str] = None,
        ghidra_info: Optional[Dict[str, Any]] = None,
    ) -> List[AddressCallEvent]:
        """
        Symbol-free TTD.Calls() equivalent using execute watchpoints.

        Two-pass approach:
        Pass 1: Execute watchpoint on entry_address to capture all call entries.
        Pass 2: Execute watchpoints on all exit_addresses to capture returns.
        Then correlate entries with exits by thread_id and stack depth.
        """
        if not self._ttdreplay or not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")

        import warnings

        # Validate that entry_address falls within a loaded module
        module_info = self.get_module_for_address(entry_address)
        if module_info is None:
            warnings.warn(
                f"WARNING: Entry address 0x{entry_address:x} does not fall within any "
                f"loaded module in the TTD trace. The address may be incorrect or the "
                f"binary may not have been rebased to match the TTD runtime addresses. "
                f"Use ghidra_rebase() with the module base from TTD before getting function boundaries."
            )
        else:
            # Validate module name if expected
            if expected_module:
                actual_module = module_info["name"].lower()
                expected_lower = expected_module.lower()
                if expected_lower not in actual_module and actual_module not in expected_lower:
                    warnings.warn(
                        f"WARNING: Entry address 0x{entry_address:x} is in module '{module_info['name']}' "
                        f"but expected module '{expected_module}'. Make sure Ghidra is loaded with the "
                        f"correct binary and rebased to the TTD runtime address."
                    )

            # Validate binary matches between TTD and Ghidra if ghidra_info provided
            if ghidra_info:
                mismatches = []

                ttd_size = module_info.get("size", 0)
                ghidra_size = ghidra_info.get("size", 0)
                if ghidra_size and ttd_size and ttd_size != ghidra_size:
                    mismatches.append(f"size (TTD: 0x{ttd_size:x}, Ghidra: 0x{ghidra_size:x})")

                ttd_checksum = module_info.get("checksum")
                ghidra_checksum = ghidra_info.get("checksum")
                if ttd_checksum and ghidra_checksum and ttd_checksum != ghidra_checksum:
                    mismatches.append(f"checksum (TTD: 0x{ttd_checksum:x}, Ghidra: 0x{ghidra_checksum:x})")

                ttd_timestamp = module_info.get("timestamp")
                ghidra_timestamp = ghidra_info.get("timestamp")
                if ttd_timestamp and ghidra_timestamp and ttd_timestamp != ghidra_timestamp:
                    mismatches.append(f"timestamp (TTD: 0x{ttd_timestamp:x}, Ghidra: 0x{ghidra_timestamp:x})")

                if mismatches:
                    warnings.warn(
                        f"WARNING: Binary mismatch detected! The DLL in the TTD trace differs from "
                        f"the one loaded in Ghidra. Mismatched fields: {', '.join(mismatches)}. "
                        f"Make sure you are analyzing the same binary version."
                    )

        cursor = self._ttdreplay._cursor

        # Save position
        saved_pos = cursor.position

        # --- Pass 1: Collect function entries ---
        first_pos = self._ttdreplay._engine.first_position
        cursor.set_position(first_pos)

        entries = []
        entry_count = [0]

        def entry_callback(hit_info, thread_view):
            if entry_count[0] >= max_calls:
                return True  # stop
            entry_count[0] += 1
            entry = {
                "position": hit_info.get("position"),
                "stack_pointer": hit_info.get("stack_pointer", 0),
                "program_counter": hit_info.get("program_counter", 0),
                "thread_id": hit_info.get("thread_id", 0),
            }
            # Read parameters directly from thread_view context
            # At function entry, RCX/RDX/R8/R9 hold the arguments
            if thread_view:
                try:
                    from ttdobjectspy.bindings import NativeThreadView
                    tv = thread_view if isinstance(thread_view, NativeThreadView) else NativeThreadView(thread_view)
                    ctx = tv.get_cross_platform_context()
                    data = ctx.Data
                    if len(data) >= 32:
                        entry["rcx"] = data[16]
                        entry["rdx"] = data[17]
                        entry["r8"] = data[23]
                        entry["r9"] = data[24]
                except Exception:
                    pass
            entries.append(entry)
            return False

        cursor.replay_with_memory_watchpoint_callback(
            entry_callback, entry_address, 1, "execute", forward=True
        )

        if not entries:
            cursor.set_position(saved_pos)
            return []

        # --- Pass 2: Collect function exits (single replay for all exit addresses) ---
        raw_exits = []

        if exit_addresses:
            # Normalize exit_addresses to list of dicts with address/type
            normalized_exits = []
            for exit_item in exit_addresses:
                if isinstance(exit_item, dict):
                    addr = exit_item.get("address")
                    if isinstance(addr, str):
                        addr = int(addr, 16)
                    normalized_exits.append({
                        "address": addr,
                        "type": exit_item.get("type", "ret"),
                    })
                else:
                    normalized_exits.append({
                        "address": int(exit_item) if isinstance(exit_item, str) else exit_item,
                        "type": "ret",
                    })

            # Build lookup from exit address to exit type
            exit_type_map = {e["address"]: e["type"] for e in normalized_exits}

            # Single replay pass: set watchpoints on ALL exit addresses at once
            cursor.set_position(first_pos)

            # Clear existing watchpoints and set up callback
            cursor._native.set_memory_watchpoint_callback(None, 0)
            cursor.clear_watchpoints()

            for exit_info in normalized_exits:
                cursor.add_memory_watchpoint(exit_info["address"], 1, "execute")

            def exit_callback(_context, wp_result_ptr, thread_view_ptr):
                from ttdobjectspy.bindings import NativeThreadView
                wp_result = wp_result_ptr.contents if wp_result_ptr else None
                thread_view = NativeThreadView(thread_view_ptr) if thread_view_ptr else None

                hit_info = {}
                if thread_view:
                    hit_info["position"] = thread_view.get_position().to_python()
                    hit_info["program_counter"] = thread_view.get_program_counter()
                    hit_info["stack_pointer"] = thread_view.get_stack_pointer()
                    hit_info["thread_id"] = thread_view.get_thread_info().ThreadId if hasattr(thread_view.get_thread_info(), 'ThreadId') else 0
                    # Read RAX directly from thread_view — at the RET instruction,
                    # RAX already contains the return value (set before RET executes)
                    hit_info["rax"] = thread_view.get_basic_return_value()

                raw_exits.append(hit_info)
                return False  # continue replay

            cursor._native.set_memory_watchpoint_callback(exit_callback, 0)

            try:
                from ttdobjectspy.bindings import EventMask
                old_mask = cursor.event_mask
                cursor.event_mask = old_mask | EventMask.MEMORY_WATCHPOINT
                cursor.replay_forward()
            finally:
                cursor._native.set_memory_watchpoint_callback(None, 0)
                for exit_info in normalized_exits:
                    cursor.remove_memory_watchpoint(exit_info["address"], 1, "execute")
                cursor.event_mask = old_mask

        # --- Correlate entries with exits, then read RAX only for matched exits ---

        def pos_tuple(p):
            if hasattr(p, "sequence"):
                return (p.sequence, p.steps)
            if isinstance(p, dict):
                return (p.get("sequence", 0), p.get("steps", 0))
            return (0, 0)

        # Sort raw exits by position for efficient matching
        raw_exits.sort(key=lambda e: pos_tuple(e.get("position")))

        results = []
        for i, entry in enumerate(entries):
            entry_pos = entry["position"]
            entry_tid = entry["thread_id"]
            entry_rsp = entry["stack_pointer"]
            entry_pos_t = pos_tuple(entry_pos)

            # Find matching exit: same thread, same RSP, position after entry
            matched_raw_exit = None
            for ex in raw_exits:
                ex_tid = ex.get("thread_id", 0)
                if ex_tid != entry_tid:
                    continue
                ex_pos_t = pos_tuple(ex.get("position"))
                if ex_pos_t <= entry_pos_t:
                    continue
                if ex["stack_pointer"] == entry_rsp:
                    matched_raw_exit = ex
                    break

            # Use pre-read RAX from thread_view — no position navigation needed
            matched_exit = None
            if matched_raw_exit:
                # Step past the RET to get the position after return
                exit_pos = matched_raw_exit["position"]
                exit_pos_str = f"{pos_tuple(exit_pos)[0]:x}:{pos_tuple(exit_pos)[1]:x}"
                cursor.set_position(exit_pos_str)
                cursor.step_forward(1)
                after_pos = cursor.position

                exit_pc = matched_raw_exit.get("program_counter", 0)
                matched_exit = {
                    "position": after_pos,
                    "rax": matched_raw_exit.get("rax", 0),
                    "exit_address": exit_pc,
                    "exit_type": exit_type_map.get(exit_pc, "ret"),
                }

            results.append(AddressCallEvent(
                entry_address=entry_address,
                position_start=TracePosition(*entry_pos_t),
                position_end=TracePosition(*pos_tuple(matched_exit["position"])) if matched_exit else None,
                rcx=entry.get("rcx", 0),
                rdx=entry.get("rdx", 0),
                r8=entry.get("r8", 0),
                r9=entry.get("r9", 0),
                rsp=entry_rsp,
                rax=matched_exit["rax"] if matched_exit else None,
                thread_id=entry_tid,
                exit_address=matched_exit["exit_address"] if matched_exit else None,
                exit_type=matched_exit["exit_type"] if matched_exit else None,
            ))

        cursor.set_position(saved_pos)
        return results

    # =========================================================================
    # TTDReplay Operations (Direct API)
    # =========================================================================

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory at current position."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.read_memory(address, size)

    def read_uint64(self, address: int) -> int:
        """Read a 64-bit integer from memory."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.read_uint64(address)

    def read_uint32(self, address: int) -> int:
        """Read a 32-bit integer from memory."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.read_uint32(address)

    def get_register(self, name: str) -> int:
        """Get a register value at current position."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.get_register(name)

    def get_registers(self) -> Dict[str, int]:
        """Get all general-purpose registers."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.get_registers()

    def replay_forward(self, max_steps: int = 0) -> dict:
        """Replay forward until watchpoint hit or step limit."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.replay_forward(max_steps)

    def replay_backward(self, max_steps: int = 0) -> dict:
        """Replay backward until watchpoint hit or step limit."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.replay_backward(max_steps)

    def add_memory_watchpoint(self, address: int, size: int,
                              access_type: str = "write") -> bool:
        """Add a memory watchpoint."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.add_memory_watchpoint(address, size, access_type)

    def remove_memory_watchpoint(self, address: int, size: int,
                                  access_type: str = "write") -> bool:
        """Remove a memory watchpoint."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.remove_memory_watchpoint(address, size, access_type)

    def clear_watchpoints(self) -> None:
        """Clear all watchpoints."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        self._ttdreplay.clear_watchpoints()

    def step_forward(self, steps: int = 1) -> dict:
        """Step forward by a specific number of steps."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.step_forward(steps)

    def step_backward(self, steps: int = 1) -> dict:
        """Step backward by a specific number of steps."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        return self._ttdreplay.step_backward(steps)

    def run_to_address(self, address: int, backward: bool = False) -> dict:
        """Run until a specific code address is executed."""
        if not self._ttdreplay.is_open:
            raise RuntimeError("TTDReplay not available")
        cursor = self._ttdreplay._cursor
        return cursor.run_to_address(address, backward)

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self) -> "UnifiedTraceSession":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __repr__(self) -> str:
        if self.is_open:
            return f"<UnifiedTraceSession trace='{self._trace_path}' backend=TTDReplay>"
        return "<UnifiedTraceSession closed>"
