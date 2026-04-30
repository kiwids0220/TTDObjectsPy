"""
TTD Cursor

High-level Python wrapper for the TTD cursor interface.
Provides navigation, memory queries, register access, and watchpoint support.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, List, Callable, Dict, Any

from ttdobjectspy.ttd_types import (
    Position, PositionRange, GuestAddress, ThreadId, UniqueThreadId,
    QueryMemoryPolicy, EventMask, ReplayFlags, EventType,
    DataAccessType, DataAccessMask, GapKind, GapEventType,
    MemoryWatchpointData, PositionWatchpointData,
    MemoryWatchpointResult, ReplayResult, GapData,
    CTTDPosition, CTTDMemoryWatchpointData, CTTDPositionWatchpointData,
    StepCount,
)
from ttdobjectspy.bindings import NativeCursor

if TYPE_CHECKING:
    from ttdobjectspy.engine import ReplayEngine


@dataclass
class RegisterState:
    """
    CPU register state at a point in execution.
    
    Supports x64 (AMD64) register set. For x86 traces, only the lower
    32 bits of each register are valid.
    """
    # General purpose registers (x64)
    rax: int = 0
    rbx: int = 0
    rcx: int = 0
    rdx: int = 0
    rsi: int = 0
    rdi: int = 0
    rbp: int = 0
    rsp: int = 0
    r8: int = 0
    r9: int = 0
    r10: int = 0
    r11: int = 0
    r12: int = 0
    r13: int = 0
    r14: int = 0
    r15: int = 0
    rip: int = 0
    rflags: int = 0
    
    # Segment registers
    cs: int = 0
    ds: int = 0
    es: int = 0
    fs: int = 0
    gs: int = 0
    ss: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "rax": f"0x{self.rax:016x}",
            "rbx": f"0x{self.rbx:016x}",
            "rcx": f"0x{self.rcx:016x}",
            "rdx": f"0x{self.rdx:016x}",
            "rsi": f"0x{self.rsi:016x}",
            "rdi": f"0x{self.rdi:016x}",
            "rbp": f"0x{self.rbp:016x}",
            "rsp": f"0x{self.rsp:016x}",
            "r8": f"0x{self.r8:016x}",
            "r9": f"0x{self.r9:016x}",
            "r10": f"0x{self.r10:016x}",
            "r11": f"0x{self.r11:016x}",
            "r12": f"0x{self.r12:016x}",
            "r13": f"0x{self.r13:016x}",
            "r14": f"0x{self.r14:016x}",
            "r15": f"0x{self.r15:016x}",
            "rip": f"0x{self.rip:016x}",
            "rflags": f"0x{self.rflags:016x}",
        }
    
    def get(self, name: str) -> int:
        """Get register value by name (case-insensitive)."""
        name = name.lower()
        if hasattr(self, name):
            return getattr(self, name)
        # Handle 32-bit register names
        reg_map = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
            'eip': 'rip', 'eflags': 'rflags',
        }
        if name in reg_map:
            return getattr(self, reg_map[name]) & 0xFFFFFFFF
        raise KeyError(f"Unknown register: {name}")


class Cursor:
    """
    High-level cursor for navigating a TTD trace.
    
    A cursor represents a focus position in the timeline and provides:
    - Position navigation (set/get position)
    - Memory queries at current position
    - Register state access
    - Watchpoint management
    - Forward/backward replay
    
    Example usage:
        cursor = engine.new_cursor()
        cursor.set_position(engine.first_position)
        
        # Query memory
        data = cursor.query_memory(0x7ff6abcd1234, 64)
        
        # Get registers
        regs = cursor.get_registers()
        print(f"RIP: {regs.rip:#x}")
        
        # Add watchpoint and replay
        cursor.add_memory_watchpoint(0x7ff6abcd1234, 8, access_type="write")
        result = cursor.replay_backward()
        print(f"Stopped at {result.position} due to {result.stop_reason}")
    """
    
    def __init__(self, native: NativeCursor, engine: "ReplayEngine"):
        """
        Initialize cursor wrapper.
        
        Args:
            native: Native cursor interface
            engine: Parent engine
        """
        self._native = native
        self._engine = engine
        self._closed = False
        self._watchpoints: List[MemoryWatchpointData] = []
    
    def close(self):
        """Close the cursor and release resources."""
        if not self._closed and self._native:
            self._native.destroy()
            self._native = None
            self._engine._remove_cursor(self)
            self._closed = True
    
    def __enter__(self) -> "Cursor":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def _ensure_open(self):
        """Raise if cursor is closed."""
        if self._closed:
            raise RuntimeError("Cursor is closed")
    
    # =========================================================================
    # Position Navigation
    # =========================================================================
    
    @property
    def position(self) -> Position:
        """Get current cursor position."""
        self._ensure_open()
        return self._native.get_position().to_python()
    
    def set_position(self, position: Position):
        """
        Set cursor to a specific position.
        
        The cursor moves to the closest valid position at or after the given position.
        
        Args:
            position: Target position (Position object or "seq:steps" string)
        """
        self._ensure_open()
        if isinstance(position, str):
            position = Position.from_string(position)
        c_pos = CTTDPosition.from_python(position)
        self._native.set_position(c_pos)
    
    def clear(self):
        """Reset cursor to invalid/uninitialized state."""
        self._ensure_open()
        self._native.clear()
    
    @property
    def program_counter(self) -> GuestAddress:
        """Get the program counter (RIP/EIP) at current position."""
        self._ensure_open()
        return GuestAddress(self._native.get_program_counter())
    
    @property  
    def stack_pointer(self) -> GuestAddress:
        """Get the stack pointer (RSP/ESP) at current position."""
        self._ensure_open()
        return GuestAddress(self._native.get_stack_pointer())
    
    @property
    def frame_pointer(self) -> GuestAddress:
        """Get the frame pointer (RBP/EBP) at current position."""
        self._ensure_open()
        return GuestAddress(self._native.get_frame_pointer())
    
    @property
    def return_value(self) -> int:
        """Get the return value register (RAX/EAX) at current position."""
        self._ensure_open()
        return self._native.get_basic_return_value()
    
    # =========================================================================
    # Register Access
    # =========================================================================
    
    def get_registers(self, thread_id: int = 0) -> RegisterState:
        """
        Get all CPU registers at current position.
        
        Args:
            thread_id: Optional thread ID (0 for current thread)
        
        Returns:
            RegisterState with all register values
        """
        self._ensure_open()
        
        # Use the reliable accessor methods
        regs = RegisterState(
            rip=self._native.get_program_counter(thread_id),
            rsp=self._native.get_stack_pointer(thread_id),
            rbp=self._native.get_frame_pointer(thread_id),
            rax=self._native.get_basic_return_value(thread_id),
        )
        
        # Try to get full context for other registers
        try:
            context = self._native.get_cross_platform_context(thread_id)
            data = context.Data
            
            # AMD64_CONTEXT layout based on IReplayEngineRegisters.h
            # Offsets are in uint64 array indices
            # The structure starts with home registers and control flags,
            # then segment registers, debug registers, then integer registers
            
            # Integer registers start at offset 0x78 (120 bytes = 15 uint64s)
            if len(data) >= 32:
                regs.rax = data[15]
                regs.rcx = data[16]
                regs.rdx = data[17]
                regs.rbx = data[18]
                regs.rsp = data[19]
                regs.rbp = data[20]
                regs.rsi = data[21]
                regs.rdi = data[22]
                regs.r8 = data[23]
                regs.r9 = data[24]
                regs.r10 = data[25]
                regs.r11 = data[26]
                regs.r12 = data[27]
                regs.r13 = data[28]
                regs.r14 = data[29]
                regs.r15 = data[30]
                regs.rip = data[31]
        except Exception:
            # Fall back to basic accessors if full context fails
            pass
        
        return regs
    
    def get_register(self, name: str, thread_id: int = 0) -> int:
        """
        Get a specific register value.
        
        Args:
            name: Register name (e.g., "rax", "rcx", "rip")
            thread_id: Optional thread ID
        
        Returns:
            Register value
        """
        return self.get_registers(thread_id).get(name)
    
    # =========================================================================
    # Memory Queries
    # =========================================================================
    
    def query_memory(self, address: int, size: int,
                     policy: QueryMemoryPolicy = QueryMemoryPolicy.DEFAULT) -> bytes:
        """
        Query memory at the current cursor position.
        
        Args:
            address: Guest address to read from
            size: Number of bytes to read
            policy: Memory query policy
        
        Returns:
            Bytes read (may be less than requested if memory unavailable)
        """
        self._ensure_open()
        return self._native.query_memory_buffer(address, size, policy)
    
    def read_uint8(self, address: int) -> int:
        """Read a uint8 from memory."""
        data = self.query_memory(address, 1)
        return data[0] if data else 0
    
    def read_uint16(self, address: int) -> int:
        """Read a uint16 from memory (little-endian)."""
        data = self.query_memory(address, 2)
        return int.from_bytes(data, 'little') if len(data) >= 2 else 0
    
    def read_uint32(self, address: int) -> int:
        """Read a uint32 from memory (little-endian)."""
        data = self.query_memory(address, 4)
        return int.from_bytes(data, 'little') if len(data) >= 4 else 0
    
    def read_uint64(self, address: int) -> int:
        """Read a uint64 from memory (little-endian)."""
        data = self.query_memory(address, 8)
        return int.from_bytes(data, 'little') if len(data) >= 8 else 0
    
    def read_pointer(self, address: int) -> int:
        """Read a pointer from memory (assumes 64-bit)."""
        return self.read_uint64(address)
    
    def read_string(self, address: int, max_length: int = 256, 
                    encoding: str = 'utf-8') -> str:
        """
        Read a null-terminated string from memory.
        
        Args:
            address: String address
            max_length: Maximum bytes to read
            encoding: String encoding
        
        Returns:
            Decoded string
        """
        data = self.query_memory(address, max_length)
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode(encoding, errors='replace')
    
    def read_wstring(self, address: int, max_length: int = 256) -> str:
        """
        Read a null-terminated wide string from memory.
        
        Args:
            address: String address
            max_length: Maximum characters to read
        
        Returns:
            Decoded string
        """
        data = self.query_memory(address, max_length * 2)
        # Find null terminator (two zero bytes)
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i+1] == 0:
                data = data[:i]
                break
        return data.decode('utf-16-le', errors='replace')
    
    # =========================================================================
    # Watchpoints
    # =========================================================================
    
    def add_memory_watchpoint(self, address: int, size: int,
                              access_type: str = "read_write",
                              thread_id: int = 0) -> bool:
        """
        Add a memory watchpoint.
        
        Args:
            address: Memory address to watch
            size: Size of memory region
            access_type: "read", "write", "execute", "read_write", or "all"
            thread_id: Restrict to specific thread (0 for any)
        
        Returns:
            True if watchpoint was added successfully
        """
        self._ensure_open()
        
        access_map = {
            "read": DataAccessMask.READ,
            "write": DataAccessMask.WRITE,
            "execute": DataAccessMask.EXECUTE,
            "read_write": DataAccessMask.READ_WRITE,
            "all": DataAccessMask.ALL,
        }
        mask = access_map.get(access_type.lower(), DataAccessMask.READ_WRITE)
        
        data = MemoryWatchpointData(
            address=GuestAddress(address),
            size=size,
            access_mask=mask,
            thread_id=UniqueThreadId(thread_id)
        )
        
        c_data = CTTDMemoryWatchpointData.from_python(data)
        result = self._native.add_memory_watchpoint(c_data)
        
        if result:
            self._watchpoints.append(data)
        
        return result
    
    def remove_memory_watchpoint(self, address: int, size: int,
                                  access_type: str = "read_write",
                                  thread_id: int = 0) -> bool:
        """
        Remove a memory watchpoint.
        
        Args must match those used when adding the watchpoint.
        """
        self._ensure_open()
        
        access_map = {
            "read": DataAccessMask.READ,
            "write": DataAccessMask.WRITE,
            "execute": DataAccessMask.EXECUTE,
            "read_write": DataAccessMask.READ_WRITE,
            "all": DataAccessMask.ALL,
        }
        mask = access_map.get(access_type.lower(), DataAccessMask.READ_WRITE)
        
        data = MemoryWatchpointData(
            address=GuestAddress(address),
            size=size,
            access_mask=mask,
            thread_id=UniqueThreadId(thread_id)
        )
        
        c_data = CTTDMemoryWatchpointData.from_python(data)
        result = self._native.remove_memory_watchpoint(c_data)
        
        if result and data in self._watchpoints:
            self._watchpoints.remove(data)
        
        return result
    
    def clear_watchpoints(self):
        """Remove all watchpoints."""
        for wp in list(self._watchpoints):
            c_data = CTTDMemoryWatchpointData.from_python(wp)
            self._native.remove_memory_watchpoint(c_data)
        self._watchpoints.clear()

    def replay_with_memory_watchpoint_callback(
        self,
        callback: Callable,
        address: int,
        size: int,
        access_type: str = "read_write",
        forward: bool = True,
        limit: Optional[Position] = None,
        max_steps: int = 0xFFFFFFFFFFFFFFFE
    ) -> List[dict]:
        """
        Replay with a memory watchpoint and collect all hits via callback.

        Args:
            callback: Function(watchpoint_result, thread_view) -> bool
                     Called on each watchpoint hit.
                     Return True to STOP replay (hit is still collected).
                     Return False to CONTINUE replay (hit is still collected).
                     All hits are collected regardless of return value.
            address: Memory address to watch
            size: Size of memory region
            access_type: "read", "write", "execute", "read_write", or "all"
            forward: True to replay forward, False for backward
            limit: Position limit for replay
            max_steps: Maximum steps to execute

        Returns:
            List of collected watchpoint hits with context
        """
        self._ensure_open()

        # Save current position to restore later
        saved_position = self.position

        hits = []

        def wrapper_callback(_context, wp_result_ptr, thread_view_ptr):
            from ttdobjectspy.bindings import NativeThreadView

            # Extract watchpoint result
            wp_result = wp_result_ptr.contents if wp_result_ptr else None
            thread_view = NativeThreadView(thread_view_ptr) if thread_view_ptr else None

            # Convert to Python types
            hit_info = {
                "address": wp_result.Address if wp_result else 0,
                "size": wp_result.Size if wp_result else 0,
                "access_type": wp_result.AccessType if wp_result else 0,
            }

            # Get thread context if available
            if thread_view:
                hit_info["thread_id"] = thread_view.get_thread_info().ThreadId if hasattr(thread_view.get_thread_info(), 'ThreadId') else 0
                hit_info["position"] = thread_view.get_position().to_python()
                hit_info["program_counter"] = thread_view.get_program_counter()
                hit_info["stack_pointer"] = thread_view.get_stack_pointer()

            # Always collect the hit
            hits.append(hit_info)

            # Call user callback to determine whether to stop or continue
            # True = stop replay, False = continue replay
            stop_replay = callback(hit_info, thread_view)
            return stop_replay

        # Clear any prior registered callbacks and watchpoints
        self._native.set_memory_watchpoint_callback(None, 0)
        self.clear_watchpoints()

        # Set up watchpoint and callback
        self.add_memory_watchpoint(address, size, access_type)
        self._native.set_memory_watchpoint_callback(wrapper_callback, 0)

        try:
            # Enable memory watchpoint events
            old_mask = self.event_mask
            self.event_mask = old_mask | EventMask.MEMORY_WATCHPOINT

            # Replay
            if forward:
                self.replay_forward(limit, max_steps)
            else:
                self.replay_backward(limit, max_steps)
        finally:
            # Clean up
            self._native.set_memory_watchpoint_callback(None, 0)
            self.remove_memory_watchpoint(address, size, access_type)
            self.event_mask = old_mask

            # Restore original position
            self.set_position(saved_position)

        return hits

    def find_all_memory_accesses(
        self,
        address: int,
        size: int = 8,
        access_type: str = "read_write",
        max_hits: int = 1000,
        forward: bool = True
    ) -> List[dict]:
        """
        Find all accesses to a memory region.

        Args:
            address: Memory address to watch
            size: Size of memory region
            access_type: "read", "write", "execute", "read_write", or "all"
            max_hits: Maximum number of hits to collect
            forward: True to search forward, False for backward

        Returns:
            List of access records with position, PC, and context
        """
        hit_count = [0]

        def collect_callback(_hit_info, _thread_view):
            """Callback to control when to stop collecting hits."""
            hit_count[0] += 1
            if hit_count[0] >= max_hits:
                return True  # Stop replay - we have enough hits
            return False  # Continue replay - collect more hits

        return self.replay_with_memory_watchpoint_callback(
            collect_callback, address, size, access_type, forward
        )

    def collect_memory_accesses_detailed(
        self,
        address: int,
        size: int = 8,
        access_type: str = "read_write",
        max_hits: int = 100,
        forward: bool = True,
        read_memory_at_access: bool = True,
        memory_read_size: int = 64,
        capture_registers: bool = True,
        capture_stack: bool = True,
        stack_depth: int = 8,
        code_address_min: Optional[int] = None,
        code_address_max: Optional[int] = None,
    ) -> List[dict]:
        """
        Collect detailed information about memory accesses for LLM analysis.

        This method uses the native watchpoint callback system with IThreadView
        to capture comprehensive context for each memory access during replay.

        Args:
            address: Memory address to watch
            size: Size of memory region to watch
            access_type: "read", "write", "execute", "read_write", or "all"
            max_hits: Maximum number of hits to collect
            forward: True to search forward, False for backward
            read_memory_at_access: If True, read memory content at the watched address
            memory_read_size: Number of bytes to read at watched address
            capture_registers: If True, capture all registers at each hit
            capture_stack: If True, capture stack values at each hit
            stack_depth: Number of stack entries (qwords) to capture
            code_address_min: If set, only include accesses where PC >= this value
            code_address_max: If set, only include accesses where PC <= this value

        Returns:
            List of detailed access records with:
            - position: Position in trace (seq:steps format)
            - program_counter: Instruction address (hex)
            - access_info: Details about the memory access
            - registers: Full register state (if capture_registers=True)
            - stack: Stack values (if capture_stack=True)
            - memory_at_address: Memory content at watched address (if read_memory_at_access=True)
            - thread_info: Thread identification
        """
        self._ensure_open()

        hits = []

        def detailed_callback(hit_info, thread_view):
            """Callback that captures detailed context using IThreadView."""
            if len(hits) >= max_hits:
                return True  # Stop replay - we have enough hits

            # Filter by code address range if specified
            pc = hit_info.get('program_counter', 0)
            if code_address_min is not None and pc < code_address_min:
                return False  # Skip - PC outside range, continue replay
            if code_address_max is not None and pc > code_address_max:
                return False  # Skip - PC outside range, continue replay

            # Extract position - it's a Position object, not a dict
            pos = hit_info.get("position")
            if pos and hasattr(pos, 'sequence'):
                pos_dict = {"sequence": pos.sequence, "steps": pos.steps}
            else:
                pos_dict = {"sequence": 0, "steps": 0}

            hit_record = {
                "position": pos_dict,
                "program_counter": f"0x{hit_info.get('program_counter', 0):x}",
                "access_info": {
                    "watched_address": f"0x{address:x}",
                    "access_address": f"0x{hit_info.get('address', 0):x}",
                    "access_size": hit_info.get("size", 0),
                    "access_type": self._access_type_to_string(hit_info.get("access_type", 0)),
                },
            }

            # Use IThreadView for thread-safe queries during callback
            if thread_view:
                # Capture registers via IThreadView accessor methods
                if capture_registers:
                    try:
                        hit_record["registers"] = {
                            "rip": f"0x{thread_view.get_program_counter():x}",
                            "rsp": f"0x{thread_view.get_stack_pointer():x}",
                            "rbp": f"0x{thread_view.get_frame_pointer():x}",
                            "rax": f"0x{thread_view.get_basic_return_value():x}",
                        }
                    except Exception as e:
                        hit_record["registers_error"] = str(e)

                # Capture stack via IThreadView
                if capture_stack:
                    try:
                        rsp = thread_view.get_stack_pointer()
                        stack_values = []
                        for i in range(stack_depth):
                            stack_addr = rsp + (i * 8)
                            mem = thread_view.query_memory_buffer(stack_addr, 8)
                            if len(mem) >= 8:
                                value = int.from_bytes(mem[:8], 'little')
                                stack_values.append({
                                    "offset": f"+0x{i*8:x}",
                                    "address": f"0x{stack_addr:x}",
                                    "value": f"0x{value:016x}",
                                })
                        hit_record["stack"] = {
                            "rsp": f"0x{rsp:x}",
                            "entries": stack_values,
                        }
                    except Exception as e:
                        hit_record["stack_error"] = str(e)

                # Read memory at watched address via IThreadView
                if read_memory_at_access:
                    try:
                        mem_data = thread_view.query_memory_buffer(address, memory_read_size)
                        hit_record["memory_at_address"] = {
                            "address": f"0x{address:x}",
                            "size": len(mem_data),
                            "hex": mem_data.hex(),
                            "ascii": "".join(chr(b) if 32 <= b < 127 else '.' for b in mem_data),
                        }
                    except Exception as e:
                        hit_record["memory_error"] = str(e)

                # Thread info from IThreadView
                try:
                    thread_info = thread_view.get_thread_info()
                    hit_record["thread_info"] = {
                        "thread_id": getattr(thread_info, 'ThreadId', 0),
                        "unique_thread_id": getattr(thread_info, 'UniqueId', 0),
                        "teb_address": f"0x{thread_view.get_teb_address():x}",
                    }
                except Exception:
                    pass

            hits.append(hit_record)
            return False  # Continue replay - collect more hits

        # Use the callback-based replay
        self.replay_with_memory_watchpoint_callback(
            detailed_callback, address, size, access_type, forward
        )

        return hits

    def _access_type_to_string(self, access_type: int) -> str:
        """Convert access type enum to string."""
        if access_type & 1:  # READ
            if access_type & 2:  # WRITE
                return "READ_WRITE"
            return "READ"
        elif access_type & 2:  # WRITE
            return "WRITE"
        elif access_type & 4:  # EXECUTE
            return "EXECUTE"
        return f"UNKNOWN({access_type})"

    def trace_value_changes_detailed(
        self,
        address: int,
        size: int = 8,
        max_changes: int = 50,
        forward: bool = True,
        capture_context: bool = True
    ) -> List[dict]:
        """
        Trace how a memory value changes over time with detailed context.

        This method uses the native watchpoint callback system with IThreadView
        to track writes and capture the value before/after each write.

        Args:
            address: Memory address to trace
            size: Size of value in bytes (1, 2, 4, or 8)
            max_changes: Maximum number of changes to track
            forward: If True, trace forward; if False, trace backward
            capture_context: If True, capture full execution context

        Returns:
            List of value changes with:
            - position: Position in trace
            - program_counter: Instruction that wrote the value
            - old_value: Value before the write
            - new_value: Value after the write
            - registers: Full register state (if capture_context=True)
            - stack: Stack trace (if capture_context=True)
        """
        self._ensure_open()

        changes = []

        # Read initial value before starting
        try:
            initial_bytes = self.query_memory(address, size)
            previous_value = [int.from_bytes(initial_bytes[:size], 'little') if initial_bytes else 0]
        except Exception:
            previous_value = [0]

        def value_change_callback(hit_info, thread_view):
            """Callback that captures value changes using IThreadView."""
            if len(changes) >= max_changes:
                return True  # Stop replay - we have enough changes

            # Read the new value via IThreadView
            new_value = 0
            if thread_view:
                try:
                    value_bytes = thread_view.query_memory_buffer(address, size)
                    new_value = int.from_bytes(value_bytes[:size], 'little') if value_bytes else 0
                except Exception:
                    pass

            # Extract position - it's a Position object, not a dict
            pos = hit_info.get("position")
            if pos and hasattr(pos, 'sequence'):
                pos_dict = {"sequence": pos.sequence, "steps": pos.steps}
            else:
                pos_dict = {"sequence": 0, "steps": 0}

            change_record = {
                "position": pos_dict,
                "program_counter": f"0x{hit_info.get('program_counter', 0):x}",
                "old_value": f"0x{previous_value[0]:x}",
                "new_value": f"0x{new_value:x}",
                "value_changed": previous_value[0] != new_value,
            }

            if capture_context and thread_view:
                # Capture registers via IThreadView accessor methods
                try:
                    change_record["registers"] = {
                        "rip": f"0x{thread_view.get_program_counter():x}",
                        "rsp": f"0x{thread_view.get_stack_pointer():x}",
                        "rbp": f"0x{thread_view.get_frame_pointer():x}",
                        "rax": f"0x{thread_view.get_basic_return_value():x}",
                    }
                except Exception:
                    pass

                # Capture stack (top 4 entries) via IThreadView
                try:
                    rsp = thread_view.get_stack_pointer()
                    stack_values = []
                    for i in range(4):
                        stack_addr = rsp + (i * 8)
                        mem = thread_view.query_memory_buffer(stack_addr, 8)
                        if len(mem) >= 8:
                            value = int.from_bytes(mem[:8], 'little')
                            stack_values.append(f"0x{value:016x}")
                    change_record["stack_top"] = stack_values
                except Exception:
                    pass

            changes.append(change_record)
            previous_value[0] = new_value  # Update for next iteration
            return False  # Continue replay - collect more changes

        # Use the callback-based replay with write watchpoint
        self.replay_with_memory_watchpoint_callback(
            value_change_callback, address, size, "write", forward
        )

        return changes

    def find_code_execution_at_address(
        self,
        code_address: int,
        max_hits: int = 100,
        forward: bool = True,
        capture_args: bool = True
    ) -> List[dict]:
        """
        Find all executions at a specific code address with call context.

        This method uses the native watchpoint callback system with IThreadView
        to capture function call arguments and context.

        Args:
            code_address: Address to monitor for execution
            max_hits: Maximum number of hits to collect
            forward: Direction to search
            capture_args: If True, capture calling convention arguments

        Returns:
            List of execution records with:
            - position: Trace position
            - arguments: First 4 args (rcx, rdx, r8, r9 on x64)
            - return_address: Return address from stack
            - stack_args: Additional args from stack
        """
        self._ensure_open()

        hits = []

        def execution_callback(hit_info, thread_view):
            """Callback that captures function call context using IThreadView."""
            if len(hits) >= max_hits:
                return True  # Stop replay - we have enough hits

            # Extract position - it's a Position object, not a dict
            pos = hit_info.get("position")
            if pos and hasattr(pos, 'sequence'):
                pos_dict = {"sequence": pos.sequence, "steps": pos.steps}
            else:
                pos_dict = {"sequence": 0, "steps": 0}

            hit_record = {
                "position": pos_dict,
                "code_address": f"0x{code_address:x}",
                "program_counter": f"0x{hit_info.get('program_counter', 0):x}",
            }

            if capture_args and thread_view:
                try:
                    # IThreadView provides limited register access (RIP, RSP, RBP, RAX)
                    # Full x64 calling convention registers (RCX, RDX, R8, R9)
                    # require full register context which isn't available via IThreadView
                    hit_record["registers"] = {
                        "rip": f"0x{thread_view.get_program_counter():x}",
                        "rsp": f"0x{thread_view.get_stack_pointer():x}",
                        "rbp": f"0x{thread_view.get_frame_pointer():x}",
                        "rax": f"0x{thread_view.get_basic_return_value():x}",
                    }

                    # Read return address from stack via IThreadView
                    try:
                        rsp = thread_view.get_stack_pointer()
                        ret_mem = thread_view.query_memory_buffer(rsp, 8)
                        if len(ret_mem) >= 8:
                            ret_addr = int.from_bytes(ret_mem[:8], 'little')
                            hit_record["return_address"] = f"0x{ret_addr:x}"
                    except Exception:
                        pass

                    # Read stack-passed arguments (5th arg and beyond) via IThreadView
                    try:
                        rsp = thread_view.get_stack_pointer()
                        stack_args = []
                        for i in range(4):  # Args 5-8 from stack
                            # Skip shadow space (32 bytes) + return address (8 bytes)
                            stack_addr = rsp + 0x28 + (i * 8)
                            mem = thread_view.query_memory_buffer(stack_addr, 8)
                            if len(mem) >= 8:
                                value = int.from_bytes(mem[:8], 'little')
                                stack_args.append(f"0x{value:x}")
                        hit_record["stack_args"] = stack_args
                    except Exception:
                        pass

                except Exception as e:
                    hit_record["args_error"] = str(e)

            hits.append(hit_record)
            return False  # Continue replay - collect more hits

        # Use the callback-based replay with execute watchpoint
        self.replay_with_memory_watchpoint_callback(
            execution_callback, code_address, 1, "execute", forward
        )

        return hits

    def set_replay_progress_callback(self, callback: Optional[Callable]):
        """
        Set callback for replay progress updates.

        Args:
            callback: Function(position) -> None
                     Called periodically during replay
                     Pass None to clear callback
        """
        self._ensure_open()

        if callback is None:
            self._native.set_replay_progress_callback(None, 0)
        else:
            def wrapper(_context, pos_ptr):
                if pos_ptr:
                    pos = pos_ptr.contents.to_python()
                    callback(pos)

            self._native.set_replay_progress_callback(wrapper, 0)

    @property
    def event_mask(self) -> EventMask:
        """Get the current event mask."""
        self._ensure_open()
        return self._native.get_event_mask()
    
    @event_mask.setter
    def event_mask(self, mask: EventMask):
        """Set which events to stop on during replay."""
        self._ensure_open()
        self._native.set_event_mask(mask)
    
    @property
    def replay_flags(self) -> ReplayFlags:
        """Get current replay flags."""
        self._ensure_open()
        return self._native.get_replay_flags()
    
    @replay_flags.setter
    def replay_flags(self, flags: ReplayFlags):
        """Set replay behavior flags."""
        self._ensure_open()
        self._native.set_replay_flags(flags)
    
    # =========================================================================
    # Replay
    # =========================================================================
    
    def replay_forward(self, limit: Optional[Position] = None,
                       max_steps: int = 0xFFFFFFFFFFFFFFFE) -> ReplayResult:
        """
        Replay forward until a watchpoint/event is hit or limit is reached.
        
        Args:
            limit: Maximum position to replay to (None = trace end)
            max_steps: Maximum steps to execute
        
        Returns:
            ReplayResult with stop reason and event details
        """
        self._ensure_open()
        
        if limit is None:
            limit = Position.MAX
        elif isinstance(limit, str):
            limit = Position.from_string(limit)
        
        c_limit = CTTDPosition.from_python(limit)
        c_result = self._native.replay_forward(c_limit, max_steps)
        
        return self._parse_replay_result(c_result)
    
    def replay_backward(self, limit: Optional[Position] = None,
                        max_steps: int = 0xFFFFFFFFFFFFFFFE) -> ReplayResult:
        """
        Replay backward until a watchpoint/event is hit or limit is reached.
        
        Args:
            limit: Minimum position to replay to (None = trace start)
            max_steps: Maximum steps to execute
        
        Returns:
            ReplayResult with stop reason and event details
        """
        self._ensure_open()
        
        if limit is None:
            limit = Position.MIN
        elif isinstance(limit, str):
            limit = Position.from_string(limit)
        
        c_limit = CTTDPosition.from_python(limit)
        c_result = self._native.replay_backward(c_limit, max_steps)
        
        return self._parse_replay_result(c_result)
    
    def step_forward(self, steps: int = 1) -> ReplayResult:
        """
        Step forward by a specific number of steps.
        
        Args:
            steps: Number of steps to execute
        
        Returns:
            ReplayResult
        """
        return self.replay_forward(max_steps=steps)
    
    def step_backward(self, steps: int = 1) -> ReplayResult:
        """
        Step backward by a specific number of steps.
        
        Args:
            steps: Number of steps to execute
        
        Returns:
            ReplayResult
        """
        return self.replay_backward(max_steps=steps)
    
    def run_to_address(self, address: int, backward: bool = False) -> ReplayResult:
        """
        Run until a specific code address is executed.
        
        Args:
            address: Code address to stop at
            backward: If True, run backward
        
        Returns:
            ReplayResult
        """
        # Add execute watchpoint
        self.add_memory_watchpoint(address, 1, access_type="execute")
        
        try:
            if backward:
                return self.replay_backward()
            else:
                return self.replay_forward()
        finally:
            self.remove_memory_watchpoint(address, 1, access_type="execute")
    
    def interrupt(self):
        """
        Interrupt an ongoing replay operation.
        
        This is thread-safe and can be called from another thread.
        """
        if self._native:
            self._native.interrupt_replay()
    
    def _parse_replay_result(self, c_result) -> ReplayResult:
        """Parse native replay result into Python object."""
        stop_reason = EventType(c_result.StopReason)
        
        result = ReplayResult(
            stop_reason=stop_reason,
            steps_executed=c_result.StepsExecuted,
            instructions_executed=c_result.InstructionsExecuted,
        )
        
        # Parse event-specific data based on stop reason
        if stop_reason == EventType.MEMORY_WATCHPOINT:
            # Extract MemoryWatchpointResult from union
            union_data = bytes(c_result._union_data)
            address = int.from_bytes(union_data[0:8], 'little')
            size = int.from_bytes(union_data[8:16], 'little')
            access_type = union_data[16]
            
            result.memory_watchpoint = MemoryWatchpointResult(
                address=GuestAddress(address),
                size=size,
                access_type=DataAccessType(access_type)
            )
        
        elif stop_reason == EventType.POSITION_WATCHPOINT:
            union_data = bytes(c_result._union_data)
            seq = int.from_bytes(union_data[0:8], 'little')
            steps = int.from_bytes(union_data[8:16], 'little')
            result.position_watchpoint = Position(seq, steps)
        
        elif stop_reason == EventType.GAP:
            union_data = bytes(c_result._union_data)
            result.gap_data = GapData(
                kind=GapKind(union_data[0]),
                event_type=GapEventType(union_data[1])
            )
        
        return result
    
    # =========================================================================
    # Context Information
    # =========================================================================
    
    @property
    def thread_count(self) -> int:
        """Get count of active threads at current position."""
        self._ensure_open()
        return self._native.get_thread_count()
    
    @property
    def module_count(self) -> int:
        """Get count of loaded modules at current position."""
        self._ensure_open()
        return self._native.get_module_count()
    
    def get_info(self) -> dict:
        """Get comprehensive information about cursor state."""
        self._ensure_open()

        regs = self.get_registers()
        return {
            "position": self.position.to_dict(),
            "program_counter": str(self.program_counter),
            "stack_pointer": str(self.stack_pointer),
            "frame_pointer": str(self.frame_pointer),
            "return_value": f"0x{self.return_value:x}",
            "thread_count": self.thread_count,
            "module_count": self.module_count,
            "watchpoint_count": len(self._watchpoints),
        }

    # =========================================================================
    # Data Flow Tracing
    # =========================================================================

    def trace_register_origin_backward(
        self,
        register_name: str,
        max_steps: int = 10000,
        max_trace_depth: int = 50
    ) -> "DataFlowTraceResult":
        """
        Track a register value backward to find its origin.

        Uses execution watchpoint on the entire address space to efficiently
        step backward and monitor register changes, following the data flow
        through register copies, memory loads, and computations.

        Args:
            register_name: Register to track (e.g., "rax", "rcx", "r8")
            max_steps: Maximum replay steps to execute
            max_trace_depth: Maximum number of data flow steps to record

        Returns:
            DataFlowTraceResult with trace steps and origin information
        """
        self._ensure_open()

        # Import disassembly helper (optional dependency)
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register, InstructionCategory
            disasm = get_disassembly_helper()
            if disasm is None:
                return DataFlowTraceResult(
                    success=False,
                    steps=[],
                    origin_found=False,
                    origin_type="error",
                    origin_detail="Capstone disassembly not available. Install with: pip install capstone",
                    termination_reason="capstone_not_available"
                )
        except ImportError as e:
            return DataFlowTraceResult(
                success=False,
                steps=[],
                origin_found=False,
                origin_type="error",
                origin_detail=f"Import error: {e}",
                termination_reason="import_error"
            )

        # Normalize register name
        target_register = normalize_register(register_name.lower())
        if not target_register:
            return DataFlowTraceResult(
                success=False,
                steps=[],
                origin_found=False,
                origin_type="error",
                origin_detail=f"Invalid register name: {register_name}",
                termination_reason="invalid_register"
            )

        # Save current position
        saved_position = self.position

        # Get initial register value
        try:
            initial_regs = self.get_registers()
            current_value = initial_regs.get(target_register)
        except Exception as e:
            return DataFlowTraceResult(
                success=False,
                steps=[],
                origin_found=False,
                origin_type="error",
                origin_detail=f"Failed to get initial register value: {e}",
                termination_reason="register_access_error"
            )

        steps: List[DataFlowStep] = []
        tracking_type = "register"
        tracking_target = target_register
        tracking_value = current_value
        origin_found = False
        origin_type = "unknown"
        origin_detail = ""
        termination_reason = "max_steps_reached"

        # Track execution context for callbacks
        trace_context = {
            "tracking_type": tracking_type,
            "tracking_target": tracking_target,
            "tracking_value": tracking_value,
            "steps": steps,
            "origin_found": False,
            "origin_type": "unknown",
            "origin_detail": "",
            "termination_reason": "max_steps_reached",
            "steps_executed": 0,
            "disasm": disasm,
            "cursor": self,
        }

        def trace_callback(hit_info, thread_view):
            """Callback to trace register changes."""
            nonlocal origin_found, origin_type, origin_detail, termination_reason

            if len(trace_context["steps"]) >= max_trace_depth:
                trace_context["termination_reason"] = "max_trace_depth"
                return True  # Accept hit = stop replay

            trace_context["steps_executed"] += 1

            if not thread_view:
                return False  # Reject hit = continue replay

            try:
                # Get current register values
                current_regs = self._get_registers_from_thread_view(thread_view)
                current_target_value = current_regs.get(trace_context["tracking_target"], 0)

                # Check if target register changed
                if current_target_value != trace_context["tracking_value"]:
                    # The instruction just executed modified our target register
                    # We're replaying backward, so we're seeing the state BEFORE this instruction
                    # The instruction at the current PC is what will set the register

                    pc = thread_view.get_program_counter()

                    # Read instruction bytes
                    try:
                        insn_bytes = thread_view.query_memory_buffer(pc, 16)
                    except Exception:
                        insn_bytes = b''

                    if insn_bytes:
                        insn = trace_context["disasm"].disassemble_one(insn_bytes, pc)
                        if insn:
                            # Check if this instruction modifies our target
                            modified_reg = trace_context["disasm"].get_modified_register(insn)
                            if modified_reg and normalize_register(modified_reg) == trace_context["tracking_target"]:
                                # Get source info
                                source_type, source_detail = trace_context["disasm"].get_source_info(insn)

                                # Get position
                                pos = hit_info.get("position")
                                if pos and hasattr(pos, 'sequence'):
                                    step_pos = pos
                                else:
                                    step_pos = Position(0, 0)

                                step = DataFlowStep(
                                    position=step_pos,
                                    instruction_address=pc,
                                    instruction_text=str(insn),
                                    tracking_type=trace_context["tracking_type"],
                                    tracking_target=trace_context["tracking_target"],
                                    value_at_step=current_target_value,
                                    source_type=source_type,
                                    source_detail=source_detail,
                                    registers=current_regs.copy(),
                                )
                                trace_context["steps"].append(step)

                                # Determine next action based on source type
                                if source_type == "immediate":
                                    # Origin found: constant value
                                    trace_context["origin_found"] = True
                                    trace_context["origin_type"] = "constant"
                                    trace_context["origin_detail"] = source_detail
                                    trace_context["termination_reason"] = "origin_found"
                                    return True  # Accept hit = stop replay

                                elif source_type == "register":
                                    # Follow source register
                                    new_target = normalize_register(source_detail)
                                    if new_target:
                                        trace_context["tracking_target"] = new_target
                                        trace_context["tracking_value"] = current_regs.get(new_target, 0)

                                elif source_type == "memory":
                                    # Switch to memory tracking (would need memory address)
                                    trace_context["origin_found"] = True
                                    trace_context["origin_type"] = "memory_read"
                                    trace_context["origin_detail"] = source_detail
                                    trace_context["termination_reason"] = "origin_found"
                                    return True  # Accept hit = stop replay

                                elif source_type == "function_return":
                                    # Value from function call
                                    trace_context["origin_found"] = True
                                    trace_context["origin_type"] = "function_return"
                                    trace_context["origin_detail"] = f"Return value from call at 0x{pc:x}"
                                    trace_context["termination_reason"] = "origin_found"
                                    return True  # Accept hit = stop replay

                                elif source_type == "computed":
                                    # Value was computed
                                    trace_context["origin_found"] = True
                                    trace_context["origin_type"] = "computed"
                                    trace_context["origin_detail"] = source_detail
                                    trace_context["termination_reason"] = "origin_found"
                                    return True  # Accept hit = stop replay

                                elif source_type == "address_computation":
                                    # LEA instruction - track base register
                                    new_target = normalize_register(source_detail)
                                    if new_target and new_target != trace_context["tracking_target"]:
                                        trace_context["tracking_target"] = new_target
                                        trace_context["tracking_value"] = current_regs.get(new_target, 0)

                                elif source_type == "stack_pop":
                                    # Value from stack
                                    trace_context["origin_found"] = True
                                    trace_context["origin_type"] = "stack_value"
                                    trace_context["origin_detail"] = "Popped from stack"
                                    trace_context["termination_reason"] = "origin_found"
                                    return True  # Accept hit = stop replay

                    # Update tracking value
                    trace_context["tracking_value"] = current_target_value

            except Exception as e:
                # Continue despite errors
                pass

            return False  # Reject hit = continue tracing

        # Set up execution watchpoint on entire address space
        # Per TTD developer guidance: use 0x1 to MAX for execution watchpoint
        old_flags = self.replay_flags
        old_mask = self.event_mask
        try:
            # Clear existing watchpoints
            self.clear_watchpoints()

            # Add execution watchpoint on entire address space
            self.add_memory_watchpoint(0x1, 0xFFFF_FFFF_FFFF_FFFE, access_type="execute")

            # Set replay flags for efficiency
            self.replay_flags = ReplayFlags.REPLAY_ONLY_CURRENT_THREAD | ReplayFlags.REPLAY_SEGMENTS_SEQUENTIALLY

            # Wrapper callback to properly handle ctypes pointers
            def wrapper_callback(_context, wp_result_ptr, thread_view_ptr):
                from ttdobjectspy.bindings import NativeThreadView

                # Wrap the thread view pointer
                thread_view = NativeThreadView(thread_view_ptr) if thread_view_ptr else None

                # Build hit info
                hit_info = {}
                if thread_view:
                    try:
                        hit_info["position"] = thread_view.get_position().to_python()
                    except Exception:
                        hit_info["position"] = None

                return trace_callback(hit_info, thread_view)

            # Set up callback
            self._native.set_memory_watchpoint_callback(wrapper_callback, 0)

            # Enable memory watchpoint events
            self.event_mask = old_mask | EventMask.MEMORY_WATCHPOINT

            # Replay backward
            self.replay_backward(max_steps=max_steps)

        except Exception as e:
            trace_context["termination_reason"] = f"replay_error: {e}"
        finally:
            # Clean up
            self._native.set_memory_watchpoint_callback(None, 0)
            self.clear_watchpoints()
            self.replay_flags = old_flags
            self.event_mask = old_mask
            self.set_position(saved_position)

        return DataFlowTraceResult(
            success=len(trace_context["steps"]) > 0 or trace_context["origin_found"],
            steps=trace_context["steps"],
            origin_found=trace_context["origin_found"],
            origin_type=trace_context["origin_type"],
            origin_detail=trace_context["origin_detail"],
            termination_reason=trace_context["termination_reason"]
        )

    def trace_memory_origin_backward(
        self,
        address: int,
        size: int = 8,
        max_steps: int = 10000
    ) -> "DataFlowTraceResult":
        """
        Track a memory value backward to find what wrote it.

        Uses write watchpoint on the target address to find the last write,
        then analyzes the instruction to determine the data source.

        Args:
            address: Memory address to track
            size: Size of memory value (1, 2, 4, or 8 bytes)
            max_steps: Maximum replay steps to execute

        Returns:
            DataFlowTraceResult with write information
        """
        self._ensure_open()

        # Import disassembly helper (optional dependency)
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register
            disasm = get_disassembly_helper()
        except ImportError:
            disasm = None

        # Save current position
        saved_position = self.position

        # Get initial memory value
        try:
            initial_bytes = self.query_memory(address, size)
            initial_value = int.from_bytes(initial_bytes[:size], 'little') if initial_bytes else 0
        except Exception as e:
            return DataFlowTraceResult(
                success=False,
                steps=[],
                origin_found=False,
                origin_type="error",
                origin_detail=f"Failed to read memory: {e}",
                termination_reason="memory_read_error"
            )

        steps: List[DataFlowStep] = []
        origin_found = False
        origin_type = "unknown"
        origin_detail = ""
        termination_reason = "max_steps_reached"

        def write_callback(hit_info, thread_view):
            """Callback to capture write information."""
            nonlocal origin_found, origin_type, origin_detail, termination_reason, steps

            if not thread_view:
                return False

            try:
                pc = thread_view.get_program_counter()

                # Get position
                pos = hit_info.get("position")
                if pos and hasattr(pos, 'sequence'):
                    step_pos = pos
                else:
                    step_pos = Position(0, 0)

                # Get registers
                regs = self._get_registers_from_thread_view(thread_view)

                # Read instruction for analysis
                insn_text = f"0x{pc:x}: [write to 0x{address:x}]"
                source_type = "unknown"
                source_detail_str = ""

                if disasm:
                    try:
                        insn_bytes = thread_view.query_memory_buffer(pc, 16)
                        if insn_bytes:
                            insn = disasm.disassemble_one(insn_bytes, pc)
                            if insn:
                                insn_text = str(insn)
                                # Get source info for memory write
                                if insn.source_reg:
                                    source_type = "register"
                                    source_detail_str = insn.source_reg
                                elif insn.immediate is not None:
                                    source_type = "immediate"
                                    source_detail_str = f"0x{insn.immediate:x}"
                                elif insn.source_mem:
                                    source_type = "memory"
                                    source_detail_str = str(insn.source_mem)
                    except Exception:
                        pass

                step = DataFlowStep(
                    position=step_pos,
                    instruction_address=pc,
                    instruction_text=insn_text,
                    tracking_type="memory",
                    tracking_target=f"0x{address:x}",
                    value_at_step=initial_value,
                    source_type=source_type,
                    source_detail=source_detail_str,
                    registers=regs.copy(),
                )
                steps.append(step)

                origin_found = True
                origin_type = f"write_from_{source_type}"
                origin_detail = f"Written by instruction at 0x{pc:x}: {insn_text}"
                termination_reason = "origin_found"

            except Exception as e:
                termination_reason = f"callback_error: {e}"

            return True  # Accept hit = stop replay after first write found

        old_mask = self.event_mask
        try:
            # Clear existing watchpoints
            self.clear_watchpoints()

            # Add write watchpoint on target address
            self.add_memory_watchpoint(address, size, access_type="write")

            # Wrapper callback to properly handle ctypes pointers
            def wrapper_callback(_context, wp_result_ptr, thread_view_ptr):
                from ttdobjectspy.bindings import NativeThreadView

                # Wrap the thread view pointer
                thread_view = NativeThreadView(thread_view_ptr) if thread_view_ptr else None

                # Build hit info
                hit_info = {}
                if thread_view:
                    try:
                        hit_info["position"] = thread_view.get_position().to_python()
                    except Exception:
                        hit_info["position"] = None

                return write_callback(hit_info, thread_view)

            # Set up callback
            self._native.set_memory_watchpoint_callback(wrapper_callback, 0)

            # Enable memory watchpoint events
            self.event_mask = old_mask | EventMask.MEMORY_WATCHPOINT

            # Replay backward to find the write
            result = self.replay_backward(max_steps=max_steps)

            if result.stop_reason == EventType.MEMORY_WATCHPOINT and not origin_found:
                # Watchpoint hit but callback didn't process it
                origin_found = True
                origin_type = "write"
                origin_detail = f"Memory written at position {self.position}"
                termination_reason = "origin_found"

        except Exception as e:
            termination_reason = f"replay_error: {e}"
        finally:
            # Clean up
            self._native.set_memory_watchpoint_callback(None, 0)
            self.clear_watchpoints()
            self.event_mask = old_mask
            self.set_position(saved_position)

        return DataFlowTraceResult(
            success=origin_found,
            steps=steps,
            origin_found=origin_found,
            origin_type=origin_type,
            origin_detail=origin_detail,
            termination_reason=termination_reason
        )

    def trace_register_taint_backward(
        self,
        register_name: str,
        max_steps: int = 10000,
        max_trace_depth: int = 100,
        track_all_writes: bool = False
    ) -> "TaintTraceResult":
        """
        Full taint analysis: track a register value backward through ALL contributing operands.

        Unlike trace_register_origin_backward which stops at computed operations,
        this method continues to trace ALL input operands that contributed to the
        computed result. For example, with 'xor r8, rax', it will continue to trace
        both the old r8 value AND rax backward.

        This enables tracking values through arithmetic operations to find ALL
        origins that contributed to the final value.

        Args:
            register_name: Register to track (e.g., "rax", "rcx", "r8")
            max_steps: Maximum replay steps to execute
            max_trace_depth: Maximum number of taint steps to record
            track_all_writes: If True, record ALL instructions that write to a tracked
                register, even if the value doesn't change (e.g., 'xor r8, r8' when r8=0).
                Default False only tracks instructions that actually change the value.

        Returns:
            TaintTraceResult with trace steps and all taint sources
        """
        self._ensure_open()

        # Import disassembly helper (optional dependency)
        try:
            from ttdobjectspy.disasm import get_disassembly_helper, normalize_register, InstructionCategory
            disasm = get_disassembly_helper()
            if disasm is None:
                return TaintTraceResult(
                    success=False,
                    steps=[],
                    taint_sources=[],
                    active_taint_set=[],
                    termination_reason="capstone_not_available",
                    steps_executed=0
                )
        except ImportError as e:
            return TaintTraceResult(
                success=False,
                steps=[],
                taint_sources=[],
                active_taint_set=[],
                termination_reason=f"import_error: {e}",
                steps_executed=0
            )

        # Normalize register name
        target_register = normalize_register(register_name.lower())
        if not target_register:
            return TaintTraceResult(
                success=False,
                steps=[],
                taint_sources=[],
                active_taint_set=[],
                termination_reason=f"invalid_register: {register_name}",
                steps_executed=0
            )

        # Save current position
        saved_position = self.position

        # Get initial register values
        try:
            initial_regs = self.get_registers()
        except Exception as e:
            return TaintTraceResult(
                success=False,
                steps=[],
                taint_sources=[],
                active_taint_set=[],
                termination_reason=f"register_access_error: {e}",
                steps_executed=0
            )

        # Initialize taint set - registers we're currently tracking
        # Maps register name -> current known value
        taint_set: Dict[str, int] = {target_register: initial_regs.get(target_register)}

        steps: List[TaintStep] = []
        taint_sources: List[TaintSource] = []
        steps_executed = 0
        termination_reason = "max_steps_reached"

        # Track execution context for callbacks
        trace_context = {
            "taint_set": taint_set,
            "steps": steps,
            "taint_sources": taint_sources,
            "steps_executed": 0,  # Tracks outer loop iterations (candidates found)
            "callback_count": 0,  # Tracks callback invocations in current replay pass
            "termination_reason": "max_steps_reached",
            "disasm": disasm,
            "normalize_register": normalize_register,
            "track_all_writes": track_all_writes,
        }

        # Use watchpoint-based approach with execution watchpoint on entire address space
        # Per TTD guidance: use execution watchpoint from 1 to 0xFFFF_FFFF_FFFF with
        # REPLAY_ONLY_CURRENT_THREAD | REPLAY_SEGMENTS_SEQUENTIALLY flags
        #
        # Key insight: When replaying backward, TTD actually replays FORWARD from an
        # earlier position. The callback sees instructions in chronological order.
        # To find the "last write before our starting position", we need to:
        # 1. Let TTD replay through, collecting ALL candidates
        # 2. Pick the LAST candidate (closest to start position) for processing
        # 3. Then step backward from that position to continue searching
        old_flags = self.replay_flags
        old_mask = self.event_mask

        try:
            # Clear existing watchpoints
            self.clear_watchpoints()

            # Add execution watchpoint on entire address space (single-step mode)
            self.add_memory_watchpoint(0x1, 0xFFFF_FFFF_FFFF_FFFE, access_type="execute")

            # Set replay flags for efficiency - single thread and sequential mode
            self.replay_flags = ReplayFlags.REPLAY_ONLY_CURRENT_THREAD | ReplayFlags.REPLAY_SEGMENTS_SEQUENTIALLY

            # Track the LAST candidate seen during each replay pass
            trace_context["last_candidate"] = None  # Will hold (step, taint_set_updates)

            def wrapper_callback(_context, wp_result_ptr, thread_view_ptr):
                from ttdobjectspy.bindings import NativeThreadView

                # Track callback invocations separately - don't count towards total steps
                # Total steps tracks outer loop iterations (candidates found)
                trace_context["callback_count"] += 1
                if trace_context["callback_count"] >= max_steps:
                    # Hit callback limit for this replay pass - stop and process candidate
                    return True  # Accept hit = stop replay

                # Wrap the thread view pointer
                thread_view = NativeThreadView(thread_view_ptr) if thread_view_ptr else None
                if not thread_view:
                    return False  # Reject hit = continue replay

                try:
                    # Get position
                    try:
                        pos = thread_view.get_position().to_python()
                    except Exception:
                        return False  # Reject hit = continue replay

                    # Get current register values
                    current_regs = self._get_registers_from_thread_view(thread_view)
                    pc = thread_view.get_program_counter()

                    # Read and disassemble instruction
                    try:
                        insn_bytes = thread_view.query_memory_buffer(pc, 16)
                    except Exception:
                        insn_bytes = b''

                    if not insn_bytes:
                        return False  # Reject hit = continue replay

                    insn = trace_context["disasm"].disassemble_one(insn_bytes, pc)
                    if not insn:
                        return False  # Reject hit = continue replay

                    modified_reg = trace_context["disasm"].get_modified_register(insn)
                    if modified_reg:
                        modified_reg = trace_context["normalize_register"](modified_reg)

                    # Check if this instruction writes to a tracked register
                    writes_to_tracked = modified_reg and modified_reg in trace_context["taint_set"]

                    if not writes_to_tracked:
                        # Don't update taint_set here - we need consistent comparisons
                        # throughout this replay pass
                        return False  # Reject hit = continue replay - not interesting

                    # This instruction writes to a tracked register!
                    # Check if value actually changed (or if track_all_writes is enabled)
                    old_value = trace_context["taint_set"].get(modified_reg, 0)
                    current_value = current_regs.get(modified_reg, 0)
                    value_changed = (current_value != old_value)

                    # If value didn't change and we're not tracking all writes, skip
                    if not value_changed and not track_all_writes:
                        # Don't update taint_set here - we need consistent comparisons
                        # throughout this replay pass
                        return False  # Reject hit = continue replay

                    # Found a candidate! Save it as the last candidate.
                    # We DON'T stop here - we want to find the LAST (closest to start) candidate.

                    # Get ALL input operands for this instruction
                    input_operands = trace_context["disasm"].get_input_operands(insn)
                    new_taint_targets = []
                    new_sources = []

                    # Enhance input operands with actual values
                    enhanced_operands = []
                    for operand in input_operands:
                        op_type = operand["type"]
                        op_value = operand["value"]
                        enhanced_op = dict(operand)  # Copy original

                        if op_type == "register":
                            reg = trace_context["normalize_register"](op_value)
                            if reg:
                                # Add actual register value
                                enhanced_op["actual_value"] = f"0x{current_regs.get(reg, 0):x}"
                                if reg != modified_reg:
                                    if reg not in trace_context["taint_set"]:
                                        new_taint_targets.append((reg, current_regs.get(reg, 0)))

                        elif op_type == "immediate":
                            new_sources.append(TaintSource(
                                source_type="constant",
                                source_detail=op_value,
                                position=pos,
                                instruction_address=pc,
                                instruction_text=str(insn),
                            ))

                        elif op_type == "memory":
                            new_sources.append(TaintSource(
                                source_type="memory",
                                source_detail=op_value,
                                position=pos,
                                instruction_address=pc,
                                instruction_text=str(insn),
                            ))

                        elif op_type == "function_return":
                            new_sources.append(TaintSource(
                                source_type="function_return",
                                source_detail=f"Return value from call at 0x{pc:x}",
                                position=pos,
                                instruction_address=pc,
                                instruction_text=str(insn),
                            ))

                        enhanced_operands.append(enhanced_op)

                    input_operands = enhanced_operands

                    # Build the step
                    # Note: current_value = value BEFORE instruction (we're replaying backward)
                    #       old_value = value AFTER instruction (from starting position)
                    # So result_value = old_value (what the instruction produced)
                    #    value_at_step = current_value (what was there before)

                    # For LEA instructions, compute the effective address for clarity
                    computed_addr = None
                    if insn.category == InstructionCategory.LEA and insn.source_mem:
                        try:
                            # LEA computes: base + index*scale + disp
                            mem = insn.source_mem
                            addr = mem.disp  # Start with displacement
                            if mem.base_reg:
                                base_reg = trace_context["normalize_register"](mem.base_reg)
                                if base_reg:
                                    addr += current_regs.get(base_reg, 0)
                            if mem.index_reg:
                                index_reg = trace_context["normalize_register"](mem.index_reg)
                                if index_reg:
                                    addr += current_regs.get(index_reg, 0) * mem.scale
                            computed_addr = addr & 0xFFFFFFFFFFFFFFFF  # Mask to 64-bit
                        except Exception:
                            pass

                    step = TaintStep(
                        position=pos,
                        instruction_address=pc,
                        instruction_text=str(insn),
                        affected_register=modified_reg,
                        input_operands=input_operands,
                        new_taint_targets=[t[0] for t in new_taint_targets],
                        value_at_step=current_value,  # Value BEFORE instruction
                        result_value=old_value,  # Value AFTER instruction (the result)
                        registers=current_regs.copy(),
                        value_changed=value_changed,
                        computed_address=computed_addr,
                    )

                    # Determine taint set changes
                    register_sources = [op for op in input_operands
                                       if op["type"] == "register" and not op.get("is_dest_also_source")]
                    should_remove = not register_sources

                    # Store this as the last candidate
                    # Don't update taint_set here - it's done after replay finishes
                    # to ensure consistent comparisons throughout this replay pass
                    trace_context["last_candidate"] = {
                        "step": step,
                        "sources": new_sources,
                        "new_taint_targets": new_taint_targets,
                        "modified_reg": modified_reg,
                        "should_remove": should_remove,
                        "new_value": current_regs.get(modified_reg, 0),
                    }

                except Exception as e:
                    trace_context["termination_reason"] = f"callback_error: {e}"

                return False  # Reject hit = continue replay to find the LAST candidate

            # Set up callback
            self._native.set_memory_watchpoint_callback(wrapper_callback, 0)

            # Enable memory watchpoint events
            self.event_mask = old_mask | EventMask.MEMORY_WATCHPOINT

            # Iterative backward replay:
            # Each replay pass finds the LAST candidate before the current position
            # We then process that candidate, update taint set, and repeat from its position
            while len(trace_context["steps"]) < max_trace_depth:
                if not trace_context["taint_set"]:
                    trace_context["termination_reason"] = "all_sources_found"
                    break

                trace_context["last_candidate"] = None
                trace_context["callback_count"] = 0  # Reset for this replay pass

                # Replay backward - will replay forward from earlier position
                # Callback collects ALL candidates, keeping only the last one
                # max_steps limits callbacks per replay pass to avoid runaway
                self.replay_backward(max_steps=max_steps)

                if trace_context["last_candidate"] is None:
                    # No candidates found - we've reached the trace start
                    trace_context["termination_reason"] = "trace_start"
                    break

                # Process the last candidate
                candidate = trace_context["last_candidate"]
                step = candidate["step"]

                # Add step and sources
                trace_context["steps"].append(step)
                trace_context["taint_sources"].extend(candidate["sources"])

                # Update taint set - add new targets
                for reg, val in candidate["new_taint_targets"]:
                    if reg not in trace_context["taint_set"]:
                        trace_context["taint_set"][reg] = val

                # Update taint set - remove or update modified register
                modified_reg = candidate["modified_reg"]
                if candidate["should_remove"]:
                    if modified_reg in trace_context["taint_set"]:
                        del trace_context["taint_set"][modified_reg]
                else:
                    trace_context["taint_set"][modified_reg] = candidate["new_value"]

                # Track that we processed a candidate
                trace_context["steps_executed"] += 1

                # Move to the candidate's position and step back one to continue
                try:
                    self.set_position(step.position)
                    self.step_backward(1)
                except Exception:
                    trace_context["termination_reason"] = "trace_start"
                    break

        except Exception as e:
            trace_context["termination_reason"] = f"replay_error: {e}"
        finally:
            # Clean up
            self._native.set_memory_watchpoint_callback(None, 0)
            self.clear_watchpoints()
            self.replay_flags = old_flags
            self.event_mask = old_mask

        # Restore position
        self.set_position(saved_position)

        return TaintTraceResult(
            success=len(trace_context["steps"]) > 0 or len(trace_context["taint_sources"]) > 0,
            steps=trace_context["steps"],
            taint_sources=trace_context["taint_sources"],
            active_taint_set=list(trace_context["taint_set"].keys()),
            termination_reason=trace_context["termination_reason"],
            steps_executed=trace_context["steps_executed"]
        )

    def _get_registers_from_thread_view(self, thread_view) -> Dict[str, int]:
        """
        Get all registers from IThreadView via cross-platform context.

        Uses get_cross_platform_context() to retrieve the full AMD64 register
        set including R8-R15 which are not directly accessible via IThreadView.

        Args:
            thread_view: Native thread view object

        Returns:
            Dictionary of register name -> value
        """
        regs = {}
        try:
            # Get basic registers from direct accessors
            regs["rip"] = thread_view.get_program_counter()
            regs["rsp"] = thread_view.get_stack_pointer()
            regs["rbp"] = thread_view.get_frame_pointer()
            regs["rax"] = thread_view.get_basic_return_value()

            # Get full context for remaining registers
            try:
                context = thread_view.get_cross_platform_context()
                data = context.Data

                # AMD64_CONTEXT layout - integer registers start at offset 15 (0x78 bytes)
                if len(data) >= 32:
                    regs["rax"] = data[15]
                    regs["rcx"] = data[16]
                    regs["rdx"] = data[17]
                    regs["rbx"] = data[18]
                    regs["rsp"] = data[19]
                    regs["rbp"] = data[20]
                    regs["rsi"] = data[21]
                    regs["rdi"] = data[22]
                    regs["r8"] = data[23]
                    regs["r9"] = data[24]
                    regs["r10"] = data[25]
                    regs["r11"] = data[26]
                    regs["r12"] = data[27]
                    regs["r13"] = data[28]
                    regs["r14"] = data[29]
                    regs["r15"] = data[30]
                    regs["rip"] = data[31]
                    if len(data) >= 33:
                        regs["rflags"] = data[32]
            except Exception:
                # Fall back to basic registers if context fails
                pass

        except Exception:
            pass
        return regs


@dataclass
class DataFlowStep:
    """
    A single step in data flow tracing.

    Records one instruction that affected the tracked value, including
    the source of the data and full execution context.
    """
    position: Position
    instruction_address: int
    instruction_text: str
    tracking_type: str  # "register" or "memory"
    tracking_target: str  # Register name or memory address
    value_at_step: int
    source_type: str  # "register", "memory", "immediate", "computed", etc.
    source_detail: str
    registers: Optional[Dict[str, int]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "position": self.position.to_dict() if hasattr(self.position, 'to_dict') else str(self.position),
            "instruction_address": f"0x{self.instruction_address:x}",
            "instruction_text": self.instruction_text,
            "tracking_type": self.tracking_type,
            "tracking_target": self.tracking_target,
            "value_at_step": f"0x{self.value_at_step:x}",
            "source_type": self.source_type,
            "source_detail": self.source_detail,
            "registers": {k: f"0x{v:x}" for k, v in self.registers.items()} if self.registers else None,
        }


@dataclass
class DataFlowTraceResult:
    """
    Result of backward data flow tracing.

    Contains the trace steps showing how data flowed through the program,
    and information about the origin of the value.
    """
    success: bool
    steps: List[DataFlowStep] = field(default_factory=list)
    origin_found: bool = False
    origin_type: str = "unknown"  # "constant", "memory_read", "function_return", "computed", etc.
    origin_detail: str = ""
    termination_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "steps": [s.to_dict() for s in self.steps],
            "step_count": len(self.steps),
            "origin_found": self.origin_found,
            "origin_type": self.origin_type,
            "origin_detail": self.origin_detail,
            "termination_reason": self.termination_reason,
        }


@dataclass
class TaintSource:
    """
    Represents a taint source - an origin point for a value.

    A taint source can be a constant, memory location, function return,
    or parameter. Multiple taint sources may contribute to a single value.
    """
    source_type: str  # "constant", "memory", "function_return", "parameter", "unknown"
    source_detail: str  # Details about the source (e.g., constant value, memory address)
    position: Optional[Position] = None  # Position where this source was identified
    instruction_address: int = 0
    instruction_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_type": self.source_type,
            "source_detail": self.source_detail,
            "position": self.position.to_dict() if self.position and hasattr(self.position, 'to_dict') else None,
            "instruction_address": f"0x{self.instruction_address:x}" if self.instruction_address else None,
            "instruction_text": self.instruction_text,
        }


@dataclass
class TaintStep:
    """
    A single step in taint analysis trace.

    Records one instruction that affected a tainted value, including
    all input operands that contributed to the result.
    """
    position: Position
    instruction_address: int
    instruction_text: str
    affected_register: str  # The register being modified
    input_operands: List[dict]  # All operands that contributed (from get_input_operands)
    new_taint_targets: List[str]  # New registers/memory to track after this step
    value_at_step: int  # Value of affected register BEFORE this instruction
    result_value: int = 0  # Value of affected register AFTER this instruction (the computed result)
    registers: Optional[Dict[str, int]] = None
    value_changed: bool = True  # False if recorded due to track_all_writes with same value
    computed_address: Optional[int] = None  # For LEA: the actual computed address

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "position": self.position.to_dict() if hasattr(self.position, 'to_dict') else str(self.position),
            "instruction_address": f"0x{self.instruction_address:x}",
            "instruction_text": self.instruction_text,
            "affected_register": self.affected_register,
            "input_operands": self.input_operands,
            "new_taint_targets": self.new_taint_targets,
            "value_before": f"0x{self.value_at_step:x}",
            "value_after": f"0x{self.result_value:x}",
            "registers": {k: f"0x{v:x}" for k, v in self.registers.items()} if self.registers else None,
            "value_changed": self.value_changed,
        }
        if self.computed_address is not None:
            result["computed_address"] = f"0x{self.computed_address:x}"
        return result


@dataclass
class TaintTraceResult:
    """
    Result of full taint analysis.

    Contains the trace steps showing how data flowed through the program,
    following ALL input operands for computed operations. This enables
    tracking values through arithmetic operations like XOR, ADD, etc.
    """
    success: bool
    steps: List[TaintStep] = field(default_factory=list)
    taint_sources: List[TaintSource] = field(default_factory=list)  # All identified origins
    active_taint_set: List[str] = field(default_factory=list)  # Registers/memory still being tracked
    termination_reason: str = ""
    steps_executed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "steps": [s.to_dict() for s in self.steps],
            "step_count": len(self.steps),
            "taint_sources": [s.to_dict() for s in self.taint_sources],
            "taint_source_count": len(self.taint_sources),
            "active_taint_set": self.active_taint_set,
            "termination_reason": self.termination_reason,
            "steps_executed": self.steps_executed,
        }
