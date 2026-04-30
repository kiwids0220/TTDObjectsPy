"""
TTD Type Definitions

This module defines Python types matching the TTD SDK's C++ types from:
- TTDCommonTypes.h
- IdnaBasicTypes.h  
- IReplayEngine.h

These types are designed to be:
1. Easy to use from Python
2. Compatible with ctypes for native interop
3. Serializable for MCP communication
"""

from __future__ import annotations

import ctypes
from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64, c_int64, c_size_t, c_wchar, c_wchar_p, c_void_p, c_bool
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Optional, Tuple, ClassVar
from uuid import UUID


# =============================================================================
# Basic Types (from IdnaBasicTypes.h)
# =============================================================================

class GuestAddress(int):
    """
    64-bit address in the guest process.
    Even for 32-bit guests, this is 64-bit (high bits should be zero).
    """
    def __new__(cls, value: int = 0):
        return super().__new__(cls, value & 0xFFFFFFFFFFFFFFFF)
    
    def __repr__(self) -> str:
        return f"GuestAddress(0x{self:016x})"
    
    def __str__(self) -> str:
        return f"0x{self:x}"


class SequenceId(int):
    """
    Timeline sequence identifier.
    Sequences are ordered and monotonically increasing.
    """
    INVALID = 0xFFFFFFFFFFFFFFFF
    MIN = 0
    MAX = 0xFFFFFFFFFFFFFFFE
    
    def __new__(cls, value: int = 0):
        return super().__new__(cls, value & 0xFFFFFFFFFFFFFFFF)
    
    def is_valid(self) -> bool:
        return self != SequenceId.INVALID
    
    def __repr__(self) -> str:
        if self == SequenceId.INVALID:
            return "SequenceId.INVALID"
        return f"SequenceId(0x{self:x})"


class StepCount(int):
    """
    Number of steps within a sequence.
    Steps are atomic advances (instructions + non-instruction events).
    """
    ZERO = 0
    MIN = 0
    MAX = 0xFFFFFFFFFFFFFFFE
    INVALID = 0xFFFFFFFFFFFFFFFF
    
    def __new__(cls, value: int = 0):
        return super().__new__(cls, value & 0xFFFFFFFFFFFFFFFF)


class ThreadId(int):
    """OS Thread ID (may be reused across different threads)."""
    INVALID = 0
    
    def __new__(cls, value: int = 0):
        return super().__new__(cls, value & 0xFFFFFFFF)


class UniqueThreadId(int):
    """Unique thread identifier within the trace (never reused)."""
    INVALID = 0
    MIN = 1
    MAX = 0xFFFFFFFF
    
    def __new__(cls, value: int = 0):
        return super().__new__(cls, value & 0xFFFFFFFF)
    
    def is_valid(self) -> bool:
        return self != UniqueThreadId.INVALID


# =============================================================================
# Position Types (from IReplayEngine.h)
# =============================================================================

@dataclass(frozen=True)
class Position:
    """
    128-bit position in TTD timeline.
    
    A position uniquely identifies a single instruction execution in the trace.
    Positions are monotonically increasing and can be compared numerically.
    
    Format: Sequence:Steps (both in hex)
    Example: "3df:1234" means sequence 0x3df, step 0x1234
    """
    sequence: int = 0
    steps: int = 0
    
    def is_valid(self) -> bool:
        """Check if this is a valid position."""
        return self.sequence != SequenceId.INVALID
    
    def to_string(self) -> str:
        """Format as 'seq:steps' in hex."""
        return f"{self.sequence:x}:{self.steps:x}"
    
    def __str__(self) -> str:
        # Check against known constants by value comparison
        if self.sequence == SequenceId.INVALID and self.steps == 0:
            return "Position.INVALID"
        if self.sequence == 0 and self.steps == 0:
            return "Position.MIN"
        if self.sequence == SequenceId.MAX and self.steps == StepCount.MAX:
            return "Position.MAX"
        return self.to_string()
    
    def __repr__(self) -> str:
        return f"Position({self.to_string()})"
    
    @classmethod
    def from_string(cls, s: str) -> "Position":
        """Parse from 'seq:steps' hex format."""
        if ":" not in s:
            raise ValueError(f"Invalid position format: {s} (expected 'seq:steps')")
        seq_str, steps_str = s.split(":", 1)
        return cls(int(seq_str, 16), int(steps_str, 16))
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "sequence": self.sequence,
            "steps": self.steps,
            "formatted": self.to_string()
        }
    
    def __lt__(self, other: "Position") -> bool:
        return (self.sequence, self.steps) < (other.sequence, other.steps)
    
    def __le__(self, other: "Position") -> bool:
        return (self.sequence, self.steps) <= (other.sequence, other.steps)
    
    def __gt__(self, other: "Position") -> bool:
        return (self.sequence, self.steps) > (other.sequence, other.steps)
    
    def __ge__(self, other: "Position") -> bool:
        return (self.sequence, self.steps) >= (other.sequence, other.steps)
    
    def __add__(self, steps: int) -> "Position":
        """Add steps to position."""
        new_steps = self.steps + steps
        if new_steps < self.steps:  # Overflow
            return Position(self.sequence + 1, new_steps)
        return Position(self.sequence, new_steps)
    
    def __sub__(self, steps: int) -> "Position":
        """Subtract steps from position."""
        new_steps = self.steps - steps
        if new_steps > self.steps:  # Underflow
            return Position(self.sequence - 1, new_steps)
        return Position(self.sequence, new_steps)
    
    @classmethod
    def get_invalid(cls) -> "Position":
        """Get the invalid position constant."""
        return cls(SequenceId.INVALID, 0)
    
    @classmethod
    def get_min(cls) -> "Position":
        """Get the minimum position constant."""
        return cls(0, 0)
    
    @classmethod
    def get_max(cls) -> "Position":
        """Get the maximum position constant."""
        return cls(SequenceId.MAX, StepCount.MAX)


# Define Position constants after class definition
Position.INVALID = Position.get_invalid()
Position.MIN = Position.get_min()
Position.MAX = Position.get_max()


@dataclass(frozen=True)
class PositionRange:
    """
    Closed range of positions [min, max].
    Both min and max are valid positions within the range.
    """
    min: Position = field(default_factory=Position.get_invalid)
    max: Position = field(default_factory=Position.get_invalid)
    
    def is_valid(self) -> bool:
        return self.min.is_valid() and self.max.is_valid()
    
    def contains(self, position: Position) -> bool:
        """Check if position is within this range (closed interval)."""
        return self.min <= position <= self.max
    
    def to_string(self) -> str:
        return f"[{self.min.to_string()}, {self.max.to_string()}]"
    
    def __str__(self) -> str:
        return self.to_string()
    
    def to_dict(self) -> dict:
        return {
            "min": self.min.to_dict(),
            "max": self.max.to_dict()
        }
    
    @classmethod
    def get_invalid(cls) -> "PositionRange":
        """Get the invalid range constant."""
        return cls(Position.INVALID, Position.INVALID)


PositionRange.INVALID = PositionRange.get_invalid()


# =============================================================================
# Enumerations (from IReplayEngine.h)
# =============================================================================

class RecordingType(IntEnum):
    """TTD recording types."""
    INVALID = 0
    FULL = 1
    SELECTIVE = 2
    CHUNK = 3
    
    def __str__(self) -> str:
        return self.name


class DataAccessType(IntEnum):
    """Type of memory access for watchpoints."""
    READ = 0
    WRITE = 1
    EXECUTE = 2
    CODE_FETCH = 3
    OVERWRITE = 4
    DATA_MISMATCH = 5
    NEW_DATA = 6
    REDUNDANT_DATA = 7
    
    def __str__(self) -> str:
        return self.name
    
    def is_before_instruction(self) -> bool:
        """Returns True if this access type triggers before the instruction."""
        return self in (DataAccessType.EXECUTE, DataAccessType.CODE_FETCH)


class DataAccessMask(IntFlag):
    """Bitmask for memory access types."""
    NONE = 0
    READ = 1 << DataAccessType.READ
    WRITE = 1 << DataAccessType.WRITE
    EXECUTE = 1 << DataAccessType.EXECUTE
    CODE_FETCH = 1 << DataAccessType.CODE_FETCH
    OVERWRITE = 1 << DataAccessType.OVERWRITE
    DATA_MISMATCH = 1 << DataAccessType.DATA_MISMATCH
    NEW_DATA = 1 << DataAccessType.NEW_DATA
    REDUNDANT_DATA = 1 << DataAccessType.REDUNDANT_DATA
    
    READ_WRITE = READ | WRITE
    ALL = 0xFF


class EventType(IntEnum):
    """Replay event types - reasons why replay might stop."""
    MEMORY_WATCHPOINT = 0
    POSITION_WATCHPOINT = 1
    EXCEPTION = 2
    GAP = 3
    THREAD = 4
    STEP_COUNT = 5
    POSITION = 6
    PROCESS = 7
    INTERRUPTED = 8
    ERROR = 9
    
    def __str__(self) -> str:
        return self.name


class EventMask(IntFlag):
    """Bitmask for event types."""
    NONE = 0
    MEMORY_WATCHPOINT = 1 << EventType.MEMORY_WATCHPOINT
    POSITION_WATCHPOINT = 1 << EventType.POSITION_WATCHPOINT
    EXCEPTION = 1 << EventType.EXCEPTION
    GAP = 1 << EventType.GAP
    THREAD = 1 << EventType.THREAD
    
    ALL = MEMORY_WATCHPOINT | POSITION_WATCHPOINT | EXCEPTION | GAP | THREAD


class QueryMemoryPolicy(IntEnum):
    """Policy for memory queries."""
    DEFAULT = 0
    THREAD_LOCAL = 1
    GLOBALLY_CONSERVATIVE = 2
    GLOBALLY_AGGRESSIVE = 3
    IN_FRAGMENT_AGGRESSIVE = 4
    
    def __str__(self) -> str:
        return self.name


class GapKind(IntEnum):
    """Kind of gap in execution."""
    NO_GAP = 0
    CONTEXT_SWITCH = 1
    UNRECORDED = 2
    LARGE = 3
    
    def __str__(self) -> str:
        return self.name


class GapKindMask(IntFlag):
    """Bitmask for gap kinds."""
    NONE = 0
    NO_GAP = 1 << GapKind.NO_GAP
    CONTEXT_SWITCH = 1 << GapKind.CONTEXT_SWITCH
    UNRECORDED = 1 << GapKind.UNRECORDED
    LARGE = 1 << GapKind.LARGE
    
    ALL = NO_GAP | CONTEXT_SWITCH | UNRECORDED | LARGE


class GapEventType(IntEnum):
    """Types of gap events."""
    SYNTHETIC_SEQUENCE = 0
    CODE_CACHE_FLUSH = 1
    PRE_ATOMIC_OPERATION = 2
    POTENTIAL_ATOMIC_COLLISION = 3
    ETW_EVENT = 4
    DEBUG_BREAK = 5
    FAST_FAIL = 6
    KERNEL_CALL = 7
    SYNTHETIC_FALLBACK = 8
    EXCEPTION_DISPATCH = 9
    UNKNOWN_INSTRUCTION = 10
    THREAD_SUSPENDED = 11
    SLIST_ROLLBACK = 12
    SYNC_POINT = 13
    PAUSE_EMULATION = 14
    STOP_EMULATION = 15
    THROTTLED = 16
    
    def __str__(self) -> str:
        return self.name


class GapEventType(IntEnum):
    """Gap event types."""
    ENTER = 0
    EXIT = 1

    def __str__(self) -> str:
        return self.name


class GapEventMask(IntFlag):
    """Bitmask for gap event types."""
    NONE = 0
    ENTER = 1 << GapEventType.ENTER
    EXIT = 1 << GapEventType.EXIT

    ALL = ENTER | EXIT


class ExceptionType(IntEnum):
    """Exception types."""
    HARDWARE = 0
    SOFTWARE = 1
    CPLUSPLUS = 2
    DEBUG_PRINT = 3

    def __str__(self) -> str:
        return self.name


class ExceptionMask(IntFlag):
    """Bitmask for exception types."""
    NONE = 0
    HARDWARE = 1 << ExceptionType.HARDWARE
    SOFTWARE = 1 << ExceptionType.SOFTWARE
    CPLUSPLUS = 1 << ExceptionType.CPLUSPLUS
    DEBUG_PRINT = 1 << ExceptionType.DEBUG_PRINT

    ALL = HARDWARE | SOFTWARE | CPLUSPLUS | DEBUG_PRINT


class ReplayFlags(IntFlag):
    """Flags that modify replay behavior."""
    NONE = 0
    DEFAULT = 0
    REPLAY_ONLY_CURRENT_THREAD = 0x0001
    REPLAY_ALL_SEGMENTS_WITHOUT_FILTERING = 0x0002
    REPLAY_SEGMENTS_SEQUENTIALLY = 0x0004
    
    ALL = (REPLAY_ONLY_CURRENT_THREAD | 
           REPLAY_ALL_SEGMENTS_WITHOUT_FILTERING |
           REPLAY_SEGMENTS_SEQUENTIALLY)


class IndexStatus(IntEnum):
    """Status of the trace index."""
    INDEX_FILE_LOADED = 0
    INDEX_FILE_NOT_PRESENT = 1
    INDEX_FILE_UNLOADABLE = 2


class IndexBuildFlags(IntFlag):
    """Flags for building the index."""
    NONE = 0
    DELETE_EXISTING_UNLOADABLE_INDEX_FILE = 0x01
    TEMPORARY_INDEX_FILE = 0x02
    MAKE_SELF_CONTAINED = 0x04
    
    ALL = (DELETE_EXISTING_UNLOADABLE_INDEX_FILE |
           TEMPORARY_INDEX_FILE |
           MAKE_SELF_CONTAINED)


# =============================================================================
# Data Structures (from IReplayEngine.h)
# =============================================================================

@dataclass
class ThreadInfo:
    """Metadata about a thread in the trace."""
    unique_id: UniqueThreadId
    thread_id: ThreadId
    lifetime: PositionRange
    active_time: PositionRange
    
    def to_dict(self) -> dict:
        return {
            "unique_id": int(self.unique_id),
            "thread_id": int(self.thread_id),
            "lifetime": self.lifetime.to_dict(),
            "active_time": self.active_time.to_dict()
        }


@dataclass
class Module:
    """Information about a loaded module."""
    name: str
    address: GuestAddress
    size: int
    checksum: int
    timestamp: int
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": str(self.address),
            "size": self.size,
            "checksum": f"0x{self.checksum:08x}",
            "timestamp": self.timestamp
        }


@dataclass
class ModuleInstance:
    """Instance of a module load/unload."""
    module: Module
    load_time: SequenceId
    unload_time: SequenceId
    
    def to_dict(self) -> dict:
        return {
            "module": self.module.to_dict(),
            "load_time": f"0x{self.load_time:x}",
            "unload_time": f"0x{self.unload_time:x}" if self.unload_time != SequenceId.INVALID else None
        }


@dataclass
class ExceptionEvent:
    """Information about an exception that occurred."""
    position: Position
    thread_id: UniqueThreadId
    exception_type: ExceptionType
    code: int
    flags: int
    program_counter: GuestAddress
    parameters: Tuple[int, ...]
    
    def to_dict(self) -> dict:
        return {
            "position": self.position.to_dict(),
            "thread_id": int(self.thread_id),
            "type": str(self.exception_type),
            "code": f"0x{self.code:08x}",
            "flags": f"0x{self.flags:08x}",
            "program_counter": str(self.program_counter),
            "parameters": [f"0x{p:x}" for p in self.parameters]
        }


@dataclass
class MemoryWatchpointData:
    """Configuration for a memory watchpoint."""
    address: GuestAddress
    size: int
    access_mask: DataAccessMask
    thread_id: UniqueThreadId = field(default_factory=lambda: UniqueThreadId(0))
    
    def to_dict(self) -> dict:
        return {
            "address": str(self.address),
            "size": self.size,
            "access_mask": str(self.access_mask),
            "thread_id": int(self.thread_id) if self.thread_id != UniqueThreadId.INVALID else None
        }


@dataclass
class PositionWatchpointData:
    """Configuration for a position (time-based) watchpoint."""
    positions: PositionRange
    thread_id: UniqueThreadId = field(default_factory=lambda: UniqueThreadId(0))
    
    def to_dict(self) -> dict:
        return {
            "positions": self.positions.to_dict(),
            "thread_id": int(self.thread_id) if self.thread_id != UniqueThreadId.INVALID else None
        }


@dataclass
class MemoryWatchpointResult:
    """Result when a memory watchpoint is hit."""
    address: GuestAddress
    size: int
    access_type: DataAccessType
    
    def to_dict(self) -> dict:
        return {
            "address": str(self.address),
            "size": self.size,
            "access_type": str(self.access_type)
        }


@dataclass
class GapData:
    """Information about a gap event."""
    kind: GapKind
    event_type: GapEventType
    
    def to_dict(self) -> dict:
        return {
            "kind": str(self.kind),
            "event_type": str(self.event_type)
        }


@dataclass
class ReplayResult:
    """Result of a replay operation."""
    stop_reason: EventType
    steps_executed: int
    instructions_executed: int
    # Event-specific data (only one is valid based on stop_reason)
    memory_watchpoint: Optional[MemoryWatchpointResult] = None
    position_watchpoint: Optional[Position] = None
    gap_data: Optional[GapData] = None
    exception: Optional[ExceptionEvent] = None
    
    def to_dict(self) -> dict:
        result = {
            "stop_reason": str(self.stop_reason),
            "steps_executed": self.steps_executed,
            "instructions_executed": self.instructions_executed
        }
        if self.memory_watchpoint:
            result["memory_watchpoint"] = self.memory_watchpoint.to_dict()
        if self.position_watchpoint:
            result["position_watchpoint"] = self.position_watchpoint.to_dict()
        if self.gap_data:
            result["gap_data"] = self.gap_data.to_dict()
        if self.exception:
            result["exception"] = self.exception.to_dict()
        return result


@dataclass
class MemoryRange:
    """A range of memory from a single position."""
    address: GuestAddress
    data: bytes
    sequence: SequenceId
    
    def to_dict(self) -> dict:
        return {
            "address": str(self.address),
            "size": len(self.data),
            "sequence": f"0x{self.sequence:x}",
            "hex": self.data.hex()
        }


@dataclass
class MemoryBuffer:
    """Memory buffer possibly from multiple positions."""
    address: GuestAddress
    data: bytes
    
    def to_dict(self) -> dict:
        return {
            "address": str(self.address),
            "size": len(self.data),
            "hex": self.data.hex()
        }


# =============================================================================
# ctypes Structures (for native interop)
# =============================================================================

class CTTDPosition(Structure):
    """C structure for TTD::Replay::Position."""
    _fields_ = [
        ("Sequence", c_uint64),
        ("Steps", c_uint64),
    ]
    
    def to_python(self) -> Position:
        return Position(self.Sequence, self.Steps)
    
    @classmethod
    def from_python(cls, pos: Position) -> "CTTDPosition":
        return cls(pos.sequence, pos.steps)


class CTTDPositionRange(Structure):
    """C structure for TTD::Replay::PositionRange."""
    _fields_ = [
        ("Min", CTTDPosition),
        ("Max", CTTDPosition),
    ]
    
    def to_python(self) -> PositionRange:
        return PositionRange(self.Min.to_python(), self.Max.to_python())


class CTTDThreadInfo(Structure):
    """C structure for TTD::Replay::ThreadInfo."""
    _fields_ = [
        ("UniqueId", c_uint32),
        ("Id", c_uint32),
        ("Lifetime", CTTDPositionRange),
        ("ActiveTime", CTTDPositionRange),
    ]
    
    def to_python(self) -> ThreadInfo:
        return ThreadInfo(
            unique_id=UniqueThreadId(self.UniqueId),
            thread_id=ThreadId(self.Id),
            lifetime=self.Lifetime.to_python(),
            active_time=self.ActiveTime.to_python()
        )


class CTTDModule(Structure):
    """C structure for TTD::Replay::Module."""
    _fields_ = [
        ("pName", c_wchar_p),
        ("NameLength", c_size_t),
        ("Address", c_uint64),
        ("Size", c_uint64),
        ("Checksum", c_uint32),
        ("Timestamp", c_uint32),
    ]
    
    def to_python(self) -> Module:
        name = self.pName[:self.NameLength] if self.pName else ""
        return Module(
            name=name,
            address=GuestAddress(self.Address),
            size=self.Size,
            checksum=self.Checksum,
            timestamp=self.Timestamp
        )


class CTTDModuleInstance(Structure):
    """C structure for TTD::Replay::ModuleInstance."""
    _fields_ = [
        ("pModule", ctypes.POINTER(CTTDModule)),
        ("LoadTime", c_uint64),
        ("UnloadTime", c_uint64),
    ]


class CTTDMemoryWatchpointData(Structure):
    """C structure for TTD::Replay::MemoryWatchpointData."""
    _fields_ = [
        ("Address", c_uint64),
        ("Size", c_uint64),
        ("AccessMask", c_uint8),
        ("_pad", c_uint8 * 3),
        ("ThreadId", c_uint32),
    ]
    
    @classmethod
    def from_python(cls, data: MemoryWatchpointData) -> "CTTDMemoryWatchpointData":
        return cls(
            Address=int(data.address),
            Size=data.size,
            AccessMask=int(data.access_mask),
            ThreadId=int(data.thread_id)
        )


class CTTDPositionWatchpointData(Structure):
    """C structure for TTD::Replay::PositionWatchpointData."""
    _fields_ = [
        ("Positions", CTTDPositionRange),
        ("ThreadId", c_uint32),
        ("_pad", c_uint32),
    ]
    
    @classmethod
    def from_python(cls, data: PositionWatchpointData) -> "CTTDPositionWatchpointData":
        return cls(
            Positions=CTTDPositionRange(
                CTTDPosition.from_python(data.positions.min),
                CTTDPosition.from_python(data.positions.max)
            ),
            ThreadId=int(data.thread_id)
        )


class CTTDMemoryWatchpointResult(Structure):
    """C structure for ICursorView::MemoryWatchpointResult."""
    _fields_ = [
        ("Address", c_uint64),
        ("Size", c_uint64),
        ("AccessType", c_uint8),
        ("_pad", c_uint8 * 7),
    ]
    
    def to_python(self) -> MemoryWatchpointResult:
        return MemoryWatchpointResult(
            address=GuestAddress(self.Address),
            size=self.Size,
            access_type=DataAccessType(self.AccessType)
        )


class CTTDGapData(Structure):
    """C structure for TTD::Replay::GapData."""
    _fields_ = [
        ("Kind", c_uint8),
        ("Event", c_uint8),
    ]
    
    def to_python(self) -> GapData:
        return GapData(
            kind=GapKind(self.Kind),
            event_type=GapEventType(self.Event)
        )


class CTTDReplayResult(Structure):
    """C structure for ICursorView::ReplayResult."""
    _fields_ = [
        ("StopReason", c_uint8),
        ("_pad1", c_uint8 * 7),
        ("StepsExecuted", c_uint64),
        ("InstructionsExecuted", c_uint64),
        # Union - we'll use the largest member
        ("_union_data", c_uint8 * 128),
    ]


class CTTDMemoryRange(Structure):
    """C structure for TTD::Replay::MemoryRange."""
    _fields_ = [
        ("Address", c_uint64),
        ("pMemory", c_void_p),
        ("Size", c_size_t),
        ("Sequence", c_uint64),
    ]


class CTTDMemoryBuffer(Structure):
    """C structure for TTD::Replay::MemoryBuffer."""
    _fields_ = [
        ("Address", c_uint64),
        ("pMemory", c_void_p),
        ("Size", c_size_t),
    ]


class CTTDMemoryBufferWithRanges(Structure):
    """C structure for TTD::Replay::MemoryBufferWithRanges."""
    _fields_ = [
        ("Buffer", CTTDMemoryBuffer),
        ("pRanges", c_void_p),  # Pointer to CTTDMemoryRange array
        ("RangeCount", c_size_t),
    ]


class CTTDBufferView(Structure):
    """C structure for TTD::BufferView (non-const)."""
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("Size", c_size_t),
    ]


class CTTDConstBufferView(Structure):
    """C structure for TTD::ConstBufferView."""
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("Size", c_size_t),
    ]


# Register context - 2672 bytes union
class CTTDRegisterContext(Structure):
    """C structure for TTD::Replay::RegisterContext."""
    _fields_ = [
        ("Data", c_uint64 * (2672 // 8)),
    ]


# Extended register context - 8832 bytes union
class CTTDExtendedRegisterContext(Structure):
    """C structure for TTD::Replay::ExtendedRegisterContext."""
    _fields_ = [
        ("Data", c_uint64 * (8832 // 8)),
    ]


# =============================================================================
# System and Hardware Information
# =============================================================================

class CTTDTimingInfo(Structure):
    """C structure for TTD::TimingInfo.

    From IdnaBasicTypes.h:
        struct TimingInfo {
            uint64_t SystemTime;
            uint64_t ProcessCreateTime;
            uint64_t ProcessUserTime;
            uint64_t ProcessKernelTime;
            uint64_t SystemUpTime;
        };
    """
    _fields_ = [
        ("SystemTime", c_uint64),
        ("ProcessCreateTime", c_uint64),
        ("ProcessUserTime", c_uint64),
        ("ProcessKernelTime", c_uint64),
        ("SystemUpTime", c_uint64),
    ]


class CTTDSystemInfoCpu(Structure):
    """CPU info union (X86 variant) inside SystemInfo.System."""
    _fields_ = [
        ("VendorId", c_uint32 * 3),           # 12 bytes
        ("VersionInformation", c_uint32),      # 4 bytes
        ("FeatureInformation", c_uint32),      # 4 bytes
        ("AMDExtendedCpuFeatures", c_uint32),  # 4 bytes
    ]


class CTTDSystemInfoSystem(Structure):
    """Nested System struct inside SystemInfo.

    From IdnaBasicTypes.h - nested struct inside SystemInfo.
    """
    _fields_ = [
        ("ProcessorArchitecture", c_uint16),
        ("ProcessorLevel", c_uint16),
        ("ProcessorRevision", c_uint16),
        ("NumberOfProcessors", c_uint8),
        ("ProductType", c_uint8),
        ("MajorVersion", c_uint32),
        ("MinorVersion", c_uint32),
        ("BuildNumber", c_uint32),
        ("PlatformId", c_uint32),
        ("CSDVersionRva", c_uint32),
        ("SuiteMask", c_uint16),
        ("Reserved2", c_uint16),
        ("Cpu", CTTDSystemInfoCpu),           # 24 bytes union
    ]


class CTTDSystemInfo(Structure):
    """C structure for TTD::SystemInfo.

    From IdnaBasicTypes.h:
        struct SystemInfo {
            uint32_t MajorVersion;
            uint32_t MinorVersion;
            uint32_t BuildNumber;
            uint32_t ProcessId;
            TimingInfo Time;
            struct { ... } System;
            char16_t UserName[64];
            char16_t SystemName[64];
        };
    """
    _fields_ = [
        ("MajorVersion", c_uint32),           # 4 bytes - Log major version
        ("MinorVersion", c_uint32),           # 4 bytes - Log minor version
        ("BuildNumber", c_uint32),            # 4 bytes - Log build version
        ("ProcessId", c_uint32),              # 4 bytes - System Process Id
        ("Time", CTTDTimingInfo),             # 40 bytes
        ("System", CTTDSystemInfoSystem),     # 48 bytes
        ("UserName", c_wchar * 64),           # 128 bytes
        ("SystemName", c_wchar * 64),         # 128 bytes
    ]


# =============================================================================
# Thread and Module Events
# =============================================================================

class CTTDActiveThreadInfo(Structure):
    """C structure for TTD::Replay::ActiveThreadInfo."""
    _fields_ = [
        ("UniqueId", c_uint32),
        ("Id", c_uint32),
        ("Position", CTTDPosition),
    ]


class CTTDThreadCreatedEvent(Structure):
    """C structure for TTD::Replay::ThreadCreatedEvent.

    From IReplayEngine.h:
        struct ThreadCreatedEvent {
            Position          Position;
            ThreadInfo const* pThreadInfo;
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),                       # 16 bytes
        ("pThreadInfo", ctypes.POINTER(CTTDThreadInfo)),  # 8 bytes
    ]


class CTTDThreadTerminatedEvent(Structure):
    """C structure for TTD::Replay::ThreadTerminatedEvent.

    From IReplayEngine.h:
        struct ThreadTerminatedEvent {
            Position          Position;
            ThreadInfo const* pThreadInfo;
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),                       # 16 bytes
        ("pThreadInfo", ctypes.POINTER(CTTDThreadInfo)),  # 8 bytes
    ]


class CTTDModuleLoadedEvent(Structure):
    """C structure for TTD::Replay::ModuleLoadedEvent.

    From IReplayEngine.h:
        struct ModuleLoadedEvent {
            Position      Position;
            Module const* pModule;
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),               # 16 bytes
        ("pModule", ctypes.POINTER(CTTDModule)),  # 8 bytes
    ]


class CTTDModuleUnloadedEvent(Structure):
    """C structure for TTD::Replay::ModuleUnloadedEvent.

    From IReplayEngine.h:
        struct ModuleUnloadedEvent {
            Position      Position;
            Module const* pModule;
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),               # 16 bytes
        ("pModule", ctypes.POINTER(CTTDModule)),  # 8 bytes
    ]


class CTTDExceptionEvent(Structure):
    """C structure for TTD::Replay::ExceptionEvent.

    From IReplayEngine.h:
        struct ExceptionEvent {
            Position          Position;
            ThreadInfo const* pThreadInfo;
            ExceptionType     Type;           // uint8_t enum
            uint32_t          Code;
            uint32_t          Flags;
            GuestAddress      RecordAddress;
            GuestAddress      ProgramCounter;
            uint32_t          ParameterCount;
            uint64_t          Parameters[15];
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),           # 16 bytes
        ("pThreadInfo", c_void_p),            # 8 bytes - pointer to ThreadInfo
        ("Type", c_uint8),                    # 1 byte - ExceptionType enum
        ("_pad0", c_uint8 * 3),               # 3 bytes padding
        ("Code", c_uint32),                   # 4 bytes - exception code (e.g. 0xc0000005)
        ("Flags", c_uint32),                  # 4 bytes
        ("_padding", c_uint32),               # 4 bytes padding for alignment
        ("RecordAddress", c_uint64),          # 8 bytes - GuestAddress
        ("ProgramCounter", c_uint64),         # 8 bytes - GuestAddress (PC/RIP)
        ("ParameterCount", c_uint32),         # 4 bytes
        ("_padding2", c_uint32),              # 4 bytes padding
        ("Parameters", c_uint64 * 15),        # 120 bytes
    ]


# =============================================================================
# Trace Metadata and Events
# =============================================================================

class GUID(Structure):
    """Windows GUID structure."""
    _fields_ = [
        ("Data1", c_uint32),
        ("Data2", c_uint16),
        ("Data3", c_uint16),
        ("Data4", c_uint8 * 8),
    ]


class CTTDRecordClient(Structure):
    """C structure for TTD::RecordClient.

    From IReplayEngine.h:
        struct RecordClient {
            RecordClientId  Id;
            GUID            ClientGuid;
            PositionRange   Lifetime;
            ConstBufferView OpenUserData;
            ConstBufferView CloseUserData;
        };
    """
    _fields_ = [
        ("Id", c_uint32),                     # 4 bytes
        ("_pad0", c_uint32),                  # 4 bytes padding
        ("ClientGuid", GUID),                 # 16 bytes
        ("Lifetime", CTTDPositionRange),      # 32 bytes
        ("OpenUserData_BaseAddress", c_void_p),   # 8 bytes
        ("OpenUserData_Size", c_size_t),          # 8 bytes
        ("CloseUserData_BaseAddress", c_void_p),  # 8 bytes
        ("CloseUserData_Size", c_size_t),         # 8 bytes
    ]


class CTTDCustomEvent(Structure):
    """C structure for TTD::CustomEvent.

    From IReplayEngine.h:
        struct CustomEvent {
            Position            Position;
            ThreadInfo const*   pThreadInfo;
            RecordClient const* pRecordClient;
            ConstBufferView     UserData;
        };
    """
    _fields_ = [
        ("Position", CTTDPosition),                        # 16 bytes
        ("pThreadInfo", ctypes.POINTER(CTTDThreadInfo)),   # 8 bytes
        ("pRecordClient", c_void_p),                       # 8 bytes (using void* to avoid forward ref)
        ("UserData_BaseAddress", c_void_p),                # 8 bytes
        ("UserData_Size", c_size_t),                       # 8 bytes
    ]


class CTTDActivity(Structure):
    """C structure for TTD::Activity.

    From IReplayEngine.h:
        struct Activity {
            RecordClient const* pRecordClient;
            ActivityId          Id;
            PositionRange       Lifetime;
        };
    """
    _fields_ = [
        ("pRecordClient", c_void_p),          # 8 bytes (using void* to avoid forward ref)
        ("Id", c_uint32),                     # 4 bytes
        ("_pad0", c_uint32),                  # 4 bytes padding
        ("Lifetime", CTTDPositionRange),      # 32 bytes
    ]


class CTTDIsland(Structure):
    """C structure for TTD::Island.

    From IReplayEngine.h:
        struct Island {
            PositionRange     Lifetime;
            ThreadInfo const* pThreadInfo;
            Activity const*   pActivity;
            ConstBufferView   UserData;
        };
    """
    _fields_ = [
        ("Lifetime", CTTDPositionRange),                   # 32 bytes
        ("pThreadInfo", ctypes.POINTER(CTTDThreadInfo)),   # 8 bytes
        ("pActivity", c_void_p),                           # 8 bytes (using void* to avoid forward ref)
        ("UserData_BaseAddress", c_void_p),                # 8 bytes
        ("UserData_Size", c_size_t),                       # 8 bytes
    ]


# =============================================================================
# Index Status and Statistics
# =============================================================================

class CTTDIndexTreeStats(Structure):
    """C structure for TTD::IndexTreeStats.

    From IReplayEngine.h:
        struct IndexTreeStats {
            uint64_t m_size;
            uint64_t m_readCount;
            uint64_t m_writeCount;
            uint64_t m_flushCount;
            uint64_t m_flushWriteCount;
            uint64_t m_lookupCount;
            uint64_t m_lookupMissCount;
            uint64_t m_lookupSequencerInsertCount;
            uint64_t m_lookupSequencerResetCount;
            uint64_t m_externalGlobalLruCount;
            uint64_t m_externalSequenceNumberEvictionCount;
        };
    """
    _fields_ = [
        ("m_size", c_uint64),
        ("m_readCount", c_uint64),
        ("m_writeCount", c_uint64),
        ("m_flushCount", c_uint64),
        ("m_flushWriteCount", c_uint64),
        ("m_lookupCount", c_uint64),
        ("m_lookupMissCount", c_uint64),
        ("m_lookupSequencerInsertCount", c_uint64),
        ("m_lookupSequencerResetCount", c_uint64),
        ("m_externalGlobalLruCount", c_uint64),
        ("m_externalSequenceNumberEvictionCount", c_uint64),
    ]


class CTTDIndexFileStats(Structure):
    """C structure for TTD::IndexFileStats.

    From IReplayEngine.h:
        struct IndexFileStats {
            IndexTreeStats m_globalMemoryIndexStats;
            IndexTreeStats m_segmentMemoryIndexStats;
            uint64_t m_mapPageCallCount;
            uint64_t m_lockPageCallCount;
        };
    """
    _fields_ = [
        ("m_globalMemoryIndexStats", CTTDIndexTreeStats),   # 88 bytes
        ("m_segmentMemoryIndexStats", CTTDIndexTreeStats),  # 88 bytes
        ("m_mapPageCallCount", c_uint64),                   # 8 bytes
        ("m_lockPageCallCount", c_uint64),                  # 8 bytes
    ]


# =============================================================================
# Windows GUID
# =============================================================================

class GUID(Structure):
    """Windows GUID structure."""
    _fields_ = [
        ("Data1", c_uint32),
        ("Data2", c_uint16),
        ("Data3", c_uint16),
        ("Data4", c_uint8 * 8),
    ]
    
    @classmethod
    def from_uuid(cls, uuid_obj: UUID) -> "GUID":
        """Create GUID from Python UUID."""
        guid = cls()
        guid.Data1 = uuid_obj.time_low
        guid.Data2 = uuid_obj.time_mid
        guid.Data3 = uuid_obj.time_hi_version
        guid.Data4[0] = uuid_obj.clock_seq_hi_variant
        guid.Data4[1] = uuid_obj.clock_seq_low
        for i, b in enumerate(uuid_obj.node.to_bytes(6, 'big')):
            guid.Data4[2 + i] = b
        return guid
    
    def to_uuid(self) -> UUID:
        """Convert to Python UUID."""
        node = int.from_bytes(bytes(self.Data4[2:8]), 'big')
        return UUID(fields=(
            self.Data1,
            self.Data2,
            self.Data3,
            self.Data4[0],
            self.Data4[1],
            node
        ))


# Well-known interface GUIDs
IID_ICursorView = GUID.from_uuid(UUID("B1D2E6AB-9052-4B72-999E-A88BA868F899"))
IID_IReplayEngineView = GUID.from_uuid(UUID("4D3420A5-37EF-4114-AE91-63D0378C84A9"))
IID_ITraceListView = GUID.from_uuid(UUID("2DBF3602-669F-490A-962C-749D91C3A1A4"))
