"""
TTD Native Bindings

Low-level ctypes bindings to TTDReplay.dll.
This module handles DLL loading, vtable access, and native function calls.

The TTD SDK uses COM-style interfaces with virtual function tables (vtables).
We access these through careful vtable offset calculations.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import (
    CFUNCTYPE, POINTER, byref, c_bool, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p, c_wchar_p, cast
)
from pathlib import Path
from typing import Callable, Optional, Type, TypeVar

from ttdobjectspy.ttd_types import (
    GUID, IID_ICursorView, IID_IReplayEngineView,
    CTTDPosition, CTTDPositionRange, CTTDThreadInfo, CTTDModule,
    CTTDMemoryWatchpointData, CTTDPositionWatchpointData,
    CTTDMemoryWatchpointResult, CTTDReplayResult,
    CTTDMemoryRange, CTTDMemoryBuffer, CTTDMemoryBufferWithRanges, CTTDBufferView,
    CTTDRegisterContext, CTTDExtendedRegisterContext,
    CTTDSystemInfo, CTTDActiveThreadInfo, CTTDModuleInstance,
    CTTDThreadCreatedEvent, CTTDThreadTerminatedEvent,
    CTTDModuleLoadedEvent, CTTDModuleUnloadedEvent,
    CTTDExceptionEvent, CTTDRecordClient, CTTDCustomEvent,
    CTTDActivity, CTTDIsland, CTTDIndexFileStats,
    QueryMemoryPolicy, EventMask, GapKindMask, GapEventMask, ExceptionMask, ReplayFlags, IndexStatus,
)


# =============================================================================
# Configuration
# =============================================================================

def find_ttd_dll() -> Path:
    """
    Find TTDReplay.dll in common locations.

    Search order:
    1. TTD_DLL_PATH environment variable
    2. Project asset folder (auto-detects architecture)
    3. WinDbg installation paths
    4. Current directory

    Architecture detection:
    - 64-bit Python: Prefers asset/amd64/ttd/TTDReplay.dll, then legacy asset/TTDReplay.dll
    - 32-bit Python: Prefers asset/amd64/ttd/wow64/TTDReplay.dll, then legacy asset/wow64/TTDReplay.dll
    """
    import struct

    # Check environment variable first
    env_path = os.environ.get("TTD_DLL_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path

    # Detect Python architecture (not OS architecture)
    is_64bit = struct.calcsize("P") * 8 == 64

    # Get project root (parent of src directory)
    project_root = Path(__file__).parent.parent.parent
    asset_dir = project_root / "asset"

    # Build search paths based on architecture
    search_paths = []

    if asset_dir.exists():
        if is_64bit:
            # 64-bit Python - prefer installer-managed layout first
            search_paths.extend([
                asset_dir / "amd64" / "ttd" / "TTDReplay.dll",
                asset_dir / "TTDReplay.dll",  # Legacy flat asset layout
            ])
        else:
            # 32-bit Python - prefer installer-managed layout first
            search_paths.extend([
                asset_dir / "amd64" / "ttd" / "wow64" / "TTDReplay.dll",
                asset_dir / "wow64" / "TTDReplay.dll",  # Legacy flat asset layout
            ])

    # Add common WinDbg installation paths
    search_paths.extend([
        # WinDbg Preview
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "Microsoft.WinDbg_8wekyb3d8bbwe" / "TTDReplay.dll",
        # Installed WinDbg (64-bit)
        Path(r"C:\Program Files\Windows Kits\10\Debuggers\x64") / "TTDReplay.dll",
        Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64") / "TTDReplay.dll",
        # Current directory
        Path.cwd() / "TTDReplay.dll",
    ])

    for dll_path in search_paths:
        if dll_path.exists():
            return dll_path

    arch_str = "64-bit" if is_64bit else "32-bit"
    raise FileNotFoundError(
        f"TTDReplay.dll not found for {arch_str} Python. "
        f"Set TTD_DLL_PATH environment variable or place DLLs in asset/ folder."
    )


# =============================================================================
# Exceptions
# =============================================================================

class TTDError(Exception):
    """Base exception for TTD errors."""
    pass


class TTDDLLNotFoundError(TTDError):
    """TTDReplay.dll could not be found or loaded."""
    pass


class TTDInitializationError(TTDError):
    """Failed to initialize TTD engine or trace."""
    pass


class TTDNotInitializedError(TTDError):
    """Operation attempted before initialization."""
    pass


class TTDVTableError(TTDError):
    """Error accessing interface vtable."""
    pass


# =============================================================================
# VTable Helper
# =============================================================================

T = TypeVar('T')


class VTable:
    """
    Helper for calling COM-style virtual functions through vtables.
    
    In COM/C++ objects, the first pointer at the object address points to
    the vtable, which is an array of function pointers.
    """
    
    def __init__(self, obj_ptr):
        """
        Initialize vtable accessor.
        
        Args:
            obj_ptr: Pointer to the COM-style object (c_void_p or int)
        """
        # Handle both c_void_p and int (raw pointer value)
        if isinstance(obj_ptr, int):
            if obj_ptr == 0:
                raise TTDVTableError("Cannot create VTable from null pointer")
            obj_ptr = c_void_p(obj_ptr)
        elif not obj_ptr or not obj_ptr.value:
            raise TTDVTableError("Cannot create VTable from null pointer")
        
        self._obj_ptr = obj_ptr
        
        # Read vtable pointer (first pointer at object address)
        vtable_ptr_ptr = cast(obj_ptr, POINTER(c_void_p))
        self._vtable_ptr = vtable_ptr_ptr.contents
        
        if not self._vtable_ptr:
            raise TTDVTableError("Object has null vtable pointer")
    
    def get_func(self, index: int, func_type: Type[T]) -> T:
        """
        Get a function from the vtable.
        
        Args:
            index: Index in the vtable
            func_type: ctypes function type (e.g., CFUNCTYPE(...))
        
        Returns:
            Callable function
        """
        # Access vtable as array of pointers
        vtable = cast(self._vtable_ptr, POINTER(c_void_p * 200))
        func_ptr = vtable.contents[index]
        
        if not func_ptr:
            raise TTDVTableError(f"Null function pointer at vtable index {index}")
        
        return func_type(func_ptr)
    
    def call(self, index: int, func_type: Type[T], *args) -> any:
        """
        Call a vtable function.
        
        The 'this' pointer is automatically prepended to the arguments.
        
        Args:
            index: Index in the vtable
            func_type: ctypes function type
            *args: Additional arguments after 'this'
        
        Returns:
            Return value from the function
        """
        func = self.get_func(index, func_type)
        return func(self._obj_ptr, *args)


# =============================================================================
# IReplayEngineView VTable Indices
# =============================================================================

class EngineVTable:
    """
    VTable indices for IReplayEngineView and IReplayEngine.
    
    Based on the virtual method order in IReplayEngine.h.
    Note: The destructor is protected and declared at the END of the class,
    so it doesn't affect the vtable indices of the public methods.
    """
    # IReplayEngineView methods (starting at index 0)
    UNSAFE_AS_INTERFACE = 0
    UNSAFE_AS_INTERFACE_CONST = 1
    GET_PEB_ADDRESS = 2
    GET_SYSTEM_INFO = 3
    GET_FIRST_POSITION = 4
    GET_LAST_POSITION = 5
    GET_LIFETIME = 6
    GET_RECORDING_TYPE = 7
    GET_THREAD_INFO = 8
    GET_THREAD_COUNT = 9
    GET_THREAD_LIST = 10
    GET_THREAD_FIRST_POSITION_INDEX = 11
    GET_THREAD_LAST_POSITION_INDEX = 12
    GET_THREAD_LIFETIME_FIRST_POSITION_INDEX = 13
    GET_THREAD_LIFETIME_LAST_POSITION_INDEX = 14
    GET_THREAD_CREATED_EVENT_COUNT = 15
    GET_THREAD_CREATED_EVENT_LIST = 16
    GET_THREAD_TERMINATED_EVENT_COUNT = 17
    GET_THREAD_TERMINATED_EVENT_LIST = 18
    GET_MODULE_COUNT = 19
    GET_MODULE_LIST = 20
    GET_MODULE_INSTANCE_COUNT = 21
    GET_MODULE_INSTANCE_LIST = 22
    GET_MODULE_INSTANCE_UNLOAD_INDEX = 23
    GET_MODULE_LOADED_EVENT_COUNT = 24
    GET_MODULE_LOADED_EVENT_LIST = 25
    GET_MODULE_UNLOADED_EVENT_COUNT = 26
    GET_MODULE_UNLOADED_EVENT_LIST = 27
    GET_EXCEPTION_EVENT_COUNT = 28
    GET_EXCEPTION_EVENT_LIST = 29
    GET_EXCEPTION_AT_OR_AFTER_POSITION = 30
    GET_KEYFRAME_COUNT = 31
    GET_KEYFRAME_LIST = 32
    GET_RECORD_CLIENT_COUNT = 33
    GET_RECORD_CLIENT_LIST = 34
    GET_RECORD_CLIENT = 35
    GET_CUSTOM_EVENT_COUNT = 36
    GET_CUSTOM_EVENT_LIST = 37
    GET_ACTIVITY_COUNT = 38
    GET_ACTIVITY_LIST = 39
    GET_ISLAND_COUNT = 40
    GET_ISLAND_LIST = 41
    NEW_CURSOR = 42
    BUILD_INDEX = 43
    GET_INDEX_STATUS = 44
    GET_INDEX_FILE_STATS = 45
    REGISTER_DEBUG_MODE_AND_LOGGING = 46
    GET_INTERNALS = 47
    GET_INTERNALS_CONST = 48
    # Protected destructor is at end of IReplayEngineView = 49
    
    # IReplayEngine methods (extends IReplayEngineView)
    # ICursor::Destroy and IReplayEngine::Destroy/Initialize come after
    DESTROY = 50
    INITIALIZE = 51


# =============================================================================
# ICursorView VTable Indices
# =============================================================================

class CursorVTable:
    """
    VTable indices for ICursorView and ICursor.
    
    Based on the virtual method order in IReplayEngine.h.
    Note: The destructor is protected and declared at the END of ICursorView,
    so it doesn't affect the vtable indices of the public methods.
    """
    # Memory queries (indices 0-4)
    QUERY_MEMORY_RANGE = 0
    QUERY_MEMORY_BUFFER = 1
    QUERY_MEMORY_BUFFER_WITH_RANGES = 2
    SET_DEFAULT_MEMORY_POLICY = 3
    GET_DEFAULT_MEMORY_POLICY = 4
    
    # General queries (indices 5-7)
    UNSAFE_GET_REPLAY_ENGINE = 5
    UNSAFE_AS_INTERFACE = 6
    UNSAFE_AS_INTERFACE_CONST = 7
    
    # Context queries on any thread (indices 8-17)
    GET_THREAD_INFO = 8
    GET_TEB_ADDRESS = 9
    GET_POSITION = 10
    GET_PREVIOUS_POSITION = 11
    GET_PROGRAM_COUNTER = 12
    GET_STACK_POINTER = 13
    GET_FRAME_POINTER = 14
    GET_BASIC_RETURN_VALUE = 15
    GET_CROSS_PLATFORM_CONTEXT = 16
    GET_AVX_EXTENDED_CONTEXT = 17
    
    # Module/thread lists (indices 18-21)
    GET_MODULE_COUNT = 18
    GET_MODULE_LIST = 19
    GET_THREAD_COUNT = 20
    GET_THREAD_LIST = 21
    
    # Event masks (indices 22-31)
    SET_EVENT_MASK = 22
    GET_EVENT_MASK = 23
    SET_GAP_KIND_MASK = 24
    GET_GAP_KIND_MASK = 25
    SET_GAP_EVENT_MASK = 26
    GET_GAP_EVENT_MASK = 27
    SET_EXCEPTION_MASK = 28
    GET_EXCEPTION_MASK = 29
    SET_REPLAY_FLAGS = 30
    GET_REPLAY_FLAGS = 31
    
    # Watchpoints (indices 32-35)
    ADD_MEMORY_WATCHPOINT = 32
    REMOVE_MEMORY_WATCHPOINT = 33
    ADD_POSITION_WATCHPOINT = 34
    REMOVE_POSITION_WATCHPOINT = 35
    
    # Position control (indices 36-38)
    CLEAR = 36
    SET_POSITION = 37
    SET_POSITION_ON_THREAD = 38
    
    # Callbacks (indices 39-47)
    SET_MEMORY_WATCHPOINT_CALLBACK = 39
    SET_POSITION_WATCHPOINT_CALLBACK = 40
    SET_GAP_EVENT_CALLBACK = 41
    SET_THREAD_CONTINUITY_BREAK_CALLBACK = 42
    SET_REPLAY_PROGRESS_CALLBACK = 43
    SET_FALLBACK_CALLBACK = 44
    SET_CALL_RETURN_CALLBACK = 45
    SET_INDIRECT_JUMP_CALLBACK = 46
    SET_REGISTER_CHANGED_CALLBACK = 47
    
    # Replay (indices 48-50)
    REPLAY_FORWARD = 48
    REPLAY_BACKWARD = 49
    INTERRUPT_REPLAY = 50
    
    # Internals (indices 51-53)
    GET_INTERNALS = 51
    GET_INTERNALS_CONST = 52
    GET_INTERNAL_DATA = 53
    
    # Protected destructor ~ICursorView() = 54
    
    # ICursor extends ICursorView, adds Destroy at index 55
    DESTROY = 55


# =============================================================================
# Function Type Definitions
# =============================================================================

# Engine functions
FN_CreateReplayEngine = CFUNCTYPE(c_uint32, POINTER(c_void_p), POINTER(GUID))

# Engine vtable functions
FN_Engine_Initialize = CFUNCTYPE(c_bool, c_void_p, c_wchar_p)
FN_Engine_Destroy = CFUNCTYPE(None, c_void_p)
# These return Position const& which is a pointer to internal storage
FN_Engine_GetPositionRef = CFUNCTYPE(POINTER(CTTDPosition), c_void_p)
FN_Engine_GetPositionRangeRef = CFUNCTYPE(POINTER(CTTDPositionRange), c_void_p)
FN_Engine_GetSize = CFUNCTYPE(c_size_t, c_void_p)
FN_Engine_GetRecordingType = CFUNCTYPE(c_uint32, c_void_p)
FN_Engine_GetPebAddress = CFUNCTYPE(c_uint64, c_void_p)
FN_Engine_NewCursor = CFUNCTYPE(c_void_p, c_void_p, POINTER(GUID))
FN_Engine_GetThreadInfo = CFUNCTYPE(POINTER(CTTDThreadInfo), c_void_p, c_uint32)
FN_Engine_GetThreadList = CFUNCTYPE(POINTER(CTTDThreadInfo), c_void_p)
FN_Engine_GetModuleList = CFUNCTYPE(POINTER(CTTDModule), c_void_p)
FN_Engine_GetSystemInfo = CFUNCTYPE(POINTER(CTTDSystemInfo), c_void_p)
FN_Engine_GetPositionIndex = CFUNCTYPE(c_size_t, c_void_p, c_uint32)
FN_Engine_GetEventCount = CFUNCTYPE(c_size_t, c_void_p)
FN_Engine_GetEventList = CFUNCTYPE(c_void_p, c_void_p)
FN_Engine_GetModuleInstanceList = CFUNCTYPE(POINTER(CTTDModuleInstance), c_void_p)
FN_Engine_GetModuleInstanceUnloadIndex = CFUNCTYPE(c_size_t, c_void_p)
FN_Engine_GetExceptionAtOrAfterPosition = CFUNCTYPE(POINTER(CTTDExceptionEvent), c_void_p, POINTER(CTTDPosition))
FN_Engine_GetKeyframeList = CFUNCTYPE(POINTER(CTTDPosition), c_void_p)
FN_Engine_GetRecordClient = CFUNCTYPE(POINTER(CTTDRecordClient), c_void_p, c_uint32)
FN_Engine_GetIndexStatus = CFUNCTYPE(c_uint32, c_void_p)
FN_Engine_GetIndexFileStats = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDIndexFileStats))
FN_Engine_BuildIndex = CFUNCTYPE(None, c_void_p)

# Cursor vtable functions
FN_Cursor_Destroy = CFUNCTYPE(None, c_void_p)
FN_Cursor_Clear = CFUNCTYPE(None, c_void_p)
FN_Cursor_SetPosition = CFUNCTYPE(None, c_void_p, POINTER(CTTDPosition))
FN_Cursor_SetPositionOnThread = CFUNCTYPE(None, c_void_p, c_uint32, POINTER(CTTDPosition))
FN_Cursor_GetPosition = CFUNCTYPE(POINTER(CTTDPosition), c_void_p, c_uint32)
FN_Cursor_GetPreviousPosition = CFUNCTYPE(POINTER(CTTDPosition), c_void_p, c_uint32)
FN_Cursor_GetProgramCounter = CFUNCTYPE(c_uint64, c_void_p, c_uint32)
FN_Cursor_GetStackPointer = CFUNCTYPE(c_uint64, c_void_p, c_uint32)
FN_Cursor_GetFramePointer = CFUNCTYPE(c_uint64, c_void_p, c_uint32)
FN_Cursor_GetBasicReturnValue = CFUNCTYPE(c_uint64, c_void_p, c_uint32)
FN_Cursor_GetTebAddress = CFUNCTYPE(c_uint64, c_void_p, c_uint32)
FN_Cursor_GetCrossPlatformContext = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDRegisterContext), c_uint32)
FN_Cursor_GetThreadCount = CFUNCTYPE(c_size_t, c_void_p)
FN_Cursor_GetModuleCount = CFUNCTYPE(c_size_t, c_void_p)

FN_Cursor_QueryMemoryRange = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryRange), c_uint64, c_uint32)
FN_Cursor_QueryMemoryBuffer = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryBuffer), c_uint64, CTTDBufferView, c_uint32)

FN_Cursor_SetEventMask = CFUNCTYPE(None, c_void_p, c_uint32)
FN_Cursor_GetEventMask = CFUNCTYPE(c_uint32, c_void_p)
FN_Cursor_SetReplayFlags = CFUNCTYPE(None, c_void_p, c_uint32)
FN_Cursor_GetReplayFlags = CFUNCTYPE(c_uint32, c_void_p)

FN_Cursor_AddMemoryWatchpoint = CFUNCTYPE(c_bool, c_void_p, POINTER(CTTDMemoryWatchpointData))
FN_Cursor_RemoveMemoryWatchpoint = CFUNCTYPE(c_bool, c_void_p, POINTER(CTTDMemoryWatchpointData))
FN_Cursor_AddPositionWatchpoint = CFUNCTYPE(c_bool, c_void_p, POINTER(CTTDPositionWatchpointData))
FN_Cursor_RemovePositionWatchpoint = CFUNCTYPE(c_bool, c_void_p, POINTER(CTTDPositionWatchpointData))

FN_Cursor_ReplayForward = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDReplayResult), CTTDPosition, c_uint64)
FN_Cursor_ReplayBackward = CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDReplayResult), CTTDPosition, c_uint64)
FN_Cursor_InterruptReplay = CFUNCTYPE(None, c_void_p)

# Callback function types
FN_MemoryWatchpointCallback = CFUNCTYPE(c_bool, c_size_t, POINTER(CTTDMemoryWatchpointResult), c_void_p)
FN_PositionWatchpointCallback = CFUNCTYPE(c_bool, c_size_t, POINTER(CTTDPosition), c_void_p)
FN_GapEventCallback = CFUNCTYPE(c_bool, c_size_t, c_uint32, c_uint32, c_void_p)  # context, GapKind, GapEventType, IThreadView
FN_ThreadContinuityBreakCallback = CFUNCTYPE(None, c_size_t)  # context
FN_ReplayProgressCallback = CFUNCTYPE(None, c_size_t, POINTER(CTTDPosition))
FN_FallbackCallback = CFUNCTYPE(None, c_size_t, c_bool, c_uint64, c_size_t, c_void_p)  # context, synthetic, address, size, IThreadView
FN_CallReturnCallback = CFUNCTYPE(None, c_size_t, c_uint32, c_uint64, c_uint64, c_void_p)  # context, type, from, to, IThreadView
FN_IndirectJumpCallback = CFUNCTYPE(None, c_size_t, c_uint64, c_uint64, c_void_p)  # context, from, to, IThreadView
FN_RegisterChangedCallback = CFUNCTYPE(None, c_size_t, c_uint8, c_void_p, c_void_p, c_size_t, c_void_p)  # context, regId, pOld, pNew, size, IThreadView

FN_Cursor_SetMemoryWatchpointCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetPositionWatchpointCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetGapEventCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetThreadContinuityBreakCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetReplayProgressCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetFallbackCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetCallReturnCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetIndirectJumpCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)
FN_Cursor_SetRegisterChangedCallback = CFUNCTYPE(None, c_void_p, c_void_p, c_size_t)


# =============================================================================
# TTD DLL Wrapper
# =============================================================================

class TTDBindings:
    """
    Low-level bindings to TTDReplay.dll.

    This class handles:
    - DLL loading and initialization
    - Exported function access
    - Engine and cursor creation
    """

    _instance: Optional["TTDBindings"] = None
    _atexit_registered: bool = False

    # Track all active engines and cursors for cleanup
    _active_engines: list = []
    _active_cursors: list = []

    def __init__(self, dll_path: Optional[Path] = None):
        """
        Initialize TTD bindings.

        Args:
            dll_path: Path to TTDReplay.dll (auto-detected if not provided)
        """
        if dll_path is None:
            dll_path = find_ttd_dll()

        self._dll_path = dll_path
        self._dll: Optional[ctypes.CDLL] = None
        self._dll_dirs: list = []

        # Exported functions
        self._create_replay_engine: Optional[Callable] = None

        self._load_dll()
        self._register_atexit()

    @classmethod
    def _register_atexit(cls):
        """Register atexit handler to clean up all resources before Python exits."""
        if not cls._atexit_registered:
            import atexit
            atexit.register(cls._cleanup_all)
            cls._atexit_registered = True

    @classmethod
    def _cleanup_all(cls):
        """Clean up all active cursors and engines in the correct order."""
        # Destroy all cursors first (they depend on engines)
        for cursor in cls._active_cursors[:]:
            try:
                if cursor._ptr:
                    cursor.destroy()
            except Exception:
                pass
        cls._active_cursors.clear()

        # Then destroy all engines
        for engine in cls._active_engines[:]:
            try:
                if engine._ptr:
                    engine.destroy()
            except Exception:
                pass
        cls._active_engines.clear()

        # Clear singleton
        cls._instance = None

    @classmethod
    def get_instance(cls, dll_path: Optional[Path] = None) -> "TTDBindings":
        """Get singleton instance of TTD bindings."""
        if cls._instance is None:
            cls._instance = cls(dll_path)
        return cls._instance
    
    def _load_dll(self):
        """Load TTDReplay.dll and set up exported functions."""
        try:
            # Add DLL directories to the Windows loader search path.
            # The installer layout places TTDReplay.dll in asset/amd64/ttd
            # and dbgeng/dbghelp siblings in asset/amd64.
            dll_dirs = [self._dll_path.parent]
            runtime_dir = self._dll_path.parent.parent
            if runtime_dir != self._dll_path.parent and (runtime_dir / "dbgeng.dll").exists():
                dll_dirs.append(runtime_dir)

            for dll_dir in dll_dirs:
                self._dll_dirs.append(os.add_dll_directory(str(dll_dir)))

            # Load the DLL
            self._dll = ctypes.CDLL(str(self._dll_path))
            
            # Set up CreateReplayEngine
            self._create_replay_engine = self._dll.CreateReplayEngine
            self._create_replay_engine.argtypes = [POINTER(c_void_p), POINTER(GUID)]
            self._create_replay_engine.restype = c_uint32
            
            print(f"[TTD] Loaded TTDReplay.dll from {self._dll_path}", file=sys.stderr)
            
        except OSError as e:
            raise TTDDLLNotFoundError(f"Failed to load TTDReplay.dll: {e}")
    
    def create_replay_engine(self) -> c_void_p:
        """
        Create a new replay engine instance.
        
        Returns:
            Pointer to IReplayEngine interface
        """
        engine_ptr = c_void_p()
        guid = IID_IReplayEngineView
        
        result = self._create_replay_engine(byref(engine_ptr), byref(guid))
        
        if result != 0 or not engine_ptr.value:
            raise TTDInitializationError(f"CreateReplayEngine failed with code {result}")
        
        return engine_ptr
    
    @property
    def dll_path(self) -> Path:
        """Path to the loaded DLL."""
        return self._dll_path


# =============================================================================
# Native Engine Interface
# =============================================================================

class NativeEngine:
    """
    Native interface to IReplayEngine.

    Wraps vtable calls to the engine interface.
    """

    def __init__(self, engine_ptr: c_void_p):
        """
        Initialize native engine wrapper.

        Args:
            engine_ptr: Pointer to IReplayEngine
        """
        self._ptr = engine_ptr
        self._vtable = VTable(engine_ptr)
        self._initialized = False
        # Register for cleanup tracking
        TTDBindings._active_engines.append(self)

    def initialize(self, trace_path: str) -> bool:
        """
        Initialize the engine with a trace file.

        Args:
            trace_path: Path to .run/.ttd/.idx file

        Returns:
            True if successful
        """
        func = self._vtable.get_func(EngineVTable.INITIALIZE, FN_Engine_Initialize)
        result = func(self._ptr, trace_path)
        self._initialized = result
        return result

    def destroy(self):
        """Destroy the engine and release resources."""
        if self._ptr:
            func = self._vtable.get_func(EngineVTable.DESTROY, FN_Engine_Destroy)
            func(self._ptr)
            self._ptr = None
            # Remove from tracking
            if self in TTDBindings._active_engines:
                TTDBindings._active_engines.remove(self)
    
    def get_peb_address(self) -> int:
        """Get the PEB address of the traced process."""
        func = self._vtable.get_func(EngineVTable.GET_PEB_ADDRESS, FN_Engine_GetPebAddress)
        return func(self._ptr)
    
    def get_first_position(self) -> CTTDPosition:
        """Get the first position in the trace."""
        func = self._vtable.get_func(EngineVTable.GET_FIRST_POSITION, FN_Engine_GetPositionRef)
        pos_ptr = func(self._ptr)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()
    
    def get_last_position(self) -> CTTDPosition:
        """Get the last position in the trace."""
        func = self._vtable.get_func(EngineVTable.GET_LAST_POSITION, FN_Engine_GetPositionRef)
        pos_ptr = func(self._ptr)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()
    
    def get_lifetime(self) -> CTTDPositionRange:
        """Get the lifetime range of the trace."""
        func = self._vtable.get_func(EngineVTable.GET_LIFETIME, FN_Engine_GetPositionRangeRef)
        range_ptr = func(self._ptr)
        if range_ptr:
            return range_ptr.contents
        return CTTDPositionRange()
    
    def get_recording_type(self) -> int:
        """Get the recording type."""
        func = self._vtable.get_func(EngineVTable.GET_RECORDING_TYPE, FN_Engine_GetRecordingType)
        return func(self._ptr)
    
    def get_thread_count(self) -> int:
        """Get the number of threads in the trace."""
        func = self._vtable.get_func(EngineVTable.GET_THREAD_COUNT, FN_Engine_GetSize)
        return func(self._ptr)
    
    def get_module_count(self) -> int:
        """Get the number of modules in the trace."""
        func = self._vtable.get_func(EngineVTable.GET_MODULE_COUNT, FN_Engine_GetSize)
        return func(self._ptr)
    
    def new_cursor(self) -> c_void_p:
        """Create a new cursor for navigation."""
        func = self._vtable.get_func(EngineVTable.NEW_CURSOR, FN_Engine_NewCursor)
        guid = IID_ICursorView
        return func(self._ptr, byref(guid))

    def get_system_info(self) -> CTTDSystemInfo:
        """
        Get system information about the traced process.

        Returns:
            System info with CPU architecture, OS version, page size, etc.
        """
        func = self._vtable.get_func(EngineVTable.GET_SYSTEM_INFO, FN_Engine_GetSystemInfo)
        info_ptr = func(self._ptr)
        if info_ptr:
            return info_ptr.contents
        return CTTDSystemInfo()

    def get_thread_info(self, unique_thread_id: int) -> CTTDThreadInfo:
        """
        Get information about a specific thread.

        Args:
            unique_thread_id: Unique thread identifier

        Returns:
            Thread information structure
        """
        func = self._vtable.get_func(EngineVTable.GET_THREAD_INFO, FN_Engine_GetThreadInfo)
        info_ptr = func(self._ptr, unique_thread_id)
        if info_ptr:
            return info_ptr.contents
        return CTTDThreadInfo()

    def get_thread_list(self) -> list[CTTDThreadInfo]:
        """
        Get list of all threads in the trace.

        Returns:
            List of thread info structures
        """
        count = self.get_thread_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_THREAD_LIST, FN_Engine_GetThreadList)
        threads_ptr = func(self._ptr)

        if not threads_ptr:
            return []

        threads = []
        for i in range(count):
            threads.append(threads_ptr[i])

        return threads

    def get_thread_first_position_index(self, unique_thread_id: int) -> int:
        """
        Get index of first position for a thread.

        Args:
            unique_thread_id: Unique thread identifier

        Returns:
            Position index
        """
        func = self._vtable.get_func(EngineVTable.GET_THREAD_FIRST_POSITION_INDEX, FN_Engine_GetPositionIndex)
        return func(self._ptr, unique_thread_id)

    def get_thread_last_position_index(self, unique_thread_id: int) -> int:
        """
        Get index of last position for a thread.

        Args:
            unique_thread_id: Unique thread identifier

        Returns:
            Position index
        """
        func = self._vtable.get_func(EngineVTable.GET_THREAD_LAST_POSITION_INDEX, FN_Engine_GetPositionIndex)
        return func(self._ptr, unique_thread_id)

    def get_thread_lifetime_first_position_index(self, unique_thread_id: int) -> int:
        """
        Get index of first position in thread's lifetime.

        Args:
            unique_thread_id: Unique thread identifier

        Returns:
            Position index
        """
        func = self._vtable.get_func(EngineVTable.GET_THREAD_LIFETIME_FIRST_POSITION_INDEX, FN_Engine_GetPositionIndex)
        return func(self._ptr, unique_thread_id)

    def get_thread_lifetime_last_position_index(self, unique_thread_id: int) -> int:
        """
        Get index of last position in thread's lifetime.

        Args:
            unique_thread_id: Unique thread identifier

        Returns:
            Position index
        """
        func = self._vtable.get_func(EngineVTable.GET_THREAD_LIFETIME_LAST_POSITION_INDEX, FN_Engine_GetPositionIndex)
        return func(self._ptr, unique_thread_id)

    def get_thread_created_event_count(self) -> int:
        """Get number of thread creation events."""
        func = self._vtable.get_func(EngineVTable.GET_THREAD_CREATED_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_thread_created_event_list(self) -> list[CTTDThreadCreatedEvent]:
        """
        Get list of thread creation events.

        Returns:
            List of thread created events
        """
        count = self.get_thread_created_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_THREAD_CREATED_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDThreadCreatedEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_thread_terminated_event_count(self) -> int:
        """Get number of thread termination events."""
        func = self._vtable.get_func(EngineVTable.GET_THREAD_TERMINATED_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_thread_terminated_event_list(self) -> list[CTTDThreadTerminatedEvent]:
        """
        Get list of thread termination events.

        Returns:
            List of thread terminated events
        """
        count = self.get_thread_terminated_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_THREAD_TERMINATED_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDThreadTerminatedEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_module_list(self) -> list[CTTDModule]:
        """
        Get list of unique modules in the trace.

        Returns:
            List of module structures
        """
        count = self.get_module_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_MODULE_LIST, FN_Engine_GetModuleList)
        modules_ptr = func(self._ptr)

        if not modules_ptr:
            return []

        modules = []
        for i in range(count):
            modules.append(modules_ptr[i])

        return modules

    def get_module_instance_count(self) -> int:
        """Get number of module load/unload instances."""
        func = self._vtable.get_func(EngineVTable.GET_MODULE_INSTANCE_COUNT, FN_Engine_GetSize)
        return func(self._ptr)

    def get_module_instance_list(self) -> list[CTTDModuleInstance]:
        """
        Get list of module instances (can have multiple loads/unloads).

        Returns:
            List of module instance structures
        """
        count = self.get_module_instance_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_MODULE_INSTANCE_LIST, FN_Engine_GetModuleInstanceList)
        instances_ptr = func(self._ptr)

        if not instances_ptr:
            return []

        instances = []
        for i in range(count):
            instances.append(instances_ptr[i])

        return instances

    def get_module_instance_unload_index(self) -> int:
        """Get index of module unload events in module instance list."""
        func = self._vtable.get_func(EngineVTable.GET_MODULE_INSTANCE_UNLOAD_INDEX, FN_Engine_GetModuleInstanceUnloadIndex)
        return func(self._ptr)

    def get_module_loaded_event_count(self) -> int:
        """Get number of module load events."""
        func = self._vtable.get_func(EngineVTable.GET_MODULE_LOADED_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_module_loaded_event_list(self) -> list[CTTDModuleLoadedEvent]:
        """
        Get list of module load events.

        Returns:
            List of module loaded events
        """
        count = self.get_module_loaded_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_MODULE_LOADED_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDModuleLoadedEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_module_unloaded_event_count(self) -> int:
        """Get number of module unload events."""
        func = self._vtable.get_func(EngineVTable.GET_MODULE_UNLOADED_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_module_unloaded_event_list(self) -> list[CTTDModuleUnloadedEvent]:
        """
        Get list of module unload events.

        Returns:
            List of module unloaded events
        """
        count = self.get_module_unloaded_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_MODULE_UNLOADED_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDModuleUnloadedEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_exception_event_count(self) -> int:
        """Get number of exception events."""
        func = self._vtable.get_func(EngineVTable.GET_EXCEPTION_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_exception_event_list(self) -> list[CTTDExceptionEvent]:
        """
        Get list of exception events.

        Returns:
            List of exception events
        """
        count = self.get_exception_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_EXCEPTION_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDExceptionEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_exception_at_or_after_position(self, position: CTTDPosition) -> Optional[CTTDExceptionEvent]:
        """
        Find the next exception at or after a given position.

        Args:
            position: Starting position to search from

        Returns:
            Exception event if found, None otherwise
        """
        func = self._vtable.get_func(EngineVTable.GET_EXCEPTION_AT_OR_AFTER_POSITION, FN_Engine_GetExceptionAtOrAfterPosition)
        event_ptr = func(self._ptr, byref(position))
        if event_ptr:
            return event_ptr.contents
        return None

    def get_keyframe_count(self) -> int:
        """Get number of keyframes (snapshot points) in the trace."""
        func = self._vtable.get_func(EngineVTable.GET_KEYFRAME_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_keyframe_list(self) -> list[CTTDPosition]:
        """
        Get list of keyframe positions.

        Keyframes are snapshot points that allow faster seeking.

        Returns:
            List of keyframe positions
        """
        count = self.get_keyframe_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_KEYFRAME_LIST, FN_Engine_GetKeyframeList)
        positions_ptr = func(self._ptr)

        if not positions_ptr:
            return []

        positions = []
        for i in range(count):
            positions.append(positions_ptr[i])

        return positions

    def get_record_client_count(self) -> int:
        """Get number of ETW providers that contributed to the trace."""
        func = self._vtable.get_func(EngineVTable.GET_RECORD_CLIENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_record_client_list(self) -> list[CTTDRecordClient]:
        """
        Get list of record clients (ETW providers).

        Returns:
            List of record client info structures
        """
        count = self.get_record_client_count()
        if count == 0:
            return []

        events = []
        for i in range(count):
            client = self.get_record_client(i)
            if client:
                events.append(client)

        return events

    def get_record_client(self, record_client_id: int) -> Optional[CTTDRecordClient]:
        """
        Get information about a specific record client.

        Args:
            record_client_id: Record client identifier

        Returns:
            Record client info if found
        """
        func = self._vtable.get_func(EngineVTable.GET_RECORD_CLIENT, FN_Engine_GetRecordClient)
        client_ptr = func(self._ptr, record_client_id)
        if client_ptr:
            return client_ptr.contents
        return None

    def get_custom_event_count(self) -> int:
        """Get number of custom debug events."""
        func = self._vtable.get_func(EngineVTable.GET_CUSTOM_EVENT_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_custom_event_list(self) -> list[CTTDCustomEvent]:
        """
        Get list of custom debug events.

        Returns:
            List of custom events
        """
        count = self.get_custom_event_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_CUSTOM_EVENT_LIST, FN_Engine_GetEventList)
        events_ptr = func(self._ptr)

        if not events_ptr:
            return []

        events = []
        events_arr = cast(events_ptr, POINTER(CTTDCustomEvent))
        for i in range(count):
            events.append(events_arr[i])

        return events

    def get_activity_count(self) -> int:
        """Get number of activity regions."""
        func = self._vtable.get_func(EngineVTable.GET_ACTIVITY_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_activity_list(self) -> list[CTTDActivity]:
        """
        Get list of activity regions.

        Returns:
            List of activity structures
        """
        count = self.get_activity_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_ACTIVITY_LIST, FN_Engine_GetEventList)
        activities_ptr = func(self._ptr)

        if not activities_ptr:
            return []

        activities = []
        activities_arr = cast(activities_ptr, POINTER(CTTDActivity))
        for i in range(count):
            activities.append(activities_arr[i])

        return activities

    def get_island_count(self) -> int:
        """Get number of execution islands (gaps in timeline)."""
        func = self._vtable.get_func(EngineVTable.GET_ISLAND_COUNT, FN_Engine_GetEventCount)
        return func(self._ptr)

    def get_island_list(self) -> list[CTTDIsland]:
        """
        Get list of execution islands.

        Islands represent gaps or discontinuities in the execution timeline.

        Returns:
            List of island structures
        """
        count = self.get_island_count()
        if count == 0:
            return []

        func = self._vtable.get_func(EngineVTable.GET_ISLAND_LIST, FN_Engine_GetEventList)
        islands_ptr = func(self._ptr)

        if not islands_ptr:
            return []

        islands = []
        islands_arr = cast(islands_ptr, POINTER(CTTDIsland))
        for i in range(count):
            islands.append(islands_arr[i])

        return islands

    def build_index(self):
        """Build or rebuild the trace index for faster seeking."""
        func = self._vtable.get_func(EngineVTable.BUILD_INDEX, FN_Engine_BuildIndex)
        func(self._ptr)

    def get_index_status(self) -> IndexStatus:
        """
        Get the status of the trace index.

        Returns:
            Index status enum value
        """
        func = self._vtable.get_func(EngineVTable.GET_INDEX_STATUS, FN_Engine_GetIndexStatus)
        return IndexStatus(func(self._ptr))

    def get_index_file_stats(self) -> CTTDIndexFileStats:
        """
        Get statistics about the index file.

        Returns:
            Index file statistics
        """
        result = CTTDIndexFileStats()
        func = self._vtable.get_func(EngineVTable.GET_INDEX_FILE_STATS, FN_Engine_GetIndexFileStats)
        func(self._ptr, byref(result))
        return result

    @property
    def ptr(self) -> c_void_p:
        """Get the raw pointer."""
        return self._ptr

    @property
    def is_initialized(self) -> bool:
        """Check if engine is initialized."""
        return self._initialized


# =============================================================================
# Native Thread View Interface
# =============================================================================

class NativeThreadView:
    """
    Native interface to IThreadView.

    Provides thread-local queries safe to call from within callbacks.
    Wraps vtable calls to the thread view interface.
    """

    def __init__(self, thread_view_ptr: c_void_p):
        """
        Initialize native thread view wrapper.

        Args:
            thread_view_ptr: Pointer to IThreadView
        """
        if isinstance(thread_view_ptr, int):
            thread_view_ptr = c_void_p(thread_view_ptr)
        self._ptr = thread_view_ptr
        self._vtable = VTable(thread_view_ptr) if thread_view_ptr else None

    def get_thread_info(self) -> CTTDThreadInfo:
        """Get thread information."""
        if not self._ptr:
            return CTTDThreadInfo()
        # IThreadView::GetThreadInfo returns ThreadInfo const&
        func = self._vtable.get_func(0, CFUNCTYPE(POINTER(CTTDThreadInfo), c_void_p))
        info_ptr = func(self._ptr)
        if info_ptr:
            return info_ptr.contents
        return CTTDThreadInfo()

    def get_teb_address(self) -> int:
        """Get TEB address for this thread."""
        if not self._ptr:
            return 0
        func = self._vtable.get_func(1, CFUNCTYPE(c_uint64, c_void_p))
        return func(self._ptr)

    def get_position(self) -> CTTDPosition:
        """Get current position for this thread."""
        if not self._ptr:
            return CTTDPosition()
        func = self._vtable.get_func(2, CFUNCTYPE(POINTER(CTTDPosition), c_void_p))
        pos_ptr = func(self._ptr)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()

    def get_previous_position(self) -> CTTDPosition:
        """Get previous position for this thread."""
        if not self._ptr:
            return CTTDPosition()
        func = self._vtable.get_func(3, CFUNCTYPE(POINTER(CTTDPosition), c_void_p))
        pos_ptr = func(self._ptr)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()

    def get_program_counter(self) -> int:
        """Get program counter (RIP/EIP)."""
        if not self._ptr:
            return 0
        func = self._vtable.get_func(4, CFUNCTYPE(c_uint64, c_void_p))
        return func(self._ptr)

    def get_stack_pointer(self) -> int:
        """Get stack pointer (RSP/ESP)."""
        if not self._ptr:
            return 0
        func = self._vtable.get_func(5, CFUNCTYPE(c_uint64, c_void_p))
        return func(self._ptr)

    def get_frame_pointer(self) -> int:
        """Get frame pointer (RBP/EBP)."""
        if not self._ptr:
            return 0
        func = self._vtable.get_func(6, CFUNCTYPE(c_uint64, c_void_p))
        return func(self._ptr)

    def get_basic_return_value(self) -> int:
        """Get basic return value (RAX/EAX)."""
        if not self._ptr:
            return 0
        func = self._vtable.get_func(7, CFUNCTYPE(c_uint64, c_void_p))
        return func(self._ptr)

    def get_cross_platform_context(self) -> CTTDRegisterContext:
        """Get full register context."""
        if not self._ptr:
            return CTTDRegisterContext()
        result = CTTDRegisterContext()
        func = self._vtable.get_func(8, CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDRegisterContext)))
        func(self._ptr, byref(result))
        return result

    def get_avx_extended_context(self) -> CTTDExtendedRegisterContext:
        """Get AVX extended register context (AVX/AVX2/AVX-512)."""
        if not self._ptr:
            return CTTDExtendedRegisterContext()
        result = CTTDExtendedRegisterContext()
        func = self._vtable.get_func(9, CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDExtendedRegisterContext)))
        func(self._ptr, byref(result))
        return result

    def query_memory_range(self, address: int) -> CTTDMemoryRange:
        """
        Query memory range at address.

        Args:
            address: Guest address to query

        Returns:
            CTTDMemoryRange with base address, size, and sequence info
        """
        if not self._ptr:
            return CTTDMemoryRange()
        result = CTTDMemoryRange()
        func = self._vtable.get_func(10, CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryRange), c_uint64))
        func(self._ptr, byref(result), address)
        return result

    def query_memory_buffer(self, address: int, size: int) -> bytes:
        """
        Query memory at current position (thread-local).

        Args:
            address: Guest address to read from
            size: Number of bytes to read

        Returns:
            Bytes read (may be less than requested)
        """
        if not self._ptr:
            return bytes()

        buffer = (ctypes.c_uint8 * size)()
        buffer_view = CTTDBufferView(ctypes.cast(buffer, c_void_p), size)
        result = CTTDMemoryBuffer()

        func = self._vtable.get_func(11, CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryBuffer), c_uint64, CTTDBufferView))
        func(self._ptr, byref(result), address, buffer_view)

        if result.pMemory and result.Size > 0:
            return bytes(ctypes.cast(result.pMemory, ctypes.POINTER(ctypes.c_uint8 * result.Size)).contents)
        return bytes()

    def query_memory_buffer_with_ranges(self, address: int, size: int) -> tuple[bytes, list[CTTDMemoryRange]]:
        """
        Query memory buffer with range information.

        Args:
            address: Guest address to read from
            size: Number of bytes to read

        Returns:
            Tuple of (bytes_data, list of CTTDMemoryRange structures)
        """
        if not self._ptr:
            return (bytes(), [])

        buffer = (ctypes.c_uint8 * size)()
        buffer_view = CTTDBufferView(ctypes.cast(buffer, c_void_p), size)
        result = CTTDMemoryBufferWithRanges()

        func = self._vtable.get_func(12, CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryBufferWithRanges), c_uint64, CTTDBufferView))
        func(self._ptr, byref(result), address, buffer_view)

        data = bytes()
        if result.Buffer.pMemory and result.Buffer.Size > 0:
            data = bytes(ctypes.cast(result.Buffer.pMemory, ctypes.POINTER(ctypes.c_uint8 * result.Buffer.Size)).contents)

        ranges = []
        if result.pRanges and result.RangeCount > 0:
            ranges_arr = ctypes.cast(result.pRanges, ctypes.POINTER(CTTDMemoryRange * result.RangeCount)).contents
            ranges = [ranges_arr[i] for i in range(result.RangeCount)]

        return (data, ranges)

    @property
    def ptr(self) -> c_void_p:
        """Get the raw pointer."""
        return self._ptr


# =============================================================================
# Native Cursor Interface
# =============================================================================

class NativeCursor:
    """
    Native interface to ICursor.

    Wraps vtable calls to the cursor interface.
    """

    def __init__(self, cursor_ptr):
        """
        Initialize native cursor wrapper.

        Args:
            cursor_ptr: Pointer to ICursor (c_void_p or int)
        """
        # Handle both c_void_p and int (raw pointer value)
        if isinstance(cursor_ptr, int):
            cursor_ptr = c_void_p(cursor_ptr)
        self._ptr = cursor_ptr
        self._vtable = VTable(cursor_ptr)
        # Register for cleanup tracking
        TTDBindings._active_cursors.append(self)

    def destroy(self):
        """Destroy the cursor."""
        if self._ptr:
            func = self._vtable.get_func(CursorVTable.DESTROY, FN_Cursor_Destroy)
            func(self._ptr)
            self._ptr = None
            # Remove from tracking
            if self in TTDBindings._active_cursors:
                TTDBindings._active_cursors.remove(self)
    
    def clear(self):
        """Clear cursor to invalid position."""
        func = self._vtable.get_func(CursorVTable.CLEAR, FN_Cursor_Clear)
        func(self._ptr)
    
    def set_position(self, position: CTTDPosition):
        """Set cursor to a specific position."""
        func = self._vtable.get_func(CursorVTable.SET_POSITION, FN_Cursor_SetPosition)
        func(self._ptr, byref(position))
    
    def get_position(self, thread_id: int = 0) -> CTTDPosition:
        """Get current position (optionally for a specific thread)."""
        func = self._vtable.get_func(CursorVTable.GET_POSITION, FN_Cursor_GetPosition)
        pos_ptr = func(self._ptr, thread_id)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()
    
    def get_program_counter(self, thread_id: int = 0) -> int:
        """Get the program counter (RIP/EIP)."""
        func = self._vtable.get_func(CursorVTable.GET_PROGRAM_COUNTER, FN_Cursor_GetProgramCounter)
        return func(self._ptr, thread_id)
    
    def get_stack_pointer(self, thread_id: int = 0) -> int:
        """Get the stack pointer (RSP/ESP)."""
        func = self._vtable.get_func(CursorVTable.GET_STACK_POINTER, FN_Cursor_GetStackPointer)
        return func(self._ptr, thread_id)
    
    def get_frame_pointer(self, thread_id: int = 0) -> int:
        """Get the frame pointer (RBP/EBP)."""
        func = self._vtable.get_func(CursorVTable.GET_FRAME_POINTER, FN_Cursor_GetFramePointer)
        return func(self._ptr, thread_id)
    
    def get_basic_return_value(self, thread_id: int = 0) -> int:
        """Get the basic return value (RAX/EAX)."""
        func = self._vtable.get_func(CursorVTable.GET_BASIC_RETURN_VALUE, FN_Cursor_GetBasicReturnValue)
        return func(self._ptr, thread_id)
    
    # Alias for convenience
    def get_return_value(self, thread_id: int = 0) -> int:
        """Get the basic return value (RAX/EAX). Alias for get_basic_return_value."""
        return self.get_basic_return_value(thread_id)
    
    def get_teb_address(self, thread_id: int = 0) -> int:
        """Get the TEB (Thread Environment Block) address."""
        func = self._vtable.get_func(CursorVTable.GET_TEB_ADDRESS, FN_Cursor_GetTebAddress)
        return func(self._ptr, thread_id)
    
    def get_cross_platform_context(self, thread_id: int = 0) -> CTTDRegisterContext:
        """Get full register context."""
        result = CTTDRegisterContext()
        func = self._vtable.get_func(CursorVTable.GET_CROSS_PLATFORM_CONTEXT, FN_Cursor_GetCrossPlatformContext)
        func(self._ptr, byref(result), thread_id)
        return result
    
    def get_thread_count(self) -> int:
        """Get count of active threads at current position."""
        func = self._vtable.get_func(CursorVTable.GET_THREAD_COUNT, FN_Cursor_GetThreadCount)
        return func(self._ptr)
    
    def get_module_count(self) -> int:
        """Get count of loaded modules at current position."""
        func = self._vtable.get_func(CursorVTable.GET_MODULE_COUNT, FN_Cursor_GetModuleCount)
        return func(self._ptr)
    
    def query_memory_buffer(self, address: int, size: int, 
                           policy: QueryMemoryPolicy = QueryMemoryPolicy.DEFAULT) -> bytes:
        """
        Query memory at current position.
        
        Args:
            address: Guest address to read from
            size: Number of bytes to read
            policy: Memory query policy
        
        Returns:
            Bytes read (may be less than requested)
        """
        # Allocate buffer for data
        buffer = (ctypes.c_uint8 * size)()
        buffer_view = CTTDBufferView(ctypes.cast(buffer, c_void_p), size)
        
        # Allocate result structure (returned via hidden first param in x64 ABI)
        result = CTTDMemoryBuffer()
        
        func = self._vtable.get_func(CursorVTable.QUERY_MEMORY_BUFFER, FN_Cursor_QueryMemoryBuffer)
        func(self._ptr, byref(result), address, buffer_view, int(policy))
        
        # Extract the data from the result
        if result.pMemory and result.Size > 0:
            return bytes(ctypes.cast(result.pMemory, ctypes.POINTER(ctypes.c_uint8 * result.Size)).contents)
        return bytes()
    
    def set_event_mask(self, mask: EventMask):
        """Set which events to stop on during replay."""
        func = self._vtable.get_func(CursorVTable.SET_EVENT_MASK, FN_Cursor_SetEventMask)
        func(self._ptr, int(mask))
    
    def get_event_mask(self) -> EventMask:
        """Get current event mask."""
        func = self._vtable.get_func(CursorVTable.GET_EVENT_MASK, FN_Cursor_GetEventMask)
        return EventMask(func(self._ptr))
    
    def set_replay_flags(self, flags: ReplayFlags):
        """Set replay behavior flags."""
        func = self._vtable.get_func(CursorVTable.SET_REPLAY_FLAGS, FN_Cursor_SetReplayFlags)
        func(self._ptr, int(flags))
    
    def get_replay_flags(self) -> ReplayFlags:
        """Get current replay flags."""
        func = self._vtable.get_func(CursorVTable.GET_REPLAY_FLAGS, FN_Cursor_GetReplayFlags)
        return ReplayFlags(func(self._ptr))
    
    def add_memory_watchpoint(self, data: CTTDMemoryWatchpointData) -> bool:
        """Add a memory watchpoint."""
        func = self._vtable.get_func(CursorVTable.ADD_MEMORY_WATCHPOINT, FN_Cursor_AddMemoryWatchpoint)
        return func(self._ptr, byref(data))
    
    def remove_memory_watchpoint(self, data: CTTDMemoryWatchpointData) -> bool:
        """Remove a memory watchpoint."""
        func = self._vtable.get_func(CursorVTable.REMOVE_MEMORY_WATCHPOINT, FN_Cursor_RemoveMemoryWatchpoint)
        return func(self._ptr, byref(data))
    
    def add_position_watchpoint(self, data: CTTDPositionWatchpointData) -> bool:
        """Add a position watchpoint."""
        func = self._vtable.get_func(CursorVTable.ADD_POSITION_WATCHPOINT, FN_Cursor_AddPositionWatchpoint)
        return func(self._ptr, byref(data))
    
    def remove_position_watchpoint(self, data: CTTDPositionWatchpointData) -> bool:
        """Remove a position watchpoint."""
        func = self._vtable.get_func(CursorVTable.REMOVE_POSITION_WATCHPOINT, FN_Cursor_RemovePositionWatchpoint)
        return func(self._ptr, byref(data))
    
    def replay_forward(self, limit: CTTDPosition = None, max_steps: int = 0xFFFFFFFFFFFFFFFE) -> CTTDReplayResult:
        """
        Replay forward until limit position or event.
        
        Args:
            limit: Maximum position to replay to (default: max position)
            max_steps: Maximum steps to execute
        
        Returns:
            Replay result with stop reason
        """
        if limit is None:
            limit = CTTDPosition(0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFE)  # Position::Max
        result = CTTDReplayResult()
        func = self._vtable.get_func(CursorVTable.REPLAY_FORWARD, FN_Cursor_ReplayForward)
        func(self._ptr, byref(result), limit, max_steps)
        return result
    
    def replay_backward(self, limit: CTTDPosition = None, max_steps: int = 0xFFFFFFFFFFFFFFFE) -> CTTDReplayResult:
        """
        Replay backward until limit position or event.
        
        Args:
            limit: Minimum position to replay to (default: min position)
            max_steps: Maximum steps to execute
        
        Returns:
            Replay result with stop reason
        """
        if limit is None:
            limit = CTTDPosition(0, 0)  # Position::Min
        result = CTTDReplayResult()
        func = self._vtable.get_func(CursorVTable.REPLAY_BACKWARD, FN_Cursor_ReplayBackward)
        func(self._ptr, byref(result), limit, max_steps)
        return result
    
    def interrupt_replay(self):
        """Interrupt an ongoing replay operation (thread-safe)."""
        func = self._vtable.get_func(CursorVTable.INTERRUPT_REPLAY, FN_Cursor_InterruptReplay)
        func(self._ptr)

    def set_position_on_thread(self, unique_thread_id: int, position: CTTDPosition):
        """
        Set cursor position on a specific thread.

        IMPORTANT: This function uses UniqueThreadId (TTD internal), NOT Windows ThreadId.
        Get UniqueThreadId from get_thread_info().UniqueId

        Args:
            unique_thread_id: TTD UniqueThreadId (from ThreadInfo.UniqueId), NOT Windows ThreadId
            position: Position to set
        """
        func = self._vtable.get_func(CursorVTable.SET_POSITION_ON_THREAD, FN_Cursor_SetPositionOnThread)
        func(self._ptr, unique_thread_id, byref(position))

    def get_thread_info(self, thread_id: int = 0) -> CTTDThreadInfo:
        """
        Get thread information for a specific thread.

        Args:
            thread_id: Thread ID (0 for current thread)

        Returns:
            Thread information structure
        """
        func = self._vtable.get_func(CursorVTable.GET_THREAD_INFO, CFUNCTYPE(POINTER(CTTDThreadInfo), c_void_p, c_uint32))
        info_ptr = func(self._ptr, thread_id)
        if info_ptr:
            return info_ptr.contents
        return CTTDThreadInfo()

    def get_previous_position(self, thread_id: int = 0) -> CTTDPosition:
        """
        Get previous position for a specific thread.

        Args:
            thread_id: Thread ID (0 for current thread)

        Returns:
            Previous position
        """
        func = self._vtable.get_func(CursorVTable.GET_PREVIOUS_POSITION, FN_Cursor_GetPreviousPosition)
        pos_ptr = func(self._ptr, thread_id)
        if pos_ptr:
            return pos_ptr.contents
        return CTTDPosition()

    def get_avx_extended_context(self, thread_id: int = 0) -> CTTDExtendedRegisterContext:
        """
        Get AVX extended register context for a specific thread.

        Args:
            thread_id: Thread ID (0 for current thread)

        Returns:
            Extended register context with AVX/AVX2/AVX-512 registers
        """
        result = CTTDExtendedRegisterContext()
        func = self._vtable.get_func(CursorVTable.GET_AVX_EXTENDED_CONTEXT,
                                     CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDExtendedRegisterContext), c_uint32))
        func(self._ptr, byref(result), thread_id)
        return result

    def get_module_list(self) -> list[CTTDModuleInstance]:
        """
        Get list of loaded modules at current position.

        Returns:
            List of module instance structures
        """
        count = self.get_module_count()
        if count == 0:
            return []

        func = self._vtable.get_func(CursorVTable.GET_MODULE_LIST,
                                     CFUNCTYPE(POINTER(CTTDModuleInstance), c_void_p))
        modules_ptr = func(self._ptr)

        if not modules_ptr:
            return []

        # Convert C array to Python list
        modules = []
        for i in range(count):
            modules.append(modules_ptr[i])

        return modules

    def get_thread_list(self) -> list[CTTDActiveThreadInfo]:
        """
        Get list of active threads at current position.

        Returns:
            List of active thread info structures
        """
        count = self.get_thread_count()
        if count == 0:
            return []

        func = self._vtable.get_func(CursorVTable.GET_THREAD_LIST,
                                     CFUNCTYPE(POINTER(CTTDActiveThreadInfo), c_void_p))
        threads_ptr = func(self._ptr)

        if not threads_ptr:
            return []

        # Convert C array to Python list
        threads = []
        for i in range(count):
            threads.append(threads_ptr[i])

        return threads

    def set_gap_kind_mask(self, mask: GapKindMask):
        """
        Set which gap kinds trigger events during replay.

        Args:
            mask: Gap kind mask (context switches, unrecorded sections, etc.)
        """
        func = self._vtable.get_func(CursorVTable.SET_GAP_KIND_MASK,
                                     CFUNCTYPE(None, c_void_p, c_uint32))
        func(self._ptr, int(mask))

    def get_gap_kind_mask(self) -> GapKindMask:
        """
        Get current gap kind mask.

        Returns:
            Gap kind mask
        """
        func = self._vtable.get_func(CursorVTable.GET_GAP_KIND_MASK,
                                     CFUNCTYPE(c_uint32, c_void_p))
        return GapKindMask(func(self._ptr))

    def set_gap_event_mask(self, mask: GapEventMask):
        """
        Set which gap event types trigger callbacks.

        Args:
            mask: Gap event mask (enter/exit events)
        """
        func = self._vtable.get_func(CursorVTable.SET_GAP_EVENT_MASK,
                                     CFUNCTYPE(None, c_void_p, c_uint32))
        func(self._ptr, int(mask))

    def get_gap_event_mask(self) -> GapEventMask:
        """
        Get current gap event mask.

        Returns:
            Gap event mask
        """
        func = self._vtable.get_func(CursorVTable.GET_GAP_EVENT_MASK,
                                     CFUNCTYPE(c_uint32, c_void_p))
        return GapEventMask(func(self._ptr))

    def set_exception_mask(self, mask: ExceptionMask):
        """
        Set which exception types trigger events during replay.

        Args:
            mask: Exception mask
        """
        func = self._vtable.get_func(CursorVTable.SET_EXCEPTION_MASK,
                                     CFUNCTYPE(None, c_void_p, c_uint32))
        func(self._ptr, int(mask))

    def get_exception_mask(self) -> ExceptionMask:
        """
        Get current exception mask.

        Returns:
            Exception mask
        """
        func = self._vtable.get_func(CursorVTable.GET_EXCEPTION_MASK,
                                     CFUNCTYPE(c_uint32, c_void_p))
        return ExceptionMask(func(self._ptr))

    def query_memory_range(self, address: int, thread_id: int = 0) -> CTTDMemoryRange:
        """
        Query memory range information at an address.

        Args:
            address: Guest address to query
            thread_id: Thread ID (0 for current thread)

        Returns:
            Memory range with base address, size, and sequence info
        """
        result = CTTDMemoryRange()
        func = self._vtable.get_func(CursorVTable.QUERY_MEMORY_RANGE, FN_Cursor_QueryMemoryRange)
        func(self._ptr, byref(result), address, thread_id)
        return result

    def query_memory_buffer_with_ranges(self, address: int, size: int,
                                       policy: QueryMemoryPolicy = QueryMemoryPolicy.DEFAULT) -> tuple[bytes, list[CTTDMemoryRange]]:
        """
        Query memory buffer with range metadata.

        Args:
            address: Guest address to read from
            size: Number of bytes to read
            policy: Memory query policy

        Returns:
            Tuple of (bytes_data, list of CTTDMemoryRange structures)
        """
        buffer = (ctypes.c_uint8 * size)()
        buffer_view = CTTDBufferView(ctypes.cast(buffer, c_void_p), size)
        result = CTTDMemoryBufferWithRanges()

        func = self._vtable.get_func(CursorVTable.QUERY_MEMORY_BUFFER_WITH_RANGES,
                                     CFUNCTYPE(c_void_p, c_void_p, POINTER(CTTDMemoryBufferWithRanges),
                                              c_uint64, CTTDBufferView, c_uint32))
        func(self._ptr, byref(result), address, buffer_view, int(policy))

        data = bytes()
        if result.Buffer.pMemory and result.Buffer.Size > 0:
            data = bytes(ctypes.cast(result.Buffer.pMemory,
                                    ctypes.POINTER(ctypes.c_uint8 * result.Buffer.Size)).contents)

        ranges = []
        if result.pRanges and result.RangeCount > 0:
            ranges_arr = ctypes.cast(result.pRanges,
                                    ctypes.POINTER(CTTDMemoryRange * result.RangeCount)).contents
            ranges = [ranges_arr[i] for i in range(result.RangeCount)]

        return (data, ranges)

    def set_default_memory_policy(self, policy: QueryMemoryPolicy):
        """
        Set default memory query policy for this cursor.

        Args:
            policy: Default memory query policy
        """
        func = self._vtable.get_func(CursorVTable.SET_DEFAULT_MEMORY_POLICY,
                                     CFUNCTYPE(None, c_void_p, c_uint32))
        func(self._ptr, int(policy))

    def get_default_memory_policy(self) -> QueryMemoryPolicy:
        """
        Get default memory query policy.

        Returns:
            Current default memory query policy
        """
        func = self._vtable.get_func(CursorVTable.GET_DEFAULT_MEMORY_POLICY,
                                     CFUNCTYPE(c_uint32, c_void_p))
        return QueryMemoryPolicy(func(self._ptr))

    def set_memory_watchpoint_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for memory watchpoint hits.

        Args:
            callback: Function(context, MemoryWatchpointResult, IThreadView) -> bool
                     Returns True to accept hit, False to reject
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_MEMORY_WATCHPOINT_CALLBACK, FN_Cursor_SetMemoryWatchpointCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            # Create ctypes callback wrapper
            cb_wrapper = FN_MemoryWatchpointCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            # Store reference to prevent garbage collection
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['memory_watchpoint'] = cb_wrapper

    def set_position_watchpoint_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for position watchpoint hits.

        Args:
            callback: Function(context, Position, IThreadView) -> bool
                     Returns True to accept hit, False to reject
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_POSITION_WATCHPOINT_CALLBACK, FN_Cursor_SetPositionWatchpointCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_PositionWatchpointCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['position_watchpoint'] = cb_wrapper

    def set_replay_progress_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for replay progress updates.

        Args:
            callback: Function(context, Position) -> None
                     Called periodically during replay
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_REPLAY_PROGRESS_CALLBACK, FN_Cursor_SetReplayProgressCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_ReplayProgressCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['replay_progress'] = cb_wrapper

    def set_gap_event_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for gap events (context switches, unrecorded sections).

        Args:
            callback: Function(context, GapKind, GapEventType, IThreadView) -> bool
                     Returns True to accept event, False to reject
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_GAP_EVENT_CALLBACK, FN_Cursor_SetGapEventCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_GapEventCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['gap_event'] = cb_wrapper

    def set_thread_continuity_break_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for thread continuity breaks.

        Called when switching between thread execution segments, useful for
        aggregating thread-local data during replay.

        Args:
            callback: Function(context) -> None
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_THREAD_CONTINUITY_BREAK_CALLBACK, FN_Cursor_SetThreadContinuityBreakCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_ThreadContinuityBreakCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['thread_continuity'] = cb_wrapper

    def set_fallback_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for fallback instruction execution.

        Args:
            callback: Function(context, synthetic, address, size, IThreadView) -> None
                     synthetic: True if instruction was emulated at record time
                     address: Instruction address
                     size: Instruction size in bytes
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_FALLBACK_CALLBACK, FN_Cursor_SetFallbackCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_FallbackCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['fallback'] = cb_wrapper

    def set_call_return_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for call/return instructions.

        Args:
            callback: Function(context, type, from_address, to_address, IThreadView) -> None
                     type: Instruction type (call, ret, iretq)
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_CALL_RETURN_CALLBACK, FN_Cursor_SetCallReturnCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_CallReturnCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['call_return'] = cb_wrapper

    def set_indirect_jump_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for indirect jump instructions.

        Args:
            callback: Function(context, from_address, to_address, IThreadView) -> None
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_INDIRECT_JUMP_CALLBACK, FN_Cursor_SetIndirectJumpCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_IndirectJumpCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['indirect_jump'] = cb_wrapper

    def set_register_changed_callback(self, callback: Optional[Callable], context: int = 0):
        """
        Set callback for register value changes.

        Args:
            callback: Function(context, regId, pOldData, pNewData, dataSizeInBytes, IThreadView) -> None
                     regId: Register identifier
                     pOldData: Pointer to old register value
                     pNewData: Pointer to new register value
                     Pass None to clear callback
            context: User context value passed to callback
        """
        func = self._vtable.get_func(CursorVTable.SET_REGISTER_CHANGED_CALLBACK, FN_Cursor_SetRegisterChangedCallback)
        if callback is None:
            func(self._ptr, None, 0)
        else:
            cb_wrapper = FN_RegisterChangedCallback(callback)
            func(self._ptr, cast(cb_wrapper, c_void_p), context)
            if not hasattr(self, '_callbacks'):
                self._callbacks = {}
            self._callbacks['register_changed'] = cb_wrapper

    @property
    def ptr(self) -> c_void_p:
        """Get the raw pointer."""
        return self._ptr
