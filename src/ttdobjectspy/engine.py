"""
TTD Replay Engine

High-level Python wrapper for the TTD replay engine.
Provides a Pythonic interface to trace loading and management.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, List

from ttdobjectspy.ttd_types import (
    Position, PositionRange, GuestAddress, RecordingType,
    ThreadInfo, Module, CTTDPosition, ReplayFlags,
)
from ttdobjectspy.bindings import (
    TTDBindings, NativeEngine, NativeCursor,
    TTDError, TTDInitializationError, TTDNotInitializedError,
)
from ttdobjectspy.cursor import Cursor


class ReplayEngine:
    """
    High-level wrapper for TTD replay engine.
    
    Example usage:
        engine = ReplayEngine()
        engine.initialize("trace.run")
        
        print(f"First position: {engine.first_position}")
        print(f"Thread count: {engine.thread_count}")
        
        cursor = engine.new_cursor()
        cursor.set_position(engine.first_position)
        
        engine.close()
    """
    
    def __init__(self, dll_path: Optional[Path] = None):
        """
        Create a new replay engine instance.
        
        Args:
            dll_path: Optional path to TTDReplay.dll
        """
        self._bindings = TTDBindings.get_instance(dll_path)
        self._native: Optional[NativeEngine] = None
        self._trace_path: Optional[Path] = None
        self._cursors: List[Cursor] = []
    
    def initialize(self, trace_path: str) -> bool:
        """
        Initialize the engine with a trace file.
        
        Args:
            trace_path: Path to .run, .ttd, or .idx file
        
        Returns:
            True if successful
        
        Raises:
            TTDInitializationError: If initialization fails
            FileNotFoundError: If trace file doesn't exist
        """
        path = Path(trace_path)
        if not path.exists():
            raise FileNotFoundError(f"Trace file not found: {trace_path}")
        
        if path.suffix.lower() not in ('.run', '.ttd', '.idx'):
            raise ValueError(f"Unsupported trace file type: {path.suffix}")
        
        # Create native engine
        engine_ptr = self._bindings.create_replay_engine()
        self._native = NativeEngine(engine_ptr)
        
        # Initialize with trace file
        if not self._native.initialize(str(path)):
            self._native.destroy()
            self._native = None
            raise TTDInitializationError(f"Failed to initialize trace: {trace_path}")
        
        self._trace_path = path
        return True
    
    def close(self):
        """Close the engine and release all resources."""
        # Destroy all cursors first
        for cursor in self._cursors:
            cursor.close()
        self._cursors.clear()
        
        # Destroy engine
        if self._native:
            self._native.destroy()
            self._native = None
        
        self._trace_path = None
    
    def __enter__(self) -> "ReplayEngine":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def _ensure_initialized(self):
        """Raise if engine is not initialized."""
        if not self._native or not self._native.is_initialized:
            raise TTDNotInitializedError("Engine not initialized. Call initialize() first.")
    
    @property
    def is_initialized(self) -> bool:
        """Check if engine is initialized with a trace."""
        return self._native is not None and self._native.is_initialized
    
    @property
    def trace_path(self) -> Optional[Path]:
        """Path to the loaded trace file."""
        return self._trace_path
    
    @property
    def first_position(self) -> Position:
        """Get the first position in the trace."""
        self._ensure_initialized()
        pos = self._native.get_first_position()
        return pos.to_python()
    
    @property
    def last_position(self) -> Position:
        """Get the last position in the trace."""
        self._ensure_initialized()
        pos = self._native.get_last_position()
        return pos.to_python()
    
    @property
    def lifetime(self) -> PositionRange:
        """Get the lifetime range of the trace."""
        self._ensure_initialized()
        range_ = self._native.get_lifetime()
        return range_.to_python()
    
    @property
    def recording_type(self) -> RecordingType:
        """Get the recording type."""
        self._ensure_initialized()
        return RecordingType(self._native.get_recording_type())
    
    @property
    def peb_address(self) -> GuestAddress:
        """Get the PEB address of the traced process."""
        self._ensure_initialized()
        return GuestAddress(self._native.get_peb_address())
    
    @property
    def thread_count(self) -> int:
        """Get the total number of threads in the trace."""
        self._ensure_initialized()
        return self._native.get_thread_count()
    
    @property
    def module_count(self) -> int:
        """Get the total number of modules in the trace."""
        self._ensure_initialized()
        return self._native.get_module_count()
    
    def new_cursor(self) -> Cursor:
        """
        Create a new cursor for navigating the trace.

        Multiple cursors can be created and used independently.

        Default replay flags are set to:
        - REPLAY_ONLY_CURRENT_THREAD: Focus on single thread execution
        - REPLAY_SEGMENTS_SEQUENTIALLY: Process segments in order

        Returns:
            A new Cursor instance
        """
        self._ensure_initialized()
        cursor_ptr = self._native.new_cursor()

        if not cursor_ptr:
            raise TTDError("Failed to create cursor")

        native_cursor = NativeCursor(cursor_ptr)
        cursor = Cursor(native_cursor, self)

        # Set default replay flags for better deterministic behavior
        default_flags = (ReplayFlags.REPLAY_ONLY_CURRENT_THREAD |
                        ReplayFlags.REPLAY_SEGMENTS_SEQUENTIALLY)
        cursor.replay_flags = default_flags

        self._cursors.append(cursor)
        return cursor
    
    def _remove_cursor(self, cursor: Cursor):
        """Remove a cursor from tracking (called by Cursor.close())."""
        if cursor in self._cursors:
            self._cursors.remove(cursor)
    
    def get_info(self) -> dict:
        """
        Get comprehensive information about the loaded trace.
        
        Returns:
            Dictionary with trace metadata
        """
        self._ensure_initialized()
        
        return {
            "path": str(self._trace_path),
            "filename": self._trace_path.name if self._trace_path else None,
            "recording_type": str(self.recording_type),
            "first_position": self.first_position.to_dict(),
            "last_position": self.last_position.to_dict(),
            "lifetime": self.lifetime.to_dict(),
            "peb_address": str(self.peb_address),
            "thread_count": self.thread_count,
            "module_count": self.module_count,
        }
