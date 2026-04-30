"""
TTDObjectsPy: Time Travel Debugging Python Bindings & MCP Server

This package provides Python bindings for Microsoft's Time Travel Debugging SDK
and an MCP server for AI-assisted reverse engineering.
"""

from ttdobjectspy.ttd_types import (
    Position,
    PositionRange,
    GuestAddress,
    ThreadId,
    UniqueThreadId,
    SequenceId,
    StepCount,
    DataAccessType,
    DataAccessMask,
    EventType,
    EventMask,
    QueryMemoryPolicy,
    RecordingType,
    ReplayFlags,
    GapKind,
    GapKindMask,
    GapEventType,
    GapEventMask,
    ExceptionMask,
    IndexStatus,
)

from ttdobjectspy.engine import ReplayEngine
from ttdobjectspy.cursor import Cursor
from ttdobjectspy.bindings import NativeThreadView

__version__ = "0.1.0"
__all__ = [
    # Types
    "Position",
    "PositionRange",
    "GuestAddress",
    "ThreadId",
    "UniqueThreadId",
    "SequenceId",
    "StepCount",
    "DataAccessType",
    "DataAccessMask",
    "EventType",
    "EventMask",
    "QueryMemoryPolicy",
    "RecordingType",
    "ReplayFlags",
    "GapKind",
    "GapKindMask",
    "GapEventType",
    "GapEventMask",
    "ExceptionMask",
    "IndexStatus",
    # Classes
    "ReplayEngine",
    "Cursor",
    "NativeThreadView",
]
