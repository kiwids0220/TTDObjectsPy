// Copyright (c) Microsoft Corporation.
//
// Additional definitions for IReplayEngine.h, to interface with the STL.

#pragma once

#include "IReplayEngine.h"

#include <memory>
#include <utility>

namespace TTD
{

namespace Replay
{

// For convenience: unique_ptr alias using the deleter above.
template < typename Interface >
using Unique = std::unique_ptr<Interface, Deleter<Interface>>;

using UniqueTraceList    = Unique<ITraceList>;
using UniqueReplayEngine = Unique<IReplayEngine>;
using UniqueCursor       = Unique<ICursor>;

extern "C" uint32_t __cdecl CreateReplayEngine(
    _Out_ IReplayEngine*&      pReplayEngine,
    _In_  GUID          const& engineGuidCreateReplayEngine
) noexcept;

inline std::pair<UniqueReplayEngine, uint32_t> MakeReplayEngine(
    _In_  GUID          const& engineGuid = __uuidof(IReplayEngineView)
) noexcept
{
    IReplayEngine* pReplayEngine = nullptr;
    uint32_t result = CreateReplayEngine(pReplayEngine, engineGuid);
    return std::make_pair(UniqueReplayEngine(pReplayEngine), result);
}

extern "C" uint32_t __cdecl CreateTraceList(
    _Out_ ITraceList*&         pTraceList,
    _In_  GUID          const& engineGuid
) noexcept;

inline std::pair<UniqueTraceList, uint32_t> MakeTraceList(
    _In_  GUID          const& engineGuid = __uuidof(ITraceListView)
) noexcept
{
    ITraceList* pTraceList = nullptr;
    uint32_t result = CreateTraceList(pTraceList, engineGuid);
    return std::make_pair(UniqueTraceList(pTraceList), result);
}

}} // namespace TTD::Replay
