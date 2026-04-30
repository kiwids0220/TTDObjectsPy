// Copyright (c) Microsoft Corporation.
#pragma once

#include "IdnaBasicTypes.h"

#pragma message("The Nirvana namespace and this header file are deprecated and will be removed in a future release.")

// Nirvana is an old name used by some parts of TTD.
// The Nirvana namespace is here just for compatibility and will be removed in some future release.
namespace /*[[deprecated]]*/ Nirvana
{

// Types
using TTD::simd64_t;
using TTD::simd128_t;
using TTD::simd256_t;
using TTD::simd512_t;
using TTD::GuestAddress;
using TTD::GuestAddressRange;
using TTD::SelectRegisters;
using TTD::ProcessorArchitecture;
using TTD::MessageSeverity;
using TTD::InjectMode;
using TTD::FindValidDataLineMode;
using TTD::ReplayCpuSupport;

// Variables
using TTD::c_nativeProcessorArchitecture;
using TTD::MaxInjectModeNameLength;

// Functions
using TTD::PtrToGuestAddress;
using TTD::GuestAddressToPtr;
using TTD::AddressInClosedRange;
using TTD::AddressInHalfOpenRange;
using TTD::GetProcessorArchitectureName;
using TTD::SanitizeAddressForUserMode;
using TTD::GetInjectModeName;
using TTD::GetReplayCpuSupportName;

}
// namespace Nirvana
