// Copyright (c) Microsoft Corporation.
#pragma once

#include <sal.h>
#include <string>
#include <cstdarg>

namespace TTD
{

class ErrorReporting
{
public:
    ErrorReporting() = default;
    virtual ~ErrorReporting() = default;

    [[deprecated("API methods must not use STL types, which may break ABI compatibility in future releases")]]
    virtual void __fastcall PrintError_DoNotUse(_In_ std::string const&) {}

    virtual void __fastcall VPrintError(_Printf_format_string_ char const* const pFmt, _In_ va_list argList) = 0;

    // This is the original overload now renamed to `PrintError_DoNotUse` above.
    // Keeping this here helps flag any leftover calls that would have invoked the method.
    void __fastcall PrintError(_In_ std::string const&) = delete;

    inline
    void PrintError(_Printf_format_string_ char const* pFmt, ...)
    {
        va_list args;
        va_start(args, pFmt);
        VPrintError(pFmt, args);
        va_end(args);
    }
};

inline
void TryPrintError(
    _Inout_opt_ ErrorReporting * const   pErrorReporting,
    _In_        std::string      const & errorMessage)
{
    if (pErrorReporting != nullptr)
    {
        pErrorReporting->PrintError("%s", errorMessage.c_str());
    }
}

inline
void TryPrintError(
    _Inout_opt_            ErrorReporting * const pErrorReporting,
    _Printf_format_string_ char const     * const pFmt, ...)
{
    if (pErrorReporting != nullptr)
    {
        va_list args;
        va_start(args, pFmt);
        pErrorReporting->VPrintError(pFmt, args);
        va_end(args);
    }
}

inline
void TryVPrintError(
    _Inout_opt_            ErrorReporting * const pErrorReporting,
    _Printf_format_string_ char const     * const pFmt, _In_ va_list argList)
{
    if (pErrorReporting != nullptr)
    {
        pErrorReporting->VPrintError(pFmt, argList);
    }
}

}// namespace TTD
