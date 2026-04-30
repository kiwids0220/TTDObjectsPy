// Copyright (c) Microsoft Corporation.
//
// Note: this API is currently in preview, and is subject to change.
//
// This file describes the interface exposed by TTD's Recording Engine, accessible via TTDLiveRecorder.dll.
//
// Definitions:
//
// "client" or "recording client" is the code that uses this API to interact with the recorder.
// "client GUID" is a GUID value belonging to the client. This value can be used to later identify
//      the various pieces of data that the client puts in the recording.
// "island" is a single stretch of recording in a single thread, from when the recording was started
//      to when it was stopped.
// "activity" is a group of islands, possibly on multiple threads, that the client marks with a common ID,
//      for some purpose known to the client.
// "custom event" is a point of interest in the recording marked by the client, with some data associated with it.
// "throttle" is a voluntary end of the current island of recording, based on some condition indicated by the client.
// "user data" is a raw array of bytes that the client may provide at various points during the recording,
//      for instance when opening the interface, starting islands or recording custom events.
//      This data will be included in the recording and it is up to the client to later correctly interpret it.
//
//
// This interface is retrieved by calling the MakeLiveRecorder() function.
// This function receives a client GUID which is used to identify the component wanting to interact with the recording.
// It is a GUID so that multiple clients can generate their own without need to coordinate with each other.
// Any data that is defined and provided by the client, including payload blobs and activity IDs,
// will have the client GUID attached to it in the file.
// The replay engine exposes all the client-defined data together with the GUID,
// so any client code using the replay engine can filter out the data that pertains to clients other than itself.
//
// The client is expected to invoke Start/StopRecordingCurrentThread() to generate islands of recorded code
// on the calling thread. Every island has a client-defined activity ID (a 32-bit token),
// so that islands belonging to the same activity may be bound together more tightly during replay.
// Every island can also have a user data blob with additional data about the reason to record the island.
//
// The client may invoke TryPause/ResumeRecording() to skip portions of code from being recorded on the calling thread.
// Note that ResumeRecording() should only be invoked if TryPauseRecording() returned true,
// which indicates that the thread was being recorded in the first place.
// This can be easily done and enforced by using the provided ScopedPauseRecording class,
// instead of calling the functions directly.
//
// The client may invoke AddCustomEvent() to add an annotation to the trace file,
// bound to the current position in the timeline.
// This custom event may be global, or assigned to the current thread.
// It may also optionally be used to generate a keyframe, which is useful if the event will be used as part of a
// memory query scheme on replay, because all memory queries coming from the index get a keyframe sequence ID.
//
// The client may use GetState() to query information about the recording performed on the calling thread.
//
// The client may call any of the DumpXXX() functions from any thread at any time to include
// snapshots of various pieces of memory in the recording.
//
// It's worth noting a subtlety in nomenclature here.
// It is said that a thread is being "recorded" when its code is being emulated and fed to the trace file.
// This is subtly different from being "in an island" or "in a Start/Stop sequence".
// When StartRecordingCurrentThread() is called, recording commences, but then it can be paused or halted arbitrarily.
// In that case, the thread is not being recorded, but it is still recording the same island when recording resumes.
//
// TTD's recording behavior is to either record everything by default or nothing by default.
// - When it's recording everything by default, all its threads will be
//   initially recording islands that are not associated with the recording client.
//   In that case, the client may use this API to monitor recorder state, pause and resume.
//   A client can also call StartRecordingCurrentThread() if they so desire (optionally calling Stop first),
//   which will terminate the current island and start a new one associated with the client.
// - When it's recording nothing by default, the only islands that will be recorded are those
//   explicitly started by the client via StartRecordingCurrentThread().
//
// It is an unlikely scenario that a process will have more than one recording client.
// The most likely way for this to happen would be an app which is attempting to control its own recording,
// but also coexisting with some client injected by a framework, like a CLR-aware recording client.
// If that ever happens, it's up to the clients to "be reasonably mindful and nice to each other".
// Pause/Resume is safe to call in all scenarios, no matter who may have started recording a thread.
// Before calling StartRecordingCurrentThread(), a client should call GetState(),
// to ensure the current thread is not being recorded on behalf of another client.

#pragma once

#include "TTDCommonTypes.h"

#include <Windows.h>

namespace TTD
{

// The exposed interface is retrieved by using this GUID.
// Any revisions to the interface will get a new GUID, to avoid interface mismatches.
// There is no expectation that new versions of TTD will support older preview interfaces,
// so an old client attempting to interface with a newer TTD record engine will just fail to obtain the interface.
class __declspec(uuid("{1173F92A-535A-4D75-A1A5-6040B589E6F5}")) ILiveRecorder;

// Recording interface.
// Clients running in-process can use this to control the recording,
// and introduce their own custom data in the trace file.
//
// Compatibility notes: this is a micro-COM interface.
// - It conforms to COM's IUnknown.
// - Uses simple ABI-stable types as parameters and return values: integrals, pointers, references
//   and enums of known undelying type.
// - All methods are noexcept.
// - The physical ABI is as defined by the MSVC compiler on Windows.
//   This defines placement of arguments and return values, callee-preserved registers and
//   vtable access and layout.
class ILiveRecorder : public IUnknown
{
public:
    // Returns false if Close() has been called.
    virtual bool IsOpen() const noexcept = 0;

    // End this client's interaction with the recorder, and optionally store a final user data.
    // Possible use for this data is to precord a summary of the recording peformed.
    // Note that a recording can be ended asynchronously before releasing the client,
    // so there's no guarantee that this data will make it into the file.
    virtual void Close(
        _When_(userDataSizeInBytes == 0, _Maybenull_)
        _In_reads_bytes_(userDataSizeInBytes) void const* pUserData,
        _In_range_(0, MaxUserDataSizeInBytes) size_t      userDataSizeInBytes
    ) noexcept = 0;

    // Retrieves the path to the file containing the recording.
    // Returns the length of the string written to pFileName.
    virtual size_t GetFileName(
        _Out_writes_z_(fileNameSize) wchar_t* pFileName,
                                     size_t   fileNameSize
    ) const noexcept = 0;

    // Insert in the file the current contents of memory between the two given addresses.
    // pBeginAddress is inclusive and pEndAddress is not, similar to C++ iterators.
    // If 'synchronous' is false, the function may return before the operation is complete.
    virtual void DumpSnapshot(
        _In_reads_to_ptr_(pEndAddress) void const* pBeginAddress,
        _In_reads_bytes_(0)            void const* pEndAddress,
                                       bool        synchronous
    ) noexcept = 0;

    // Insert in the file the current contents of memory of the given loaded module.
    // If 'writableOnly' is true, only writable memory will be recorded (usually the module's global data segment).
    // This operation is always synchronous, and will be complete when the function returns.
    virtual void DumpModuleData(_In_ HMODULE, bool writableOnly) noexcept = 0;

    // Dump a snapshot of all the process heaps into the trace file.
    // This operation is always synchronous, and will be complete when the function returns.
    virtual void DumpHeaps() noexcept = 0;

    // Adds an event in the trace file with some associated user data.
    // Note that the user data is technically optional if no data is given,
    // but without it there's no way to distinguish this event from any other,
    // except by its position in the recording timeline.
    // The replay engine exposes all events, and associates them to the client,
    // which is identifiable via the client GUID.
    // Possible uses for custom events:
    //  - Marking points of interest in the timeline.
    //  - Signaling actions taken by the client.
    //  - Recording some meaningful piece of metadata.
    virtual void AddCustomEvent(
                                              CustomEventType,
                                              CustomEventFlags,
        _When_(userDataSizeInBytes == 0, _Maybenull_)
        _In_reads_bytes_(userDataSizeInBytes) void const* pUserData,
        _In_range_(0, MaxUserDataSizeInBytes) size_t      userDataSizeInBytes
    ) noexcept = 0;

    // Start recording a new island in the calling thread with the given Activity ID.
    // A throttle may be specified as a maximum count of instructions to record,
    // with InstructionCount::Max meaning no throttle.
    // If the current thread was recording already,
    // then recording will be stopped as if StopRecordingCurrentThread had been called,
    // and then started anew using the new activity ID and throttle.
    // The provided user data, if any, will be associated with the new island.
    // This operation is always synchronous, and the current thread will already be recording when the function returns.
    virtual void StartRecordingCurrentThread(
                                              ActivityId,
                                              InstructionCount maxInstructionsToRecord,
        _When_(userDataSizeInBytes == 0, _Maybenull_)
        _In_reads_bytes_(userDataSizeInBytes) void const*      pUserData,
        _In_range_(0, MaxUserDataSizeInBytes) size_t           userDataSizeInBytes
    ) noexcept = 0;

    // Utility inlined overload without user data, because this should be fairly common.
    inline
    void StartRecordingCurrentThread(ActivityId activity, InstructionCount maxInstructionsToRecord) noexcept
    {
        return StartRecordingCurrentThread(activity, maxInstructionsToRecord, nullptr, 0);
    }

    // Stop recording instructions on the calling thread, ending the current island if any.
    // Returns the number of instructions that were recorded into the island.
    // If the calling thread wasn't recording because it had reached its throttle or because it was paused,
    // then the result will be the count of instructions recorded until the pause or throttle.
    // If the calling thread wasn't recording because recording never was started,
    // or because recording was already explicitly stopped via this function,
    // then the result will be InstructionCount::Zero.
    virtual InstructionCount StopRecordingCurrentThread() noexcept = 0;

    // Query the current instruction counts relevant to the throttle.
    // If the calling thread is actively recording an island, then upon return
    // the counts returned will already be stale by some indeterminate amount.
    // Returns all InstructionCount::Zero if not within an island.
    virtual void GetThrottleState(_Out_ ThrottleState&) const noexcept = 0;

    // Convenience overload to get the throttle state as a return value.
    inline
    ThrottleState GetThrottleState() const noexcept
    {
        ThrottleState result;
        GetThrottleState(result);
        return result;
    }

    // Reset the throttle as if we had called Stop and then Start again with this new throttle.
    // It returns the number of instructions that were recorded before the throttle was reset.
    // If called outside of an island, this does nothing and returns InstructionCount::Zero.
    virtual InstructionCount ResetThrottle(InstructionCount maxInstructionsToRecord) noexcept = 0;

    // Raw APIs to stop and then restart the recording.
    // Useful when we want to avoid recording client code.

    // TryPauseRecording() returns true only if the thread was being actively recorded.
    // This result should be checked when calling ResumeRecording() after the client code finishes.
    // ResumeRecording() shouldn't be called if TryPauseRecording() returned false.
    virtual bool TryPauseRecording() noexcept = 0;

    // Resume recording on for the current thread if it had already been started, but recording was paused.
    // Returns true if the current thread is being recorded upon return.
    // This result is not reliable, as recording may be stopped at any time via throttling,
    // but it may be used for logging purposes.
    virtual bool ResumeRecording() noexcept = 0;

    // Check the record engine's state for the current thread.
    // If this is called while the current thread is being recorded,
    // the result might be already stale upon returning to the caller (might get throttled on the way out).
    // Even if the current thread is not being recorded, the potential existence of a global throttle
    // might switch the state from Recording or Paused to Throttled at any time, without notice.
    // Please exercise caution and use defensive programming techniques when using this function.
    virtual ThreadRecordingState GetState() const noexcept = 0;

    // Templates added for convenience, they all adapt to interface functions defined above:

    template < typename UserData >
    inline
    void Close(_In_ UserData const& userData) noexcept
    {
        return Close(&userData, sizeof(userData));
    }

    template < typename UserData >
    inline
    void AddCustomEvent(
             CustomEventType  const type,
             CustomEventFlags const flags,
        _In_ UserData        const& userData
    ) noexcept
    {
        return AddCustomEvent(type, flags, &userData, sizeof(userData));
    }

    template < typename UserData >
    inline
    void StartRecordingCurrentThread(
             ActivityId       const activity,
             InstructionCount const maxInstructionsToRecord,
        _In_ UserData        const& userData
    ) noexcept
    {
        return StartRecordingCurrentThread(activity, maxInstructionsToRecord, &userData, sizeof(userData));
    }

    // RAII helper to reliably pause emulation over a piece of code, and resume recording afterwards.
    // Note: If a client throws an exception while paused,
    // this class will automatically resume recording in the middle of the stack unwinding,
    // when the unwinder goes past the function that used it.
    // This is perfectly safe, but it might look disconcerting on replay.
    class ScopedPauseRecording
    {
    public:
        // Note: we want the emulated portion of the pause/resume sequence to be as lean as possible.
        // __forceinline expresses this intent: we'd rather not emulate the call into the constructor,
        // or the return from the destructor, when not inlined.
        __forceinline ScopedPauseRecording(_Inout_ ILiveRecorder* const pLiveRecorder) noexcept : m_pLiveRecorder(pLiveRecorder->TryPauseRecording() ? pLiveRecorder : nullptr) {}
        __forceinline ~ScopedPauseRecording() noexcept { if (m_pLiveRecorder != nullptr) { m_pLiveRecorder->ResumeRecording(); } }

        // true if the current thread was originally recording (if the destructor will resume recording).
        bool WasRecording() const noexcept { return m_pLiveRecorder != nullptr; }

        // No copying or moving. Just pure RAII.
        ScopedPauseRecording           (ScopedPauseRecording const&) = delete;
        ScopedPauseRecording           (ScopedPauseRecording&&)      = delete;
        ScopedPauseRecording& operator=(ScopedPauseRecording const&) = delete;
        ScopedPauseRecording& operator=(ScopedPauseRecording&&)      = delete;

    private:
        ILiveRecorder* m_pLiveRecorder; // Set to nullptr if recording was off, so we won't resume.
    };
};

// Create a new TTD live recorder object to interact with and control the current recording.
// A possible use of the user data is to store configuration parameters of the client, for access at replay time.
// writerGuid must be the GUID of this ILiveRecorder interface.
// This will ensure we can't get a different incompatible version of this interface.
// Note that it's defaulted to the correct value for convenience, so the calling code doesn't need to specify it.
extern "C" ILiveRecorder* __cdecl TTDMakeLiveRecorder(
    _In_                                  GUID const& clientGuid,
    _When_(userDataSizeInBytes == 0, _Maybenull_)
    _In_reads_bytes_(userDataSizeInBytes) void const* pUserData,
    _In_range_(0, MaxUserDataSizeInBytes) size_t      userDataSizeInBytes,
    _In_                                  GUID const& recorderGuid        = __uuidof(ILiveRecorder)
) noexcept;

template < typename UserData >
inline
ILiveRecorder* MakeLiveRecorder(
    _In_ GUID     const& clientGuid,
    _In_ UserData const& userData,
    _In_ GUID     const& recorderGuid = __uuidof(ILiveRecorder)
) noexcept
{
    return TTDMakeLiveRecorder(clientGuid, &userData, sizeof(userData), recorderGuid);
}

}
// namespace TTD
