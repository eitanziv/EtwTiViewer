#pragma once
/*
 * EtwConsumer.h — Real-time ETW consumer for the Microsoft-Windows-Threat-Intelligence
 * provider ({F4E1897C-BB5D-5668-F1D8-040F4D8DD344}).
 *
 * WHY THIS EXISTS
 * ===============
 * EtwRegister() in a kernel driver registers the driver as an ETW *provider*.
 * It cannot receive the kernel's built-in ETW-TI events (ALLOCVM_REMOTE,
 * PROTECTVM_*, MAPVIEW_*, etc.) — those are written by ntoskrnl's own internal
 * registration and flow to ETW *consumer sessions*.
 *
 * This class creates a real-time consumer session directly in EtwTiViewer.exe.
 * Because the process has been patched to PS_PROTECTED_ANTIMALWARE_LIGHT
 * (EPROCESS->Protection = 0x31), the kernel's ETW-TI access check passes and
 * all subscribed event types arrive in the EventRecordCallback.
 *
 * USAGE
 * =====
 *   EtwConsumer c;
 *   std::string err = c.Start(keywordMask, &evBuf);
 *   if (!err.empty()) { /* display error *\/ }
 *   // ... later ...
 *   c.Stop();
 */

#include <Windows.h>
#include <evntrace.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>

#include "EventBuffer.h"   // for TiEvent

class EtwConsumer {
public:
    EtwConsumer()  = default;
    ~EtwConsumer() { Stop(); }

    /*
     * Start — create a real-time ETW session, enable the ETW-TI provider with
     * the given keyword mask, open a trace handle, and spawn a background thread
     * running ProcessTrace().
     *
     * onEvent is called on the ProcessTrace thread for each received TiEvent.
     * Typical use: log the event, then push it into an EventBuffer.
     *
     * Returns an empty string on success, or an error message on failure.
     * The most common failure is ERROR_ACCESS_DENIED (5) from EnableTraceEx2 —
     * this means EPROCESS->Protection has not been patched to 0x31 yet.
     */
    std::string Start(ULONGLONG keywordMask, std::function<void(TiEvent&&)> onEvent);

    /*
     * Stop — closes the trace handle (which unblocks ProcessTrace), joins the
     * background thread, and stops the ETW session.  Safe to call even if
     * Start() was never called or already failed.
     */
    void Stop();

    bool IsRunning() const { return m_running.load(std::memory_order_relaxed); }

    /* Last error string set during Start() for display in the UI */
    const std::string& LastError() const { return m_lastError; }

    static const wchar_t   kSessionName[];   /* "EtwTiViewerSession" */

private:
    static void WINAPI StaticCallback(PEVENT_RECORD er);
    void OnEvent(PEVENT_RECORD er);
    static EtwConsumer*    s_instance;

    TRACEHANDLE                    m_session = 0;
    TRACEHANDLE                    m_trace   = INVALID_PROCESSTRACE_HANDLE;
    std::thread                    m_thread;
    std::atomic<bool>              m_running{false};
    std::function<void(TiEvent&&)> m_onEvent;
    std::string                    m_lastError;
};
