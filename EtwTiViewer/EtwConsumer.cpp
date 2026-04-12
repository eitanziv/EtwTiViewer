/*
 * EtwConsumer.cpp — Real-time ETW consumer for Microsoft-Windows-Threat-Intelligence.
 */

#include "EtwConsumer.h"
#include "EventBuffer.h"

#include <tdh.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

// ============================================================================
// Statics
// ============================================================================

const wchar_t EtwConsumer::kSessionName[] = L"EtwTiViewerSession";
EtwConsumer*  EtwConsumer::s_instance     = nullptr;

static const GUID kEtwTiGuid = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

// ============================================================================
// Event-ID to name table (matches ntoskrnl's ETW-TI manifest)
// ============================================================================

static const char* EtwTiEventName(USHORT id)
{
    static const char* kNames[] = {
        nullptr,                               // 0  (unused)
        "ALLOCVM_LOCAL",                       // 1
        "ALLOCVM_LOCAL_KERNEL_CALLER",         // 2
        "ALLOCVM_REMOTE",                      // 3
        "ALLOCVM_REMOTE_KERNEL_CALLER",        // 4
        "PROTECTVM_LOCAL",                     // 5
        "PROTECTVM_LOCAL_KERNEL_CALLER",       // 6
        "PROTECTVM_REMOTE",                    // 7
        "PROTECTVM_REMOTE_KERNEL_CALLER",      // 8
        "MAPVIEW_LOCAL",                       // 9
        "MAPVIEW_LOCAL_KERNEL_CALLER",         // 10
        "MAPVIEW_REMOTE",                      // 11
        "MAPVIEW_REMOTE_KERNEL_CALLER",        // 12
        "QUEUEUSERAPC_REMOTE",                 // 13
        "QUEUEUSERAPC_REMOTE_KERNEL_CALLER",   // 14
        "SETTHREADCONTEXT_REMOTE",             // 15
        "SETTHREADCONTEXT_REMOTE_KERNEL_CALLER", // 16
        "READVM_LOCAL",                        // 17
        "READVM_REMOTE",                       // 18
        "WRITEVM_LOCAL",                       // 19
        "WRITEVM_REMOTE",                      // 20
        "SUSPEND_THREAD",                      // 21
        "RESUME_THREAD",                       // 22
        "SUSPEND_PROCESS",                     // 23
        "RESUME_PROCESS",                      // 24
        "FREEZE_PROCESS",                      // 25
        "THAW_PROCESS",                        // 26
        "CONTEXT_PARSE",                       // 27
        "EXECUTION_ADDRESS_VAD_PROBE",         // 28
        "EXECUTION_ADDRESS_MMF_NAME_PROBE",    // 29
        "READWRITEVM_NO_SIGNATURE_RESTRICTION",// 30
        "DRIVER_EVENTS",                       // 31
        "DEVICE_EVENTS",                       // 32
    };
    if (id < (USHORT)(sizeof(kNames) / sizeof(kNames[0])) && kNames[id])
        return kNames[id];
    return nullptr;
}

// ============================================================================
// Internal helpers
// ============================================================================

/* Allocate + init an EVENT_TRACE_PROPERTIES large enough for our session name */
static EVENT_TRACE_PROPERTIES* AllocProps()
{
    const ULONG nameSz = (ULONG)((wcslen(EtwConsumer::kSessionName) + 1) * sizeof(wchar_t));
    const ULONG total  = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + nameSz;
    auto* p = static_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, total));
    if (!p) return nullptr;
    p->Wnode.BufferSize  = total;
    p->Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;     // QPC timestamps
    p->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);
    return p;
}

/* Format one ETW property value as a printable string */
static std::string FormatPropValue(const EVENT_PROPERTY_INFO& pi,
                                   const BYTE* data, ULONG dataLen)
{
    char buf[128];
    if (dataLen == 0) return "";

    USHORT inType = pi.nonStructType.InType;

    switch (inType) {
    case TDH_INTYPE_UINT8:
        snprintf(buf, sizeof(buf), "%u", (unsigned)*data);
        return buf;

    case TDH_INTYPE_UINT16:
        if (dataLen >= 2) {
            snprintf(buf, sizeof(buf), "%u", (unsigned)*(const UINT16*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_UINT32:
        if (dataLen >= 4) {
            UINT32 v = *(const UINT32*)data;
            snprintf(buf, sizeof(buf), "%u (0x%X)", v, v);
            return buf;
        }
        break;

    case TDH_INTYPE_UINT64:
        if (dataLen >= 8) {
            UINT64 v = *(const UINT64*)data;
            snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)v);
            return buf;
        }
        break;

    case TDH_INTYPE_INT32:
        if (dataLen >= 4) {
            snprintf(buf, sizeof(buf), "%d", *(const INT32*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_INT64:
        if (dataLen >= 8) {
            snprintf(buf, sizeof(buf), "%lld", (long long)*(const INT64*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_POINTER:
        if (dataLen >= 8) {
            snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)*(const UINT64*)data);
            return buf;
        } else if (dataLen >= 4) {
            snprintf(buf, sizeof(buf), "0x%08X", *(const UINT32*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_HEXINT32:
        if (dataLen >= 4) {
            snprintf(buf, sizeof(buf), "0x%08X", *(const UINT32*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_HEXINT64:
        if (dataLen >= 8) {
            snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)*(const UINT64*)data);
            return buf;
        }
        break;

    case TDH_INTYPE_UNICODESTRING: {
        const wchar_t* ws = reinterpret_cast<const wchar_t*>(data);
        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, narrow, (int)sizeof(narrow) - 1, nullptr, nullptr);
        return narrow;
    }

    case TDH_INTYPE_ANSISTRING:
        return std::string(reinterpret_cast<const char*>(data),
                           strnlen(reinterpret_cast<const char*>(data), dataLen));

    default:
        break;
    }

    /* Fallback: hex dump of up to 8 bytes */
    std::string hex;
    ULONG n = (std::min)(dataLen, (ULONG)8);
    for (ULONG i = 0; i < n; i++) {
        char h[4];
        snprintf(h, sizeof(h), "%02X ", data[i]);
        hex += h;
    }
    return hex;
}

// ============================================================================
// EtwConsumer::Start
// ============================================================================

std::string EtwConsumer::Start(ULONGLONG keywordMask, std::function<void(TiEvent&&)> onEvent)
{
    Stop();   // clean up any previous session
    m_onEvent   = std::move(onEvent);
    m_lastError.clear();

    /* ---- Stop any lingering session with our name from a prior crash ---- */
    {
        auto* props = AllocProps();
        if (props) {
            props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
    }

    /* ---- Create real-time trace session ---- */
    auto* props = AllocProps();
    if (!props) return (m_lastError = "Out of memory allocating trace properties");
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    ULONG err = StartTraceW(&m_session, kSessionName, props);
    free(props);

    if (err != ERROR_SUCCESS) {
        m_session = 0;
        char msg[128];
        snprintf(msg, sizeof(msg), "StartTraceW failed: error %lu", err);
        return (m_lastError = msg);
    }

    /* ---- Enable the ETW-TI provider ---- */
    ENABLE_TRACE_PARAMETERS ep = {};
    ep.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    err = EnableTraceEx2(m_session, &kEtwTiGuid,
                         EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                         TRACE_LEVEL_VERBOSE,
                         keywordMask,
                         0,   // MatchAllKeyword
                         0,   // Timeout (async)
                         &ep);
    if (err != ERROR_SUCCESS) {
        /* Stop the session we just created */
        auto* sp = AllocProps();
        if (sp) { ControlTraceW(m_session, nullptr, sp, EVENT_TRACE_CONTROL_STOP); free(sp); }
        m_session = 0;

        char msg[320];
        if (err == ERROR_ACCESS_DENIED) {
            snprintf(msg, sizeof(msg),
                     "EnableTraceEx2 ACCESS DENIED (error 5). "
                     "Patch EPROCESS->Protection to 0x31 in WinDbg before clicking Start:\n"
                     "  kd> !process 0 0 EtwTiViewer.exe\n"
                     "  kd> eb <EPROCESS>+<Protection_offset> 31");
        } else {
            snprintf(msg, sizeof(msg), "EnableTraceEx2 failed: error %lu", err);
        }
        return (m_lastError = msg);
    }

    /* ---- Open for real-time consumption ---- */
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName       = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwConsumer::StaticCallback;

    s_instance = this;
    m_trace    = OpenTraceW(&logfile);
    if (m_trace == INVALID_PROCESSTRACE_HANDLE) {
        err = GetLastError();
        auto* sp = AllocProps();
        if (sp) { ControlTraceW(m_session, nullptr, sp, EVENT_TRACE_CONTROL_STOP); free(sp); }
        m_session  = 0;
        s_instance = nullptr;
        char msg[128];
        snprintf(msg, sizeof(msg), "OpenTraceW failed: error %lu", err);
        return (m_lastError = msg);
    }

    /* ---- Spawn ProcessTrace thread ---- */
    m_running = true;
    m_thread  = std::thread([this]() {
        ProcessTrace(&m_trace, 1, nullptr, nullptr);
        m_running = false;
    });

    return {};  // success
}

// ============================================================================
// EtwConsumer::Stop
// ============================================================================

void EtwConsumer::Stop()
{
    /* CloseTrace causes ProcessTrace to return, which exits the thread */
    if (m_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_trace);
        m_trace = INVALID_PROCESSTRACE_HANDLE;
    }
    if (m_thread.joinable())
        m_thread.join();
    m_running = false;

    if (m_session != 0) {
        auto* props = AllocProps();
        if (props) {
            ControlTraceW(m_session, nullptr, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        m_session = 0;
    }

    m_onEvent  = nullptr;
    s_instance = nullptr;
}

// ============================================================================
// Event callback
// ============================================================================

/*static*/ void WINAPI EtwConsumer::StaticCallback(PEVENT_RECORD er)
{
    if (s_instance)
        s_instance->OnEvent(er);
}

void EtwConsumer::OnEvent(PEVENT_RECORD er)
{
    if (!m_onEvent) return;

    /* Skip events from other providers that ended up on this session */
    if (!IsEqualGUID(er->EventHeader.ProviderId, kEtwTiGuid))
        return;

    TiEvent ev;

    /* Timestamp: QPC-based LARGE_INTEGER, 100-ns intervals from FILETIME epoch */
    ev.timestamp.dwLowDateTime  = er->EventHeader.TimeStamp.LowPart;
    ev.timestamp.dwHighDateTime = static_cast<DWORD>(er->EventHeader.TimeStamp.HighPart);
    ev.eventId = er->EventHeader.EventDescriptor.Id;
    ev.pid     = er->EventHeader.ProcessId;
    ev.tid     = er->EventHeader.ThreadId;

    /* Event name from our table; fall back to "ETW_TI_<id>" */
    const char* knownName = EtwTiEventName(ev.eventId);
    if (knownName) {
        ev.name = knownName;
    } else {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "ETW_TI_%u", (unsigned)ev.eventId);
        ev.name = tmp;
    }

    /* Decode properties using TDH */
    ULONG infoSz = 0;
    TdhGetEventInformation(er, 0, nullptr, nullptr, &infoSz);
    if (infoSz > 0 && infoSz <= 65536) {
        std::vector<BYTE> infoBuf(infoSz);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.data());

        if (TdhGetEventInformation(er, 0, nullptr, info, &infoSz) == ERROR_SUCCESS) {

            /* If TDH knows the event name and we don't, use it */
            if (!knownName && info->EventNameOffset != 0) {
                const wchar_t* wn = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<BYTE*>(info) + info->EventNameOffset);
                char narrow[128] = {};
                WideCharToMultiByte(CP_UTF8, 0, wn, -1, narrow, sizeof(narrow) - 1, nullptr, nullptr);
                if (narrow[0]) ev.name = narrow;
            }

            /* Iterate top-level properties */
            for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                const EVENT_PROPERTY_INFO& pi = info->EventPropertyInfoArray[i];
                const wchar_t* propNameW = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<BYTE*>(info) + pi.NameOffset);

                char propName[128] = {};
                WideCharToMultiByte(CP_UTF8, 0, propNameW, -1,
                                    propName, sizeof(propName) - 1, nullptr, nullptr);

                /* Fetch raw property bytes */
                PROPERTY_DATA_DESCRIPTOR desc = {};
                desc.PropertyName = reinterpret_cast<ULONGLONG>(propNameW);
                desc.ArrayIndex   = ULONG_MAX;

                ULONG propSz = 0;
                if (TdhGetPropertySize(er, 0, nullptr, 1, &desc, &propSz) != ERROR_SUCCESS)
                    continue;

                std::vector<BYTE> propData(propSz + 2, 0);   // +2 for wide-string null
                if (TdhGetProperty(er, 0, nullptr, 1, &desc,
                                   propSz, propData.data()) != ERROR_SUCCESS)
                    continue;

                std::string val = FormatPropValue(pi, propData.data(), propSz);
                ev.fields.emplace_back(propName, std::move(val));
            }
        }
    }

    m_onEvent(std::move(ev));
}
