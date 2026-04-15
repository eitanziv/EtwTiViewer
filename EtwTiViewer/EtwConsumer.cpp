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
// Task ID → operation name and Keyword bitmask → variant suffix
//
// Task IDs verified against repnz/etw-providers-docs manifest and
// fluxsec.red ETW-TI implementation.
// ============================================================================

static const char* TaskToString(USHORT task)
{
    switch (task) {
        case 1:  return "ALLOCVM";
        case 2:  return "PROTECTVM";
        case 3:  return "MAPVIEW";
        case 4:  return "QUEUEUSERAPC";
        case 5:  return "SETTHREADCONTEXT";
        case 6:  return "READVM";
        case 7:  return "WRITEVM";
        case 8:  return "SUSPENDRESUME_THREAD";
        case 9:  return "SUSPENDRESUME_PROCESS";
        case 10: return "DRIVER_DEVICE";
        default: return "UNKNOWN";
    }
}

static std::string KeywordToSuffix(USHORT task, ULONGLONG keyword)
{
    switch (task) {
    case 1: /* ALLOCVM — bits 0x1/0x2/0x4/0x8 */
        if (keyword & 0x8ULL) return "_REMOTE_KERNEL_CALLER";
        if (keyword & 0x4ULL) return "_REMOTE";
        if (keyword & 0x2ULL) return "_LOCAL_KERNEL_CALLER";
        if (keyword & 0x1ULL) return "_LOCAL";
        break;
    case 2: /* PROTECTVM — bits 0x10/0x20/0x40/0x80 */
        if (keyword & 0x80ULL) return "_REMOTE_KERNEL_CALLER";
        if (keyword & 0x40ULL) return "_REMOTE";
        if (keyword & 0x20ULL) return "_LOCAL_KERNEL_CALLER";
        if (keyword & 0x10ULL) return "_LOCAL";
        break;
    case 3: /* MAPVIEW — bits 0x100/0x200/0x400/0x800 */
        if (keyword & 0x800ULL) return "_REMOTE_KERNEL_CALLER";
        if (keyword & 0x400ULL) return "_REMOTE";
        if (keyword & 0x200ULL) return "_LOCAL_KERNEL_CALLER";
        if (keyword & 0x100ULL) return "_LOCAL";
        break;
    case 4: /* QUEUEUSERAPC — bits 0x1000/0x2000 (remote only) */
        if (keyword & 0x2000ULL) return "_REMOTE_KERNEL_CALLER";
        if (keyword & 0x1000ULL) return "_REMOTE";
        break;
    case 5: /* SETTHREADCONTEXT — bits 0x4000/0x8000 (remote only) */
        if (keyword & 0x8000ULL) return "_REMOTE_KERNEL_CALLER";
        if (keyword & 0x4000ULL) return "_REMOTE";
        break;
    case 6: /* READVM — bits 0x10000/0x20000 */
        if (keyword & 0x20000ULL) return "_REMOTE";
        if (keyword & 0x10000ULL) return "_LOCAL";
        break;
    case 7: /* WRITEVM — bits 0x40000/0x80000 */
        if (keyword & 0x80000ULL) return "_REMOTE";
        if (keyword & 0x40000ULL) return "_LOCAL";
        break;
    case 8: /* SUSPENDRESUME_THREAD — bits 0x100000/0x200000 */
        if (keyword & 0x200000ULL) return "_RESUME";
        if (keyword & 0x100000ULL) return "_SUSPEND";
        break;
    case 9: /* SUSPENDRESUME_PROCESS — bits 0x400000/0x800000/0x1000000/0x2000000 */
        if (keyword & 0x2000000ULL) return "_THAW";
        if (keyword & 0x1000000ULL) return "_FREEZE";
        if (keyword & 0x800000ULL)  return "_RESUME";
        if (keyword & 0x400000ULL)  return "_SUSPEND";
        break;
    default:
        break;
    }
    return "";
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
    ev.task    = er->EventHeader.EventDescriptor.Task;
    ev.keyword = er->EventHeader.EventDescriptor.Keyword;
    ev.pid     = er->EventHeader.ProcessId;
    ev.tid     = er->EventHeader.ThreadId;

    /* Build the full event name from Task (operation category) + Keyword (variant suffix) */
    ev.name = std::string(TaskToString(ev.task)) + KeywordToSuffix(ev.task, ev.keyword);

    /* Decode properties using TDH */
    ULONG infoSz = 0;
    TdhGetEventInformation(er, 0, nullptr, nullptr, &infoSz);
    if (infoSz > 0 && infoSz <= 65536) {
        std::vector<BYTE> infoBuf(infoSz);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.data());

        if (TdhGetEventInformation(er, 0, nullptr, info, &infoSz) == ERROR_SUCCESS) {

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
