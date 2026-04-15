<div align="center">
  <img src="icon.svg" width="120" alt="EtwTiViewer icon"/>
</div>

# EtwTiViewer

A research tool for live exploration of the **Microsoft-Windows-Threat-Intelligence** (`ETW-TI`) ETW provider — the same telemetry source commercial EDRs use to detect in-memory attacks and process injection.

> **Research and education only.** Requires kernel debugging, test-signed drivers, and deliberate security-boundary patching. Run exclusively in isolated VMs. Some parts of this project were built with LLM-assisted development and may contain bugs, be carefull using this tool in production environments.

![Interface](screenshots/interface.png)

---

## What is ETW-TI?

`Microsoft-Windows-Threat-Intelligence` (GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) is a **Secure ETW provider** built into `ntoskrnl.exe` that fires on low-level security-relevant operations:

| Keyword | What it covers |
|---|---|
| `ALLOCVM_REMOTE` / `LOCAL` | Cross-process / local virtual memory allocation |
| `PROTECTVM_REMOTE` / `LOCAL` | Protection changes (`VirtualProtectEx`, RWX marking) |
| `MAPVIEW_REMOTE` / `LOCAL` | Section mapping into another / same process |
| `QUEUEUSERAPC_REMOTE` | APC injection into a remote thread |
| `SETTHREADCONTEXT_REMOTE` | Thread register-state overwrite (shellcode injection) |
| `READVM_REMOTE` / `WRITEVM_REMOTE` | Cross-process memory read/write |
| `SUSPEND/RESUME_THREAD` | Thread suspension during injection |
| `FREEZE/THAW_PROCESS` | Whole-process freezing |
| `PROCESS_IMPERSONATION_*` | Token impersonation up / down / revert |

---

## Why access is restricted — and how we bypass it

The kernel requires the subscribing process to be **`PS_PROTECTED_ANTIMALWARE_LIGHT`** (`EPROCESS->Protection = 0x31`), backed by an ELAM certificate Microsoft only issues to commercial security vendors. Without it, `EnableTraceEx2` returns `ERROR_ACCESS_DENIED`.

The workaround: patch the one-byte `Protection` field of `EtwTiViewer.exe`'s `EPROCESS` in an active kernel debugger session before starting a capture. The patch is non-persistent — a process restart resets it.

```
PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31
  ↳ Type   = PsProtectedTypeProtectedLight  (bits [2:0] = 3)
  ↳ Signer = PsProtectedSignerAntimalware   (bits [6:3] = 1)
```

**WinDbg procedure** (run with `EtwTiViewer.exe` already open):

```
kd> !process 0 0 EtwTiViewer.exe
   PROCESS ffffe7054f0f8080  ...

kd> dt nt!_EPROCESS ffffe7054f0f8080 Protection
   +0x87a Protection : _PS_PROTECTION

kd> eb ffffe7054f0f8080+0x87a 31
kd> g
```

> The `Protection` offset varies between Windows builds — always query it with `dt` rather than hardcoding it.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Kernel                                                              │
│                                                                      │
│  ntoskrnl.exe — ETW-TI instrumentation                               │
│    EtwTiLogAllocateVirtualMemory() ─────────────────────────────►    │
│    EtwTiLogProtectVirtualMemory()     ETW real-time session          │
│    EtwTiLogMapViewOfSection()         "EtwTiViewerSession"           │
│                                                                      │
│  EtwTiDriver.sys (WDM)                                               │
│    PsSetCreateProcessNotifyRoutineEx  ──► PROCESS_CREATE/EXIT        │
│    PsSetLoadImageNotifyRoutine        ──► IMAGE_LOAD                 │
│    Pipe worker: ZwCreateFile → \\.\pipe\EtwTiForwarder               │
│    IOCTL_ETWTI_START runs in EtwTiViewer.exe context                 │
│      (so the EPROCESS->Protection check hits the patched process)    │
└───────────────────────────┬──────────────────────────────────────────┘
                            │ named pipe — binary wire protocol
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  EtwTiViewer.exe  (C++17, ImGui + DirectX 11)                        │
│                                                                      │
│  PipeClient     — ReadFile(pipe) → decode PIPE_EVENT_HEADER          │
│  EtwConsumer    — StartTraceW / EnableTraceEx2 / ProcessTrace        │
│                   TDH decodes PEVENT_RECORD → TiEvent                │
│  Both sources   → EventBuffer (ring, 50 000 events)                  │
│  Render thread  → ImGui UI, JSONL file logging                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Event sources**

| Source | Events | Requires |
|---|---|---|
| `PsSetCreateProcessNotifyRoutineEx` | `PROCESS_CREATE`, `PROCESS_EXIT` | Driver loaded |
| `PsSetLoadImageNotifyRoutine` | `IMAGE_LOAD` | Driver loaded |
| ETW-TI consumer (user-mode) | All keyword-gated events | `EPROCESS->Protection = 0x31` |

**Wire format** (`PIPE_EVENT_HEADER`, 18 bytes): `Magic (4)` · `EventId (2)` · `Pid (4)` · `Tid (4)` · `Timestamp/FILETIME (8)` · `NameLen (2)` · `FieldsLen (2)` — followed by a UTF-8 name and `key=value\0` field pairs. `PIPE_TYPE_MESSAGE` ensures each `ReadFile` returns exactly one event.

**IOCTL interface**

| IOCTL | I/O | Purpose |
|---|---|---|
| `IOCTL_ETWTI_START` | In: `ULONGLONG KeywordMask` | Start session; register provider in caller context |
| `IOCTL_ETWTI_STOP` | — | Stop session; remove PS callbacks |
| `IOCTL_ETWTI_STATUS` | Out: running / EVT/s / dropped | Poll driver health |
| `IOCTL_ETWTI_SET_VERBOSE` | In: `ULONG` | Toggle per-event `DbgPrintEx` |

---

## Repository layout

```
EtwTiSuite/
├── EtwTiDriver/
│   ├── EtwTiDriver.c        DriverEntry, IOCTL handler, pipe server, PS callbacks
│   ├── EtwTiShared.h        IOCTL codes + pipe wire types (shared with viewer)
│   ├── EtwTiDriver.inf      Non-PnP driver manifest
│   └── build.bat            MSBuild + self-sign → deploy-ready .sys
├── EtwTiViewer/
│   ├── ImGuiApp.h/.cpp      UI: keyword panel, toolbar, event table, logging
│   ├── EtwConsumer.h/.cpp   Real-time ETW consumer
│   ├── PipeClient.h/.cpp    Pipe reader → EventBuffer
│   ├── DriverControl.h/.cpp IOCTL wrappers
│   └── EventBuffer.h        Thread-safe ring buffer (50 000 events)
├── third_party/imgui/       Clone separately (see Setup)
└── EtwTiSuite.sln
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10 21H2+ / Windows 11 x64 | Run in a VM |
| Visual Studio 2022 (v143) | C++17 |
| WDK 10.0.22621+ | Matched to VS install |
| Test-signing enabled + Secure Boot off | `bcdedit /set testsigning on` + reboot |
| Administrator account | Driver install and viewer launch |
| WinDbg kernel debug session | Required for the EPROCESS patch |

---

## Setup

```cmd
# 1. Clone ImGui (docking branch)
mkdir third_party
cd third_party
git clone --branch docking https://github.com/ocornut/imgui.git imgui

# 2. Enable test-signing (VM only) and reboot
bcdedit /set testsigning on && shutdown /r /t 0

# 3. Build the driver (self-signs the .sys)
cd EtwTiDriver && build.bat

# 4. Build the viewer — open EtwTiSuite.sln in VS, Release|x64, Ctrl+Shift+B
#    or: msbuild EtwTiSuite.sln /p:Configuration=Release /p:Platform=x64 /t:EtwTiViewer

# 5. Install the driver (elevated prompt)
sc create EtwTiDriver type= kernel start= demand binPath= "C:\...\EtwTiDriver.sys"
sc start EtwTiDriver
# Expect: STATE: 4 RUNNING
# Error 577 = test-signing not on or VM not rebooted

# 6. Stop and uninstall (always click Stop in the viewer first)
sc stop EtwTiDriver && sc delete EtwTiDriver
```

---

## Usage

**1. Patch EPROCESS->Protection** (see WinDbg procedure above) while `EtwTiViewer.exe` is running.

**2. Launch the viewer** — `EtwTiViewer\x64\Release\EtwTiViewer.exe` (as Administrator). Status bar indicators:
- **Driver** — green when `\\.\EtwTiDriver` opens
- **Pipe** — green when the driver connects to the forwarder pipe
- **ETW-TI** — green when `EnableTraceEx2` succeeds (requires the patch)

**3. Capture:**
1. Check keywords in the **Keywords** panel (or **Select All**)
2. Click **Start** — driver IOCTL + ETW consumer session begin simultaneously
3. Events stream into the **Events** table in real time
4. Use **Filter** to substring-match on name or any field value
5. Toggle **Log [ON]** to stream to a JSONL file
6. Hover any status indicator for a detailed tooltip
7. Click **Stop** → **Clear** to reset

**Kernel debug output:** `kd> ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF` then enable **KD Verbose** in the toolbar.

---

## Resources

- **fluxsec.red** — [ETW-TI: Rust Consumer](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer) — detailed walkthrough of the provider, its access model, and consumer implementation
- **Sanctum** by 0xflux — [github.com/0xflux/Sanctum](https://github.com/0xflux/Sanctum) — proof-of-concept EDR in Rust demonstrating real-world ETW-TI consumption

---

## Disclaimer

Provided for defensive research and education only — to validate detection logic, evaluate ETW-TI telemetry coverage, and document provider behaviour. Using this tool against systems you do not own, or to develop evasion techniques for production environments, is outside the intended use and your sole responsibility.
