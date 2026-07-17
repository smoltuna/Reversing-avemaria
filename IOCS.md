# Indicators of Compromise

Attribution: **AveMaria / Warzone RAT** family.
All network indicators are defanged (`.` → `[.]`). Refang before any live-traffic use.

## Sample

| Property | Value |
|---|---|
| Family | AveMaria / Warzone RAT |
| Sample name (as analyzed) | `Trojan.Win32.Agentb.exe` |
| Second-stage payload name | `637.exe` |
| Compiler | Microsoft Visual C++ (v7.10, 14.16 / Visual 2017) |
| Compile timestamp | `0x5C8B50C7` — Wed Mar 13 01:37:27 2019 |
| `.text` entropy | 6.493 (elevated — dropper-consistent) |
| Family strings | `AVE_MARI`, `warzone160` |
| Developer trace | `C:\Users\louis\Documents\workspace\MortyCrypter\MsgBox.exe` (custom crypter "MortyCrypter", dev user `louis`) |

## Network

### C2 — RAT callback
| Type | Indicator | Context |
|---|---|---|
| Domain | `tresor2020[.]ddns[.]net` | Regular-interval DNS A-record lookups from injected `svchost.exe` (PID 2108). TCP/UDP session attempts followed by ICMP "Destination unreachable" in the sandbox. VirusTotal confirms as Warzone RAT C2. |

Evidence: [evidence/payload/network/fakenet.txt](evidence/payload/network/fakenet.txt), [evidence/payload/network/wireshark.txt](evidence/payload/network/wireshark.txt)

### C2 — DLL staging
NSS decrypt helpers pulled at runtime (used to decrypt Firefox credentials):

| URL |
|---|
| `http://5.206.225[.]104/dll/softokn3.dll` |
| `http://5.206.225[.]104/dll/msvcp140.dll` |
| `http://5.206.225[.]104/dll/mozglue.dll` |
| `http://5.206.225[.]104/dll/vcruntime140.dll` |
| `http://5.206.225[.]104/dll/freebl3.dll` |
| `http://5.206.225[.]104/dll/nss3.dll` |

Evidence: [evidence/payload/static/pestudio-strings.txt](evidence/payload/static/pestudio-strings.txt)

### Maldoc dropper URLs
Compromised WordPress hosts serving `637.exe`. The PowerShell dropper iterates and stops at the first success.

| # | URL |
|---|---|
| 1 | `https://laclinika[.]com/wp-admin/r42ar70/` |
| 2 | `https://thechasermart[.]com/wp-admin/7u93/` |
| 3 | `https://zamusicport[.]com/wp-content/Vmc/` |
| 4 | `https://zaloshop[.]net/wp-admin/8j0827/` |
| 5 | `https://www[.]leatherbyd[.]com/PHPMailer-master/q91l5u01353/` |

Evidence: [evidence/maldoc/deobfuscated.ps1](evidence/maldoc/deobfuscated.ps1)

## Host

### Filesystem
| Path | Purpose |
|---|---|
| `%LOCALAPPDATA%\VirtualStore\Program Files\Microsoft DN1\` | Staging directory (name mimics legitimate). |
| `%LOCALAPPDATA%\Microsoft Vision\` | Additional staging directory. |
| `%APPDATA%\Microsoft Vision\<DD-MM-YYYY_HH.MM.SS>` | Per-session keylog file. Path built via `SHGetFolderPathW(CSIDL=0x1C)` + `lstrcatW("\Microsoft Vision\")` + `GetLocalTime` timestamp. |
| `%USERPROFILE%\637.exe` | Stage-2 payload written by the maldoc dropper. |
| Payload size gate | `>= 23512 bytes` — dropper validates before executing (filters HTTP error pages). |

### Registry
| Key | Change | Purpose |
|---|---|---|
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\MaxConnectionsPer1_0Server` | Added `= 0x0A` | Raise per-server connection cap to accelerate C2 traffic. |
| `HKCU\...\Internet Settings\MaxConnectionsPerServer` | Added `= 0x0A` | Same. |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\ServiceInstances\730fc3c4-2466-4af1-9ba5-c212d98971cd` | Deleted (also `WOW6432Node` variant) | Group-Policy `ServiceInstances` tampering — likely weakens defenses or registers a malicious component. |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\ServiceInstances` | Re-created (also `WOW6432Node` variant) | |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` (`InitWindows`) | Referenced in strings | Autorun intent — not observed in this run (Autoruns showed no diff → likely conditional/hidden). |
| Terminal Services values `fDenyTSConnections`, `EnableConcurrentSessions`, `AllowMultipleTSSessions` | Targeted in strings | RDP re-enable + multi-session for remote-desktop backdoor. |

### Process behavior
- **No child processes** spawned by the RAT itself; runs isolated under `explorer.exe`.
- **High internal thread count** — network traffic surfaces from injected `svchost.exe` (PID 2108) instead of the RAT process.
- **Elevation attempt** via string `Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}`.
- **Self-delete pattern** in strings: `cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q ...`.
- **Maldoc chain**: `winword.exe → wmiprvse.exe → powershell.exe -w hidden -en <b64>` — WMI-based process creation via `winmgmts:Win32_Process` breaks the Office parent-child chain.

### Maldoc structural markers
- Word 97-2003 doc, contains `Microsoft Forms 2.0 Form` (ActiveX embed).
- `Document_open` AutoExec.
- Obfuscated VBA module names: `Pvncafg`, `Llzjsomymu`, `Qnrnsagenrr`, `Pvndiiicafg`.
- Metadata: `Author: Mathilde Bernard` (likely fake), `Create/Modify: 2019:12:19 13:19:00` (identical → auto-generated).
- WMI-string delimiter: `8**hjK%%%^^hjkHSB3423DFFF` (used to split/rejoin `winmgmts:Win32_Process`).

## Detection

YARA rule targeting the maldoc: [detections/ave-maria-warzone.yar](detections/ave-maria-warzone.yar)

The rule combines high-signal traits: `Document_open` AutoExec, obfuscated identifier fragments (`Pvncafg`, `Llzjsomymu`, `Qnrnsagenrr`), and split PowerShell command strings (`owershei` / `ll -w hi` / `dden -en cmu`) that survive the maldoc's string-concatenation obfuscation.

## Safety

Handle all referenced samples and captures only in an isolated analysis environment.
