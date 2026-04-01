# Malware Simulation Analysis

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=700&size=34&duration=3200&pause=900&color=00B894&center=true&vCenter=true&width=980&lines=Malware+Simulation+Investigation;Static+%2B+Dynamic+Analysis+Pipeline;From+Macro+Trigger+to+Runtime+Behavior" alt="Title banner" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Analysis-Static%20%2B%20Dynamic-0B132B?style=for-the-badge&logo=hackaday&logoColor=white" alt="analysis badge" />
  <img src="https://img.shields.io/badge/Focus-Macro%20Dropper%20%7C%20PE%20Behavior-1C2541?style=for-the-badge" alt="focus badge" />
  <img src="https://img.shields.io/badge/License-MIT-2EC4B6?style=for-the-badge" alt="license badge" />
</p>

---

## Overview

This repository contains a complete malware-analysis case study built from both document-based and executable-based evidence.

The objective is to reconstruct the attack chain end-to-end:

1. Initial malicious document behavior (macro stage).
2. Payload retrieval and execution logic.
3. Host and network behavior observed in a controlled environment.
4. Detection artifacts (YARA and IOC extraction).

The dataset combines static reverse engineering, runtime telemetry, network captures, and registry/process deltas.

---

## Tech Stack And Tooling

### Languages / Formats

- VBA macro code (inside malicious Office document)
- PowerShell (deobfuscated downloader)
- YARA rules
- PCAP / PCAPNG network traces
- CSV and TXT forensic exports

### Analysis Toolchain

- ExifTool (document metadata)
- OLETools / `olevba` (macro extraction and deobfuscation)
- ViperMonkey (macro emulation)
- IDA (disassembly and API/behavior mapping)
- PEStudio (imports and suspicious strings)
- FakeNet-NG (simulated network sinkhole)
- Wireshark (packet-level inspection)
- Process Explorer (process tree snapshot)
- Process Monitor (filesystem/registry/runtime traces)
- Regshot (registry delta)
- Autoruns (persistence/autostart snapshot archive)

---

## Repository Structure And File-by-File Purpose

### Root

- `Codice_Malevolo-Report.pdf`
  - Final report document summarizing the analysis workflow and findings.
- `LICENSE`
  - MIT license.

### `shared/documento malevolo/`

- `deobfuscated.ps1`
  - Deobfuscated PowerShell downloader logic.
  - Builds `%USERPROFILE%\637.exe`, iterates over multiple fallback URLs, downloads payload, checks minimum size (`>= 23512`), and executes it.
- `exiftool.txt`
  - Document metadata extraction.
  - Indicates OLE/Word-style structure and macro-related clues (including "Microsoft Forms 2.0 Form").
- `olevba.txt`
  - Static macro extraction/deobfuscation output.
  - Shows `Document_open` entry point, obfuscated VBA symbols, and split strings reassembling hidden PowerShell command fragments.
- `VIPERMONKEY_ANALISI.txt`
  - Macro emulation transcript.
  - Confirms `document_open` execution path and records interesting calls (`GetObject`, `CreateObject`, `Create`).
- `strings.txt`
  - Raw strings dump of the malicious document.
  - Useful for low-level indicator hunting and format/embedded-object fingerprints.
- `rules.yar`
  - Custom YARA detection rule matching the macro family through:
    - Forms marker
    - `Document_open` entry point
    - Obfuscated symbol names
    - Fragmented PowerShell signature parts

### `shared/file malevolo/`

- `ida.txt`
  - Disassembly export with API-level behavior evidence.
  - Highlights network download and execution/persistence primitives, including `URLDownloadToFileW`, `RegOpenKeyEx*`, `RegCreateKeyEx*`, `RegSetValueEx*`, `WSAStartup`, and `cmd.exe` invocations.
  - Contains embedded URL indicators (for example `http://5.206.225.104/dll/...`).
- `pestudio imports.txt`
  - API import catalog grouped by capability.
  - Shows registry, network, process injection, threading, crypto, and execution-related functions.
- `pestudio strings.txt`
  - Suspicious string corpus.
  - Includes command-line artifacts, URL indicators, Run-key path strings, DLL names, and anti-analysis/execution clues.
- `procexplorer.txt`
  - Process list snapshot from the dynamic session.
  - Captures runtime context with active monitoring tools and system process landscape.
- `procmon.CSV`
  - Host event telemetry (file/registry/process operations).
  - Provides granular event timeline for behavioral correlation during execution window.
- `fakenet.txt`
  - FakeNet-NG traffic log.
  - Shows repeated DNS requests and beacon-like patterns to suspicious domains such as `tresor2020.ddns.net`.
- `wireshark-capture.pcapng`
  - Raw packet capture for deep network forensics.
- `packets_20250612_143859 (fakenet).pcap`
  - Packet capture associated with FakeNet session.
- `wireshark.txt`
  - Text export of packet-level observations.
  - Useful for quick grep-able review without opening GUI tools.
- `~res-x64.txt`
  - Regshot diff output (registry deltas before/after execution window).
- `DESKTOP-BJO110K-autoruns.arn`
  - Autoruns snapshot archive in OLE Compound File format (`D0 CF 11 E0 ...` header).
  - Serves as persistence/autostart evidence container.

---

## Reconstructed Behavior Highlights

- Macro-triggered execution starts at `Document_open`.
- Obfuscated VBA assembles hidden PowerShell execution.
- PowerShell downloader attempts multiple fallback URLs.
- Payload is saved as `%USERPROFILE%\637.exe` and executed after size validation.
- Static binary evidence indicates capability for:
  - Registry interaction and potential Run-key persistence.
  - Network retrieval of additional modules.
  - Process/memory operations associated with advanced execution behaviors.
- Dynamic telemetry (FakeNet/Wireshark/Procmon/Regshot) supports runtime correlation.

---

## IOC Snapshot (From Collected Artifacts)

### Domains / Network Targets

- `tresor2020.ddns.net`
- `laclinika.com`
- `thechasermart.com`
- `zamusicport.com`
- `zaloshop.net`
- `www.leatherbyd.com`
- `5.206.225.104`

### Filenames / Paths

- `%USERPROFILE%\637.exe`
- `Software\Microsoft\Windows\CurrentVersion\Run\`
- `\System32\cmd.exe`

---

## Screenshots Status

No image assets are currently present in this repository (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg` were not found), so there are no ready-to-embed screenshots yet.

If you want to visually enhance this README, the best screenshots to add are:

1. `olevba` macro table and deobfuscation output.
2. FakeNet DNS callbacks (`tresor2020.ddns.net`).
3. Wireshark stream or endpoint summary.
4. Procmon filtered events around payload execution.
5. IDA view showing `URLDownloadToFileW` + registry calls.

Recommended folder for future assets: `assets/screenshots/`

---

## License

Distributed under the MIT License. See `LICENSE` for details.
