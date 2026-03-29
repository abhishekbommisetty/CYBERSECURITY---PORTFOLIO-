# Digital Forensics & Incident Response (DFIR) | Memory Analysis + Criminal Investigation | 

![Volatility](https://img.shields.io/badge/Volatility-Framework-black?style=for-the-badge)
![Autopsy](https://img.shields.io/badge/Autopsy-DFIR-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)
![SOC](https://img.shields.io/badge/SOC_L1-Analyst-FF4500?style=for-the-badge)

-----

## Project Overview

This project covers two DFIR investigations — memory forensics malware analysis across two memory dumps, and a multi-device criminal digital forensics case. Each investigation follows structured DFIR methodology: evidence acquisition, artifact extraction, IOC identification, timeline reconstruction, and documented findings.

**Skills Demonstrated:**

- Memory forensics using Volatility — process analysis, network connection extraction, and memory injection detection
- Malware identification and VirusTotal IOC validation
- Multi-device digital forensics using Autopsy across suspect hardware
- Steganographic artifact detection and encrypted volume analysis
- Evidence correlation and forensic timeline reconstruction

**Tools & Technologies:**
`Volatility Framework` · `Autopsy` · `VirusTotal` · `Windows Registry Analysis` · `Steganography Detection` · `TrueCrypt`

**Full Visual Report:** [Download PDF Report →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/e59930ddf363fbc76c0264a81d35aad99e842ae0/digital-forensics/DFIR%20-%20NARCOS%20CASE.pdf)

**Full Visual Report:** [Download PDF Report →]
-----

## Investigation Summary Table

|Case|Investigation Type                                          |Tool                     |Verdict                     |Severity|MITRE TTPs                 |
|----|------------------------------------------------------------|-------------------------|----------------------------|--------|---------------------------|
|1   |Memory Forensics — Trojan + C2 Detection                    |Volatility               |✅ Confirmed Trojan          |**P1**  |T1055, T1071.001, T1105    |
|2   |Memory Forensics — Privilege Escalation + Credential Dumping|Volatility               |✅ Confirmed Compromise      |**P1**  |T1055, T1003.001, T1547.001|
|3   |Narcos Criminal Case — Multi-Device DFIR                    |Autopsy + Manual Analysis|✅ Confirmed Criminal Network|**P1**  |T1001.002, T1041, T1219    |

-----

## Case 1 — Memory Forensics: Trojan & C2 Communication Detection (T1055, T1071.001, T1105)

### Evidence Details

|Field          |Value                                                 |
|---------------|------------------------------------------------------|
|Memory Image   |`Sample1.dmp`                                         |
|OS Profile     |`WinXPSP2x86`                                         |
|Image Timestamp|2012-07-22                                            |
|Severity       |**P1 — Active Trojan with Confirmed C2 Communication**|

-----

### Investigation

**Step 1 — Identify the correct memory profile**

```bash
vol.py -f Sample1.dmp imageinfo
```

**Why:** `imageinfo` scans the memory image for OS version signatures and suggests compatible Volatility profiles. Running this first ensures all subsequent plugin output is parsed against the correct kernel structures — using a wrong profile produces corrupted or missing results.

**Results:** Suggested profile `WinXPSP2x86` confirmed — Windows XP SP2, 32-bit. Image acquisition timestamp: `2012-07-22`.

-----

**Step 2 — Enumerate all running processes**

```bash
vol.py -f Sample1.dmp --profile=WinXPSP2x86 pslist
```

**Why:** `pslist` walks the `EPROCESS` doubly-linked list to enumerate all active processes at the time of capture. Reviewing process names, parent-child relationships, and PIDs surfaces any processes that are anomalous by name, parent, or execution context.

**Results:** `reader_sl.exe` identified — PID `1640`, parent `explorer.exe`, 5 threads, 39 handles. Flagged for investigation: `reader_sl.exe` is not a standard Windows or Adobe process when executing as a child of `explorer.exe` with minimal thread/handle count.

-----

**Step 3 — Extract active and recently closed network connections**

```bash
vol.py -f Sample1.dmp --profile=WinXPSP2x86 connections
vol.py -f Sample1.dmp --profile=WinXPSP2x86 connscan
```

**Why:** `connections` shows currently active TCP connections from kernel structures. `connscan` extends this by scanning raw memory for connection artifacts — capturing recently closed connections that `connections` misses. Running both together gives the complete network picture.

**Results:**

- `reader_sl.exe` (PID 1640) → outbound connection to `125.19.103.198:8080`
- Additional connection artifact to `41.168.5.140:8080` recovered via `connscan`
- Port 8080 is a common C2 callback port used to blend with HTTP traffic — both IPs are external, non-corporate addresses

-----

**Step 4 — Detect process injection and shellcode in memory**

```bash
vol.py -f Sample1.dmp --profile=WinXPSP2x86 malfind -p 1640
```

**Why:** `malfind` scans Virtual Address Descriptor (VAD) memory regions for executable pages with `PAGE_EXECUTE_READWRITE` protection — a strong indicator of injected shellcode, as legitimate code is typically either writable or executable, not both simultaneously. It also checks for MZ headers in unexpected memory regions.

**Results:**

- `PAGE_EXECUTE_READWRITE` memory region detected within PID 1640
- MZ header (`4D 5A`) found at the start of the injected region — indicates a full PE executable injected into process memory
- Shellcode artifact confirmed — code execution capability from injected region

-----

**Step 5 — Validate malware identity via IOC submission**

Extracted memory artifact from PID 1640 submitted to VirusTotal for hash-based identification.

**Results:** **26/71 engines** flagged the sample — classified as **Trojan** with remote execution capability. Confirmed malicious — not a false positive.

-----

### Key Findings

- `reader_sl.exe` (PID 1640) confirmed as trojan — masquerading as a legitimate reader process
- Active C2 communication established to `125.19.103.198:8080` and `41.168.5.140:8080`
- PE executable injected into process memory with `PAGE_EXECUTE_READWRITE` protection and MZ header
- VirusTotal: 26/71 detections — Trojan classification confirmed

**MITRE ATT&CK:**

- `T1055 — Process Injection` (PE injection into reader_sl.exe memory space)
- `T1071.001 — Application Layer Protocol: Web Protocols` (C2 over port 8080)
- `T1105 — Ingress Tool Transfer` (remote payload delivery capability confirmed)

-----

### Actions & Recommendations

|Action             |Detail                                                                                                       |
|-------------------|-------------------------------------------------------------------------------------------------------------|
|**Immediate**      |Isolate the affected host — active C2 channel to external IPs must be severed                                |
|**IOC Block**      |Block `125.19.103.198` and `41.168.5.140` at perimeter firewall; submit IPs to threat intel platform         |
|**Malware Removal**|Terminate PID 1640; locate and delete `reader_sl.exe` on disk; scan all user-accessible directories          |
|**Forensics**      |Dump and preserve full memory image before remediation for deeper analysis of injected payload               |
|**Detection**      |Create EDR/AV rule flagging `reader_sl.exe` by name and hash; alert on outbound port 8080 to non-approved IPs|
|**Escalation**     |Escalate to Tier 2 / Malware Analysis team — active trojan with confirmed C2 requires full IR engagement     |

-----

## Case 2 — Memory Forensics: Privilege Escalation & Credential Dumping (T1055, T1003.001, T1547.001)

### Evidence Details

|Field             |Value                                                                  |
|------------------|-----------------------------------------------------------------------|
|Memory Image      |`Sample2.dmp`                                                          |
|OS Profile        |`Win7SP0x86`                                                           |
|Suspicious Process|`conhost.exe` (PID 2168)                                               |
|Severity          |**P1 — Confirmed Privilege Escalation with Credential Dumping Attempt**|

-----

### Investigation

**Step 1 — Profile the memory image**

```bash
vol.py -f Sample2.dmp imageinfo
```

**Results:** Profile `Win7SP0x86` confirmed — Windows 7 SP0, 32-bit.

-----

**Step 2 — Enumerate processes and identify anomalous parent-child relationships**

```bash
vol.py -f Sample2.dmp --profile=Win7SP0x86 pstree
```

**Why:** `pstree` renders the full process hierarchy as a tree, making abnormal parent-child relationships immediately visible. Legitimate Windows processes have well-known parent processes — any deviation is a high-confidence anomaly indicator.

**Results:** `conhost.exe` (PID 2168) found with parent `winlogon.exe` — this is abnormal. On Windows 7, `conhost.exe` should be spawned by `csrss.exe`, not `winlogon.exe`. A `conhost.exe` child of `winlogon.exe` indicates process masquerading or injection into the authentication subsystem.

-----

**Step 3 — Investigate persistence via registry Run keys**

```bash
vol.py -f Sample2.dmp --profile=Win7SP0x86 printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Why:** The `Run` registry key is one of the most common persistence locations — entries here execute automatically at user login. Dumping this key from memory surfaces any malicious persistence entries that may have been set by the attacker.

**Results:** Suspicious entry found — `IEPreload.exe` registered under the `Run` key, pointing to a path in `AppData`. `IEPreload.exe` is not a legitimate Internet Explorer component — this is a persistence mechanism masquerading as a browser-related process.

-----

**Step 4 — Identify credential dumping artifacts**

```bash
vol.py -f Sample2.dmp --profile=Win7SP0x86 cmdline
vol.py -f Sample2.dmp --profile=Win7SP0x86 filescan | grep -i "ram.dmp\|winpmem"
```

**Why:** `cmdline` recovers command-line arguments for all processes from memory — revealing tools executed with specific arguments. Scanning for `winpmem` and `ram.dmp` confirms whether a memory dumping tool was run, indicating credential harvesting intent (LSASS dump).

**Results:** `winpmem` tool artifacts identified — `ram.dmp` output file referenced in recovered command history. `winpmem` is a legitimate memory acquisition tool frequently abused by attackers to dump LSASS memory and extract credentials offline.

-----

### Key Findings

- `conhost.exe` (PID 2168) spawned by `winlogon.exe` — abnormal parent relationship indicates process masquerading or injection into authentication subsystem
- `IEPreload.exe` registered in `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` from `AppData` — confirmed malicious persistence
- `winpmem` used to create `ram.dmp` — LSASS credential dumping attempt confirmed
- Full privilege escalation chain present: initial access → persistence establishment → credential harvesting

**MITRE ATT&CK:**

- `T1055 — Process Injection` (conhost.exe masquerading under winlogon.exe)
- `T1003.001 — OS Credential Dumping: LSASS Memory` (winpmem → ram.dmp)
- `T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys` (IEPreload.exe persistence)

-----

### Actions & Recommendations

|Action              |Detail                                                                                                                                                             |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Immediate**       |Isolate host; terminate anomalous `conhost.exe` (PID 2168)                                                                                                         |
|**Persistence**     |Remove `IEPreload.exe` Run key entry (`reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v IEPreload /f`); locate and delete the binary from `AppData`|
|**Credential Reset**|Assume all credentials on this host are compromised — force password resets for all accounts that have logged into this machine                                    |
|**Forensics**       |Preserve `ram.dmp` if recoverable — may contain plaintext credentials extracted by attacker                                                                        |
|**Detection**       |Alert on `winpmem` execution and `ram.dmp` creation via EDR; alert on `conhost.exe` spawned by any parent other than `csrss.exe`                                   |
|**Escalation**      |Escalate to Tier 2 — credential dumping indicates lateral movement risk; audit all systems this host had network access to                                         |

-----

## Case 3 — Narcos Criminal Case: Multi-Device Digital Forensics Investigation (T1001.002, T1041, T1219)

### Case Background

Law enforcement intercepted a **1kg methamphetamine shipment** and detained three suspects. Digital devices were seized for forensic analysis to establish the criminal network’s communication structure, operational planning, and evidence of coordination.

### Suspects

|Suspect         |Role                              |Device Examined|
|----------------|----------------------------------|---------------|
|John Fredricksen|International Supplier            |Laptop         |
|Steve Kowhai    |Local Distributor                 |Mobile Device  |
|Jane Esteban    |Undercover Law Enforcement Officer|—              |

-----

### Investigation Methodology

All devices processed using **Autopsy** digital forensics platform. Investigation covered: file system artifacts, deleted file recovery, communication logs, steganographic analysis, and encrypted volume identification.

-----

**Step 1 — Communication artifact extraction**

Autopsy keyword search and timeline analysis across all seized devices targeting:

- Discord application logs and message history
- ProtonMail browser artifacts and cached communications
- Email metadata and attachment history

**Results:**

- Discord logs recovered from John’s laptop — direct communications with Steve Kowhai coordinating shipment logistics, quantities, and delivery schedules
- ProtonMail session artifacts recovered — encrypted email channel used for external coordination with international contacts outside the primary suspect network
- Communication timeline established across both suspects’ devices — messages corroborate each other, confirming coordinated operation

-----

**Step 2 — Steganographic image analysis**

Images recovered from John’s laptop submitted to steganographic analysis tools to detect hidden data embedded within image files.

**Results:**

- Hidden data extracted from recovered image files — concealed text containing operational details embedded within image pixel data
- Steganography used as a covert communication channel to avoid plaintext keyword detection in standard comms monitoring
- Extracted content included coordinates, quantities, and contact identifiers

**MITRE ATT&CK:** `T1001.002 — Data Obfuscation: Steganography`

-----

**Step 3 — Encrypted volume identification**

```
Autopsy → File Analysis → Unallocated Space + Volume Identification
```

**Results:** TrueCrypt encrypted volumes identified on John’s laptop. Volume headers confirmed TrueCrypt signature — contents inaccessible without passphrase. Presence of encrypted volumes alongside steganographic communications confirms deliberate operational security tradecraft by the suspect.

-----

**Step 4 — Malware and remote access tool identification**

Running process artifacts and installed application analysis performed on John’s laptop image.

**Results:** **Quasar RAT** artifacts identified — a remote access trojan used for remote control of John’s laptop. Quasar RAT installation logs, configuration files, and connection artifacts recovered. Indicates either John’s device was compromised by an external party, or the RAT was used as part of the network’s operational infrastructure.

**MITRE ATT&CK:** `T1219 — Remote Access Software`

-----

**Step 5 — Operational planning document recovery**

Autopsy file carving and deleted file recovery across all devices.

**Results:** Recovered artifacts including:

- Shipment manifest documents detailing quantities, packaging, and delivery routes
- Flight booking records corroborating travel aligned with shipment dates
- Client contact lists with associated quantities and payment records
- Geographic route maps corresponding to distribution paths

**MITRE ATT&CK:** `T1041 — Exfiltration Over C2 Channel` (data exfiltration via RAT infrastructure)

-----

### Evidence Correlation Summary

|Evidence Type                    |Source Device   |Significance                                          |
|---------------------------------|----------------|------------------------------------------------------|
|Discord communication logs       |John’s Laptop   |Direct coordination with Steve Kowhai                 |
|ProtonMail artifacts             |John’s Laptop   |External encrypted channel to international contacts  |
|Steganographic images            |John’s Laptop   |Covert operational data hidden in image files         |
|TrueCrypt encrypted volumes      |John’s Laptop   |Deliberate OPSEC — contents unknown without passphrase|
|Quasar RAT artifacts             |John’s Laptop   |Remote access compromise or operational tool          |
|Shipment documents + client lists|Multiple Devices|Direct operational evidence of trafficking network    |

-----

### Key Findings

- **John Fredricksen** confirmed as international supplier — laptop contained full operational infrastructure: RAT, encrypted volumes, steganographic communications, and shipment documentation
- **Steve Kowhai** confirmed as local distributor — Discord logs establish direct coordination with John on shipment logistics
- Three-layer communication security employed: Discord (primary), ProtonMail (encrypted backup), steganography (covert)
- TrueCrypt volumes indicate additional evidence likely exists but remains encrypted
- Quasar RAT presence requires determination of whether John was a victim of compromise or an operator

**MITRE ATT&CK:**

- `T1001.002 — Data Obfuscation: Steganography` (covert communication channel)
- `T1219 — Remote Access Software` (Quasar RAT on John’s laptop)
- `T1041 — Exfiltration Over C2 Channel` (data movement via RAT infrastructure)

-----

### Forensic Recommendations

|Action              |Detail                                                                                                                             |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|
|**Legal**           |Apply for court order to compel TrueCrypt passphrase disclosure — encrypted volumes likely contain additional operational evidence |
|**Quasar RAT**      |Determine RAT operator — if externally controlled, identify C2 server for attribution; if self-installed, treat as operational tool|
|**ProtonMail**      |Submit legal request to Proton AG for account metadata (IP logs, account creation) — content encryption does not protect metadata  |
|**Steganography**   |Submit all recovered images to forensic steganography tools for complete hidden data extraction                                    |
|**Network**         |Trace international contacts identified in ProtonMail and Discord logs for wider network attribution                               |
|**Chain of Custody**|Maintain full forensic chain of custody for all recovered artifacts — required for court admissibility                             |

-----

## Project Summary

Across three investigations, this project demonstrates DFIR analyst capability across memory forensics and criminal digital forensics:

- **Case 1** → Identified active trojan (`reader_sl.exe`) via process analysis, memory injection detection, and C2 connection extraction — confirmed by 26/71 VirusTotal detections
- **Case 2** → Reconstructed privilege escalation chain through abnormal process tree analysis, registry persistence detection, and credential dumping artifact recovery
- **Case 3** → Conducted multi-device criminal forensics investigation — correlating Discord logs, steganographic artifacts, encrypted volumes, RAT presence, and operational documents across two suspects to establish a confirmed drug trafficking network

Each case was investigated from evidence acquisition through artifact extraction, finding documentation, MITRE ATT&CK mapping, and specific remediation or legal recommendations — covering the full DFIR analyst workflow.

-----

> **Note:** All memory forensics cases were conducted on provided sample memory dumps in an isolated lab environment. The Narcos case is a structured forensic simulation using fictional suspects for DFIR training purposes.
