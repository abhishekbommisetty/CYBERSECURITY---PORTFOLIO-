# SIEM Log Analysis & Threat Detection Using Splunk | SOC L1 Project

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![SOC](https://img.shields.io/badge/SOC_L1-Analyst-FF4500?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)

-----

## Project Overview

This project simulates a real SOC L1 analyst shift, investigating **3 high-priority security alerts** using Splunk SIEM. Each case follows a structured triage workflow — from alert ingestion to log correlation, finding documentation, and escalation recommendations — mirroring production SOC operations.

**Skills Demonstrated:**

- Alert triage across Linux `secure` logs, Sysmon, and Windows Event Logs
- SPL query writing for log filtering, correlation, and statistical analysis
- MITRE ATT&CK TTP mapping for each confirmed threat
- Structured incident documentation with severity classification

**Tools & Technologies:**
`Splunk SIEM` · `SPL` · `Linux secure logs` · `Sysmon (EventCode 3)` · `Windows Event Logs` · `MITRE ATT&CK`

**Full Visual Report:** [Download PDF Report →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/main/SOC-SIEM-Analysis/SIEM%20-%20ANALYSIS%20USING%20SPLUNK.pdf)

-----

## Alert Summary Table

|Case|Alert Type                                 |Log Source         |Verdict                      |Severity|MITRE TTPs                            |
|----|-------------------------------------------|-------------------|-----------------------------|--------|--------------------------------------|
|1   |Brute Force Attack                         |Linux `secure` logs|✅ Confirmed                  |**P1**  |T1110                                 |
|2   |Suspicious Network Connection + Persistence|Sysmon + WinEvent  |✅ Confirmed                  |**P1**  |T1571, T1053.005                      |
|3   |Remote SSH Persistence via New User        |Linux `secure` logs|✅ Confirmed — Full Compromise|**P1**  |T1136.001, T1098, T1021.004, T1053.003|

-----

## Case 1 — Brute Force Attack (T1110)

### Alert Details

|Field      |Value                                    |
|-----------|-----------------------------------------|
|Alert Name |Brute Force Activity Detection           |
|Time       |17/09/2025 09:00:21 AM                   |
|Target Host|WIN-2404                                 |
|Source IP  |10.10.242.248                            |
|Log Source |Linux `secure` logs (`linux-alert` index)|
|Severity   |**P1 — Active Credential Attack**        |

-----

### Investigation

**Step 1 — Pull all authentication events from the suspicious IP in chronological order**

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
```

**Why:** Filtering directly on the source IP and authentication keywords isolates the full event sequence — failed attempts, invalid users, and eventual successful login — in one pass, allowing pattern identification without noise.

**Results:** 843 total events returned — 840 `Failed password` / `Invalid user` events followed by 3 `Accepted password` events for user `emma.johnson`, confirming a successful brute-force login after sustained credential stuffing.

-----

### Key Findings

- **840 failed authentication attempts** from `10.10.242.248` targeting `emma.johnson` on `WIN-2404`
- Attempts involved both valid usernames (`Invalid user` events) and direct password guessing
- **3 successful logins** recorded after the failure burst — brute force succeeded
- Attack window: concentrated within a short timeframe, indicating automated tooling

**MITRE ATT&CK:** `T1110 — Brute Force`

-----




### Actions & Recommendations

|Action        |Detail                                                                                                          |
|--------------|----------------------------------------------------------------------------------------------------------------|
|**Immediate** |Block source IP `10.10.242.248` at perimeter firewall                                                           |
|**Account**   |Force password reset for `emma.johnson`; audit active sessions                                                  |
|**Policy**    |Enforce Account Lockout Policy: 5 failed attempts → 15-minute lockout (`secpol.msc` → Account Lockout Threshold)|
|**Detection** |Create Splunk alert: >10 `Failed password` events from single IP within 60 seconds                              |
|**Escalation**|Escalate to Tier 2 — successful login after brute force = confirmed credential compromise                       |

-----

## Case 2 — Suspicious Network Connection + Scheduled Task Persistence (T1571, T1053.005)

### Alert Details

|Field          |Value                                            |
|---------------|-------------------------------------------------|
|Alert Name     |Suspicious Network Connection — Non-Standard Port|
|Target Host    |WIN-105                                          |
|Suspicious Port|5678                                             |
|Log Source     |Sysmon (EventCode 3) + Windows Event Logs        |
|Severity       |**P1 — Suspected C2 Beaconing with Persistence** |

-----

### Investigation

**Step 1 — Isolate the suspicious outbound connection using Sysmon EventCode 3**

```spl
index=task4 ComputerName=WIN-105 DestinationPort=5678 EventCode=3
| table _time Image SourceIp DestinationIp DestinationPort
```

**Why:** Sysmon EventCode 3 logs network connection events at the process level. Filtering on the target host and port immediately surfaces which process initiated the connection and where it was communicating.

**Results:** `C:\Windows\Temp\SharePsInf.exe` initiated an outbound connection from `10.10.81.100` to `10.10.114.58` on port `5678`. The process image path (`C:\Windows\Temp\`) is a common malware drop location — legitimate system processes do not execute from Temp.

-----

**Step 2 — Correlate with scheduled task creation to identify persistence mechanism**

```spl
index=task4 "schtasks" OR "scheduled task"
| table _time CommandLine Image
```

**Why:** Malware establishing a C2 channel typically also creates persistence. Querying for `schtasks` usage alongside the suspicious process reveals whether the attacker set up scheduled execution.

**Results:** 4 events returned — `schtasks.exe` was invoked by `C:\Windows\System32\schtasks.exe` with command lines creating scheduled tasks pointing to `C:\Windows\Temp\SharePsInf.exe`, confirming automated re-execution persistence.

-----

### Key Findings

- Process `SharePsInf.exe` dropped in `C:\Windows\Temp\` — suspicious path for an executable
- Outbound connection to `10.10.114.58:5678` — non-standard port consistent with C2 traffic
- Scheduled tasks created to re-execute the binary — confirms persistence intent
- No legitimate software uses port 5678 in this environment

**MITRE ATT&CK:**

- `T1571 — Non-Standard Port` (C2 communication on port 5678)
- `T1053.005 — Scheduled Task/Job: Scheduled Task` (persistence via schtasks)

-----




### Actions & Recommendations

|Action         |Detail                                                                                        |
|---------------|----------------------------------------------------------------------------------------------|
|**Immediate**  |Isolate `WIN-105` from the network                                                            |
|**Containment**|Delete all scheduled tasks referencing `SharePsInf.exe` (`schtasks /delete /tn <taskname> /f`)|
|**Forensics**  |Collect and submit `C:\Windows\Temp\SharePsInf.exe` for static + dynamic malware analysis     |
|**Network**    |Block outbound traffic to `10.10.114.58` and port `5678` at the firewall                      |
|**Escalation** |Escalate to Tier 2 / IR team — active C2 channel with confirmed persistence                   |

-----

## Case 3 — Remote SSH Persistence via Unauthorized User (T1136.001, T1098, T1021.004, T1053.003)

### Alert Details

|Field      |Value                                                    |
|-----------|---------------------------------------------------------|
|Alert Name |Possible Persistence — New User Created                  |
|Target Host|Ubuntu Server                                            |
|New User   |`remote-ssh`                                             |
|Log Source |Linux `secure` logs (`task5` index)                      |
|Severity   |**P1 — Confirmed Compromise with Full Persistence Chain**|

-----

### Investigation & Attack Timeline

|Time                |Event                                               |SPL Query Used                  |
|--------------------|----------------------------------------------------|--------------------------------|
|08/12/25 08:52:57   |`remote-ssh` user created                           |`index=task5 useradd remote-ssh`|
|08/12/25 08:52:45–57|Privilege escalation to root via sudo               |Privilege escalation query      |
|08/12/25 08:54–09:31|SSH sessions opened (password + publickey)          |SSH login query                 |
|08/12/25 08:49–09:33|Failed password attempts before access              |Auth failure count query        |
|08/12/25 09:00–09:33|Cron jobs + netcat reverse shell + SSH -R forwarding|Persistence artifact query      |

-----

**Step 1 — Confirm unauthorized user creation**

```spl
index=task5 useradd remote-ssh
```

**Results:** 3 events — `remote-ssh` created with UID=1001, GID=1004, home directory `/home/remote-ssh`, shell `/bin/bash`. Creation executed via `sudo` by user `jack-brown`, confirming attacker already had privilege at this stage.

-----

**Step 2 — Trace privilege escalation path**

```spl
index=task5 (sudo OR su OR "privilege escalation" OR "to root")
| table _time user src_user command
```

**Results:** 11 events showing `jack-brown` escalating to `root` repeatedly between 08:49–08:52, with commands executed as root immediately before user creation — confirms `jack-brown` was the initial access account used to escalate.

-----

**Step 3 — Identify SSH login activity and source IP**

```spl
index=task5 "Accepted password" OR "Accepted publickey" OR "sshd.*session opened"
| table _time user src_ip
```

**Results:** 4 successful SSH sessions — 3 as `ubuntu` and 1 as `jack-brown`, all originating from external IP `10.14.54.32`. Both password and public key authentication used, indicating the attacker pre-staged an SSH key for persistent keyless access.

-----

**Step 4 — Quantify failed authentication attempts**

```spl
index=task5 "Failed password" OR "authentication failure"
| stats count
```

**Results:** 7 failed authentication events prior to successful access — lower count than Case 1, suggesting targeted access rather than mass brute-force; attacker likely had prior knowledge of credentials.

-----

**Step 5 — Identify persistence artifacts across the full kill chain**

```spl
index=task5 (cron OR crontab OR "reverse shell" OR nc OR netcat OR "ssh -R")
| table _time command
```

**Results:** 8 events — cron job entries, netcat reverse shell commands, and `ssh -R` remote forwarding commands executed between 09:00–09:33, establishing three independent persistence mechanisms.

-----

### Key Findings

- **Unauthorized user `remote-ssh`** created via `sudo` by compromised account `jack-brown`
- **Full privilege escalation chain confirmed** — `jack-brown` → `root` → user creation
- **External attacker IP:** `10.14.54.32` — authenticated via both password and pre-staged public key
- **Three persistence mechanisms deployed:** cron job re-execution, netcat reverse shell, SSH remote port forwarding (`ssh -R`)
- 7 failed attempts before access — suggests credential-based initial access, not brute force

**MITRE ATT&CK:**

- `T1136.001 — Create Account: Local Account` (remote-ssh user creation)
- `T1098 — Account Manipulation` (SSH public key staged for persistent access)
- `T1021.004 — Remote Services: SSH` (external SSH access from 10.14.54.32)
- `T1053.003 — Scheduled Task/Job: Cron` (cron-based persistence)

-----


### Actions & Recommendations

|Action                 |Detail                                                                                                                                    |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
|**Immediate**          |Isolate Ubuntu server; revoke all active SSH sessions                                                                                     |
|**Account**            |Delete `remote-ssh` user (`userdel -r remote-ssh`); lock `jack-brown` account                                                             |
|**SSH Hardening**      |Audit `~/.ssh/authorized_keys` for all users; remove unauthorized public keys                                                             |
|**Persistence Cleanup**|Audit and purge all cron jobs (`crontab -l` for each user); kill active netcat processes                                                  |
|**Network**            |Block outbound connections to `10.14.54.32`; restrict SSH to allowlisted IPs only (`/etc/ssh/sshd_config` — `AllowUsers`, `ListenAddress`)|
|**Forensics**          |Collect full auth logs, bash history, and cron artifacts before remediation                                                               |
|**Escalation**         |Escalate immediately to Tier 2 / IR — confirmed full compromise with multi-vector persistence                                             |

-----

## Project Summary

Across this SOC L1 simulation, three P1 alerts were triaged and fully investigated using purposeful SPL queries, structured log correlation, and MITRE ATT&CK mapping:

- **Case 1** → Confirmed brute-force credential attack; 840 failed attempts leading to successful login
- **Case 2** → Identified C2 beaconing via non-standard port with scheduled task persistence
- **Case 3** → Reconstructed complete attack chain — initial access, privilege escalation, lateral movement, and three-mechanism persistence deployment

Each case was investigated from alert to actionable recommendation, demonstrating the core triage, correlation, and escalation workflow expected of a SOC L1 analyst.

-----

> **⚠️Note:** SPL queries documented represent the key investigative steps. Additional queries were executed during investigation for validation and correlation — only the most analytically significant are included here for clarity. 




