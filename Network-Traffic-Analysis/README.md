# Network Traffic Analysis & Security Log Investigation | SOC L1 Project

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Windows](https://img.shields.io/badge/Windows_Event_Logs-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)
![SOC](https://img.shields.io/badge/SOC_L1-Analyst-FF4500?style=for-the-badge)

-----

## Project Overview

This project covers three independent SOC L1 investigations across network traffic and host-based log sources. Each case simulates a real analyst workflow — from alert identification through packet-level or log-level analysis, threat confirmation, MITRE ATT&CK mapping, and actionable escalation.

**Skills Demonstrated:**

- Packet capture analysis and protocol dissection (Wireshark, Tcpdump)
- Cleartext credential interception detection across insecure protocols
- Windows Security Event Log investigation using PowerShell
- ARP poisoning detection and MITM attack reconstruction
- MITRE ATT&CK TTP mapping across network and host attack vectors

**Tools & Technologies:**
`Wireshark` · `Tcpdump` · `PowerShell` · `Windows Event Viewer` · `Arpspoof` · `Linux CLI`

**Full Visual Report:** [Download PDF Report →](Network_Traffic_Analysis_Report.pdf)

-----

## Alert Summary Table

|Case|Scenario                                            |Tool Used                |Verdict                |Severity|MITRE TTPs      |
|----|----------------------------------------------------|-------------------------|-----------------------|--------|----------------|
|1   |FTP Cleartext Credential Interception               |Wireshark                |✅ Confirmed            |**P2**  |T1040           |
|2   |Windows Security Log — Unauthorized Account Creation|PowerShell + Event Viewer|✅ Confirmed            |**P2**  |T1136.001, T1078|
|3   |ARP Spoofing & MITM Credential Capture              |Tcpdump + Wireshark      |✅ Confirmed — Full MITM|**P1**  |T1557.002, T1040|

-----

## Case 1 — FTP Cleartext Credential Interception (T1040)

### Alert Details

|Field     |Value                                             |
|----------|--------------------------------------------------|
|Alert Type|Cleartext Credential Transmission Detected        |
|Protocol  |FTP (TCP Port 21)                                 |
|Tool      |Wireshark                                         |
|Log Source|Packet Capture (.pcap)                            |
|Severity  |**P2 — Credential Exposure via Insecure Protocol**|

-----

### Investigation

**Step 1 — Isolate FTP authentication traffic from the packet capture**

```
Wireshark Display Filter: ftp
```

**Why:** FTP operates entirely in plaintext over TCP port 21. Applying the `ftp` display filter strips all non-FTP traffic and surfaces the authentication exchange directly — USER and PASS commands are transmitted as readable ASCII, requiring no decryption.

**Results:** FTP session captured in full. The authentication sequence showed the `USER` command followed immediately by the `PASS` command in consecutive packets, both transmitted without any encryption layer.

-----

**Step 2 — Extract credentials from the packet stream**

```
Wireshark: Follow TCP Stream → Filter on Port 21
```

**Why:** Following the TCP stream reconstructs the full FTP session conversation in sequence, making the credential exchange and any subsequent FTP commands (directory listing, file transfers) readable as a complete session log.

**Results:**

- **Username:** transmitted in plaintext, visible in USER packet
- **Password:** transmitted in plaintext, visible in PASS packet
- FTP server responded with `230 Login successful` — confirming valid credentials captured
- Subsequent `LIST` and `RETR` commands visible — attacker or analyst can see all file operations

-----

### Key Findings

- FTP session captured with full plaintext credential exchange — no encryption present
- Server confirmed successful authentication (`230 Login successful`)
- All post-login FTP commands and file transfer contents visible in the stream
- Any attacker with passive network access on the same segment can capture identical data

**MITRE ATT&CK:** `T1040 — Network Sniffing`

-----

### Actions & Recommendations

|Action       |Detail                                                                                                                 |
|-------------|-----------------------------------------------------------------------------------------------------------------------|
|**Immediate**|Identify and rotate the compromised FTP credentials                                                                    |
|**Protocol** |Disable FTP entirely; migrate to SFTP (TCP 22) or FTPS (TCP 990) — both encrypt the credential exchange and data stream|
|**Detection**|Create Wireshark/IDS rule alerting on `ftp` traffic containing `PASS` commands from internal hosts                     |
|**Policy**   |Enforce firewall rule blocking outbound TCP 21 at the perimeter; document as prohibited protocol in security policy    |
|**Audit**    |Review FTP server access logs for prior sessions — credential may have been captured before this detection             |

-----

## Case 2 — Windows Security Log Investigation: Unauthorized Account Creation (T1136.001, T1078)

### Alert Details

|Field      |Value                                            |
|-----------|-------------------------------------------------|
|Alert Type |Unauthorized User Account Created                |
|Target Host|WIN-DESKTOP                                      |
|New Account|`admin1234`                                      |
|Log Source |Windows Security Event Log                       |
|Severity   |**P2 — Unauthorized Privileged Account Creation**|

-----

### Investigation

**Step 1 — Pull the 10 most recent Security log events to establish baseline activity**

```powershell
Get-WinEvent security -MaxEvents 10
```

**Why:** Starting broad with recent events establishes timeline context before narrowing to specific Event IDs. This surfaces any immediately suspicious activity and confirms the log source is populating correctly before running targeted queries.

**Results:** Event ID `5379` (Credential Manager credentials were read) appeared repeatedly — indicating active credential access activity on the host, warranting deeper investigation.

-----

**Step 2 — Target Event ID 4720 to confirm unauthorized account creation**

```powershell
Get-WinEvent -FilterHashtable @{logname='security'; id=4720}
```

**Why:** Event ID 4720 is the Windows Security log entry generated specifically when a new user account is created. Filtering directly on this Event ID returns only account creation events with full metadata — who created it, when, on which domain.

**Results:**

- **Account Created:** `admin1234`
- **Password Set:** `P@ssw0rd` (weak, dictionary-susceptible credential)
- **Created By:** `CYRIN User` on domain `WIN-DESKTOP`
- Timestamp confirmed creation occurred during the investigation window

-----

**Step 3 — Trace post-creation privilege assignment**

```powershell
Get-WinEvent -FilterHashtable @{logname='security'; id=4732}
```

**Why:** Event ID 4732 logs when a user is added to a security-enabled local group. Immediately checking this after finding account creation reveals whether the attacker escalated the new account’s privileges — particularly addition to the `Administrators` group.

**Results:** `admin1234` added to local group — confirming privilege escalation intent beyond simply creating a low-privilege account.

-----

**Step 4 — Check for failed login attempts against the new account**

```powershell
Get-WinEvent -FilterHashtable @{logname='security'; id=4625}
```

**Why:** Event ID 4625 (Failed Logon) after account creation can indicate either the attacker testing credentials or an automated system flagging the account. Combined with Event ID 5379 (Credential Manager read), this helps determine if the account was actively used.

**Results:** Event ID `4625` detected — failed logon attempt recorded. Event ID `5379` also present — Credential Manager was accessed, suggesting credential harvesting activity on the host.

-----

### Event ID Reference

|Event ID|Description              |Finding                             |
|--------|-------------------------|------------------------------------|
|4720    |User account created     |`admin1234` created by `CYRIN User` |
|4732    |User added to local group|`admin1234` granted group membership|
|4724    |Password reset attempted |Password manipulation activity      |
|4625    |Failed logon attempt     |Failed login recorded post-creation |
|5379    |Credential Manager read  |Active credential access on host    |

-----

### Key Findings

- Unauthorized account `admin1234` created with weak password `P@ssw0rd` — trivially brute-forceable
- Account immediately added to privileged local group — attacker establishing admin-level persistence
- Credential Manager accessed (Event ID 5379) — possible credential harvesting for lateral movement
- Failed logon (Event ID 4625) — account tested after creation

**MITRE ATT&CK:**

- `T1136.001 — Create Account: Local Account` (admin1234 creation)
- `T1078 — Valid Accounts` (use of created account for access)

-----

### Actions & Recommendations

|Action        |Detail                                                                                                                                                         |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Immediate** |Disable and delete `admin1234` account (`net user admin1234 /delete`)                                                                                          |
|**Credential**|Audit Credential Manager on `WIN-DESKTOP` — enumerate stored credentials (`cmdkey /list`) and clear unauthorized entries                                       |
|**Policy**    |Restrict account creation rights via GPO: `Computer Configuration → Windows Settings → Security Settings → User Rights Assignment → Add workstations to domain`|
|**Detection** |Configure SIEM alert on Event ID 4720 + 4732 occurring within 60 seconds on the same host — strong indicator of persistence account creation                   |
|**Audit**     |Review all accounts with local administrator group membership (`net localgroup administrators`) and remove unauthorized entries                                |
|**Escalation**|Escalate to Tier 2 — Credential Manager access (5379) alongside account creation suggests this host may be a pivot point                                       |

-----

## Case 3 — ARP Spoofing & MITM Credential Capture (T1557.002, T1040)

### Alert Details

|Field               |Value                                                 |
|--------------------|------------------------------------------------------|
|Attack Type         |ARP Cache Poisoning / Man-in-the-Middle               |
|Victim 1            |`192.168.2.101`                                       |
|Victim 2            |`192.168.2.103`                                       |
|Attacker Position   |Inline — between both victims                         |
|Protocol Intercepted|Telnet (TCP Port 23)                                  |
|Severity            |**P1 — Active MITM with Confirmed Credential Capture**|

-----

### Investigation & Attack Timeline

|Step|Action                                                |Command Used                                  |
|----|------------------------------------------------------|----------------------------------------------|
|1   |ARP cache poisoned — attacker inserted between victims|`arpspoof -t 192.168.2.101 192.168.2.103`     |
|2   |Traffic redirected through attacker system            |IP forwarding enabled on attacker host        |
|3   |Full session captured to pcap                         |`tcpdump -w task2.pcap`                       |
|4   |Pcap analyzed in Wireshark                            |Telnet stream followed — credentials extracted|

-----

**Step 1 — Execute ARP poisoning to intercept traffic**

```bash
arpspoof -t 192.168.2.101 192.168.2.103
```

**Why:** ARP spoofing sends forged ARP reply packets to both victims, associating the attacker’s MAC address with the IP of the other party. Both victims update their ARP cache to route traffic through the attacker — creating a transparent interception point without disrupting the session.

**Results:** ARP cache of `192.168.2.101` updated to map `192.168.2.103`’s IP to attacker MAC. All traffic between the two hosts now passes through the attacker system.

-----

**Step 2 — Capture intercepted traffic to file**

```bash
tcpdump -w task2.pcap
```

**Why:** Writing the capture to a `.pcap` file rather than reading live allows offline analysis in Wireshark with full filtering and stream reconstruction capabilities — more thorough than live terminal output.

**Results:** Full session capture obtained including the Telnet authentication exchange and all subsequent session commands.

-----

**Step 3 — Analyze capture in Wireshark and extract credentials**

```
Wireshark Display Filter: telnet
Follow TCP Stream → Port 23
```

**Why:** Telnet transmits every keystroke as an individual TCP packet in plaintext. Following the TCP stream on port 23 reconstructs the session character-by-character, making credentials and all typed commands fully visible.

**Results:**

- **Username captured:** `abhi`
- **Password captured:** `kali`
- Source and destination MAC addresses confirmed attacker’s interception position
- Full Telnet session content visible — all commands executed post-login readable

-----

### Key Findings

- ARP poisoning successfully executed — attacker confirmed inline between `192.168.2.101` and `192.168.2.103`
- Telnet session intercepted — protocol transmits all data including credentials in cleartext (TCP port 23)
- **Credentials captured:** username `abhi`, password `kali` — full authentication compromise
- MITM position maintained transparently — neither victim detected the interception
- All post-login Telnet commands visible to attacker

**MITRE ATT&CK:**

- `T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning`
- `T1040 — Network Sniffing` (Telnet credential capture via Tcpdump + Wireshark)

-----

### Actions & Recommendations

|Action           |Detail                                                                                                                                       |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
|**Immediate**    |Rotate compromised credentials for user `abhi` across all systems                                                                            |
|**Protocol**     |Disable Telnet permanently — replace with SSH (`apt remove telnetd`; enforce `AllowUsers` in `/etc/ssh/sshd_config`)                         |
|**ARP Hardening**|Enable Dynamic ARP Inspection (DAI) on managed switches — validates ARP packets against DHCP snooping binding table, blocking spoofed replies|
|**Detection**    |Deploy ARP monitoring: alert on duplicate IP-to-MAC mappings (`arpwatch`) or rapid ARP reply bursts from a single MAC                        |
|**Network**      |Enable DHCP Snooping on all VLANs — provides the binding table DAI requires and prevents rogue DHCP servers                                  |
|**Escalation**   |Escalate to Tier 2 — determine scope of interception, identify any additional sessions captured during the attack window                     |

-----

## Project Summary

Across three investigations, this project demonstrates SOC L1 analyst capability across both network traffic and host-based log sources:

- **Case 1** → Identified FTP plaintext credential transmission through packet-level protocol dissection — confirmed credential exposure and recommended secure protocol migration
- **Case 2** → Reconstructed unauthorized account creation and privilege escalation through Windows Event ID correlation — identified 5 distinct Event IDs mapping the full attack sequence
- **Case 3** → Executed and detected a complete ARP spoofing MITM attack chain — from cache poisoning through traffic capture to plaintext credential extraction via Telnet stream reconstruction

Each case was investigated from initial alert through log/packet analysis, finding documentation, MITRE ATT&CK mapping, and specific remediation — covering the full triage-to-escalation workflow expected at SOC L1.

-----

> **Note:** Cases 1 and 3 involve intentional simulation of attack techniques in an isolated lab environment for detection and analysis purposes. All findings are documented for defensive SOC training.
