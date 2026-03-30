# Hi, I’m Abhishek Bommisetty 👋

<a href="https://www.linkedin.com/in/abhishek-bommisetty-90b48a1b7/" target="_blank">
  <img src="https://img.shields.io/badge/-LinkedIn-0072b1?&style=for-the-badge&logo=linkedin&logoColor=white" />
</a>
<a href="https://github.com/abhishekbommisetty" target="_blank">
  <img src="https://img.shields.io/badge/-GitHub-181717?&style=for-the-badge&logo=github&logoColor=white" />
</a>

-----

## About Me

I’m an aspiring **SOC L1 Analyst** with hands-on experience across 10+ cybersecurity projects covering the full spectrum of blue-team and offensive security work — from SIEM alert triage and memory forensics to malware reverse engineering, penetration testing, and Python security automation.

I hold **CompTIA Security+** and **TryHackMe SOC Level 1** certifications and have built every project in this portfolio through deliberate, lab-based practice — not coursework theory. Each project is fully documented with methodology, findings, MITRE ATT&CK mapping, and analyst-level recommendations, reflecting the workflow I would bring to a real SOC environment from day one.

-----

## Objective

My goal is to join a Security Operations Center as a **Tier 1 SOC Analyst** where I can contribute to alert triage, log correlation, threat detection, and incident escalation — while continuing to grow across the SOC L1 → L2 path. Every project in this portfolio was built with that role in mind.

-----

## Skills

|Skill                               |Tools & Application                                                                  |
|------------------------------------|-------------------------------------------------------------------------------------|
|**SOC Alert Triage & Investigation**|Splunk SPL · Event ID correlation · Five Ws reporting · escalation documentation     |
|**SIEM Log Analysis**               |Splunk dashboards · KQL · index/sourcetype querying · real-time alerting             |
|**Network Traffic Analysis**        |Wireshark · Tcpdump · protocol dissection · C2 detection · ARP/MITM analysis         |
|**Intrusion Detection**             |Snort rule writing · NIDS/NIPS modes · signature-based detection                     |
|**Malware Analysis**                |PEStudio · DIE · FLOSS · Regshot · Procmon · static + dynamic triage                 |
|**Digital Forensics & IR**          |Volatility (`pslist` · `malfind` · `connscan`) · Autopsy · memory artifact extraction|
|**Threat Intelligence**             |MITRE ATT&CK mapping · IOC enrichment · VirusTotal · AbuseIPDB · URLhaus             |
|**Python Security Scripting**       |Scapy · Paramiko · Requests · Fernet encryption · multi-threaded tooling             |
|**Penetration Testing**             |Nmap · Metasploit · Burp Suite · privilege escalation · post-exploitation            |
|**GRC**                             |ISO 27001 · NIST CSF · COBIT · risk assessment · compliance gap analysis             |
|**Linux CLI**                       |Log analysis · `grep` · `find` · file forensics · bash scripting                     |
|**Windows Forensics**               |Event Viewer · registry analysis · Event IDs 4624/4625/4720/4732                     |

-----

## Tools

<table>
  <tr>
    <td><b>SIEM & Log Analysis</b></td>
    <td>Splunk · Elastic Stack (KQL, Kibana)</td>
  </tr>
  <tr>
    <td><b>Network Analysis & IDS</b></td>
    <td>Wireshark · Tcpdump · Snort</td>
  </tr>
  <tr>
    <td><b>Digital Forensics</b></td>
    <td>Volatility · Autopsy · NetworkMiner</td>
  </tr>
  <tr>
    <td><b>Malware Analysis</b></td>
    <td>PEStudio · Detect It Easy · FLOSS · Regshot · Procmon</td>
  </tr>
  <tr>
    <td><b>Threat Intelligence</b></td>
    <td>MITRE ATT&CK Navigator · VirusTotal · AbuseIPDB · URLhaus</td>
  </tr>
  <tr>
    <td><b>Offensive Security</b></td>
    <td>Nmap · Metasploit · Burp Suite · Arpspoof</td>
  </tr>
  <tr>
    <td><b>Scripting & Automation</b></td>
    <td>Python (Scapy · Paramiko · Requests · Cryptography) · Bash</td>
  </tr>
  <tr>
    <td><b>OS & CLI</b></td>
    <td>Linux · Windows Event Viewer · Registry Editor</td>
  </tr>
</table>

-----

## Certifications

<a href="https://drive.google.com/file/d/1ypn_l_EPyDEkgVO_gSaEBxqIug5lkfv1/view?usp=drivesdk" target="_blank">
  <img src="https://img.shields.io/badge/-Security%2B-FF0000?&style=for-the-badge&logo=CompTIA&logoColor=white" />
</a>
<a href="https://drive.google.com/file/d/1eMzUzLb4AtzZDlUk0JR5SCPmEsqx33M0/view?usp=drivesdk" target="_blank">
  <img src="https://img.shields.io/badge/-SOC%20Level%201-00BFFF?&style=for-the-badge&logo=TryHackMe&logoColor=white" />
</a>

-----

## Projects

### 🔵 Blue Team & SOC

|#|Project                                                                             |Description                                                                                                                                                                       |
|-|------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1|[SIEM Log Analysis & Threat Detection](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/SOC-SIEM-Analysis/)                 |Investigated 3 real-world SOC alerts in Splunk — brute force, C2 persistence, and SSH compromise — using 70+ SPL queries across Linux secure logs, Sysmon, and Windows Event Logs |
|2|[Network Traffic Analysis & Security Log Investigation](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/Network-Traffic-Analysis/)|Detected FTP credential interception, unauthorized Windows account creation, and a full ARP spoofing MITM attack chain using Wireshark, Tcpdump, and PowerShell Event Log analysis|
                                                |

### 🔴 Malware Analysis & DFIR

|#|Project                                                                        |Description                                                                                                                                                                                                                                |
|-|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|3,4|[Malware Analysis — C2 Implant & Ransomware](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/malware-analysis/)              |Full static and dynamic analysis of two malware samples — a C2 spy implant (WS2_32 + IPHLPAPI imports, beacon to 192.229.231.5) and PhotoCrypter ransomware (Base64-encoded ransom note, Pastebin C2, HKCU Run persistence)                |
|5,6|[Digital Forensics & IR — Memory Analysis + Narcos Case](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/digital-forensics/)|Volatility memory forensics across two dumps (trojan process injection, credential dumping via winpmem) and a multi-device criminal DFIR investigation covering Discord artifacts, steganographic images, TrueCrypt volumes, and Quasar RAT|

### 🟠 Offensive Security

|#|Project                                                                         |Description                                                                                                                                                                                                                                                           |
|-|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|7,8|[Penetration Testing — Web + Network](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/pen-testing/)                   |Web application assessment confirming SQLi, stored/reflected XSS, broken access control, and IDOR across OWASP Juice Shop and WebGoat; network boot-to-root achieving SYSTEM via EternalBlue (MS17-010) with post-exploitation credential dumping and lateral movement|
|8,9|[Python Security Automation & Offensive Scripting](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/python-scripting/)|Built a dual-mode ARP reconnaissance tool (passive sniffing + active scanning via Scapy) and a four-module offensive framework — multi-threaded port scanner, SSH brute force (Paramiko), HTTP directory buster, and encrypted reverse shell (Fernet)                 |

### 🟣 GRC & Governance

|#|Project                                            |Description                                                                                                                                                                                                          |
|-|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|10,11|[GRC Implementation Project](./https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/grc-documentation/)|Designed and implemented an enterprise cybersecurity GRC program across ISO 27001, NIST CSF, COBIT, and CIS Controls — covering risk assessment, control mapping, and compliance alignment to GDPR, PCI DSS, and DORA|

### 🟡 Academic Projects

|# |Project                                                               |Description                                                                                                                                                                                   |
|--|----------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|12 |[Online Banking Portal — Secure Transaction System](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/tree/d67d91f921d3e441897c4a0a46d81e0a2b1d1aa2/bachelors-projects)|Built a web banking application with dual-password architecture and grid-based debit card verification — separating login authentication from transaction authorization                       |


-----

> 💡 Each project folder contains a full README with methodology, findings, and where applicable — MITRE ATT&CK mapping and analyst recommendations. PDF reports are linked within each project.
