# RustRecon

> OSCP-focused async recon framework — auto-classifies Linux / Windows / Active Directory targets and runs the right tool chain for each.

Built in Rust for speed. Replaces AutoRecon with smarter target detection, a clean HTML report, and full OSCP module coverage.

RustRecon is a fast, async network reconnaissance framework built in Rust, designed for OSCP exam prep and penetration testing labs. Unlike traditional recon tools that run the same scans against every target, RustRecon first fingerprints the target — detecting whether it's a Linux box, a Windows standalone machine, or an Active Directory domain controller — then runs only the tools and checks that are relevant.

Built to replace AutoRecon with smarter target classification, live progress indicators, and a clean HTML report sorted by severity. Every scan produces a full output directory with raw tool results, an extracted findings list, auto-generated manual command suggestions, and a dark-themed HTML report you can open in a browser immediately.

Covers the full OSCP attack surface: port scanning via rustscan and nmap, web enumeration with feroxbuster/nikto/whatweb, SMB with enum4linux-ng and CrackMapExec, Active Directory with Kerbrute/BloodHound/Impacket, network services including DNS zone transfer, SNMP, NFS, Redis, and post-discovery with searchsploit version matching and automatic credential/hash extraction from all output.

No auto-exploitation. Stays within OSCP exam rules.

For authorised testing only.

---

## Quick start

```bash
# Single target (auto-detect OS type)
sudo rustrecon 10.10.10.1

# AD target with credentials
sudo rustrecon 10.10.10.1 -d corp.local -u admin -p Password1

# Force target type
sudo rustrecon 10.10.10.1 --type ad -d corp.local

# Multiple targets from file
sudo rustrecon -t targets.txt -m 3

# Skip portscan — only enumerate known ports
rustrecon 10.10.10.1 --ports 80,443,445

# Only run specific phases
rustrecon 10.10.10.1 --only web,smb

# Pass-the-hash
rustrecon 10.10.10.1 -u administrator --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

---

## How it works

```
Target IP
   │
   ▼
Phase 1 — Port scan
   rustscan (fast sweep) → nmap -sV -sC -A (deep) → nmap -sU (UDP top 200)
   │
   ▼
Auto-classify
   Port 88+389 = Active Directory
   Port 445+3389 = Windows standalone
   Port 22 + Linux keywords = Linux
   │
   ├──── Linux ──────────────────────────────────────────────────────────────┐
   │     SSH version, NFS mounts, rpcbind, finger                           │
   │                                                                         │
   ├──── Windows ────────────────────────────────────────────────────────────┤
   │     RPC enum, WinRM check, RDP vuln scan, CrackMapExec (if creds)      │
   │                                                                         │
   ├──── Active Directory ───────────────────────────────────────────────────┤
   │     LDAP anon bind, Kerbrute user enum, AS-REP roasting,               │
   │     Kerberoasting (if creds), BloodHound ingestor, secretsdump         │
   │                                                                         │
   ├──── Web (any HTTP/HTTPS port) ──────────────────────────────────────────┤
   │     whatweb, feroxbuster, nikto, curl headers, wpscan, sslscan, ffuf  │
   │                                                                         │
   ├──── SMB (445/139) ──────────────────────────────────────────────────────┤
   │     enum4linux-ng, smbclient, smbmap, nmap smb-vuln scripts,           │
   │     MS17-010 check, SMB signing check, CrackMapExec                   │
   │                                                                         │
   ├──── Network services ───────────────────────────────────────────────────┤
   │     DNS (zone transfer), FTP (anon login), SMTP, SNMP (community       │
   │     string brute), NFS exports, Redis unauth, MySQL/MSSQL, RPC null    │
   │                                                                         │
   └──── Post-scan ─────────────────────────────────────────────────────────┘
         searchsploit version matching, credential/hash pattern extraction

Phase 6 — Reports
   results/<ip>/report/report.html    ← main HTML report
   results/<ip>/report/findings.md    ← severity-sorted findings
   results/<ip>/scans/_manual_commands.txt  ← next-step commands
   results/<ip>/scans/_patterns.txt   ← extracted creds/hashes/paths
   results/<ip>/scans/*.txt           ← raw tool output
```

---

## Output structure

```
results/
└── 10.10.10.1/
    ├── scans/
    │   ├── nmap_full.txt          nmap deep scan
    │   ├── nmap_full.xml          nmap XML (for importers)
    │   ├── nmap_udp.txt           UDP top 200
    │   ├── rustscan.txt           fast sweep results
    │   ├── ferox_tcp80.txt        feroxbuster output
    │   ├── nikto_tcp80.txt        nikto output
    │   ├── enum4linux.txt         SMB enumeration
    │   ├── ldap_users.txt         LDAP user dump (if AD + creds)
    │   ├── kerbrute_users.txt     valid domain users
    │   ├── asrep.txt              AS-REP hashes (crack with hashcat -m 18200)
    │   ├── kerberoast.txt         TGS hashes (crack with hashcat -m 13100)
    │   ├── searchsploit_all.txt   version-matched exploits
    │   ├── _patterns.txt          extracted creds/hashes/IPs/keys
    │   ├── _manual_commands.txt   suggested next steps
    │   └── _commands.log          everything that ran
    ├── loot/                      drop files/hashes you find here
    ├── exploit/                   drop exploit code here
    └── report/
        ├── report.html            ← open this in browser
        ├── findings.md            ← CRITICAL → INFO sorted
        ├── local.txt              paste local.txt flag
        └── proof.txt              paste proof.txt flag
```

---

## Options

| Flag | Description |
|------|-------------|
| `TARGET` | IP address or hostname |
| `-t FILE` | File with one target per line |
| `-o DIR` | Output directory (default: `results`) |
| `-d DOMAIN` | Domain name (e.g. `corp.local`) — required for AD |
| `-u USER` | Username for authenticated scans |
| `-p PASS` | Password |
| `--hash LM:NT` | NTLM hash for pass-the-hash attacks |
| `--type TYPE` | Force type: `auto`, `linux`, `windows`, `ad` |
| `-m N` | Max concurrent scans (default: 5) |
| `--ports` | Skip portscan, enumerate these ports only |
| `--only PHASES` | Comma-separated: `portscan,web,smb,windows,linux,ad,network,exploit` |
| `--userlist FILE` | Username wordlist for brute-force hints |
| `--passlist FILE` | Password wordlist for brute-force hints |
| `-v` | Verbose (repeat for more: `-vv`) |

---

## Installation

```bash
git clone https://github.com/yourname/rustrecon
cd rustrecon
cargo build --release
sudo ./install.sh
```

Requires Kali Linux. The installer handles: nmap, feroxbuster, enum4linux-ng, smbclient, smbmap, nikto, whatweb, crackmapexec, evil-winrm, kerbrute, bloodhound-python, impacket, SecLists, rustscan.

---


## Uninstallation

```bash
cd rustrecon
sudo ./uninstall.sh
```

The uninstaller will ask for confirmation before removing anything. It removes:

| What | Path |
|------|------|
| Binary | `/usr/local/bin/rustrecon` |
| Config (if any) | `~/.config/rustrecon/` |

**It does NOT remove:**
- Your `results/` directory — all your scan output is kept safe
- System tools (nmap, feroxbuster, smbclient, etc.) — these are standard Kali tools used by many other things

To manually remove the binary without the script:
```bash
sudo rm /usr/local/bin/rustrecon
```

To reinstall after uninstalling:
```bash
cargo build --release
sudo ./install.sh
```

---
## OSCP exam tips

- Run `sudo rustrecon <ip>` so nmap can do SYN scan + UDP
- Start RustRecon on a target, then **manually work another target** while it runs
- Check `_manual_commands.txt` immediately — these are your next steps
- Check `_patterns.txt` for any credentials extracted automatically
- The HTML report is your working doc — open it in the browser, it auto-sorts by severity
- For AD boxes: always provide `-d DOMAIN` even if you guess the domain name
- AS-REP and Kerberoast hashes go straight to `hashcat` — commands are in `_manual_commands.txt`

---

## Tool coverage by OSCP module

| Module | Tools |
|--------|-------|
| Info gathering | nmap, rustscan, whatweb, curl, dnsrecon |
| Web attacks | feroxbuster, nikto, ffuf, wpscan, sslscan, nuclei |
| SMB / Windows | enum4linux-ng, smbclient, smbmap, crackmapexec, impacket |
| Active Directory | kerbrute, ldapsearch, GetNPUsers, GetUserSPNs, BloodHound, secretsdump |
| Network services | onesixtyone, snmpwalk, showmount, redis-cli, rpcclient |
| Post-discovery | searchsploit, pattern extractor (hashes, creds, keys) |
| Brute force hints | hydra commands generated for SSH, FTP, RDP, MySQL, WinRM |

---

*For authorised testing only. No auto-exploitation — stays within OSCP exam rules.*
