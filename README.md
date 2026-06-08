# 🛡️ Luban 2040 v2

> **Advanced Reconnaissance & Vulnerability Assessment Framework**  
> Built for Ethical Hackers, Penetration Testers, and Bug Bounty Hunters.  
> Author: **m.alfahdi**

---


## ⚠️ Legal Warning

```
THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY.

Using Luban 2040 against systems you do NOT have explicit written permission
to test is ILLEGAL and may violate:
  - Computer Fraud and Abuse Act (CFAA) – USA
  - Computer Misuse Act – UK
  - Cybercrime laws in Oman, GCC, and most countries worldwide

The author is NOT responsible for any misuse or damage caused by this tool.
Always obtain written authorization before testing any target.
```

## The ScreenShot at the end of README.md file

---

## 📁 Project Structure (map of Luban 2040 v2 ) 
```
luban2040/
├── luban2040.py          # Main entry point
├── config.json           # API keys (Shodan) Optional and not Required 
├── requirements.txt      # Python dependencies
├── setup.sh              # Auto-installer script
├── README.md 
└── core/
    ├── __init__.py
    ├── recon.py           # DNS, subdomains, wayback, takeover
    ├── webscanner.py      # Headers, CORS, tech, dirs, JS secrets
    ├── vulnerability.py   # XSS, SQLi, CMDi, LFI, IDOR, SSRF, SSTI
    ├── portscanner.py     # TCP port scanner with banner grabbing
    ├── bruteforce.py      # HTTP / SSH / FTP brute force
    ├── cvefinder.py       # CVE lookup
    ├── redteam.py         # SMB, LDAP, RDP, WinRM, Kerberos, SNMP
    └── stealth.py         # Anti-bot / WAF bypass HTTP engine
```


### 📄 File Descriptions

| File | Role | Needs API? |
|---|---|---|
| `luban2040.py` | CLI controller, argument parsing, module orchestrator | No |
| `recon.py` | Passive + active reconnaissance on domains | No |
| `webscanner.py` | Web surface scanning (headers, dirs, JS, CORS) | No |
| `vulnerability.py` | Active vuln testing with payloads | No |
| `portscanner.py` | Lightweight TCP scanner for common ports | No |
| `bruteforce.py` | Credential brute force for HTTP/SSH/FTP | No |
| `cvefinder.py` | CVE lookup using free + paid APIs | Shodan (optional) |
| `redteam.py` | Internal network attack simulation | No |
| `stealth.py` | Smart HTTP engine with WAF/bot bypass | No |
| `config.json` | Stores your Shodan API key | — |

---

## ⚙️ Installation

### Requirements
- Python 3.8+
- Linux / macOS (Kali Linux recommended)
- pip

```bash
    pip3 install paramiko
```

### Quick Install

```bash
git clone < PUT YOU LUBAN 2040 V2 GitHub URL >
cd luban2040
chmod +x setup.sh
./setup.sh
```

### Manual Install

```bash
pip install -r requirements.txt
pip install colorama
```

## If you have any issue install the core libraries manually through Python virtual environments(venv):
```bash
pip install requests pyfiglet termcolor cloudscraper dnspython beautifulsoup4 ldap3 pysmb impacket shodan paramiko
pip3 install cloudscraper
pip3 install requests beautifulsoup4 urllib3
pip install paramiko
```



### Optional: Cloudflare / WAF Bypass Engine

```bash
pip install "scrapling[fetchers]"
scrapling install
```

### Shodan API Key (required only for `-org` / `-q`)

Edit `config.json`:
```json
{
    "api_key": "YOUR_SHODAN_API_KEY"
}
```

---

## 🚀 Usage

```bash
python3 luban2040.py [MODULE] [TARGET] [OPTIONS]
```

### Syntax Pattern

| Part | Meaning | Example |
|---|---|---|
| `python3 luban2040.py` | Run the tool | — |
| `-host` / `-web` / `-redteam` | Choose the module | `-web` |
| Target value | The domain, URL, or IP | `https://example.com` |
| `--flag` | Enable a specific check | `--xss` |
| `-t N` | Number of threads | `-t 20` |
| `-v` | Verbose (show all requests/errors) | `-v` |
| `-o name` | Output file prefix | `-o myreport` |
---

## 📌 Command Reference

### 🔍 Reconnaissance

| Command | Description |
|---|---|
| `-host example.com` | DNS enum + CVE scan on resolved IPs |
| `-host example.com --subs` | Add subdomain enumeration |
| `-host example.com --takeover` | Check subdomain takeover |
| `-host example.com --wayback` | Fetch historical URLs (7 sources) |
| `-host example.com --subs --takeover --wayback` | Full recon |

### 🌐 Web Scanning

| Command | Description |
|---|---|
| `-web https://example.com --headers` | Security headers check |
| `-web https://example.com --cors` | CORS misconfiguration |
| `-web https://example.com --tech` | Technology fingerprinting |
| `-web https://example.com --sensitive` | Sensitive file exposure |
| `-web https://example.com --js` | JS secrets / API keys |
| `-web https://example.com --dirb` | Directory brute force |
| `-web https://example.com --redirect` | Open redirect check |

### 💉 Vulnerability Scanning

| Command | Description |
|---|---|
| `-web https://example.com --xss` | XSS (100+ payloads, WAF bypass) |
| `-web https://example.com --sqli` | SQL Injection (error + time-based) |
| `-web https://example.com --cmdi` | Command Injection |
| `-web https://example.com --lfi` | Local File Inclusion |
| `-web https://example.com --idor` | IDOR detection |
| `-web https://example.com --ssrf` | SSRF (AWS metadata, localhost) |
| `-web https://example.com --ssti` | SSTI (Jinja2, Twig, Freemarker) |
| `-web https://example.com --graphql` | GraphQL introspection |


### 💉 Vulnerability Scanning

| Flag | Vulnerability | Severity | How It Works |
|---|---|---|---|
| `--xss` | Cross-Site Scripting | Medium–High | 100+ payloads in forms + URL params + WAF bypass |
| `--sqli` | SQL Injection | High–Critical | Error-based + time-based (SLEEP/WAITFOR) |
| `--cmdi` | Command Injection | Critical | Time-delay detection via `sleep`/`ping` payloads |
| `--lfi` | Local File Inclusion | High | Path traversal to `/etc/passwd`, `win.ini`, etc. |
| `--idor` | Insecure Direct Object Reference | Medium–High | Parameter ID swap (numbers, UUIDs, usernames) |
| `--ssrf` | Server-Side Request Forgery | High–Critical | Internal IP + AWS metadata endpoint probing |
| `--ssti` | Server-Side Template Injection | Critical | Math detection `{{7*7}}` = 49 evaluation |
| `--graphql` | GraphQL Introspection | Low–Medium | Schema leak via `__schema` queries |


#### Security Headers Reference

| Header | Purpose | Risk if Missing |
|---|---|---|
| `Strict-Transport-Security` | Force HTTPS | SSL stripping attacks |
| `Content-Security-Policy` | Block inline scripts | XSS amplification |
| `X-Frame-Options` | Block iframes | Clickjacking |
| `X-Content-Type-Options` | Prevent MIME sniffing | Drive-by downloads |
| `Referrer-Policy` | Control referrer data leaks | Info disclosure |
| `Permissions-Policy` | Restrict browser features | Sensor/camera abuse |


#### XSS Payload Categories

| Category | Count | Purpose |
|---|---|---|
| Basic XSS | ~20 | Standard `<script>`, `onerror`, SVG tags |
| Advanced Polyglots | ~15 | Multi-context bypass (attr, JS, HTML) |
| WAF Bypass | ~15 | Encoding, case mixing, whitespace tricks |
| Framework-Specific | ~7 | Angular, Vue, Svelte, AngularJS |
| Event Handlers | ~11 | `onpageshow`, `onhashchange`, rare events |



### 🔴 Red Team

| Command | Description |
|---|---|
| `-redteam <Target ip adress>` | Run all red team checks |

**Red team checks include:**
- SMB enum + signing check + EternalBlue risk
- MS17-010 (EternalBlue)
- ZeroLogon (CVE-2020-1472)
- LDAP anonymous bind + user/computer enum
- NetBIOS enumeration
- RDP BlueKeep check
- WinRM exposure
- Kerberos AS-REP Roasting
- SNMP community string brute force
- MSSQL anonymous login
- Print Spooler (PrintNightmare) check

### 🔢 Port Scanner

| Command | Description |
|---|---|
| `-host example.com --portscan` | Scan 28 common ports + banner |

| Port | Service | Risk if Open |
|---|---|---|
| 21 | FTP | Anonymous login, plaintext credentials |
| 22 | SSH | Brute force, weak/default keys |
| 23 | Telnet | Plaintext protocol — always critical |
| 25 | SMTP | Open relay, email spoofing |
| 53 | DNS | Zone transfer, cache poisoning |
| 80 | HTTP | Full web attack surface |
| 110 | POP3 | Plaintext email credentials |
| 139/445 | SMB | EternalBlue, ransomware entry point |
| 143 | IMAP | Email enumeration |
| 443 | HTTPS | Web attack surface (encrypted) |
| 993 | IMAPS | Encrypted IMAP |
| 1433 | MSSQL | DB access, xp_cmdshell RCE |
| 3306 | MySQL | DB access, credential brute force |
| 3389 | RDP | BlueKeep, brute force |
| 5432 | PostgreSQL | Direct DB access |
| 5900 | VNC | Remote desktop — often no auth |
| 5985 | WinRM | Remote PowerShell execution |
| 6379 | Redis | Unauthenticated access, config write RCE |
| 8080 | HTTP Alt | Dev servers, exposed admin panels |
| 8443 | HTTPS Alt | Dev/staging web applications |
| 9200 | Elasticsearch | Unauthenticated data dump |
| 27017 | MongoDB | Unauthenticated DB access |

### 🔑 Brute Force

| Command | Description |
|---|---|
| `-web https://example.com --brute` | HTTP Basic Auth brute force |
| `-host example.com --brute` | HTTP + SSH + FTP brute force |

| Protocol | Default Port | Detection Method |
|---|---|---|
| HTTP Basic Auth | 80 / 443 | Status code ≠ 401 → success |
| SSH | 22 | Paramiko authentication success |
| FTP | 21 | ftplib connection success |



**Built-in wordlists:**
- 80+ usernames (admin, root, developer, jenkins, gitlab, etc.)
- 200+ passwords (modern leaked passwords 2024–2026, seasonal patterns)





### 🔎 CVE  (`-org` / `-q` / `-host`)

| Command | Requires Shodan Key? | Description |
|---|---|---|
| `-org "Company"` | ✅ Yes | Find all IPs for an org then scan CVEs |
| `-q "nginx 1.14"` | ✅ Yes | Custom Shodan dork → CVE scan |
| `-host example.com` | ❌ No | Free scan via internetdb.shodan.io |
| `-cvss 7.0` | ❌ No | Filter results to CVSS ≥ 7.0 only |


**CVE sources:** NVD, EPSS, Vulners, Exploit-DB, CVEDetails and other DB from DarkWeb (.onion).

#### CVE Output Icons

| Icon | Meaning |
|---|---|
| 🔥 | Public exploit confirmed (immediate action required) |
| ⚠️ | Potential / unconfirmed exploit exists |
| `*` | CVE found, no known public exploit |

---

## ⚡ Full Scan Modes

```bash
# Full web scan (all web + vuln checks)
python3 luban2040.py -web https://example.com --full-web

# Full scan (recon + web + vuln + ports + red team)
python3 luban2040.py -host example.com -web https://example.com --full

# Complete scan (domain + web)
python3 luban2040.py -host example.com -web https://example.com --full -t 20 -v -o full_report

```

---

## 📋 Additional Options

| Flag | Description |
|---|---|
| `-o report` | Custom output prefix (default: timestamped) |
| `-t 20` | Thread count (default: 10) |
| `-v` | Verbose mode |
| `-cvss 5.0` | Minimum CVSS score filter |

---

## 💾 Output Files

All results are saved as JSON files with all Details :

| File | Contents | Use For |
|---|---|---|
| `*_recon.json` | DNS records, subdomains, wayback URLs, takeover results | Scope mapping |
| `*_web.json` | Headers, CORS, tech stack, dirs, JS secrets, admin panels | Attack surface |
| `*_vulns.json` | XSS, SQLi, CMDi, LFI, IDOR, SSRF, SSTI findings | Bug bounty reports |
| `*_ports.json` | Open ports + service banners per IP | Network exposure |
| `*_cves.json` | CVEs with CVSS, EPSS %, exploit status per IP | Patch prioritization |
| `*_redteam.json` | SMB, LDAP, RDP, Kerberos, SNMP, MSSQL results | Internal audit |
| `*_brute.json` | Found credentials (protocol + user:pass) | Credential reporting |

---

## 🧪 Example Commands

```bash
# Recon only
python3 luban2040.py -host example.com --subs --wayback

# Web surface + full vuln scan
python3 luban2040.py -web https://example.com --full-web -o example_report

# Full scan with threads + verbose
python3 luban2040.py -host example.com -web https://example.com --full -t 20 -v

# Internal red team
python3 luban2040.py -redteam <Target IP adresses>

# CVE scan via Shodan
python3 luban2040.py -org "Target Corp" -cvss 7.0

# CVE scan free (no key needed)
python3 luban2040.py -host example.com -cvss 5.0

# Brute force only
python3 luban2040.py -web https://example.com --brute -t 5 -v

# Targeted vuln checks only
python3 luban2040.py -web https://example.com --xss --sqli --ssrf -o vulns_only

# Subdomain + takeover check
python3 luban2040.py -host example.com --subs --takeover -v
```

---

## 🔧 Troubleshooting
| Problem | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | Missing dependency | `pip install -r requirements.txt` |
| `Shodan API key required` | No key in config.json | Add key to `config.json` |
| `No IPs resolved` | Bad domain or DNS failure | Check domain spelling, use `-v` |
| `Impacket missing` | Not installed | `pip install impacket` |
| `paramiko missing` | Not installed | `pip install paramiko` |
| `pysnmp missing` | Not installed | `pip install pysnmp` |
| `pymssql missing` | Not installed | `pip install pymssql` |
| `ldap3 missing` | Not installed | `pip install ldap3` |
| Cloudflare blocks scan | WAF protection | `pip install "scrapling[fetchers]" && scrapling install` |
| SMB scan fails | Needs root on some systems | Run with `sudo python3` |
| Slow scan | Too many threads | Reduce with `-t 5` |
| Empty JSON output | Target unreachable | Confirm target is live and in scope |

## ScreenShots Luban 2040 v2 : 
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%201.PNG)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%202.png)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%203.PNG)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%204.png)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%205.png)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%206.png)
![image alt](https://github.com/7m7n/Luban-2040-v2/blob/e6dafcce7240035cf473de05f8f54b2b005384fc/Screenshot%207.png)
---
## 📜 License

This tool is released for **educational and authorized security testing purposes only**.  
Unauthorized use is strictly prohibited and illegal.

---

*Luban 2040 v2  by m.alfahdi*
