# AnasOsint

![AO Logo](AO.png)
**Smart Advanced OSINT Tool by Anas Labrini** 🚀
Developed with love in Python ❤ by [anasslabrini](https://github.com/anasslabrini).
MyWebSite: [anaslabrini](https://anaslabrini.netlify.app)

AnasOsint is a modular, extensible, and interactive framework designed for comprehensive Open Source Intelligence (OSINT) gathering on:

- **Emails**  
- **Phone Numbers**  
- **IP Addresses**  
- **Domains**

It supports both **interactive menu-driven** operation and **command-line** execution, with **basic** and **advanced** scan modes across 20+ data sources per lookup type.

---

## 🔧 Project Structure

```
AnasOsint/
├── main.py                  # Entry point: interactive menu & CLI
├── requirements.txt         # Python dependencies
├── modules/                 # Lookup modules
│   ├── email_lookup.py
│   ├── phone_lookup.py
│   ├── ip_lookup.py
│   └── domain_lookup.py
├── utils/
│   └── output_manager.py    # Unified colored output & report writer
└── reports/                 # Auto-created when saving reports
```

- **main.py**: Handles CLI args (`--email`, `--phone`, `--ip`, `--domain`, `--advanced`, `--save-report`) or launches the interactive menu.
- **modules/**: Contains one Python file per lookup type. Each module defines:
  1. **Basic checks** (always executed, no API keys needed).
  2. **Advanced checks** (prompt for API keys, then query 20+ external OSINT APIs).
- **utils/output_manager.py**: Provides `info()`, `success()`, `warning()`, `error()` for colored console output, plus `set_report()` and timestamped logging to an optional report file.

---

## 📦 Requirements

- **Python 3.8+**  
- **Pip** package manager  

Install dependencies:

```bash
pip install -r requirements.txt
```

**requirements.txt**:
```text
colorama
requests
dnspython
python-whois
```

---

## ⚙️ Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/anaslabrini/AnasOsint.git
   cd AnasOsint
   ```

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Create reports directory**  
   ```bash
   mkdir reports
   ```

---

## 🚀 Usage

### 1. Interactive Mode

```bash
python3 main.py
```

- Choose from:
  - `1` Email Lookup  
  - `2` Phone Lookup  
  - `3` IP Lookup  
  - `4` Domain Lookup  
  - `0` Exit  
- For each lookup:
  - Enter the target (email/phone/IP/domain).  
  - Choose **Save report?** (y/n).  
  - The module then prompts for **advanced scan** keys if desired.

### 2. CLI Mode

```bash
python3 main.py [OPTIONS]
```

| Option               | Description                                          |
|----------------------|------------------------------------------------------|
| `-e`, `--email`      | Lookup an email address.                             |
| `-p`, `--phone`      | Lookup a phone number.                               |
| `-i`, `--ip`         | Lookup an IP address.                                |
| `-d`, `--domain`     | Lookup a domain.                                     |
| `-a`, `--advanced`   | Prompt for advanced-scan API keys.                   |
| `-s`, `--save-report`| Save results to `reports/<target>_report.txt`.       |

**Examples**:

```bash
# Email lookup, save report
python3 main.py --email user@example.com --save-report

# IP lookup with advanced scan
python3 main.py --ip 8.8.8.8 --advanced --save-report

# Domain lookup, interactive menu
python3 main.py
```

---

## 📑 Detailed Module Flow

### email_lookup.py

1. **Gravatar profile**  
2. **Google Dorks** (PDF, LinkedIn, Pastebin, GitHub, Twitter)  
3. **MX/DNS** record validation  
4. **HaveIBeenPwned** (API)  
5. **Hunter.io**, **EmailRep.io**, **LeakCheck**, **MailboxLayer**, **EmailHippo**, **IntelligenceX**, **Hacked-Emails**, **PGP Keyservers**, **Social Media Dorks**, **LinkedIn**, **Pastebin**, ... (20+ sources)

### phone_lookup.py

1. **Basic NumVerify stub**  
2. **Social Media Dorks**  
3. **NumVerify**, **Twilio**, **Nexmo**, **OpenCNAM**, **Truecaller**, **Pipl**, **Whitepages**, **FullContact**, **NumberAPI**, **PhoneFormat.io**, **HLR Lookup**, **Infobel**, **FraudCheck**, **CallerIDAPI**, ... (20+ sources)

### ip_lookup.py

1. **Reverse DNS**, **HTTP ping stub**  
2. **Basic ipinfo.io**  
3. **ipinfo.io**, **Shodan**, **AbuseIPDB**, **VirusTotal**, **Censys**, **GreyNoise**, **ThreatCrowd**, **URLScan.io**, **PassiveTotal**, **SecurityTrails**, **DNSDB**, **ViewDNS**, **AlienVault**, **BinaryEdge**, **IPQualityScore**, **PhishTank**, **Spamhaus DNSBL**, ... (20+ sources)

### domain_lookup.py

1. **WHOIS** (python-whois)  
2. **DNS records** (A, AAAA, MX, TXT, NS, CNAME)  
3. **crt.sh** subdomain enumeration  
4. **SecurityTrails**, **VirusTotal**, **Censys**, **Shodan**, **ThreatCrowd**, **URLScan.io**, **PassiveTotal**, **DNSDB**, **ViewDNS**, **BuiltWith**, **DomainTools**, **AlienVault**, **Spyse**, **Netcraft**, **Brandfetch**, **RiskIQ**, **IntelligenceX**, **Hacked-Emails DB**, ... (20+ sources)

---

## 📄 Report Files

- Auto-saved under `reports/` when `--save-report` or interactive “save report” is used.  
- Filename: `<target>_report.txt`  
- Each line is timestamped, color tags stripped, for easy parsing.

---

## 🤝 Contributing

Contributions welcome!  

1. Fork the repo  
2. Create feature branch  
3. Commit & PR  

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**AnasOsint** was developed by **Anas Labrini** for Cybersecurity and aims to provide cybersecurity teams and information security experts with reliable and in-depth intelligence during the reconnaissance and initial assessment phases.

---

## ⚠️ Legal Disclaimer

> This tool is intended for educational purposes and certified security testing **only**. Unauthorized use of domains or systems without express permission is strictly prohibited. **Anas Labrini** is not responsible for any misuse or illegal activity related to this tool.
