# 🛡️ SecureNet Guardian — Network Security Assessment Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status: Active">
  <img src="https://img.shields.io/badge/PRs-Welcome-orange.svg" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Tests-Passing-brightgreen" alt="Tests Passing">
  <img src="https://img.shields.io/badge/Code%20Style-PEP%208-informational" alt="PEP 8">
</p>

<p align="center">
  A modular, beginner-friendly Python toolkit for performing basic security
  assessments on systems and networks you own or are authorized to test.
</p>

---

## ⚠️ Ethical Use Notice

This toolkit is built strictly for **educational and authorized security
assessment purposes**. Only use it against systems and networks you own or
have explicit written permission to test. The authors are not responsible
for misuse.

---

## 📖 Project Overview

**SecureNet Guardian** is a network security assessment toolkit developed
as a team Cyber Security project. It brings together several fundamental
security-assessment techniques — host discovery, port scanning, banner
grabbing, password strength analysis, file integrity checking, and log
analysis — into a single, easy-to-use command-line application, complete
with professional HTML/PDF report generation.

The project was built to be genuinely useful as a learning resource: every
module is short, documented, and independently testable, so students can
read the source code and understand exactly how each technique works.

## 🎯 Objectives

- Provide a hands-on, working implementation of core security assessment
  techniques taught in introductory Cyber Security courses.
- Keep the codebase simple and readable for 2nd-year CS/Cyber Security
  students.
- Produce clear, professional, exportable reports (HTML/PDF/CSV).
- Demonstrate good software engineering practices: modular design, unit
  testing, documentation, and version control discipline.

## ❓ Problem Statement

Newcomers to cyber security often rely on complex, black-box scanning
tools without understanding how the underlying techniques work. There is a
need for a lightweight, transparent toolkit that demonstrates *how* host
discovery, port scanning, and log analysis actually work under the hood —
while still producing genuinely useful, professional output.

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 Network Host Discovery | Sweep a CIDR range to identify live hosts using ICMP-style pings |
| 🔍 TCP Port Scanner | Multithreaded scan of common service ports |
| 🏷️ Banner Grabbing | Read service banners to fingerprint running software |
| ⚠️ Basic Vulnerability Checks | Flag commonly risky service configurations (e.g. Telnet, exposed SMB) |
| 🔑 Password Strength Analyzer | Entropy-based scoring with heuristic checks |
| 🧾 File Integrity Checker (SHA-256) | Generate and verify file integrity baselines |
| 📜 Log File Analyzer | Detect brute-force login attempts and summarize access logs |
| 📄 Security Report Generator | Export findings as polished HTML or PDF reports |
| 📊 CSV Export | Export raw results for further analysis in Excel/Sheets |
| 💻 CLI Interface | Simple, unified command-line interface for every module |

## 🧰 Technology Stack

- **Language:** Python 3.9+
- **Standard Library:** `socket`, `threading`, `concurrent.futures`,
  `hashlib`, `csv`, `json`, `argparse`, `ipaddress`
- **Third-party:** `requests`, `colorama`, `rich`, `reportlab`
- **Testing:** `pytest`

## 🏗️ System Architecture

```
                        ┌───────────────────────┐
                        │        main.py         │
                        │   (CLI / argparse)      │
                        └───────────┬─────────────┘
                                    │
        ┌───────────────┬──────────┼──────────┬───────────────┬────────────────┐
        ▼                ▼          ▼          ▼               ▼                ▼
 host_discovery      scanner    banner_grabber password_    integrity_      log_analyzer
     .py               .py           .py       checker.py   checker.py         .py
        │                │            │            │             │              │
        └────────────────┴─────┬──────┴────────────┴──────┬──────┴──────────────┘
                                ▼                           ▼
                            utils.py               report_generator.py
                       (shared helpers)              (HTML / PDF output)
```

See [`docs/Architecture.md`](docs/Architecture.md) for the full breakdown
of module responsibilities and data flow.

## 📁 Folder Structure

```
CyberSecurity-Toolkit/
│
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── CONTRIBUTING.md
├── CHANGELOG.md
│
├── docs/
│   ├── Project_Report.md
│   ├── Architecture.md
│   └── Screenshots/
│
├── src/
│   ├── main.py               # CLI entry point
│   ├── scanner.py            # TCP port scanner + basic vuln checks
│   ├── host_discovery.py     # Network host discovery
│   ├── banner_grabber.py     # Service banner grabbing
│   ├── password_checker.py   # Password strength analyzer
│   ├── integrity_checker.py  # SHA-256 file integrity checker
│   ├── log_analyzer.py       # Log file analyzer
│   ├── report_generator.py   # HTML/PDF report generation
│   └── utils.py              # Shared helpers
│
├── sample_outputs/           # Example CSV/HTML/PDF/log outputs
├── assets/                   # Static assets (icons, diagrams)
└── tests/                    # Unit tests (pytest)
```

## ⚙️ Installation Guide

### Prerequisites
- Python 3.9 or higher
- `pip` package manager
- (Optional) `git` for cloning the repository

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/CyberSecurity-Toolkit.git
cd CyberSecurity-Toolkit

# 2. Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the toolkit
cd src
python main.py --help
```

## 🚀 Usage Instructions

All commands are run through `src/main.py` using subcommands:

```bash
python main.py <command> [options]
```

| Command | Purpose |
|---|---|
| `discover` | Discover live hosts on a network range |
| `scan` | Scan TCP ports on a target host |
| `banner` | Grab a service banner from a specific port |
| `password` | Analyze password strength (interactive, hidden input) |
| `integrity` | Generate or verify a file integrity baseline |
| `logs` | Analyze an auth log or access log file |
| `full-scan` | Run a full assessment and generate an HTML/PDF report |

## 💡 Example Commands

```bash
# Discover live hosts on your local subnet
python main.py discover --network 192.168.1.0/24 --export

# Scan common ports on a host
python main.py scan --host 192.168.1.10

# Scan a custom port range
python main.py scan --host 192.168.1.10 --ports 1-1024 --export

# Grab a banner from port 22
python main.py banner --host 192.168.1.10 --port 22

# Analyze password strength (prompts securely, input hidden)
python main.py password

# Generate a file integrity baseline
python main.py integrity --path ../sample_outputs --baseline baseline.json

# Verify files against a previously generated baseline
python main.py integrity --baseline baseline.json --verify

# Analyze an SSH auth log for brute-force attempts
python main.py logs --file ../sample_outputs/sample_auth.log --type auth

# Run a full assessment and generate an HTML + PDF report
python main.py full-scan --host 192.168.1.10 --export html,pdf,csv
```

## 🖥️ Sample Output

```
[*] Scanning 71 port(s) on 192.168.1.10 ...
[+] Port 22/tcp open  (SSH)
[+] Port 80/tcp open  (HTTP)
[!] Port 23/tcp open  (Telnet)
[!] 1 potentially risky service(s) detected.

[*] Length: 18 characters
[*] Estimated entropy: 117.98 bits
[*] Strength: Very Strong (4/4)

[+] Integrity check passed -- no changes detected.

[!] 1 IP(s) exceeded the brute-force threshold.
[+] HTML report generated: sample_outputs/report_20260628_094512.html
```

Example generated artifacts are available in [`sample_outputs/`](sample_outputs/),
including a sample HTML report, PDF report, and CSV exports.

## 📸 Screenshots Section

> Screenshots go here once the team captures them locally.
> See [`docs/Screenshots/README.md`](docs/Screenshots/README.md) for the
> suggested list of screenshots and naming convention.

| CLI Banner | Port Scan Results |
|---|---|
| _screenshot placeholder_ | _screenshot placeholder_ |

| Password Analysis | HTML Report |
|---|---|
| _screenshot placeholder_ | _screenshot placeholder_ |

## 🎓 Learning Outcomes

Through this project, the team gained practical experience with:

- Socket programming and TCP connection fundamentals
- Multithreading with `concurrent.futures` for network I/O
- Regular expressions for log parsing
- SHA-256 hashing and file integrity monitoring concepts
- Password entropy theory and heuristic strength scoring
- Building CLI applications with `argparse`
- Generating HTML and PDF reports programmatically
- Writing unit tests with `pytest`
- Git/GitHub collaboration as a team

## 🔮 Future Enhancements

- [ ] UDP port scanning support
- [ ] Integration with the Have I Been Pwned API for real breach checking
- [ ] Optional Flask-based web dashboard
- [ ] Scheduled integrity checks with email alerting
- [ ] IPv6 support for discovery and scanning
- [ ] Support for additional log formats (Windows Event Logs, firewall logs)

## 👥 Team Members & Contributions

| Member | Role & Contributions |
|---|---|
| **Abdul Rahim R** | Project Lead · Network Scanner Module · Final Integration |
| **Lokesh D** | Password Strength Analyzer · File Integrity Checker |
| **Nishith P** | Banner Grabbing Module · Log Analysis Module |
| **Saran V** | Report Generation · Documentation · Testing |
| **Sivaguru S** | README Documentation · GitHub Repository Management · Bug Fixing · Code Review |

## 📚 References

1. Python Software Foundation — [`socket`](https://docs.python.org/3/library/socket.html) documentation
2. Python Software Foundation — [`hashlib`](https://docs.python.org/3/library/hashlib.html) documentation
3. Python Software Foundation — [`concurrent.futures`](https://docs.python.org/3/library/concurrent.futures.html) documentation
4. OWASP Foundation — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
5. NIST SP 800-63B — [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
6. [ReportLab Documentation](https://docs.reportlab.com/)

Full project report available at [`docs/Project_Report.md`](docs/Project_Report.md).

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">Built with 🐍 Python by the SecureNet Guardian Team</p>
