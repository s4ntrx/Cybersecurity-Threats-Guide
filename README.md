# Cybersecurity Threats & Vulnerabilities Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

An educational guide to understanding, detecting, and preventing common cybersecurity threats. Each topic pairs documentation with Python detection scripts and prevention examples.

## Table of Contents

- [About](#about)
- [Project status](#project-status)
- [Repository structure](#repository-structure)
- [Categories](#categories)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Web app and API](#web-app-and-api)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## About

This repository is for security professionals, developers, and students who want working examples next to the theory. A typical topic contains:

- **Documentation** on how the threat works
- **Detection scripts** that look for signs of the attack
- **Prevention examples** with code
- **Best practices** for implementation

The scripts are teaching material. Read and test them in a lab before relying on them in production.

## Project status

This is an early-stage guide. Six categories exist, and most topics have documentation plus detection and prevention scripts. Several topics named in earlier versions of this README are not written yet; they are listed under [Roadmap](#roadmap) instead of being counted as done.

## Repository structure

```
cybersecurity-threats-guide/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
│
├── 01-network-security/
│   ├── ddos-attacks/
│   │   ├── detection/
│   │   │   ├── ddos_detection.py
│   │   │   └── traffic_analyzer.py
│   │   ├── prevention/
│   │   │   ├── firewall_rules.txt
│   │   │   └── rate_limiting.py
│   │   └── README.md
│   ├── man-in-the-middle/
│   │   ├── detection/
│   │   │   ├── arp_spoof_detector.py
│   │   │   └── ssl_strip_detector.py
│   │   ├── prevention/
│   │   │   ├── certificate_pinning.py
│   │   │   └── ssl_tls_config.py
│   │   └── README.md
│   ├── port-scanning/
│   │   ├── detection/
│   │   │   ├── ids_rules.txt
│   │   │   └── port_scan_detector.py
│   │   ├── prevention/
│   │   │   ├── firewall_config.py
│   │   │   └── stealth_mode.py
│   │   └── README.md
│   └── README.md
│
├── 02-web-application-security/
│   ├── sql-injection/
│   │   ├── detection/
│   │   │   ├── sql_injection_detector.py
│   │   │   └── sql_injection_scanner.py
│   │   ├── prevention/
│   │   │   ├── input_validation.py
│   │   │   └── parameterized_queries.py
│   │   └── README.md
│   ├── xss-attacks/
│   │   ├── detection/
│   │   │   └── xss_detector.py
│   │   └── README.md
│   └── README.md
│
├── 03-malware-analysis/
│   ├── ransomware/
│   │   ├── detection/
│   │   │   ├── file_monitor.py
│   │   │   └── ransomware_behavior.py
│   │   ├── prevention/
│   │   │   ├── app_whitelisting.py
│   │   │   └── backup_system.py
│   │   └── README.md
│   ├── rootkits/
│   │   ├── detection/
│   │   │   ├── integrity_checker.py
│   │   │   └── rootkit_detector.py
│   │   ├── prevention/
│   │   │   ├── kernel_patching.py
│   │   │   └── secure_boot.py
│   │   └── README.md
│   ├── trojans/
│   │   ├── detection/
│   │   │   ├── process_analyzer.py
│   │   │   └── trojan_scanner.py
│   │   ├── prevention/
│   │   │   ├── av_config.py
│   │   │   └── sandbox_setup.py
│   │   └── README.md
│   └── README.md
│
├── 04-social-engineering/
│   ├── phishing/
│   │   ├── detection/
│   │   │   ├── email_analyzer.py
│   │   │   └── phishing_detector.py
│   │   ├── prevention/
│   │   │   ├── email_filters.py
│   │   │   └── training_materials.md
│   │   └── README.md
│   ├── pretexting/
│   │   ├── detection/
│   │   │   └── social_engineering_detector.py
│   │   ├── prevention/
│   │   │   └── security_policy.md
│   │   └── README.md
│   └── README.md
│
├── 05-cryptography/
│   ├── encryption/
│   │   └── symmetric/
│   │       └── aes_example.py
│   ├── hashing/
│   │   ├── README.md
│   │   ├── integrity_checker.py
│   │   └── password_hashing.py
│   └── README.md
│
├── 06-incident-response/
│   ├── containment/
│   │   ├── backup_recovery.py
│   │   └── isolation_script.py
│   ├── forensics/
│   │   ├── README.md
│   │   ├── disk_forensics.py
│   │   └── memory_analyzer.py
│   └── README.md
│
├── api/                 # Flask API (experimental, see "Web app and API")
├── cybersec-app/        # Next.js site (see cybersec-app/README.md)
└── tools/
    ├── setup_tools.sh
    ├── requirements.txt
    └── requirements-optional.txt
```

## Categories

Topics marked *planned* do not have content yet.

### 1. [Network Security](01-network-security/README.md)

- [DDoS Attacks](01-network-security/ddos-attacks/README.md)
- [Man-in-the-Middle](01-network-security/man-in-the-middle/README.md)
- [Port Scanning](01-network-security/port-scanning/README.md)
- DNS Spoofing *(planned)*

### 2. [Web Application Security](02-web-application-security/README.md)

- [SQL Injection](02-web-application-security/sql-injection/README.md)
- [Cross-Site Scripting (XSS)](02-web-application-security/xss-attacks/README.md), detection only
- Cross-Site Request Forgery (CSRF) *(planned)*
- Session Hijacking *(planned)*

### 3. [Malware Analysis](03-malware-analysis/README.md)

- [Ransomware](03-malware-analysis/ransomware/README.md)
- [Trojans](03-malware-analysis/trojans/README.md)
- [Rootkits](03-malware-analysis/rootkits/README.md)
- Keyloggers *(planned)*

### 4. [Social Engineering](04-social-engineering/README.md)

- [Phishing](04-social-engineering/phishing/README.md)
- [Pretexting](04-social-engineering/pretexting/README.md)
- Baiting *(planned)*
- Tailgating *(planned)*

### 5. [Cryptography](05-cryptography/README.md)

- Symmetric encryption (AES example)
- [Hashing and password hashing](05-cryptography/hashing/README.md)
- Asymmetric encryption *(planned)*
- Digital signatures *(planned)*
- Key management *(planned)*

### 6. [Incident Response](06-incident-response/README.md)

- [Digital forensics](06-incident-response/forensics/README.md)
- Containment and recovery scripts
- Post-incident analysis *(planned)*

## Getting started

### Prerequisites

- Python 3.10 or higher
- pip
- Basic understanding of networking and security concepts
- Administrative privileges for scripts that capture packets or inspect processes

### Installation

1. Clone the repository:

```bash
git clone https://github.com/s4ntrx/Cybersecurity-Threats-Guide.git
cd Cybersecurity-Threats-Guide
```

2. Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements.txt
```

3. Optional: memory forensics support (installs Volatility 3):

```bash
pip install -r tools/requirements-optional.txt
```

`tools/setup_tools.sh` checks your Python version and system tools if you prefer a guided setup.

## Usage

### Running detection scripts

```bash
cd 01-network-security/ddos-attacks/detection/
sudo python ddos_detection.py --interface eth0 --threshold 1000
```

Run `python <script>.py --help` to see the options for any script.

### Using prevention examples

```bash
cd 02-web-application-security/sql-injection/prevention/
python parameterized_queries.py
```

Or import the class directly:

```python
from parameterized_queries import SecureDatabaseQueries

db = SecureDatabaseQueries(db_type="sqlite", db_name="demo.db")
db.connect()
db.create_users_table()
user = db.get_user_secure("alice")
```

## Web app and API

- `cybersec-app/` is a Next.js site that presents the guide's content. Setup is in [cybersec-app/README.md](cybersec-app/README.md).
- `api/` is a small Flask API with health, tools, and scan endpoints. It is experimental: its HTML routes expect `templates/` and `static/` directories that are not in the repository yet.

## Roadmap

Gaps between earlier README promises and the repository today:

- Web: CSRF (docs, detection, prevention), session hijacking, XSS prevention and CSP analysis, SQL injection WAF rules
- Network: DNS spoofing
- Malware: keyloggers
- Social engineering: baiting, tailgating
- Cryptography: asymmetric encryption (RSA), digital signatures, key management, a README for the encryption section
- Incident response: post-incident analysis, a README for containment
- Root-level helper scripts and a `resources/` folder of links, books, and certifications

## Contributing

Contributions are welcome. Read the [Contributing Guidelines](CONTRIBUTING.md) first, then:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push the branch
5. Open a Pull Request

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

**IMPORTANT**: The code and information in this repository are for **educational and defensive purposes only**.

- Do not use these techniques against systems you do not own or have explicit permission to test
- Follow responsible disclosure practices
- The author is not responsible for misuse of this material
- Some scripts may trigger security alerts, so use them only in controlled environments
