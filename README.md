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
├── TOPIC_TEMPLATE.md
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
│   ├── dns-spoofing/
│   │   ├── detection/
│   │   │   └── dns_spoof_detector.py
│   │   ├── prevention/
│   │   │   └── dnssec_check.py
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
│   │   │   ├── port_scan_detector.py
│   │   │   └── scan_alerts.json
│   │   ├── prevention/
│   │   │   ├── firewall_config.py
│   │   │   └── stealth_mode.py
│   │   └── README.md
│   └── README.md
│
├── 02-web-application-security/
│   ├── csrf/
│   │   ├── detection/
│   │   │   └── csrf_detector.py
│   │   ├── prevention/
│   │   │   └── csrf_protection.py
│   │   └── README.md
│   ├── file-inclusion/
│   │   ├── detection/
│   │   │   └── lfi_detector.py
│   │   ├── prevention/
│   │   │   └── safe_file_access.py
│   │   └── README.md
│   ├── security-misconfig/
│   │   ├── detection/
│   │   │   └── security_headers_checker.py
│   │   └── README.md
│   ├── session-hijacking/
│   │   ├── detection/
│   │   │   └── session_security_checker.py
│   │   ├── prevention/
│   │   │   └── secure_session.py
│   │   └── README.md
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
│   │   ├── prevention/
│   │   │   ├── csp_analyzer.py
│   │   │   └── output_encoding.py
│   │   └── README.md
│   └── README.md
│
├── 03-malware-analysis/
│   ├── keyloggers/
│   │   ├── detection/
│   │   │   └── keylogger_detector.py
│   │   └── README.md
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
│   │   │   ├── rootkit_detector.log
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
│   ├── baiting/
│   │   ├── detection/
│   │   │   └── usb_bait_scanner.py
│   │   └── README.md
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
│   ├── tailgating/
│   │   ├── detection/
│   │   │   ├── sample_access_log.csv
│   │   │   └── tailgating_log_analyzer.py
│   │   └── README.md
│   └── README.md
│
├── 05-cryptography/
│   ├── digital-signatures/
│   │   ├── README.md
│   │   └── file_signer.py
│   ├── encryption/
│   │   ├── asymmetric/
│   │   │   ├── README.md
│   │   │   └── rsa_example.py
│   │   └── symmetric/
│   │       └── aes_example.py
│   ├── hashing/
│   │   ├── README.md
│   │   ├── integrity_checker.py
│   │   └── password_hashing.py
│   ├── key-management/
│   │   ├── README.md
│   │   └── key_manager.py
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
│   ├── post-incident/
│   │   ├── README.md
│   │   ├── post_incident_report.py
│   │   └── sample_incident.json
│   └── README.md
│
├── tests/               # pytest suite for the scripts
├── api/                 # Flask API (experimental, see "Web app and API")
├── cybersec-app/        # Next.js site (see cybersec-app/README.md)
└── tools/
    ├── requirements-optional.txt
    ├── requirements.txt
    └── setup_tools.sh
```

## Categories

Topics marked *planned* do not have content yet.

### 1. [Network Security](01-network-security/README.md)

- [DDoS Attacks](01-network-security/ddos-attacks/README.md)
- [Man-in-the-Middle](01-network-security/man-in-the-middle/README.md)
- [Port Scanning](01-network-security/port-scanning/README.md)
- [DNS Spoofing](01-network-security/dns-spoofing/README.md)

### 2. [Web Application Security](02-web-application-security/README.md)

- [SQL Injection](02-web-application-security/sql-injection/README.md)
- [Cross-Site Scripting (XSS)](02-web-application-security/xss-attacks/README.md)
- [Cross-Site Request Forgery (CSRF)](02-web-application-security/csrf/README.md)
- [Session Hijacking](02-web-application-security/session-hijacking/README.md)
- [File Inclusion and Path Traversal](02-web-application-security/file-inclusion/README.md)
- [Security Misconfiguration](02-web-application-security/security-misconfig/README.md)

### 3. [Malware Analysis](03-malware-analysis/README.md)

- [Ransomware](03-malware-analysis/ransomware/README.md)
- [Trojans](03-malware-analysis/trojans/README.md)
- [Rootkits](03-malware-analysis/rootkits/README.md)
- [Keyloggers](03-malware-analysis/keyloggers/README.md) (detection only)

### 4. [Social Engineering](04-social-engineering/README.md)

- [Phishing](04-social-engineering/phishing/README.md)
- [Pretexting](04-social-engineering/pretexting/README.md)
- [Baiting](04-social-engineering/baiting/README.md)
- [Tailgating](04-social-engineering/tailgating/README.md)

### 5. [Cryptography](05-cryptography/README.md)

- Symmetric encryption (hybrid AES example)
- [Asymmetric encryption (RSA)](05-cryptography/encryption/asymmetric/README.md)
- [Hashing and password hashing](05-cryptography/hashing/README.md)
- [Digital signatures](05-cryptography/digital-signatures/README.md)
- [Key management](05-cryptography/key-management/README.md)

### 6. [Incident Response](06-incident-response/README.md)

- [Digital forensics](06-incident-response/forensics/README.md)
- Containment and recovery scripts
- [Post-incident analysis](06-incident-response/post-incident/README.md)

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

Some scripts also need system software: `tshark` (Wireshark) for `traffic_analyzer.py` and a running Redis server for `rate_limiting.py`. Registry checks in the ransomware detector only run on Windows.

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

Remaining gaps:

- New topics were added in October 2026 and are marked Draft: their references still need an independent review, and several "Real-world example" sections need a primary source added
- Apply the [topic template](TOPIC_TEMPLATE.md) (standards mapping and review date) to the older topics: ransomware, trojans, rootkits, phishing, pretexting, DDoS, MITM, port scanning, forensics
- SQL injection WAF rules; a README for the containment scripts and for symmetric encryption
- Topics listed as planned in the category pages: ARP poisoning page, worms, botnets, quid pro quo, vishing, smishing
- A `resources/` folder of links, books, and certifications
- Test the scripts that change system state (firewall, isolation, sandbox, kernel hardening, secure boot, antivirus configuration) in a disposable virtual machine; they have only been reviewed by reading the code

## Contributing

Contributions are welcome. Read the [Contributing Guidelines](CONTRIBUTING.md) first, and start new topics from [TOPIC_TEMPLATE.md](TOPIC_TEMPLATE.md). Then:

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
