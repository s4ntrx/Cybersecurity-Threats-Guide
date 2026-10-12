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

```mermaid
flowchart TB

    ROOT(("⬡ CYBERSECURITY<br/>THREAT INTELLIGENCE"))

    %% SIX THREAT CLUSTERS
    ROOT <==> NET
    ROOT <==> WEB
    ROOT <==> MAL
    ROOT <==> SOCIAL
    ROOT <==> CRYPTO
    ROOT <==> IR

    NET(("01<br/>NETWORK<br/>SECURITY"))
    WEB(("02<br/>WEB APP<br/>SECURITY"))
    MAL(("03<br/>MALWARE<br/>ANALYSIS"))
    SOCIAL(("04<br/>SOCIAL<br/>ENGINEERING"))
    CRYPTO(("05<br/>CRYPTOGRAPHY"))
    IR(("06<br/>INCIDENT<br/>RESPONSE"))

    %% NETWORK CLUSTER
    NET --- DDOS["DDoS Attacks"]
    NET --- MITM["Man-in-the-Middle"]
    NET --- PORT["Port Scanning"]

    DDOS --- DD["Detection / Prevention"]
    MITM --- MD["Detection / Prevention"]
    PORT --- PD["Detection / Prevention"]

    %% WEB CLUSTER
    WEB --- SQL["SQL Injection"]
    WEB --- XSS["XSS Attacks"]

    SQL --- SD["Detection / Prevention"]
    XSS --- XD["Detection"]

    %% MALWARE CLUSTER
    MAL --- RANSOM["Ransomware"]
    MAL --- ROOTKIT["Rootkits"]
    MAL --- TROJAN["Trojans"]

    RANSOM --- RD["Detection / Prevention"]
    ROOTKIT --- RKD["Detection / Prevention"]
    TROJAN --- TD["Detection / Prevention"]

    %% SOCIAL ENGINEERING CLUSTER
    SOCIAL --- PHISH["Phishing"]
    SOCIAL --- PRETEXT["Pretexting"]

    PHISH --- PHD["Detection / Prevention"]
    PRETEXT --- PTD["Detection / Prevention"]

    %% CRYPTOGRAPHY CLUSTER
    CRYPTO --- ENC["Symmetric Encryption"]
    CRYPTO --- HASH["Hashing"]

    ENC --- AES["aes_example.py"]
    HASH --- HASHFILES["Integrity Checker<br/>Password Hashing"]

    %% INCIDENT RESPONSE CLUSTER
    IR --- CONT["Containment"]
    IR --- FORENSICS["Forensics"]

    CONT --- CONTFILES["Backup Recovery<br/>Isolation Script"]
    FORENSICS --- FORENSICFILES["Disk Forensics<br/>Memory Analyzer"]

    %% DEFENSE CAPABILITIES
    ROOT <--> DEFENSE(("DEFENSE<br/>LAYER"))

    DEFENSE --- DETECT["Threat Detection"]
    DEFENSE --- PREVENT["Threat Prevention"]
    DEFENSE --- RESPOND["Incident Handling"]

    %% PLATFORM
    ROOT <--> PLATFORM(("APPLICATION<br/>PLATFORM"))

    PLATFORM --- FRONTEND["Next.js<br/>cybersec-app/"]
    PLATFORM --- API["Flask API<br/>api/ · Experimental"]

    FRONTEND <-->|"API Requests"| API

    %% REPOSITORY SUPPORT
    ROOT -.-> SUPPORT(("PROJECT<br/>FOUNDATION"))

    SUPPORT --- DOCS["README.md<br/>CONTRIBUTING.md"]
    SUPPORT --- TEMPLATE["TOPIC_TEMPLATE.md"]
    SUPPORT --- LICENSE["LICENSE"]
    SUPPORT --- TOOLS["Development Tools<br/>Setup and Requirements"]

    %% STYLES
    classDef core fill:#020617,color:#67E8F9,stroke:#22D3EE,stroke-width:4px
    classDef domain fill:#172554,color:#DBEAFE,stroke:#60A5FA,stroke-width:3px
    classDef webdomain fill:#3B0764,color:#F3E8FF,stroke:#C084FC,stroke-width:3px
    classDef malwaredomain fill:#450A0A,color:#FEE2E2,stroke:#F87171,stroke-width:3px
    classDef socialdomain fill:#431407,color:#FFEDD5,stroke:#FB923C,stroke-width:3px
    classDef cryptodomain fill:#052E16,color:#DCFCE7,stroke:#4ADE80,stroke-width:3px
    classDef incidentdomain fill:#422006,color:#FEF9C3,stroke:#FACC15,stroke-width:3px
    classDef leaf fill:#111827,color:#E5E7EB,stroke:#64748B,stroke-width:1px
    classDef defense fill:#083344,color:#A5F3FC,stroke:#06B6D4,stroke-width:3px
    classDef platform fill:#312E81,color:#E0E7FF,stroke:#818CF8,stroke-width:3px
    classDef support fill:#27272A,color:#FAFAFA,stroke:#A1A1AA,stroke-width:2px

    class ROOT core
    class NET domain
    class WEB webdomain
    class MAL malwaredomain
    class SOCIAL socialdomain
    class CRYPTO cryptodomain
    class IR incidentdomain
    class DDOS,MITM,PORT,DD,MD,PD,SQL,XSS,SD,XD,RANSOM,ROOTKIT,TROJAN,RD,RKD,TD,PHISH,PRETEXT,PHD,PTD,ENC,HASH,AES,HASHFILES,CONT,FORENSICS,CONTFILES,FORENSICFILES leaf
    class DEFENSE,DETECT,PREVENT,RESPOND defense
    class PLATFORM,FRONTEND,API platform
    class SUPPORT,DOCS,TEMPLATE,LICENSE,TOOLS support

    linkStyle default stroke:#64748B,stroke-width:1.5px
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
