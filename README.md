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

    ROOT["CYBERSECURITY THREATS GUIDE"]

    ROOT --> CORE
    ROOT --> PLATFORM
    ROOT --> DEVTOOLS

    subgraph CORE["CYBERSECURITY KNOWLEDGE BASE"]
        direction TB

        NET["01. Network Security"]
        WEB["02. Web Application Security"]
        MAL["03. Malware Analysis"]
        SOC["04. Social Engineering"]
        CRYPTO["05. Cryptography"]
        IR["06. Incident Response"]

        NET --> DDOS["DDoS Attacks"]
        NET --> MITM["Man-in-the-Middle"]
        NET --> PORT["Port Scanning"]

        WEB --> SQL["SQL Injection"]
        WEB --> XSS["XSS Attacks"]

        MAL --> RANSOM["Ransomware"]
        MAL --> ROOTKIT["Rootkits"]
        MAL --> TROJAN["Trojans"]

        SOC --> PHISH["Phishing"]
        SOC --> PRETEXT["Pretexting"]

        CRYPTO --> ENC["Encryption"]
        CRYPTO --> HASH["Hashing"]

        IR --> CONT["Containment"]
        IR --> FORENSICS["Forensics"]
    end

    subgraph SECURITY_WORKFLOW["SECURITY ANALYSIS WORKFLOW"]
        direction LR
        DETECT["Threat Detection"]
        ANALYZE["Analysis"]
        PREVENT["Threat Prevention"]
        DOCUMENT["Documentation"]

        DETECT --> ANALYZE
        ANALYZE --> PREVENT
        PREVENT --> DOCUMENT
    end

    DDOS -.-> DETECT
    MITM -.-> DETECT
    PORT -.-> DETECT
    SQL -.-> DETECT
    XSS -.-> DETECT
    RANSOM -.-> DETECT
    ROOTKIT -.-> DETECT
    TROJAN -.-> DETECT
    PHISH -.-> DETECT
    PRETEXT -.-> DETECT

    subgraph PLATFORM["APPLICATION PLATFORM"]
        direction TB

        FRONTEND["cybersec-app/"]
        NEXT["Next.js Frontend"]

        BACKEND["api/"]
        FLASK["Flask API - Experimental"]

        FRONTEND --> NEXT
        BACKEND --> FLASK

        NEXT <-->|"HTTP / API Requests"| FLASK
    end

    subgraph DEVTOOLS["PROJECT CONFIGURATION AND TOOLS"]
        direction TB

        SETUP["setup_tools.sh"]
        REQ["requirements.txt"]
        OPT["requirements-optional.txt"]

        DOCS["README.md"]
        LICENSE["LICENSE"]
        CONTRIB["CONTRIBUTING.md"]
        TEMPLATE["TOPIC_TEMPLATE.md"]
    end

    ROOT --> DOCS

    classDef rootStyle fill:#15365C,color:#FFFFFF,stroke:#0B1F38,stroke-width:3px
    classDef domainStyle fill:#D9EAF7,color:#15365C,stroke:#4682B4,stroke-width:2px
    classDef topicStyle fill:#E2F0D9,color:#21511A,stroke:#70AD47,stroke-width:1px
    classDef workflowStyle fill:#FFF2CC,color:#7F6000,stroke:#D6B656,stroke-width:2px
    classDef platformStyle fill:#E4DFEC,color:#403152,stroke:#8064A2,stroke-width:2px
    classDef toolStyle fill:#FCE4D6,color:#843C0C,stroke:#C65911,stroke-width:1px

    class ROOT rootStyle
    class NET,WEB,MAL,SOC,CRYPTO,IR domainStyle
    class DDOS,MITM,PORT,SQL,XSS,RANSOM,ROOTKIT,TROJAN,PHISH,PRETEXT,ENC,HASH,CONT,FORENSICS topicStyle
    class DETECT,ANALYZE,PREVENT,DOCUMENT workflowStyle
    class FRONTEND,NEXT,BACKEND,FLASK platformStyle
    class SETUP,REQ,OPT,DOCS,LICENSE,CONTRIB,TEMPLATE toolStyle
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
