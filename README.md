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

    %% ==========================================
    %% CYBERSECURITY COMMAND CENTER
    %% ==========================================

    START(["◈ CYBERSECURITY THREATS GUIDE<br/>THREAT INTELLIGENCE COMMAND CENTER"])

    START --> CONTROL

    CONTROL{{"CENTRAL SECURITY HUB<br/>Monitor · Investigate · Defend"}}

    %% THREAT INTELLIGENCE DIVISIONS
    subgraph THREAT_GRID["01 / THREAT INTELLIGENCE DIVISIONS"]
        direction LR

        subgraph G1["NETWORK OPERATIONS"]
            direction TB
            N1["01 · Network Security"]
            N2["DDoS Attacks"]
            N3["Man-in-the-Middle"]
            N4["Port Scanning"]
            N1 --> N2
            N1 --> N3
            N1 --> N4
        end

        subgraph G2["APPLICATION DEFENSE"]
            direction TB
            W1["02 · Web Security"]
            W2["SQL Injection"]
            W3["XSS Attacks"]
            W1 --> W2
            W1 --> W3
        end

        subgraph G3["MALWARE INTELLIGENCE"]
            direction TB
            M1["03 · Malware Analysis"]
            M2["Ransomware"]
            M3["Rootkits"]
            M4["Trojans"]
            M1 --> M2
            M1 --> M3
            M1 --> M4
        end

        subgraph G4["HUMAN THREAT ANALYSIS"]
            direction TB
            S1["04 · Social Engineering"]
            S2["Phishing"]
            S3["Pretexting"]
            S1 --> S2
            S1 --> S3
        end

        subgraph G5["CRYPTOGRAPHIC SERVICES"]
            direction TB
            C1["05 · Cryptography"]
            C2["Symmetric Encryption"]
            C3["Hashing"]
            C1 --> C2
            C1 --> C3
        end

        subgraph G6["INCIDENT COMMAND"]
            direction TB
            I1["06 · Incident Response"]
            I2["Containment"]
            I3["Forensics"]
            I1 --> I2
            I1 --> I3
        end
    end

    CONTROL ==> THREAT_GRID

    %% SECURITY OPERATIONS PIPELINE
    subgraph SOC["02 / SECURITY OPERATIONS PIPELINE"]
        direction LR
        D["01<br/>DETECT"]
        A["02<br/>ANALYZE"]
        P["03<br/>PREVENT"]
        R["04<br/>RESPOND"]
        L["05<br/>LEARN"]

        D ==> A
        A ==> P
        P ==> R
        R ==> L
        L -.-> D
    end

    THREAT_GRID ==> SOC

    %% APPLICATION INFRASTRUCTURE
    subgraph PLATFORM["03 / APPLICATION & ENGINEERING PLATFORM"]
        direction LR

        subgraph FRONTEND["PRESENTATION"]
            F1["Next.js Website"]
            F2["cybersec-app/"]
            F1 --- F2
        end

        subgraph BACKEND["SERVICE LAYER"]
            B1["Flask API"]
            B2["api/ · Experimental"]
            B1 --- B2
        end

        subgraph ENGINEERING["ENGINEERING TOOLKIT"]
            E1["setup_tools.sh"]
            E2["requirements.txt"]
            E3["requirements-optional.txt"]
        end

        FRONTEND <-->|"HTTP / API"| BACKEND
    end

    SOC ==> PLATFORM

    %% KNOWLEDGE AND GOVERNANCE
    subgraph GOVERNANCE["04 / KNOWLEDGE & GOVERNANCE"]
        direction LR
        DOC1["README.md"]
        DOC2["CONTRIBUTING.md"]
        DOC3["TOPIC_TEMPLATE.md"]
        DOC4["LICENSE"]
    end

    PLATFORM --- GOVERNANCE

    %% VISUAL DESIGN
    classDef command fill:#101827,color:#67E8F9,stroke:#22D3EE,stroke-width:4px
    classDef network fill:#172554,color:#DBEAFE,stroke:#3B82F6,stroke-width:2px
    classDef application fill:#3B0764,color:#F3E8FF,stroke:#A855F7,stroke-width:2px
    classDef malware fill:#450A0A,color:#FEE2E2,stroke:#EF4444,stroke-width:2px
    classDef social fill:#431407,color:#FFEDD5,stroke:#F97316,stroke-width:2px
    classDef crypto fill:#052E16,color:#DCFCE7,stroke:#22C55E,stroke-width:2px
    classDef incident fill:#422006,color:#FEF9C3,stroke:#EAB308,stroke-width:2px
    classDef pipeline fill:#1E293B,color:#BAE6FD,stroke:#38BDF8,stroke-width:2px
    classDef infrastructure fill:#27272A,color:#FAFAFA,stroke:#A1A1AA,stroke-width:1px

    class START,CONTROL command
    class N1,N2,N3,N4 network
    class W1,W2,W3 application
    class M1,M2,M3,M4 malware
    class S1,S2,S3 social
    class C1,C2,C3 crypto
    class I1,I2,I3 incident
    class D,A,P,R,L pipeline
    class F1,F2,B1,B2,E1,E2,E3,DOC1,DOC2,DOC3,DOC4 infrastructure

    style THREAT_GRID fill:#0B1220,stroke:#334155,stroke-width:2px
    style SOC fill:#0F172A,stroke:#38BDF8,stroke-width:2px
    style PLATFORM fill:#111827,stroke:#A78BFA,stroke-width:2px
    style GOVERNANCE fill:#18181B,stroke:#71717A,stroke-width:2px
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
