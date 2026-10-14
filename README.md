# Cybersecurity Threats & Vulnerabilities Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

<a href="https://paystack.shop/pay/bxg5kd2ghg">
  <img src="https://img.shields.io/badge/%E2%9D%A4%20Support%20my%20work-Paystack-00C3A0?style=flat&labelColor=202B2A"
       alt="Support my work via Paystack"
       height="28"
       style="border-radius: 18px;">

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
    ROOT["cybersecurity-threats-guide/"]

    ROOT --> DOCS
    ROOT --> NETWORK
    ROOT --> WEBSEC
    ROOT --> MALWARE
    ROOT --> SOCIAL
    ROOT --> CRYPTO
    ROOT --> INCIDENT
    ROOT --> APPLICATIONS
    ROOT --> TOOLING

    subgraph DOCS["Project Documentation"]
        direction TB
        README["README.md"]
        LICENSE["LICENSE"]
        CONTRIBUTING["CONTRIBUTING.md"]
        TEMPLATE["TOPIC_TEMPLATE.md"]
    end

    subgraph NETWORK["01 - Network Security"]
        direction TB

        subgraph DDOS["DDoS Attacks"]
            direction LR
            DDOS_DET["Detection"]
            DDOS_PREV["Prevention"]
            DDOS_DET --> DDOS1["ddos_detection.py"]
            DDOS_DET --> DDOS2["traffic_analyzer.py"]
            DDOS_PREV --> DDOS3["firewall_rules.txt"]
            DDOS_PREV --> DDOS4["rate_limiting.py"]
            DDOS_README["README.md"]
        end

        subgraph MITM["Man-in-the-Middle"]
            direction LR
            MITM_DET["Detection"]
            MITM_PREV["Prevention"]
            MITM_DET --> MITM1["arp_spoof_detector.py"]
            MITM_DET --> MITM2["ssl_strip_detector.py"]
            MITM_PREV --> MITM3["certificate_pinning.py"]
            MITM_PREV --> MITM4["ssl_tls_config.py"]
            MITM_README["README.md"]
        end

        subgraph PORTSCAN["Port Scanning"]
            direction LR
            PORT_DET["Detection"]
            PORT_PREV["Prevention"]
            PORT_DET --> PORT1["ids_rules.txt"]
            PORT_DET --> PORT2["port_scan_detector.py"]
            PORT_PREV --> PORT3["firewall_config.py"]
            PORT_PREV --> PORT4["stealth_mode.py"]
            PORT_README["README.md"]
        end

        NETWORK_README["README.md"]
    end

    subgraph WEBSEC["02 - Web Application Security"]
        direction TB

        subgraph SQL["SQL Injection"]
            direction LR
            SQL_DET["Detection"]
            SQL_PREV["Prevention"]
            SQL_DET --> SQL1["sql_injection_detector.py"]
            SQL_DET --> SQL2["sql_injection_scanner.py"]
            SQL_PREV --> SQL3["input_validation.py"]
            SQL_PREV --> SQL4["parameterized_queries.py"]
            SQL_README["README.md"]
        end

        subgraph XSS["XSS Attacks"]
            direction LR
            XSS_DET["Detection"]
            XSS_DET --> XSS1["xss_detector.py"]
            XSS_README["README.md"]
        end

        WEBSEC_README["README.md"]
    end

    subgraph MALWARE["03 - Malware Analysis"]
        direction TB

        subgraph RANSOM["Ransomware"]
            direction LR
            RANSOM_DET["Detection"]
            RANSOM_PREV["Prevention"]
            RANSOM_DET --> RANSOM1["file_monitor.py"]
            RANSOM_DET --> RANSOM2["ransomware_behavior.py"]
            RANSOM_PREV --> RANSOM3["app_whitelisting.py"]
            RANSOM_PREV --> RANSOM4["backup_system.py"]
            RANSOM_README["README.md"]
        end

        subgraph ROOTKITS["Rootkits"]
            direction LR
            ROOTKIT_DET["Detection"]
            ROOTKIT_PREV["Prevention"]
            ROOTKIT_DET --> ROOTKIT1["integrity_checker.py"]
            ROOTKIT_DET --> ROOTKIT2["rootkit_detector.py"]
            ROOTKIT_PREV --> ROOTKIT3["kernel_patching.py"]
            ROOTKIT_PREV --> ROOTKIT4["secure_boot.py"]
            ROOTKIT_README["README.md"]
        end

        subgraph TROJANS["Trojans"]
            direction LR
            TROJAN_DET["Detection"]
            TROJAN_PREV["Prevention"]
            TROJAN_DET --> TROJAN1["process_analyzer.py"]
            TROJAN_DET --> TROJAN2["trojan_scanner.py"]
            TROJAN_PREV --> TROJAN3["av_config.py"]
            TROJAN_PREV --> TROJAN4["sandbox_setup.py"]
            TROJAN_README["README.md"]
        end

        MALWARE_README["README.md"]
    end

    subgraph SOCIAL["04 - Social Engineering"]
        direction TB

        subgraph PHISHING["Phishing"]
            direction LR
            PHISH_DET["Detection"]
            PHISH_PREV["Prevention"]
            PHISH_DET --> PHISH1["email_analyzer.py"]
            PHISH_DET --> PHISH2["phishing_detector.py"]
            PHISH_PREV --> PHISH3["email_filters.py"]
            PHISH_PREV --> PHISH4["training_materials.md"]
            PHISH_README["README.md"]
        end

        subgraph PRETEXTING["Pretexting"]
            direction LR
            PRETEXT_DET["Detection"]
            PRETEXT_PREV["Prevention"]
            PRETEXT_DET --> PRETEXT1["social_engineering_detector.py"]
            PRETEXT_PREV --> PRETEXT2["security_policy.md"]
            PRETEXT_README["README.md"]
        end

        SOCIAL_README["README.md"]
    end

    subgraph CRYPTO["05 - Cryptography"]
        direction TB

        subgraph ENCRYPTION["Encryption"]
            direction LR
            SYMMETRIC["Symmetric Encryption"]
            SYMMETRIC --> AES["aes_example.py"]
        end

        subgraph HASHING["Hashing"]
            direction LR
            HASH_README["README.md"]
            HASH1["integrity_checker.py"]
            HASH2["password_hashing.py"]
        end

        CRYPTO_README["README.md"]
    end

    subgraph INCIDENT["06 - Incident Response"]
        direction TB

        subgraph CONTAINMENT["Containment"]
            direction LR
            CONTAIN1["backup_recovery.py"]
            CONTAIN2["isolation_script.py"]
        end

        subgraph FORENSICS["Forensics"]
            direction LR
            FORENSICS_README["README.md"]
            FORENSICS1["disk_forensics.py"]
            FORENSICS2["memory_analyzer.py"]
        end

        INCIDENT_README["README.md"]
    end

    subgraph APPLICATIONS["Applications"]
        direction TB
        API["api/"]
        API_DESC["Flask API - Experimental"]
        API --> API_DESC

        NEXTJS["cybersec-app/"]
        NEXTJS_DESC["Next.js Website"]
        NEXTJS_README["README.md"]
        NEXTJS --> NEXTJS_DESC
        NEXTJS --> NEXTJS_README
    end

    subgraph TOOLING["Development Tools"]
        direction TB
        SETUP["setup_tools.sh"]
        REQUIREMENTS["requirements.txt"]
        OPTIONAL["requirements-optional.txt"]
    end

    classDef rootStyle fill:#15365C,color:#FFFFFF,stroke:#0B1F38,stroke-width:3px
    classDef sectionStyle fill:#D9EAF7,color:#15365C,stroke:#4682B4,stroke-width:2px
    classDef topicStyle fill:#E2F0D9,color:#215E21,stroke:#70AD47,stroke-width:1px
    classDef moduleStyle fill:#FFF2CC,color:#7F6000,stroke:#D6B656,stroke-width:1px
    classDef fileStyle fill:#FFFFFF,color:#333333,stroke:#999999,stroke-width:1px
    classDef supportStyle fill:#E4DFEC,color:#403152,stroke:#8064A2,stroke-width:2px

    class ROOT rootStyle
    class DOCS,NETWORK,WEBSEC,MALWARE,SOCIAL,CRYPTO,INCIDENT,APPLICATIONS,TOOLING sectionStyle
    class DDOS,MITM,PORTSCAN,SQL,XSS,RANSOM,ROOTKITS,TROJANS,PHISHING,PRETEXTING,ENCRYPTION,HASHING,CONTAINMENT,FORENSICS topicStyle
    class DDOS_DET,DDOS_PREV,MITM_DET,MITM_PREV,PORT_DET,PORT_PREV,SQL_DET,SQL_PREV,XSS_DET,RANSOM_DET,RANSOM_PREV,ROOTKIT_DET,ROOTKIT_PREV,TROJAN_DET,TROJAN_PREV,PHISH_DET,PHISH_PREV,PRETEXT_DET,PRETEXT_PREV,SYMMETRIC moduleStyle
    class README,LICENSE,CONTRIBUTING,TEMPLATE,DDOS1,DDOS2,DDOS3,DDOS4,DDOS_README,MITM1,MITM2,MITM3,MITM4,MITM_README,PORT1,PORT2,PORT3,PORT4,PORT_README,NETWORK_README,SQL1,SQL2,SQL3,SQL4,SQL_README,XSS1,XSS_README,WEBSEC_README,RANSOM1,RANSOM2,RANSOM3,RANSOM4,RANSOM_README,ROOTKIT1,ROOTKIT2,ROOTKIT3,ROOTKIT4,ROOTKIT_README,TROJAN1,TROJAN2,TROJAN3,TROJAN4,TROJAN_README,MALWARE_README,PHISH1,PHISH2,PHISH3,PHISH4,PHISH_README,PRETEXT1,PRETEXT2,PRETEXT_README,SOCIAL_README,AES,HASH_README,HASH1,HASH2,CRYPTO_README,CONTAIN1,CONTAIN2,FORENSICS_README,FORENSICS1,FORENSICS2,INCIDENT_README,API_DESC,NEXTJS_DESC,NEXTJS_README,SETUP,REQUIREMENTS,OPTIONAL fileStyle
    class API,NEXTJS supportStyle
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

## 💚 Support My Open-Source Work

If my projects help you, consider supporting my work. Your contribution helps me maintain existing projects and build more tools for the developer community.

[![Support my open-source work](https://img.shields.io/badge/Support%20my%20open--source%20work-Paystack-00C3A0?style=for-the-badge&logo=paystack&logoColor=white)](https://paystack.shop/pay/bxg5kd2ghg)
