# 🌐 Network Security

[Back to Main](../README.md)

## Overview
Network security involves protecting the usability, reliability, integrity, and safety of network infrastructure. This section covers various network-based threats, their detection methods, and prevention strategies.

## 📋 Categories Covered

1. [DDoS Attacks](./ddos-attacks/README.md)
2. [Man-in-the-Middle (MITM)](./man-in-the-middle/README.md)
3. [Port Scanning](./port-scanning/README.md)
4. [DNS Spoofing](./dns-spoofing/README.md)
5. ARP Poisoning *(planned)*

## 🛡️ Common Network Threats

| Threat | Description | Risk Level |
|--------|-------------|------------|
| DDoS | Overwhelming resources with traffic | High |
| MITM | Intercepting communication | Critical |
| Port Scanning | Reconnaissance for vulnerabilities | Medium |
| DNS Spoofing | Redirecting to malicious sites | High |
| ARP Poisoning | Manipulating network mappings | Critical |

## 🚀 Quick Start

```bash
# Navigate to specific threat directory
cd ddos-attacks/detection/

# Run detection scripts with appropriate permissions
sudo python3 ddos_detection.py --interface eth0

# Check prevention examples
cd ../prevention/
python3 rate_limiting.py --help
```

## 📊 Network Monitoring Tools
- Wireshark/TShark - Packet analysis

- Snort/Suricata - IDS/IPS

- ntopng - Network traffic monitoring

- Nagios - Infrastructure monitoring

## ⚠️ Important Notes
- Some scripts require root/administrator privileges

- Always test in isolated environments first

- Monitor performance impact of detection scripts

- Combine multiple detection methods for accuracy

## 📚 Additional Resources

- [OWASP Network Security](https://owasp.org/www-project-top-ten/)
- [CIS Network Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Network Security Guidelines](https://www.nist.gov/cyberframework)

