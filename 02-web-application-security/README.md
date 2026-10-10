# 🌐 Web Application Security

[Back to Main](../README.md)

## Overview
Web application security focuses on securing websites, web applications, and web services from various cyber threats. This section covers common web vulnerabilities, their detection methods, and prevention strategies.

## 📋 Categories Covered

1. [SQL Injection](./sql-injection/README.md)
2. [Cross-Site Scripting (XSS)](./xss-attacks/README.md)
3. Cross-Site Request Forgery (CSRF) *(planned)*
4. Session Hijacking *(planned)*
5. File Inclusion Vulnerabilities *(planned)*
6. Security Misconfiguration *(planned)*

## OWASP Top 10:2025

The current list, published by OWASP in late 2025. Categories that map to a topic in this repository are linked.

| Rank | Category | What it covers |
|------|----------|----------------|
| A01 | Broken Access Control | Users act outside their permissions; now also includes server-side request forgery (SSRF) |
| A02 | Security Misconfiguration | Insecure defaults, unnecessary features, exposed admin interfaces |
| A03 | Software Supply Chain Failures | Compromised dependencies, build systems and distribution channels |
| A04 | Cryptographic Failures | Weak or missing encryption, exposed sensitive data |
| A05 | [Injection](./sql-injection/README.md) | SQL, NoSQL, OS command injection and cross-site scripting |
| A06 | Insecure Design | Missing security controls at the design stage |
| A07 | Authentication Failures | Weak login, session and credential handling |
| A08 | Software or Data Integrity Failures | Unverified updates, plugins and CI/CD pipeline changes |
| A09 | Security Logging and Alerting Failures | Missing logs and alerts, so attacks go unnoticed |
| A10 | Mishandling of Exceptional Conditions | Errors and failures handled in ways that expose data or break security checks |

Source: [owasp.org/Top10/2025](https://owasp.org/Top10/2025/). Last reviewed 2026-10-10. Earlier versions of this page showed the 2021 list.

## 🚀 Quick Start

```bash
# Navigate to specific vulnerability directory
cd sql-injection/detection/

# Run vulnerability scanner
python3 sql_injection_detector.py -u http://testphp.vulnweb.com/artists.php

# Check prevention examples
cd ../prevention/
python3 parameterized_queries.py
```
## 🔧 Web Security Testing Tools

### 🔍 Automated Scanners

- **[OWASP ZAP](https://www.zaproxy.org/)** – Open source web application security scanner  
- **[Burp Suite](https://portswigger.net/burp)** – Web vulnerability scanner and testing platform  
- **[Nuclei](https://nuclei.projectdiscovery.io/)** – Fast template-based vulnerability scanner  
- **[Arachni](http://www.arachni-scanner.com/)** – Feature-rich web application security scanner  

---

### 🛠 Manual Testing Tools

- **[cURL](https://curl.se/)** – Command-line tool for making HTTP requests  
- **[Postman](https://www.postman.com/)** – API development and testing platform  
- **[Wireshark](https://www.wireshark.org/)** – Network protocol analyzer and traffic analysis tool  
- **Browser DevTools** – Built-in browser tools for client-side debugging (Chrome, Firefox, Edge)

## 📊 Security Testing Methodology
```text
Reconnaissance → Scanning → Vulnerability Assessment → Exploitation (Ethical) → Reporting → Remediation
```

## 💡 Best Practices

### 🧑‍💻 Development Phase

- **Secure Coding** – Follow OWASP secure coding guidelines  
- **Input Validation** – Validate all user inputs  
- **Output Encoding** – Prevent XSS attacks  
- **Parameterized Queries** – Prevent SQL injection  
- **CSRF Tokens** – Protect state-changing operations  

---

### 🚀 Deployment Phase

- **Security Headers** – Implement CSP, HSTS, X-Frame-Options  
- **HTTPS Everywhere** – Encrypt all traffic  
- **Least Privilege** – Grant minimal required permissions  
- **Regular Updates** – Apply patches and updates consistently  
- **Web Application Firewall (WAF)** – Deploy WAF protection  

---

### 🔄 Maintenance Phase

- **Regular Scanning** – Perform automated vulnerability scans  
- **Penetration Testing** – Conduct manual security testing  
- **Bug Bounty Program** – Enable crowdsourced security testing  
- **Security Training** – Provide ongoing developer education  
- **Incident Response** – Prepare and test breach response plans  

---

## ⚠️ Important Notes

- Always obtain proper authorization before testing  
- Use isolated testing environments  
- Document all findings responsibly  
- Follow responsible disclosure practices  
- Some tools may trigger security alerts  

---

## 📚 Additional Resources

- [OWASP Web Security](https://owasp.org/)  
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)  
- [CWE Top 25](https://cwe.mitre.org/top25/)  
- [PortSwigger Research](https://portswigger.net/research)  
- [Google Web Security](https://web.dev/secure/)  

---

## 🎓 Learning Platforms

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)  
- [DVWA – Damn Vulnerable Web Application](https://dvwa.co.uk/)  
- [Hack The Box](https://www.hackthebox.com/)  
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)  
- [PentesterLab](https://pentesterlab.com/)

