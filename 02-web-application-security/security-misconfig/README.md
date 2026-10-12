# Security Misconfiguration

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | A02:2025 Security Misconfiguration |
| MITRE ATT&CK (v19) | Initial Access / T1190 Exploit Public-Facing Application |
| CWE | CWE-16 Configuration |
| CAPEC | not applicable |
| Example CVE | not applicable |

## What it is

Security misconfiguration is any insecure setting that the software allows: default credentials, unnecessary services, verbose errors, exposed admin panels or files, missing security headers, over-permissive cloud storage or firewall rules.

## How it works

Modern stacks have hundreds of settings and insecure defaults. A single forgotten `.git` folder, `.env` file or open storage bucket can expose source code, credentials or customer data without any exploit being needed.

## Real-world example

In 2019 Capital One disclosed a breach in which a misconfigured web application firewall let an attacker make the server request cloud metadata and obtain credentials, which were then used to copy data from storage. The details are in the US Department of Justice's public indictment of the attacker.

## Detection

- Missing or weak security headers (`security_headers_checker.py` grades them A to F)
- Exposed `.git`, `.env`, backup and status files, confirmed by response content rather than HTTP 200 alone
- Version numbers in `Server` and `X-Powered-By`
- Directory listings and verbose error pages

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Harden from a baseline (CIS Benchmarks) and apply it through code, not by hand
2. Remove unused features, sample apps and default accounts
3. Deploy only the files the site needs; keep secrets out of the web root and out of git
4. Send HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy` and clickjacking protection
5. Scan configuration continuously and on every deploy

## Scripts in this topic

- [security_headers_checker.py](./detection/security_headers_checker.py): headers, version leaks, exposed files, grade

## Common mistakes

- Treating headers as a checklist without a working CSP
- Trusting HTTP 200 as proof a path exists (many sites answer 200 to everything)
- Hardening production but leaving staging and test servers open

## Test it safely

Only test systems you own or have written permission to test. Practice against a deliberately vulnerable app such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), or a local test server you write yourself.

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
