# File Inclusion and Path Traversal

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | Broken Access Control (path traversal); Injection family (remote file inclusion) |
| MITRE ATT&CK (v19) | Initial Access / T1190 Exploit Public-Facing Application |
| CWE | CWE-22 Path Traversal; CWE-98 PHP Remote File Inclusion |
| CAPEC | CAPEC-126 Path Traversal |
| Example CVE | not applicable |

## What it is

File inclusion bugs let a user control which file the server reads or executes. Local file inclusion (LFI) and path traversal expose files such as configuration and password files; remote file inclusion (RFI) can make the server run an attacker's code.

## How it works

The application builds a path from a request value (`?page=report.txt`). If it does not confine the result to one folder, input such as `../../etc/passwd` walks out of that folder. Encodings (`..%2f`, `....//`, backslashes) get past filters that only look for `../`. In languages whose include statement accepts URLs, a remote address can be loaded and executed.

## Real-world example

No single incident is cited here yet. Contributors: add one with a primary source. Path traversal is among the most frequently reported weakness classes in the NVD.

## Detection

- Responses containing `root:x:0:0:` or `[extensions]` after a traversal payload (`lfi_detector.py` checks for exactly these signatures)
- Web logs with `..`, `%2e%2e`, `....//` or absolute system paths in parameters
- Unexpected file reads by the web server user (file-integrity and auditd rules)

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Do not build paths from user input: map a short key to a fixed file (`allowlist_lookup`)
2. If a name is unavoidable, resolve the real path and require it to stay inside the base directory (`safe_join`)
3. Allow only expected file extensions; reject null bytes and absolute paths
4. Disable remote includes (`allow_url_include=Off` in PHP) and run the web server with least privilege
5. Keep sensitive files outside the web root

## Scripts in this topic

- [lfi_detector.py](./detection/lfi_detector.py): read-only traversal probes
- [safe_file_access.py](./prevention/safe_file_access.py): allow-list lookup and `safe_join`

## Common mistakes

- Blocking the text `../` (trivially bypassed by encoding)
- Checking the path before decoding it
- Forgetting symlinks inside the base directory
- Validating the extension before resolving the path

## Test it safely

Only test systems you own or have written permission to test. Practice against a deliberately vulnerable app such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), or a local test server you write yourself. The detector sends only read-only local probes and never a remote URL.

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-98](https://cwe.mitre.org/data/definitions/98.html)
