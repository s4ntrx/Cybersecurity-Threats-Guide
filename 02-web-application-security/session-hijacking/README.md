# Session Hijacking and Fixation

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | Authentication Failures (session management) |
| MITRE ATT&CK (v19) | Credential Access / T1539 Steal Web Session Cookie |
| CWE | CWE-384 Session Fixation; CWE-613 Insufficient Session Expiration |
| CAPEC | CAPEC-593 Session Hijacking |
| Example CVE | not applicable |

## What it is

Session hijacking is taking over another user's authenticated session by stealing or guessing the session identifier. Session fixation is the reverse: the attacker plants a known identifier before the user logs in and reuses it afterwards.

## How it works

After login the site gives the browser a session id and trusts it on every request. Anyone who obtains that id (from network sniffing on plain HTTP, XSS reading `document.cookie`, malware, a leaked log, or a guessable id) can present it and act as the user. With fixation, the site keeps the id it was given before login, so the attacker already knows the post-login id.

## Real-world example

In October 2010 the Firesheep extension showed that anyone on shared Wi-Fi could hijack accounts on major sites that only encrypted the login page. The publicity pushed large sites to serve whole sessions over HTTPS.

## Detection

- Missing `Secure`, `HttpOnly` or `SameSite` cookie flags (`session_security_checker.py`)
- Low-entropy, short, repeated or sequential session ids
- The session id unchanged after login (fixation test)
- The same session id used from two different browsers or networks at nearly the same time

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Serve the whole site over HTTPS and send HSTS
2. Random 128-bit-plus ids from a CSPRNG; store only a hash server-side
3. Issue a new id at login and on privilege change; destroy the old one
4. `Secure; HttpOnly; SameSite` cookie attributes and the `__Host-` prefix
5. Idle and absolute timeouts; real logout that destroys the server-side session
6. Fix XSS: it is the most common way to read session cookies

## Scripts in this topic

- [session_security_checker.py](./detection/session_security_checker.py): cookie flags, id quality, optional fixation test
- [secure_session.py](./prevention/secure_session.py): session manager with rotation, timeouts and hashed storage

## Common mistakes

- Encrypting only the login page
- Binding a session to an IP address that changes on mobile networks without a fallback
- Using the user id or a timestamp as the session id
- Logging out only on the client by deleting the cookie

## Test it safely

Only test systems you own or have written permission to test. Practice against a deliberately vulnerable app such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), or a local test server you write yourself.

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1539](https://attack.mitre.org/techniques/T1539/)
- [CWE-384](https://cwe.mitre.org/data/definitions/384.html)
