# Cross-Site Request Forgery (CSRF)

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | Broken Access Control family (CSRF was grouped there in 2021; confirm in the 2025 text) |
| MITRE ATT&CK (v19) | not applicable |
| CWE | CWE-352 Cross-Site Request Forgery |
| CAPEC | CAPEC-62 Cross Site Request Forgery |
| Example CVE | Many; search the NVD for CWE-352 |

## What it is

CSRF tricks a logged-in user's browser into sending a state-changing request (change email, transfer money) to a site that trusts the session cookie. The server sees a valid cookie and cannot tell the user did not intend the action.

## How it works

Browsers attach cookies to requests automatically, including requests triggered by another site's page. An attacker hosts a page with a hidden form that posts to the victim site. When a logged-in user visits it, the browser sends the cookie along with the forged request. The attacker never sees the response; the damage is the action itself.

## Real-world example

No single incident is cited here yet. Contributors: add one with a primary source (see [TOPIC_TEMPLATE.md](../../TOPIC_TEMPLATE.md)). The OWASP CSRF page lists documented cases.

## Detection

- Forms that change state without an unpredictable token (`csrf_detector.py` checks this statically)
- Session cookies without `SameSite`
- No `Origin`/`Referer` validation on state-changing endpoints
- Server logs: state-changing requests whose `Origin` is another site

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Anti-CSRF tokens bound to the session on every state-changing request (`prevention/csrf_protection.py`)
2. `SameSite=Lax` or `Strict` on session cookies
3. Validate `Origin` (or `Referer`) on POST/PUT/PATCH/DELETE
4. Never change state on GET requests
5. Require re-authentication for sensitive actions
6. Add a CSP `form-action` directive

## Scripts in this topic

- [csrf_detector.py](./detection/csrf_detector.py): read-only form and cookie check
- [csrf_protection.py](./prevention/csrf_protection.py): signed session-bound tokens and Origin check

## Common mistakes

- Relying on SameSite alone: it does not cover same-site attackers or older browsers
- Putting the token in a cookie only and comparing it to the same cookie without signing
- Accepting requests that have no `Origin` and no token
- Checking the token only on POST while PUT/DELETE are unprotected

## Test it safely

Only test systems you own or have written permission to test. Practice against a deliberately vulnerable app such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), or a local test server you write yourself.

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
- [CAPEC-62](https://capec.mitre.org/data/definitions/62.html)
