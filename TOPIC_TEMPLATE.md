# Topic template

Copy this file to `<category>/<topic>/README.md` and replace every `<placeholder>`. Delete a section only if it truly does not apply, and say why in one line.

---

```markdown
# <Topic name>

> **Last reviewed:** YYYY-MM-DD | **Status:** Draft | Reviewed | Needs update

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | <A0X:2025 - Name, or "not applicable"> |
| MITRE ATT&CK (v19) | <Tactic> / <Txxxx Technique name> |
| CWE | <CWE-xxx Name> |
| CAPEC | <CAPEC-xxx Name, if one exists> |
| Example CVEs | <CVE-YYYY-NNNNN, if relevant> |

## What it is
Two to four sentences in plain language. What is attacked, and what does the attacker gain?

## How it works
The mechanism, with a small diagram or code snippet if it helps.

## Real-world example
One documented incident: date, what happened, root cause, impact. Link a primary source (vendor advisory, CISA, court filing, post-mortem). Do not invent or embellish incidents.

## Detection
- Signals in logs and telemetry (what a defender would actually see)
- Tools and rules (Sigma, YARA, Suricata, SIEM queries)
- Scripts in this repository (linked)

## Prevention
Ordered from strongest to weakest control. Say which controls fix the cause and which only reduce risk.

## Code examples
Short, runnable, and tested. State the Python version and any system requirements.

## Common mistakes
What people believe protects them but does not.

## Test it safely
Lab targets you may attack (for example DVWA or OWASP Juice Shop), plus the authorization warning.

## References
Primary sources first.
```

## Review rules

1. **Last reviewed** changes only when someone has checked the page against current sources, not when a typo is fixed.
2. A page is **Needs update** if it was last reviewed more than 12 months ago, or if a framework it maps to has released a new version (OWASP Top 10, MITRE ATT&CK, NIST).
3. Every script linked from a page must start with `--help` on a clean install of `tools/requirements.txt`.
4. Every code example in a page must be run before it is committed.
5. Prefer primary sources (vendor advisories, standards bodies, government agencies) over blog summaries.
