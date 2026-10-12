# DNS Spoofing and Cache Poisoning

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | not applicable |
| MITRE ATT&CK (v19) | Related: Credential Access / T1557 Adversary-in-the-Middle |
| CWE | not applicable |
| CAPEC | CAPEC-142 DNS Cache Poisoning |
| Example CVE | CVE-2008-1447 (Kaminsky DNS cache poisoning) |

## What it is

DNS spoofing makes a victim's resolver or device accept a forged DNS answer, so a real name such as your bank's domain leads to an attacker's server. The attacker can then show a look-alike site, read traffic, or block updates.

## How it works

Plain DNS over UDP has no proof of who sent an answer. A forger must match the query's 16-bit transaction ID and source port and answer before the real server. If the forged reply arrives first, a caching resolver stores it and serves it to every client until the record's TTL expires. On a local network an attacker can instead sit in the path (see ARP spoofing) and answer queries directly.

## Real-world example

In 2008 Dan Kaminsky showed that cache poisoning could be done quickly and reliably against resolvers that used predictable source ports (CVE-2008-1447). Vendors responded by randomising source ports. Source: [CERT/CC VU#800113](https://www.kb.cert.org/vuls/id/800113).

## Detection

- Two answers for one query with different addresses: `CONFLICTING_ANSWERS` (the forged-versus-genuine race)
- An answer from a server the query was not sent to: `WRONG_SOURCE`
- An answer with no matching query: `UNSOLICITED_RESPONSE`
- A public name resolving to a private or loopback address: `PRIVATE_ANSWER` (spoofing or DNS rebinding)

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Enable DNSSEC validation on your resolver and sign your own zones (`prevention/dnssec_check.py` shows whether it is working)
2. Use encrypted DNS (DNS-over-TLS or DNS-over-HTTPS) to a resolver you trust
3. Keep resolver software patched; make sure it randomises source ports and transaction IDs
4. Restrict recursion to your own clients; do not run an open resolver
5. Defend the local network against ARP spoofing (dynamic ARP inspection, static entries for gateways)

## Scripts in this topic

- [dns_spoof_detector.py](./detection/dns_spoof_detector.py): live capture or `.pcap` analysis
- [dnssec_check.py](./prevention/dnssec_check.py): is the zone signed, and does your resolver validate?

## Common mistakes

- Believing HTTPS makes DNS spoofing harmless: it limits damage only if users never click through certificate warnings
- Checking only the first answer: forged replies race the real one
- Running a validating resolver but never checking that it actually sets the AD flag

## Test it safely

Only test systems you own or have written permission to test. Practice against a deliberately vulnerable app such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), or a local test server you write yourself. The detector can be tested offline with a `.pcap` file: `python detection/dns_spoof_detector.py -r capture.pcap`.

## References

- [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) DNS Security Introduction and Requirements
- [CAPEC-142](https://capec.mitre.org/data/definitions/142.html)
- [MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/)
