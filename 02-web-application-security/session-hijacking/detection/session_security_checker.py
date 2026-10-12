#!/usr/bin/env python3
"""
Session security checker
Location: 02-web-application-security/session-hijacking/detection/session_security_checker.py

Read-only checks of how a site you own handles session cookies:

  * cookie flags: Secure, HttpOnly, SameSite, overly long lifetime
  * session id quality: collects several fresh ids and checks length, uniqueness, character
    variety and estimated entropy (predictable ids can be guessed or enumerated)
  * HSTS on HTTPS sites (stops downgrade and cookie sniffing)
  * optional session FIXATION test: log in with the cookie you were given before login and see
    whether the server keeps it (it should issue a new id)

Exit codes: 0 = nothing found, 1 = findings, 2 = could not complete.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from urllib.parse import urlsplit

import requests

SESSION_NAME = re.compile(r"sess|sid|token|auth|jwt|login", re.I)


def parse_set_cookie(header):
    name, _, rest = header.partition("=")
    value = rest.split(";", 1)[0]
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in rest.split(";")[1:]}
    return {"name": name.strip(), "value": value, "attrs": attrs}


def entropy_bits(value):
    """Upper-bound estimate: length * Shannon entropy of the characters actually used."""
    if not value:
        return 0.0
    counts = Counter(value)
    per_char = -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())
    return per_char * len(value)


def check_cookie(cookie, https):
    findings, name, attrs = [], cookie["name"], cookie["attrs"]
    if not SESSION_NAME.search(name):
        return findings
    if https and "secure" not in attrs:
        findings.append(("HIGH", f"cookie '{name}' lacks the Secure flag (sent over plain HTTP)"))
    if "httponly" not in attrs:
        findings.append(("HIGH", f"cookie '{name}' lacks HttpOnly (readable by JavaScript, so XSS can steal it)"))
    if "samesite" not in attrs:
        findings.append(("MEDIUM", f"cookie '{name}' has no SameSite attribute"))
    max_age = attrs.get("max-age")
    if isinstance(max_age, str) and max_age.isdigit() and int(max_age) > 30 * 86400:
        findings.append(("MEDIUM", f"cookie '{name}' lives {int(max_age) // 86400} days; long-lived sessions widen the theft window"))
    if name.startswith("__Host-") and ("domain" in attrs or attrs.get("path") != "/"):
        findings.append(("MEDIUM", f"cookie '{name}' uses the __Host- prefix but not its required attributes"))
    return findings


def check_session_ids(ids):
    findings = []
    if len(ids) < 2:
        return findings
    if len(set(ids)) < len(ids):
        findings.append(("HIGH", "the server issued the same session id to different clients"))
    shortest = min(len(i) for i in ids)
    bits = min(entropy_bits(i) for i in ids)
    if shortest < 16 or bits < 64:
        findings.append(("HIGH", f"session ids look weak: shortest {shortest} chars, about {bits:.0f} bits of entropy "
                                 f"(aim for 128+ bits from a CSPRNG)"))
    numeric = [int(i) for i in ids if i.isdigit()]
    if len(numeric) == len(ids) and sorted(numeric) == numeric and len(set(numeric)) > 1:
        findings.append(("HIGH", "session ids are numeric and increasing: they can be enumerated"))
    return findings


def fresh_session_cookie(url, timeout):
    """GET with no cookies and return the first session-looking Set-Cookie, or None."""
    response = requests.get(url, timeout=timeout)
    for header in response.raw.headers.getlist("Set-Cookie"):
        cookie = parse_set_cookie(header)
        if SESSION_NAME.search(cookie["name"]):
            return cookie, response
    return None, response


def fixation_test(login_url, user, password, user_field, pass_field, timeout):
    session = requests.Session()
    session.get(login_url, timeout=timeout)
    before = {c.name: c.value for c in session.cookies if SESSION_NAME.search(c.name)}
    reply = session.post(login_url, data={user_field: user, pass_field: password}, timeout=timeout, allow_redirects=True)
    if reply.status_code >= 400:
        return [("LOW", f"the login request returned HTTP {reply.status_code}; fixation test is inconclusive "
                        f"(check --login-url, --user-field and --pass-field)")]
    after = {c.name: c.value for c in session.cookies if SESSION_NAME.search(c.name)}
    if not before:
        return [("LOW", "no session cookie was set before login, so fixation could not be tested")]
    kept = [n for n in before if after.get(n) == before[n]]
    if kept:
        return [("HIGH", f"session fixation: cookie(s) {', '.join(kept)} kept the same value after login")]
    return []


def main():
    parser = argparse.ArgumentParser(description="Session cookie security checker (read-only)")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--samples", type=int, default=10, help="how many fresh session ids to collect")
    parser.add_argument("--login-url"); parser.add_argument("--user"); parser.add_argument("--password")
    parser.add_argument("--user-field", default="username"); parser.add_argument("--pass-field", default="password")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("-o", "--output")
    parser.add_argument("--yes", action="store_true", help="confirm you are authorized to test this target")
    args = parser.parse_args()

    if not args.yes:
        try:
            if input("[?] Do you have permission to test this target? (yes/no): ").strip().lower() != "yes":
                return 2
        except EOFError:
            print("[!] No interactive input. Re-run with --yes if you are authorized.")
            return 2

    https = urlsplit(args.url).scheme == "https"
    findings, ids = [], []
    try:
        for _ in range(args.samples):
            cookie, response = fresh_session_cookie(args.url, args.timeout)
            if cookie:
                ids.append(cookie["value"])
                if len(ids) == 1:
                    findings += check_cookie(cookie, https)
        if https and "Strict-Transport-Security" not in response.headers:
            findings.append(("MEDIUM", "no Strict-Transport-Security header on an HTTPS site"))
        if args.login_url and args.user:
            findings += fixation_test(args.login_url, args.user, args.password or "", args.user_field,
                                      args.pass_field, args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[x] SCAN DID NOT COMPLETE: {exc}")
        return 2

    if not ids:
        findings.append(("LOW", "no session cookie was issued to an anonymous visitor (nothing to check)"))
    findings += check_session_ids(ids)
    print(f"[*] {args.url}: {len(ids)} session id sample(s)")
    for severity, message in findings:
        print(f"  [{severity}] {message}")
    if not findings:
        print("[+] No session-handling weaknesses found.")
    if args.output:
        json.dump([{"severity": s, "message": m} for s, m in findings], open(args.output, "w"), indent=2)
    return 1 if [f for f in findings if f[0] != "LOW"] else 0


if __name__ == "__main__":
    sys.exit(main())
