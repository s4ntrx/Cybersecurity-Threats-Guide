#!/usr/bin/env python3
"""
Security misconfiguration checker (OWASP Top 10:2025 A02)
Location: 02-web-application-security/security-misconfig/detection/security_headers_checker.py

Read-only GET requests to a site you own:

  * missing or weak security headers (HSTS, CSP, X-Content-Type-Options, clickjacking protection,
    Referrer-Policy, Permissions-Policy)
  * version disclosure in Server / X-Powered-By
  * commonly exposed files and panels (.git, .env, backups, server-status, phpinfo ...). A path only
    counts as exposed when the response CONTENT matches what that file looks like, not just HTTP 200,
    because many sites answer 200 for every URL.
  * directory listings

Prints a grade from A to F. Exit codes: 0 = grade A or B, 1 = worse, 2 = could not complete.
"""

import argparse
import json
import re
import sys
from urllib.parse import urljoin, urlsplit

import requests

EXPOSED = [
    ("/.git/HEAD", re.compile(r"^ref:\s*refs/", re.M), "HIGH", "git repository exposed (source code and history)"),
    ("/.env", re.compile(r"^[A-Z][A-Z0-9_]*=.+", re.M), "HIGH", ".env file exposed (secrets)"),
    ("/server-status", re.compile(r"Apache Server Status", re.I), "MEDIUM", "Apache server-status page exposed"),
    ("/phpinfo.php", re.compile(r"<title>phpinfo\(\)", re.I), "MEDIUM", "phpinfo() page exposed"),
    ("/.DS_Store", re.compile(r"Bud1"), "LOW", ".DS_Store file exposed (directory contents leak)"),
    ("/backup.zip", re.compile(r"^PK\x03\x04"), "HIGH", "backup archive exposed"),
    ("/actuator/env", re.compile(r"propertySources|activeProfiles"), "HIGH", "Spring Boot actuator /env exposed"),
]
VERSION_LEAK = re.compile(r"\d+\.\d+")


def check_headers(headers, https):
    findings = []
    h = {k.lower(): v for k, v in headers.items()}
    if https and "strict-transport-security" not in h:
        findings.append(("MEDIUM", "missing Strict-Transport-Security"))
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(("MEDIUM", "missing Content-Security-Policy"))
    elif "unsafe-inline" in csp and "script-src" in csp:
        findings.append(("MEDIUM", "CSP allows 'unsafe-inline' scripts"))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(("LOW", "missing X-Content-Type-Options: nosniff"))
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        findings.append(("MEDIUM", "no clickjacking protection (X-Frame-Options or CSP frame-ancestors)"))
    if "referrer-policy" not in h:
        findings.append(("LOW", "missing Referrer-Policy"))
    if "permissions-policy" not in h:
        findings.append(("LOW", "missing Permissions-Policy"))
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        if name in h and VERSION_LEAK.search(h[name]):
            findings.append(("LOW", f"{name} discloses a version: {h[name]}"))
    return findings


def check_exposed(base_url, timeout):
    findings = []
    baseline = requests.get(urljoin(base_url, "/nonexistent-" + "x7q2k9"), timeout=timeout)
    for path, signature, severity, message in EXPOSED:
        try:
            response = requests.get(urljoin(base_url, path), timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        body = response.text if "zip" not in path else response.content.decode("latin-1")
        if response.status_code == 200 and signature.search(body) and body != baseline.text:
            findings.append((severity, f"{message}: {path}"))
    listing = requests.get(urljoin(base_url, "/"), timeout=timeout)
    if re.search(r"<title>Index of /", listing.text, re.I):
        findings.append(("MEDIUM", "directory listing is enabled on /"))
    return findings


def grade(findings):
    points = sum({"HIGH": 25, "MEDIUM": 10, "LOW": 3}[s] for s, _ in findings)
    return "A" if points == 0 else "B" if points <= 12 else "C" if points <= 25 else "D" if points <= 50 else "F"


def main():
    parser = argparse.ArgumentParser(description="Security header and misconfiguration checker (read-only)")
    parser.add_argument("-u", "--url", required=True); parser.add_argument("-o", "--output")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--yes", action="store_true", help="confirm you are authorized to test this target")
    args = parser.parse_args()

    if not args.yes:
        try:
            if input("[?] Do you have permission to test this target? (yes/no): ").strip().lower() != "yes":
                return 2
        except EOFError:
            print("[!] No interactive input. Re-run with --yes if you are authorized.")
            return 2
    try:
        response = requests.get(args.url, timeout=args.timeout)
        findings = check_headers(response.headers, urlsplit(args.url).scheme == "https")
        findings += check_exposed(args.url, args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[x] SCAN DID NOT COMPLETE: {exc}")
        return 2

    for severity, message in sorted(findings, key=lambda f: ["HIGH", "MEDIUM", "LOW"].index(f[0])):
        print(f"  [{severity}] {message}")
    result = grade(findings)
    print(f"[*] Grade: {result}")
    if args.output:
        json.dump({"url": args.url, "grade": result, "findings": findings}, open(args.output, "w"), indent=2)
    return 0 if result in "AB" else 1


if __name__ == "__main__":
    sys.exit(main())
