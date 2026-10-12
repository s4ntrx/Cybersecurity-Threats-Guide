#!/usr/bin/env python3
"""
Content-Security-Policy analyzer
Location: 02-web-application-security/xss-attacks/prevention/csp_analyzer.py

Reads a CSP (from --policy text or fetched from --url) and lists the weaknesses that let XSS
through despite having a policy. A CSP is a second line of defence behind output encoding.

Checks: missing script-src/default-src, 'unsafe-inline', 'unsafe-eval', wildcard or
scheme-only sources (https:, data:), missing object-src and base-uri, missing frame-ancestors.

Exit codes: 0 = no issues, 1 = issues found, 2 = input problem.
"""

import argparse
import sys

import requests


def parse_csp(policy):
    directives = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def analyse(policy):
    d = parse_csp(policy)
    issues = []
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        issues.append(("HIGH", "no script-src or default-src: scripts are not restricted"))
    else:
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        if "'unsafe-inline'" in script and not (has_nonce and "'strict-dynamic'" in script or has_nonce):
            issues.append(("HIGH", "script-src allows 'unsafe-inline' without a nonce or hash: injected scripts will run"))
        if "'unsafe-eval'" in script:
            issues.append(("MEDIUM", "script-src allows 'unsafe-eval' (eval and string timers)"))
        for token in script:
            if token == "*" or token in ("https:", "http:", "data:"):
                issues.append(("HIGH", f"script-src source '{token}' is too broad: any matching host can supply scripts"))
            elif token.startswith("*."):
                issues.append(("MEDIUM", f"script-src wildcard '{token}' trusts every subdomain"))
    if "object-src" not in d and not (d.get("default-src") and "'none'" in d["default-src"]):
        issues.append(("MEDIUM", "no object-src 'none' (plugins can be abused)"))
    if "base-uri" not in d:
        issues.append(("MEDIUM", "no base-uri (an injected <base> tag can redirect relative script URLs)"))
    if "frame-ancestors" not in d:
        issues.append(("LOW", "no frame-ancestors (clickjacking protection)"))
    return issues


def main():
    parser = argparse.ArgumentParser(description="Content-Security-Policy analyzer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--policy", help="CSP header value"); group.add_argument("--url", help="fetch the header from this URL")
    args = parser.parse_args()
    policy = args.policy
    if args.url:
        try:
            policy = requests.get(args.url, timeout=10).headers.get("Content-Security-Policy")
        except requests.exceptions.RequestException as exc:
            print(f"[x] Could not fetch {args.url}: {exc}")
            return 2
        if not policy:
            print("[x] The response has no Content-Security-Policy header")
            return 1
    issues = analyse(policy)
    for severity, message in issues:
        print(f"  [{severity}] {message}")
    print("[+] No issues found" if not issues else f"[!] {len(issues)} issue(s)")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
