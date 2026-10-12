#!/usr/bin/env python3
"""
Local file inclusion / path traversal detector
Location: 02-web-application-security/file-inclusion/detection/lfi_detector.py

For each GET parameter, requests well-known harmless system files through traversal sequences
and looks for their unmistakable content (the /etc/passwd line format, the win.ini header).
Only LOCAL, READ-ONLY probes are sent. The scanner never sends a remote URL for the target to
fetch (that would make the target contact third parties), so remote file inclusion (RFI) is
checked by reviewing code, not by this tool.

Exit codes: 0 = nothing found, 1 = vulnerability found, 2 = could not complete.
"""

import argparse
import json
import re
import sys
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests

TRAVERSAL = ["../" * 6, "..%2f" * 6, "....//" * 6, "..\\" * 6, "%2e%2e/" * 6]
TARGETS = [
    ("etc/passwd", re.compile(r"root:[x*!]?:0:0:")),
    ("windows/win.ini", re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)),
]
SKIP_NAMES = {"submit", "csrf", "csrf_token", "token"}


def build_url(url, param, value):
    parts = urlsplit(url)
    pairs = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    # `safe` keeps our own %2f / %2e sequences intact instead of double-encoding them
    return urlunsplit(parts._replace(query=urlencode(pairs, quote_via=lambda s, safe, e, er: quote(s, safe="%/\\."))))


def test_parameter(url, param, timeout):
    for sequence in TRAVERSAL:
        for target, signature in TARGETS:
            try:
                response = requests.get(build_url(url, param, sequence + target), timeout=timeout)
            except requests.exceptions.RequestException:
                continue
            if signature.search(response.text):
                return {"parameter": param, "technique": "path traversal", "payload": sequence + target,
                        "evidence": f"response contains the signature of {target}"}
    return None


def main():
    parser = argparse.ArgumentParser(description="Local file inclusion / path traversal detector (read-only probes)")
    parser.add_argument("-u", "--url", required=True, help="e.g. http://localhost:8080/file?name=report.txt")
    parser.add_argument("-o", "--output"); parser.add_argument("--timeout", type=int, default=10)
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
        requests.get(args.url, timeout=args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[x] SCAN DID NOT COMPLETE: target unreachable: {exc}")
        return 2

    params = [k for k, _ in parse_qsl(urlsplit(args.url).query, keep_blank_values=True) if k.lower() not in SKIP_NAMES]
    if not params:
        print("[x] SCAN DID NOT COMPLETE: no query parameters to test")
        return 2
    findings = []
    for param in params:
        print(f"[*] Testing parameter: {param}")
        found = test_parameter(args.url, param, args.timeout)
        if found:
            findings.append(found)
            print(f"  [HIGH] {found['technique']} via payload {found['payload']}: {found['evidence']}")
    if not findings:
        print("[+] No file inclusion / path traversal detected with these probes.")
    if args.output:
        json.dump(findings, open(args.output, "w"), indent=2)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
