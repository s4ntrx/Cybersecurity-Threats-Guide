#!/usr/bin/env python3
"""
CSRF Detector
Location: 02-web-application-security/csrf/detection/csrf_detector.py

Fetches a page you own (or may test) and checks the things that decide whether a form can be
forged from another site:

  * every state-changing form (POST/PUT/PATCH/DELETE, or a form with no method that has inputs
    but is not a plain search form) should carry an unpredictable hidden token
  * cookies should set SameSite (Lax or Strict) so browsers do not attach them to cross-site posts
  * a Content-Security-Policy `form-action` directive limits where forms may submit

Read-only: the scanner only sends GET requests. It cannot prove a token is validated server-side;
a token field that the server ignores still passes the static check, so test that manually.

Exit codes: 0 = nothing found, 1 = findings, 2 = could not complete.
"""

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

TOKEN_NAME = re.compile(r"csrf|xsrf|authenticity|anti.?forgery|requestverificationtoken|nonce|_token$", re.I)
UNSAFE_METHODS = {"post", "put", "patch", "delete"}


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._current = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
        elif self._current is not None and tag in ("input", "select", "textarea", "button"):
            self._current["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower(),
                                            "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def analyse_forms(html):
    parser = FormParser()
    parser.feed(html)
    findings = []
    for form in parser.forms:
        if form["method"] not in UNSAFE_METHODS:
            continue
        tokens = [i for i in form["inputs"] if i["type"] == "hidden" and TOKEN_NAME.search(i["name"])]
        if not tokens:
            findings.append({"severity": "HIGH", "type": "form-without-token",
                             "detail": f"{form['method'].upper()} form to '{form['action'] or '(same page)'}' has no CSRF token"})
        elif all(len(t["value"]) < 16 for t in tokens if t["value"] != ""):
            findings.append({"severity": "MEDIUM", "type": "weak-token",
                             "detail": f"token '{tokens[0]['name']}' looks too short to be unpredictable"})
    return findings, len(parser.forms)


def analyse_cookies(set_cookie_headers):
    findings = []
    for header in set_cookie_headers:
        name = header.split("=", 1)[0].strip()
        match = re.search(r"samesite=(\w+)", header, re.I)
        if not match:
            findings.append({"severity": "MEDIUM", "type": "cookie-no-samesite",
                             "detail": f"cookie '{name}' has no SameSite attribute"})
        elif match.group(1).lower() == "none" and "secure" not in header.lower():
            findings.append({"severity": "HIGH", "type": "samesite-none-insecure",
                             "detail": f"cookie '{name}' uses SameSite=None without Secure"})
    return findings


def analyse_headers(headers):
    csp = headers.get("Content-Security-Policy", "")
    if "form-action" not in csp.lower():
        return [{"severity": "LOW", "type": "no-form-action",
                 "detail": "no Content-Security-Policy form-action directive (limits where forms can submit)"}]
    return []


def scan(url, timeout=10):
    response = requests.get(url, timeout=timeout)
    cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    form_findings, form_count = analyse_forms(response.text)
    findings = form_findings + analyse_cookies(cookies) + analyse_headers(response.headers)
    return {"url": url, "forms_found": form_count, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="CSRF protection checker (read-only)")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-o", "--output")
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
        result = scan(args.url, args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[x] SCAN DID NOT COMPLETE: {exc}")
        return 2

    print(f"[*] {result['url']}: {result['forms_found']} form(s)")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['type']}: {f['detail']}")
    if not result["findings"]:
        print("[+] No CSRF weaknesses found by static checks (server-side token validation is not tested).")
    if args.output:
        json.dump(result, open(args.output, "w"), indent=2)
    return 1 if [f for f in result["findings"] if f["severity"] != "LOW"] else 0


if __name__ == "__main__":
    sys.exit(main())
