#!/usr/bin/env python3
"""
XSS Vulnerability Detector (reflected XSS)
Location: 02-web-application-security/xss-attacks/detection/xss_detector.py

Checks the GET parameters of a web application you own (or have written
permission to test) for reflected cross-site scripting.

Method: instead of firing a long list of attack strings and regex-matching the
whole page, the scanner sends a harmless random marker next to the characters
that matter (< > " '), finds where the marker is reflected, works out the HTML
context (body text, attribute, <script>, comment) and reports which characters
come back un-encoded. A page that HTML-encodes its output (the correct fix) is
therefore reported as safe, and nothing executable is ever sent.

Exit codes: 0 = no finding, 1 = vulnerability found, 2 = scan could not complete.
"""

import argparse
import json
import re
import secrets
import sys
from datetime import datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# What an attacker needs in each context, and a manual proof-of-concept to try.
CONTEXT_RULES = {
    "HTML body":      {"needs": ("lt", "gt"), "poc": "<svg onload=alert(1)>",
                       "why": "tags can be injected into the page body"},
    "HTML comment":   {"needs": ("lt", "gt"), "poc": "--><svg onload=alert(1)>",
                       "why": "the comment can be closed and tags injected"},
    "script block":   {"needs": ("sq",), "poc": "';alert(1);//",
                       "why": "a JavaScript string can be broken out of"},
    "attribute (double-quoted)": {"needs": ("dq",), "poc": '" autofocus onfocus=alert(1) x="',
                       "why": "the attribute value can be closed and an event handler added"},
    "attribute (single-quoted)": {"needs": ("sq",), "poc": "' autofocus onfocus=alert(1) x='",
                       "why": "the attribute value can be closed and an event handler added"},
    "attribute (unquoted)": {"needs": (), "poc": " autofocus onfocus=alert(1) ",
                       "why": "a space is enough to add an event handler"},
}


class XSSDetector:
    def __init__(self, target_url, timeout=10, cookie=None, proxy=None):
        if urlsplit(target_url).scheme not in ("http", "https"):
            raise ValueError("Target URL must start with http:// or https://")
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Educational Purpose)"})
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.results = {"target": target_url, "timestamp": datetime.now().isoformat(),
                        "scan_completed": False, "error": None, "vulnerable": False,
                        "vulnerabilities": [], "summary": {}}

    # ------------------------------------------------------------------ helpers
    def extract_parameters(self):
        return parse_qsl(urlsplit(self.target_url).query, keep_blank_values=True)

    def send(self, param, value):
        """GET the target with `param` replaced by `value`. Returns the response or None on a network error."""
        pairs = [(k, value if k == param else v) for k, v in self.extract_parameters()]
        parts = urlsplit(self.target_url)
        url = urlunsplit(parts._replace(query=urlencode(pairs, quote_via=quote)))
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None

    @staticmethod
    def determine_context(text, position):
        """Classify what surrounds `position` in the HTML."""
        before = text[:position]
        lower = before.lower()

        if lower.rfind("<!--") > lower.rfind("-->"):
            return "HTML comment", None
        if lower.rfind("<script") > lower.rfind("</script"):
            return "script block", None

        last_open, last_close = before.rfind("<"), before.rfind(">")
        if last_open > last_close:                       # inside a tag, i.e. an attribute value
            tag = before[last_open:]
            quote_char = None
            match = re.search(r"=\s*([\"']?)[^\"'<>]*$", tag)
            if match:
                quote_char = match.group(1)
            if quote_char == '"':
                return "attribute (double-quoted)", '"'
            if quote_char == "'":
                return "attribute (single-quoted)", "'"
            return "attribute (unquoted)", None
        return "HTML body", None

    # ------------------------------------------------------------------ testing
    def test_parameter(self, param, original):
        print(f"\n{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
        core = "xs" + secrets.token_hex(4)

        # Request 1: plain marker only. The page is untouched by special characters, so the
        # context at every reflection point is classified correctly.
        plain = self.send(param, core)
        if plain is None:
            print(f"{Fore.YELLOW}  [!] No response, skipping{Style.RESET_ALL}")
            return []
        contexts = []
        for match in re.finditer(re.escape(core), plain.text):
            context, _ = self.determine_context(plain.text, match.start())
            if context not in contexts:
                contexts.append(context)
        if not contexts:
            print("  [-] Value is not reflected in the response")
            return []

        # Request 2: marker next to each special character, to see which come back un-encoded.
        probe = f"{core}lt<{core}gt>{core}dq\"{core}sq'{core}end"
        probed = self.send(param, probe)
        if probed is None:
            print(f"{Fore.YELLOW}  [!] No response to the probe, skipping{Style.RESET_ALL}")
            return []
        survives = {
            "lt": f"{core}lt<" in probed.text,
            "gt": f"{core}gt>" in probed.text,
            "dq": f'{core}dq"' in probed.text,
            "sq": f"{core}sq'" in probed.text,
        }

        findings = []
        for context in contexts:
            rule = CONTEXT_RULES[context]
            if all(survives[c] for c in rule["needs"]):
                findings.append({
                    "parameter": param, "type": "Reflected XSS", "context": context,
                    "evidence": "unencoded characters reflected: " +
                                (", ".join({"lt": "<", "gt": ">", "dq": '"', "sq": "'"}[c] for c in survives if survives[c]) or "none needed"),
                    "explanation": rule["why"], "manual_poc": rule["poc"],
                    "response_code": probed.status_code,
                })
                print(f"{Fore.RED}  [!] Reflected XSS in context: {context}{Style.RESET_ALL}")
                print(f"      {rule['why']}")
        if not findings:
            print(f"{Fore.GREEN}  [+] Reflected but special characters are encoded - no XSS{Style.RESET_ALL}")
        return findings

    def scan(self):
        print(f"\n{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[+] Target is reachable (HTTP {response.status_code}){Style.RESET_ALL}")
        except requests.exceptions.RequestException as exc:
            self.results["error"] = f"Target unreachable: {exc}"
            print(f"{Fore.RED}[x] {self.results['error']}{Style.RESET_ALL}")
            return self.results

        parameters = self.extract_parameters()
        if not parameters:
            self.results["error"] = "No query parameters found in the URL (add e.g. ?q=test)"
            print(f"{Fore.YELLOW}[!] {self.results['error']}{Style.RESET_ALL}")
            return self.results

        vulnerabilities = []
        for name, value in parameters:
            vulnerabilities.extend(self.test_parameter(name, value))

        self.results["vulnerabilities"] = vulnerabilities
        self.results["vulnerable"] = bool(vulnerabilities)
        self.results["summary"] = {
            "total_parameters": len(parameters),
            "vulnerable_parameters": len({v["parameter"] for v in vulnerabilities}),
            "total_vulnerabilities": len(vulnerabilities),
        }
        self.results["scan_completed"] = True
        return self.results

    def print_report(self):
        bar = "=" * 60
        print(f"\n{Fore.CYAN}{bar}\nXSS SCAN REPORT\n{bar}{Style.RESET_ALL}")
        if not self.results["scan_completed"]:
            print(f"\n{Fore.RED}[x] SCAN DID NOT COMPLETE - no conclusion can be drawn.{Style.RESET_ALL}")
            print(f"    Reason: {self.results['error']}")
            return
        if self.results["vulnerable"]:
            print(f"\n{Fore.RED}[!] XSS VULNERABILITIES DETECTED{Style.RESET_ALL}")
            for i, vuln in enumerate(self.results["vulnerabilities"], 1):
                print(f"\n  {i}. Parameter: {vuln['parameter']}  Context: {vuln['context']}")
                print(f"     Evidence: {vuln['evidence']}")
                print(f"     Meaning:  {vuln['explanation']}")
                print(f"     Try manually in a test browser: {vuln['manual_poc']}")
            print("\n  Fix: HTML-encode untrusted data for the context where it is printed, and add a Content-Security-Policy.")
        else:
            print(f"\n{Fore.GREEN}[+] No reflected XSS found in the tested parameters.{Style.RESET_ALL}")
            print("    Stored and DOM-based XSS are not covered by this scanner.")

    def save_results(self, output_file):
        try:
            with open(output_file, "w") as handle:
                json.dump(self.results, handle, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except OSError as exc:
            print(f"{Fore.RED}[x] Could not save results: {exc}{Style.RESET_ALL}")


def confirm_permission(assume_yes):
    if assume_yes:
        print(f"{Fore.YELLOW}[i] --yes given: you are confirming you may test this target.{Style.RESET_ALL}")
        return True
    try:
        answer = input(f"{Fore.YELLOW}[?] Do you have permission to test this target? (yes/no): {Style.RESET_ALL}")
    except EOFError:
        print(f"\n{Fore.RED}[!] No interactive input available. Re-run with --yes if you are authorized.{Style.RESET_ALL}")
        return False
    return answer.strip().lower() == "yes"


def main():
    parser = argparse.ArgumentParser(description="Reflected XSS scanner (non-destructive)")
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. http://localhost:8080/search?q=test")
    parser.add_argument("-o", "--output", help="Write results to this JSON file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--cookie", help='Session cookie, e.g. "session=abc123"')
    parser.add_argument("--proxy", help="Proxy server, e.g. http://127.0.0.1:8080")
    parser.add_argument("--yes", action="store_true", help="Skip the permission prompt (you confirm you are authorized)")
    args = parser.parse_args()

    if not confirm_permission(args.yes):
        print(f"{Fore.RED}[!] Exiting. Only test systems you own or have written permission to test.{Style.RESET_ALL}")
        return 2
    try:
        scanner = XSSDetector(args.url, args.timeout, args.cookie, args.proxy)
    except ValueError as exc:
        print(f"{Fore.RED}[x] {exc}{Style.RESET_ALL}")
        return 2

    scanner.scan()
    scanner.print_report()
    if args.output:
        scanner.save_results(args.output)
    if not scanner.results["scan_completed"]:
        return 2
    return 1 if scanner.results["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
