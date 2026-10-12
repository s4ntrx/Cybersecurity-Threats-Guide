#!/usr/bin/env python3
"""
SQL Injection Detector
Location: 02-web-application-security/sql-injection/detection/sql_injection_detector.py

Tests the parameters of a web application you own (or have written permission
to test) for SQL injection, using three techniques:

  * error-based    - the injected input makes the database leak an error
  * boolean-based  - a TRUE condition and a FALSE condition give different pages
  * time-based     - an injected delay function makes the response slow

All probes are NON-DESTRUCTIVE: nothing in the payload list writes, changes or
deletes data. (Earlier versions sent DROP TABLE / INSERT / INTO OUTFILE payloads,
which could damage a vulnerable target.)

Exit codes: 0 = no finding, 1 = vulnerability found, 2 = scan could not complete.
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests
from colorama import Fore, Style, init

init(autoreset=True)

SLEEP_SECONDS = 5
TIME_THRESHOLD = SLEEP_SECONDS - 0.5      # a delayed response must take at least this long
MAX_BASELINE_SECONDS = 2.0                # skip time-based tests if the page is already slow

# Probes that provoke a database error. Appended to the original parameter value.
ERROR_PAYLOADS = ["'", '"', "')", "\\", "' OR '1'='1", '" OR "1"="1', "' UNION SELECT NULL--", "1 AND 1=1"]

# (TRUE condition, FALSE condition) pairs for boolean-based detection.
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
]

# (label, payload) delay probes for time-based detection.
TIME_PAYLOADS = [
    ("MySQL", "' OR SLEEP(5)-- -"),
    ("MySQL (numeric)", " OR SLEEP(5)-- -"),
    ("PostgreSQL", "'; SELECT pg_sleep(5)--"),
    ("SQL Server", "'; WAITFOR DELAY '0:0:5'--"),
]

ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB) server",
        r"You have an error in your SQL syntax", r"Unknown column '[^']+' in 'where clause'",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result", r"PG::SyntaxError",
        r"ERROR:\s+syntax error at or near", r"ERROR:\s+operator does not exist",
        r"unterminated quoted string at or near",
    ],
    "Oracle": [r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver", r"quoted string not properly terminated"],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"valid SQLite", r"unrecognized token", r"sqlite3\.OperationalError",
        r"SQLITE_ERROR", r"near \"[^\"]*\": syntax error",
    ],
    "SQL Server": [
        r"SQL Server.*Driver", r"Driver.*SQL Server", r"SQLServer JDBC Driver", r"com\.microsoft\.sqlserver",
        r"Unclosed quotation mark", r"Microsoft OLE DB Provider for ODBC Drivers", r"Incorrect syntax near",
    ],
    "General": [
        r"SQL syntax", r"mysql_fetch", r"mysqli_error", r"PDOException", r"\[SQL Server\]",
        r"Dynamic SQL Error", r"SQLSTATE\[",
    ],
}
_COMPILED = {db: [re.compile(p, re.IGNORECASE) for p in pats] for db, pats in ERROR_PATTERNS.items()}


class SQLInjectionDetector:
    def __init__(self, target_url, method="GET", threads=5, timeout=10,
                 cookie=None, proxy=None, data=None):
        scheme = urlsplit(target_url).scheme
        if scheme not in ("http", "https"):
            raise ValueError("Target URL must start with http:// or https://")

        self.target_url = target_url
        self.method = method.upper()
        self.threads = max(1, threads)
        self.timeout = timeout
        self.body_pairs = parse_qsl(data, keep_blank_values=True) if data else []

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Educational Purpose)"})
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        self.results = {
            "target": target_url,
            "method": self.method,
            "timestamp": datetime.now().isoformat(),
            "scan_completed": False,
            "error": None,
            "vulnerable": False,
            "database_type": None,
            "vulnerabilities": [],
            "summary": {"total_parameters_tested": 0, "total_vulnerabilities_found": 0,
                        "vulnerable_parameters": [], "database_types": []},
        }

    # ------------------------------------------------------------------ requests
    def extract_parameters(self):
        """Return [(name, value)] for the query string (GET) or --data body (POST)."""
        if self.method == "POST":
            return list(self.body_pairs)
        return parse_qsl(urlsplit(self.target_url).query, keep_blank_values=True)

    def send(self, param, value):
        """Send the request with `param` set to `value`. Returns (response, seconds) or (None, seconds)."""
        pairs = [(k, value if k == param else v) for k, v in self.extract_parameters()]
        start = time.monotonic()
        try:
            if self.method == "POST":
                response = self.session.post(self.target_url, data=pairs, timeout=self.timeout)
            else:
                parts = urlsplit(self.target_url)
                url = urlunsplit(parts._replace(query=urlencode(pairs, quote_via=quote)))
                response = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException:
            return None, time.monotonic() - start
        return response, time.monotonic() - start

    @staticmethod
    def match_error(text):
        for db, patterns in _COMPILED.items():
            for pattern in patterns:
                if pattern.search(text):
                    return db, pattern.pattern
        return None, None

    # ------------------------------------------------------------------ testing
    def test_parameter(self, param, original):
        """Test one parameter. Returns a list of findings."""
        print(f"\n{Fore.CYAN}[*] Testing parameter: {param} ({self.method}){Style.RESET_ALL}")
        findings = []

        baseline, baseline_time = self.send(param, original)
        if baseline is None:                     # never use `if not response`: it is False for HTTP 4xx/5xx
            print(f"{Fore.YELLOW}  [!] No response for the baseline request, skipping{Style.RESET_ALL}")
            return findings
        baseline_db, _ = self.match_error(baseline.text)

        # 1. Error-based. HTTP 500 pages are exactly where database errors appear, so they are analysed.
        for payload in ERROR_PAYLOADS:
            response, elapsed = self.send(param, original + payload)
            if response is None:
                continue
            db, pattern = self.match_error(response.text)
            if db and db != baseline_db:         # ignore pages that always contain error-like text
                findings.append({"parameter": param, "technique": "error-based", "payload": payload,
                                 "database": db, "evidence": pattern, "confidence": "HIGH",
                                 "response_code": response.status_code, "response_time": round(elapsed, 2)})
                print(f"{Fore.RED}  [!] Error-based SQL injection ({db}) with payload: {payload}{Style.RESET_ALL}")
                break

        # 2. Boolean-based. Only meaningful if the page is stable between identical requests.
        again, _ = self.send(param, original)
        if again is not None and again.text == baseline.text:
            for true_cond, false_cond in BOOLEAN_PAIRS:
                r_true, _ = self.send(param, original + true_cond)
                r_false, _ = self.send(param, original + false_cond)
                if r_true is None or r_false is None:
                    continue
                if r_true.text == baseline.text and r_false.text != r_true.text:
                    findings.append({"parameter": param, "technique": "boolean-based",
                                     "payload": f"{true_cond}  vs  {false_cond}", "database": "Unknown",
                                     "evidence": "TRUE condition matches the normal page, FALSE condition differs",
                                     "confidence": "MEDIUM", "response_code": r_true.status_code,
                                     "response_time": 0})
                    print(f"{Fore.RED}  [!] Boolean-based SQL injection with: {true_cond}{Style.RESET_ALL}")
                    break
        else:
            print(f"{Fore.YELLOW}  [i] Page content changes between identical requests; boolean test skipped{Style.RESET_ALL}")

        # 3. Time-based. Each hit is repeated once to rule out a slow server.
        if baseline_time < MAX_BASELINE_SECONDS:
            for label, payload in TIME_PAYLOADS:
                response, elapsed = self.send(param, original + payload)
                if response is None or elapsed < TIME_THRESHOLD:
                    continue
                _, repeat = self.send(param, original + payload)
                if repeat >= TIME_THRESHOLD:
                    findings.append({"parameter": param, "technique": "time-based", "payload": payload,
                                     "database": label, "evidence": f"responses took {elapsed:.1f}s and {repeat:.1f}s",
                                     "confidence": "HIGH", "response_code": response.status_code,
                                     "response_time": round(elapsed, 2)})
                    print(f"{Fore.RED}  [!] Time-based SQL injection ({label}) with payload: {payload}{Style.RESET_ALL}")
                    break
        return findings

    # ------------------------------------------------------------------ scan flow
    def scan(self):
        print(f"\n{Fore.CYAN}[*] Target: {self.target_url}  Method: {self.method}  Threads: {self.threads}{Style.RESET_ALL}")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[+] Target is reachable (HTTP {response.status_code}){Style.RESET_ALL}")
        except requests.exceptions.RequestException as exc:
            self.results["error"] = f"Target unreachable: {exc}"
            print(f"{Fore.RED}[x] {self.results['error']}{Style.RESET_ALL}")
            return self.results

        parameters = self.extract_parameters()
        if not parameters:
            self.results["error"] = ("No parameters to test. For GET put them in the URL (?id=1); "
                                     "for POST pass --data 'a=1&b=2'.")
            print(f"{Fore.YELLOW}[!] {self.results['error']}{Style.RESET_ALL}")
            return self.results

        print(f"[*] Found {len(parameters)} parameter(s): {', '.join(n for n, _ in parameters)}")
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            batches = list(pool.map(lambda p: self.test_parameter(p[0], p[1]), parameters))

        vulnerabilities = [finding for batch in batches for finding in batch]
        self.results["vulnerabilities"] = vulnerabilities
        self.results["vulnerable"] = bool(vulnerabilities)
        known_dbs = [v["database"] for v in vulnerabilities if v["database"] not in ("Unknown", "General")]
        self.results["database_type"] = known_dbs[0] if known_dbs else None
        self.results["summary"] = {
            "total_parameters_tested": len(parameters),
            "total_vulnerabilities_found": len(vulnerabilities),
            "vulnerable_parameters": sorted({v["parameter"] for v in vulnerabilities}),
            "database_types": sorted({v["database"] for v in vulnerabilities}),
        }
        self.results["scan_completed"] = True
        return self.results

    def print_report(self):
        bar = "=" * 60
        print(f"\n{Fore.CYAN}{bar}\nSCAN REPORT\n{bar}{Style.RESET_ALL}")
        print(f"Target: {self.target_url}\nTimestamp: {self.results['timestamp']}")

        if not self.results["scan_completed"]:
            print(f"\n{Fore.RED}[x] SCAN DID NOT COMPLETE - no conclusion can be drawn.{Style.RESET_ALL}")
            print(f"    Reason: {self.results['error']}")
            return

        if self.results["vulnerable"]:
            print(f"\n{Fore.RED}[!] VULNERABILITIES DETECTED{Style.RESET_ALL}")
            if self.results["database_type"]:
                print(f"    Database type: {self.results['database_type']}")
            for i, vuln in enumerate(self.results["vulnerabilities"], 1):
                print(f"\n  {i}. Parameter: {vuln['parameter']}  [{vuln['technique']}, {vuln['confidence']} confidence]")
                print(f"     Payload:  {vuln['payload']}")
                print(f"     Database: {vuln['database']}")
                print(f"     Evidence: {vuln['evidence']}")
        else:
            print(f"\n{Fore.GREEN}[+] No SQL injection detected in the tested parameters.{Style.RESET_ALL}")
            print("    This does not prove the application is safe: only the probes above were tried.")

        summary = self.results["summary"]
        print(f"\nParameters tested: {summary['total_parameters_tested']}   "
              f"Findings: {summary['total_vulnerabilities_found']}")

    def save_results(self, output_file):
        try:
            with open(output_file, "w") as handle:
                json.dump(self.results, handle, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except OSError as exc:
            print(f"{Fore.RED}[x] Could not save results: {exc}{Style.RESET_ALL}")


def confirm_permission(assume_yes):
    """Ask the operator to confirm authorization. Returns False on 'no' or when stdin is closed."""
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
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner (non-destructive)")
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. http://localhost:8080/item?id=1")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-d", "--data", help="POST body parameters, e.g. 'user=a&id=1' (with -m POST)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Parameters tested in parallel")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--cookie", help='Session cookie, e.g. "session=abc123"')
    parser.add_argument("--proxy", help="Proxy server, e.g. http://127.0.0.1:8080")
    parser.add_argument("-o", "--output", help="Write results to this JSON file")
    parser.add_argument("--yes", action="store_true", help="Skip the permission prompt (you confirm you are authorized)")
    args = parser.parse_args()

    if not confirm_permission(args.yes):
        print(f"{Fore.RED}[!] Exiting. Only test systems you own or have written permission to test.{Style.RESET_ALL}")
        return 2

    try:
        scanner = SQLInjectionDetector(args.url, args.method, args.threads, args.timeout,
                                       args.cookie, args.proxy, args.data)
    except ValueError as exc:
        print(f"{Fore.RED}[x] {exc}{Style.RESET_ALL}")
        return 2

    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
        return 2

    scanner.print_report()
    if args.output:
        scanner.save_results(args.output)

    if not scanner.results["scan_completed"]:
        return 2
    return 1 if scanner.results["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
