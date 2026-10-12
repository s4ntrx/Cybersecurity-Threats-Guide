#!/usr/bin/env python3
"""
SQL Injection Scanner (simple front end)
Location: 02-web-application-security/sql-injection/detection/sql_injection_scanner.py

A minimal command line for quick GET-parameter checks. It reuses the engine in
sql_injection_detector.py, so both tools share one set of (non-destructive)
payloads, error patterns and reporting. Use sql_injection_detector.py directly
when you need POST bodies, cookies, a proxy or threading.

Exit codes: 0 = no finding, 1 = vulnerability found, 2 = scan could not complete.
"""

import argparse
import sys

from sql_injection_detector import SQLInjectionDetector, confirm_permission


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner (simple)")
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. http://localhost:8080/item?id=1")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="Write results to this JSON file")
    parser.add_argument("--yes", action="store_true", help="Skip the permission prompt (you confirm you are authorized)")
    args = parser.parse_args()

    if not confirm_permission(args.yes):
        print("[!] Exiting. Only test systems you own or have written permission to test.")
        return 2

    try:
        scanner = SQLInjectionDetector(args.url, timeout=args.timeout)
    except ValueError as exc:
        print(f"[x] {exc}")
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
