#!/usr/bin/env python3
"""
DNSSEC check
Location: 01-network-security/dns-spoofing/prevention/dnssec_check.py

DNSSEC signs DNS data so a resolver can prove an answer was not forged. This tool asks, for a domain:

  1. Is the zone signed? (DNSKEY records exist)
  2. Does YOUR resolver validate? (the AD "authenticated data" flag is set on a signed name)

Results:
  VALIDATED          signed zone, resolver validated it (AD flag set)         -> good
  SIGNED_NOT_CHECKED signed zone, but your resolver does not validate         -> switch resolver
  UNSIGNED           the domain does not use DNSSEC                           -> ask the owner to sign it
  ERROR              lookup failed (network, SERVFAIL = possible validation failure)

Exit codes: 0 = VALIDATED, 1 = anything else.
Other defences: DNS-over-TLS/HTTPS to a trusted resolver, source-port randomisation, and keeping
resolver software patched.
"""

import argparse
import sys

import dns.flags
import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver
import dns.rdatatype


def default_resolver():
    return dns.resolver.Resolver().nameservers[0]


def check_domain(domain, resolver_ip, timeout=5.0, query=dns.query.udp):
    """Return (status, detail). `query` is injectable so the logic can be tested offline."""
    try:
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = query(request, resolver_ip, timeout=timeout)
    except (dns.exception.DNSException, OSError) as exc:
        return "ERROR", f"lookup failed: {exc}"

    if response.rcode() == dns.rcode.SERVFAIL:
        return "ERROR", "SERVFAIL: for signed domains this can mean DNSSEC validation FAILED (possible tampering)"
    has_keys = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
    if not has_keys:
        return "UNSIGNED", f"{domain} publishes no DNSKEY records"
    if response.flags & dns.flags.AD:
        return "VALIDATED", f"{domain} is signed and {resolver_ip} validated it"
    return "SIGNED_NOT_CHECKED", f"{domain} is signed but {resolver_ip} did not set the AD flag"


def main():
    parser = argparse.ArgumentParser(description="DNSSEC signing and validation check")
    parser.add_argument("domain", nargs="+")
    parser.add_argument("--resolver", help="resolver IP (default: system resolver)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    resolver_ip = args.resolver or default_resolver()
    print(f"[*] Resolver: {resolver_ip}")
    worst = 0
    for domain in args.domain:
        status, detail = check_domain(domain, resolver_ip, args.timeout)
        print(f"  {domain:30} {status:20} {detail}")
        worst = worst or (0 if status == "VALIDATED" else 1)
    return worst


if __name__ == "__main__":
    sys.exit(main())
