#!/usr/bin/env python3
"""
DNS spoofing / cache-poisoning detector
Location: 01-network-security/dns-spoofing/detection/dns_spoof_detector.py

Passively watches DNS traffic (live or from a .pcap) and raises alerts for the patterns a spoofing
attack produces:

  CONFLICTING_ANSWERS  two responses to the same query (same id, name, client) carry different
                       answers: the classic race between a forged and a genuine reply
  WRONG_SOURCE         the response came from a different server than the one the query was sent to
  UNSOLICITED_RESPONSE a response arrived for a query this host never sent (blind injection)
  PRIVATE_ANSWER       a public name resolved to a private/loopback address (spoof or DNS rebinding);
                       names under --internal-domains are exempt

Detection logic lives in DNSSpoofDetector.process_packet(), which only reads packets, so it can be
tested offline. Live capture needs root and libpcap.

Exit codes (pcap mode): 0 = no alerts, 1 = alerts raised.
"""

import argparse
import ipaddress
import json
import sys
import time
from collections import OrderedDict
from datetime import datetime

from scapy.all import DNS, DNSRR, IP, UDP, rdpcap, sniff

NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10")]


def is_non_public(address):
    ip = ipaddress.ip_address(address)
    return any(ip in network for network in NON_PUBLIC if network.version == ip.version)


class DNSSpoofDetector:
    def __init__(self, internal_domains=(), query_ttl=10.0, max_tracked=20000, log_file=None):
        self.internal = tuple(d.lower().rstrip(".") for d in internal_domains)
        self.query_ttl = query_ttl
        self.max_tracked = max_tracked
        self.log_file = log_file
        self.pending = OrderedDict()      # (client, id, qname) -> (server, time)
        self.answers = {}                 # (client, id, qname) -> (frozenset(answers), source)
        self.alerts = []
        self.stats = {"queries": 0, "responses": 0, "alerts": 0}

    @staticmethod
    def _answers(dns):
        """A and AAAA addresses in the answer section (scapy >= 2.5 exposes records as a list)."""
        return frozenset(str(record.rdata) for record in (dns.an or []) if getattr(record, "type", None) in (1, 28))

    def _alert(self, kind, message, **details):
        alert = {"time": datetime.now().isoformat(timespec="seconds"), "type": kind, "message": message, **details}
        self.alerts.append(alert)
        self.stats["alerts"] += 1
        print(f"[ALERT] {kind}: {message}")
        if self.log_file:
            with open(self.log_file, "a") as handle:
                handle.write(json.dumps(alert) + "\n")

    def _expire(self, now):
        while self.pending:
            key, (_, seen) = next(iter(self.pending.items()))
            if now - seen > self.query_ttl or len(self.pending) > self.max_tracked:
                self.pending.popitem(last=False)
                self.answers.pop(key, None)
            else:
                break

    def _is_internal(self, qname):
        return any(qname == d or qname.endswith("." + d) for d in self.internal) or qname.endswith((".local", ".lan", ".internal", ".home.arpa"))

    def process_packet(self, packet, now=None):
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
            return
        now = now if now is not None else time.time()
        dns = packet[DNS]
        if not dns.qd:
            return
        qname = dns.qd[0].qname.decode(errors="replace").lower().rstrip(".")
        self._expire(now)

        if dns.qr == 0:                                       # query: client -> server
            self.stats["queries"] += 1
            self.pending[(packet[IP].src, dns.id, qname)] = (packet[IP].dst, now)
            return

        self.stats["responses"] += 1                          # response: server -> client
        client, source = packet[IP].dst, packet[IP].src
        key = (client, dns.id, qname)
        answers = self._answers(dns)

        if key not in self.pending:
            self._alert("UNSOLICITED_RESPONSE", f"{source} answered '{qname}' to {client} but no matching query was seen",
                        client=client, source=source, name=qname)
        else:
            server = self.pending[key][0]
            if source != server:
                self._alert("WRONG_SOURCE", f"query for '{qname}' went to {server} but the answer came from {source}",
                            client=client, source=source, expected=server, name=qname)
            previous = self.answers.get(key)
            if previous and previous[0] != answers:
                self._alert("CONFLICTING_ANSWERS",
                            f"two different answers for '{qname}' (id {dns.id}): {sorted(previous[0])} from {previous[1]} "
                            f"vs {sorted(answers)} from {source}", name=qname, first=sorted(previous[0]), second=sorted(answers))
            self.answers[key] = (answers, source)

        if not self._is_internal(qname):
            for address in answers:
                if is_non_public(address):
                    self._alert("PRIVATE_ANSWER", f"public name '{qname}' resolved to non-public address {address}",
                                name=qname, address=address)


def main():
    parser = argparse.ArgumentParser(description="DNS spoofing detector")
    parser.add_argument("-i", "--interface", help="capture interface (needs root)")
    parser.add_argument("-r", "--pcap", help="read packets from a pcap file instead")
    parser.add_argument("--internal-domains", default="", help="comma-separated domains allowed to resolve to private IPs")
    parser.add_argument("-l", "--log", help="append alerts to this JSON-lines file")
    parser.add_argument("--yes", action="store_true", help="confirm you may monitor this network")
    args = parser.parse_args()
    if not (args.interface or args.pcap):
        parser.error("give --interface or --pcap")

    detector = DNSSpoofDetector([d for d in args.internal_domains.split(",") if d], log_file=args.log)
    if args.pcap:
        try:
            packets = rdpcap(args.pcap)
        except (OSError, Exception) as exc:
            print(f"[x] Cannot read {args.pcap}: {exc}")
            return 2
        for packet in packets:
            detector.process_packet(packet, now=float(packet.time))
        print(f"[*] {detector.stats['queries']} queries, {detector.stats['responses']} responses, {detector.stats['alerts']} alert(s)")
        return 1 if detector.alerts else 0

    if not args.yes:
        try:
            if input("[?] Do you have permission to monitor this network? (yes/no): ").strip().lower() != "yes":
                return 2
        except EOFError:
            print("[!] No interactive input. Re-run with --yes if you are authorized.")
            return 2
    print(f"[*] Monitoring DNS on {args.interface}. Ctrl+C to stop.")
    try:
        sniff(iface=args.interface, filter="udp port 53", prn=detector.process_packet, store=False)
    except (PermissionError, OSError) as exc:
        print(f"[x] Capture failed ({exc}). Run as root and check the interface name.")
        return 2
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
