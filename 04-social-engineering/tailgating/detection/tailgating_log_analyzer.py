#!/usr/bin/env python3
"""
Tailgating and badge-misuse analyzer
Location: 04-social-engineering/tailgating/detection/tailgating_log_analyzer.py

Tailgating (piggybacking) is following an authorised person through a controlled door. Technology
cannot see it directly, but access-control logs show its side effects. Input is a CSV with columns:

  timestamp,door,badge_id,direction,event[,people_count]
  event: granted | denied | forced | held_open        direction: in | out
  people_count (optional): people counted by a door sensor for that event

Rules:
  PEOPLE_MISMATCH     sensor counted more people than badge events: classic tailgating
  ANTI_PASSBACK       a badge went 'in' twice with no 'out' between (passed back, or someone followed)
  IMPOSSIBLE_TRAVEL   one badge at two different doors within --min-travel seconds (cloned or shared badge)
  FORCED_OR_HELD      door forced or held open
  AFTER_HOURS         granted entry outside --hours (default 07-19) or at weekends
  DENIED_THEN_GRANTED three or more denials followed by a grant on the same door (credential guessing)

Exit codes: 0 = no findings, 1 = findings, 2 = input problem.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime

REQUIRED = {"timestamp", "door", "badge_id", "direction", "event"}


def load(path):
    with open(path, newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing column(s): {', '.join(sorted(missing))}")
        rows = []
        for number, row in enumerate(reader, 2):
            try:
                row["_t"] = datetime.fromisoformat(row["timestamp"].strip().replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"line {number}: invalid timestamp {row['timestamp']!r}")
            row["event"] = row["event"].strip().lower()
            row["direction"] = row["direction"].strip().lower()
            rows.append(row)
    return sorted(rows, key=lambda r: r["_t"])


def analyse(rows, min_travel=60, hours=(7, 19)):
    findings = []

    def add(rule, row, message):
        findings.append({"rule": rule, "time": row["timestamp"], "door": row["door"], "badge": row["badge_id"], "message": message})

    inside = {}                  # (badge, door) -> time of the last 'in' with no 'out' yet
    last_seen = {}               # badge -> (door, time)
    denials = defaultdict(int)   # door -> consecutive denials
    for row in rows:
        badge, door, event = row["badge_id"], row["door"], row["event"]

        if event in ("forced", "held_open"):
            add("FORCED_OR_HELD", row, f"door {event.replace('_', ' ')}")
        if event == "denied":
            denials[door] += 1
            continue
        if event != "granted":
            continue

        if denials[door] >= 3:
            add("DENIED_THEN_GRANTED", row, f"{denials[door]} denials on this door before this grant")
        denials[door] = 0

        count = (row.get("people_count") or "").strip()
        if count.isdigit() and int(count) > 1:
            add("PEOPLE_MISMATCH", row, f"sensor counted {count} people for one badge event")

        if row["direction"] == "in":
            if (badge, door) in inside:
                add("ANTI_PASSBACK", row, f"badge went in at this door again without an 'out' since {inside[(badge, door)]}")
            inside[(badge, door)] = row["timestamp"]
        elif row["direction"] == "out":
            inside.pop((badge, door), None)

        if badge in last_seen:
            prev_door, prev_time = last_seen[badge]
            if prev_door != door and (row["_t"] - prev_time).total_seconds() < min_travel:
                add("IMPOSSIBLE_TRAVEL", row, f"badge used at {prev_door} only {(row['_t'] - prev_time).total_seconds():.0f}s earlier")
        last_seen[badge] = (door, row["_t"])

        if row["direction"] == "in" and (row["_t"].weekday() >= 5 or not hours[0] <= row["_t"].hour < hours[1]):
            add("AFTER_HOURS", row, "entry outside normal hours")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Tailgating and badge-misuse analyzer")
    parser.add_argument("log", help="access log CSV")
    parser.add_argument("--min-travel", type=int, default=60, help="seconds needed to walk between two doors")
    parser.add_argument("--hours", default="7-19", help="normal hours, e.g. 7-19")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    try:
        start, end = (int(x) for x in args.hours.split("-"))
        findings = analyse(load(args.log), args.min_travel, (start, end))
    except (OSError, ValueError) as exc:
        print(f"[x] {exc}")
        return 2
    for f in findings:
        print(f"  [{f['rule']}] {f['time']} door={f['door']} badge={f['badge']}: {f['message']}")
    print("[+] No tailgating indicators." if not findings else f"[!] {len(findings)} finding(s). Review the door camera footage for each.")
    if args.output:
        json.dump(findings, open(args.output, "w"), indent=2)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
