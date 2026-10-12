#!/usr/bin/env python3
"""
Post-incident analysis report generator
Location: 06-incident-response/post-incident/post_incident_report.py

Reads an incident record (JSON) and produces a Markdown report with:
  * the timeline, sorted by time
  * response metrics: time to detect, contain, eradicate, recover (and total duration)
  * data-quality warnings (missing phases, events out of order, no owners on action items)
  * root cause, impact, lessons learned and action items

Phases follow the NIST SP 800-61 lifecycle: detection, containment, eradication, recovery.
Blameless by design: describe systems and decisions, not people's faults.

Exit codes: 0 report written, 2 input problem.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta

PHASES = ["start", "detected", "contained", "eradicated", "recovered", "closed"]


def parse_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def human(delta):
    if delta is None:
        return "not recorded"
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "negative (check timestamps)"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    return " ".join(p for p in (f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m") if p) or "0m"


def analyse(incident):
    problems = []
    events = []
    for index, event in enumerate(incident.get("events", []), 1):
        try:
            events.append({**event, "_t": parse_time(event["time"])})
        except (KeyError, ValueError):
            problems.append(f"event {index} has a missing or invalid ISO-8601 time: {event.get('time')!r}")
    events.sort(key=lambda e: e["_t"])

    first = {}
    for event in events:
        first.setdefault(event.get("type", "note"), event["_t"])

    for phase in PHASES[:5]:
        if phase not in first:
            problems.append(f"no '{phase}' event recorded, so related metrics are unavailable")

    seen = [first[p] for p in PHASES if p in first]
    if seen != sorted(seen):
        problems.append("lifecycle events are out of order (for example 'contained' before 'detected')")

    def gap(a, b):
        return first[b] - first[a] if a in first and b in first else None

    metrics = {
        "Time to detect (start to detected)": gap("start", "detected"),
        "Time to contain (detected to contained)": gap("detected", "contained"),
        "Time to eradicate (contained to eradicated)": gap("contained", "eradicated"),
        "Time to recover (detected to recovered)": gap("detected", "recovered"),
        "Total duration (start to closed)": gap("start", "closed") or gap("start", "recovered"),
    }
    for item in incident.get("action_items", []):
        if not item.get("owner") or not item.get("due"):
            problems.append(f"action item without owner or due date: {item.get('item', '?')}")
    return events, metrics, problems


def render(incident, events, metrics, problems):
    lines = [f"# Post-incident report: {incident.get('title', 'Untitled incident')}", ""]
    lines += [f"- **Severity:** {incident.get('severity', 'not set')}",
              f"- **Detected by:** {incident.get('detected_by', 'not set')}",
              f"- **Report generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]

    lines += ["## Summary", "", incident.get("summary", "_Add a two to three sentence summary._"), ""]
    lines += ["## Timeline", "", "| Time | Phase | What happened |", "|---|---|---|"]
    for event in events:
        lines.append(f"| {event['time']} | {event.get('type', 'note')} | {event.get('description', '')} |")
    lines += ["", "## Response metrics", "", "| Metric | Value |", "|---|---|"]
    lines += [f"| {name} | {human(value)} |" for name, value in metrics.items()]

    lines += ["", "## Root cause", "", incident.get("root_cause", "_Not yet determined._"), ""]
    lines += ["## Impact", "", incident.get("impact", "_Not yet assessed._"), ""]
    for heading, key in (("What went well", "what_went_well"), ("What went wrong", "what_went_wrong")):
        lines += [f"## {heading}", ""]
        lines += [f"- {entry}" for entry in incident.get(key, [])] or ["_Nothing recorded._"]
        lines.append("")
    lines += ["## Action items", "", "| Action | Owner | Due |", "|---|---|---|"]
    for item in incident.get("action_items", []):
        lines.append(f"| {item.get('item', '')} | {item.get('owner', 'UNASSIGNED')} | {item.get('due', 'NO DATE')} |")
    if problems:
        lines += ["", "## Data-quality warnings", ""] + [f"- {p}" for p in problems]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate a post-incident report from a JSON incident record")
    parser.add_argument("-i", "--input", required=True, help="incident JSON file")
    parser.add_argument("-o", "--output", default="post_incident_report.md")
    args = parser.parse_args()
    try:
        incident = json.load(open(args.input))
    except (OSError, ValueError) as exc:
        print(f"[x] Cannot read {args.input}: {exc}")
        return 2
    events, metrics, problems = analyse(incident)
    open(args.output, "w").write(render(incident, events, metrics, problems))
    print(f"[+] Report written to {args.output}")
    for problem in problems:
        print(f"[!] {problem}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
