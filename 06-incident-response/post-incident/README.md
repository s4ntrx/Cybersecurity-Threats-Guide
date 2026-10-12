# Post-Incident Analysis

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | not applicable |
| MITRE ATT&CK (v19) | Map each technique observed in the incident to its ATT&CK ID in the report |
| CWE | not applicable |
| CAPEC | not applicable |
| Guidance | NIST SP 800-61 (incident handling lifecycle; confirm the current revision) |

## What it is

Post-incident analysis (a post-mortem or lessons-learned review) turns an incident into improvements. It records what happened, how quickly the team detected and contained it, why it was possible, and who will fix what by when.

## How it works

A good review is blameless: it asks what in the system and process allowed the failure, not who to blame. It is built from a timeline, response metrics (time to detect, contain, eradicate, recover), a root cause, an impact statement and owned, dated action items.

## Real-world example

`sample_incident.json` is a fictional phishing-led account takeover used to demonstrate the format. It is not a real case.

## Detection

- Missing lifecycle events (no detection or containment time recorded)
- Events out of order, which usually means timestamps were copied from different time zones
- Action items without an owner or a due date

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Hold the review within a week, while memories are fresh
2. Write a timeline from logs, not from memory
3. Track the four metrics over time: a falling time to detect is the clearest sign of improvement
4. Assign every action item an owner and a date, and review them until closed
5. Share the lessons with the wider organisation

## Scripts in this topic

- [post_incident_report.py](./post_incident_report.py): Markdown report from an incident JSON file
- [sample_incident.json](./sample_incident.json): example input

## Common mistakes

- Writing the report to assign blame
- Stopping at the proximate cause instead of asking why the control failed
- Filing action items that nobody tracks

## Test it safely

Copy `sample_incident.json`, edit it with your own timeline, and run `post_incident_report.py`.

## References

- [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r3/final) Incident Response Recommendations
- [MITRE ATT&CK](https://attack.mitre.org/)
