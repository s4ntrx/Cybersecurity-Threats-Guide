# Tailgating (Piggybacking)

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | not applicable |
| MITRE ATT&CK (v19) | not applicable (physical access) |
| CWE | not applicable |
| CAPEC | not applicable |
| Control reference | NIST SP 800-53 PE-3 Physical Access Control |

## What it is

Tailgating is entering a controlled area by following an authorised person through a door, often by looking busy, carrying boxes, or simply asking someone to hold the door. The attacker needs no badge.

## How it works

The attack relies on politeness. People hesitate to challenge a stranger. A successful entry gives physical access to workstations, network ports, server rooms and paper records.

## Real-world example

No single incident is cited here yet. Physical-intrusion assessments regularly report tailgating as a successful method; add a primary source when expanding this section.

## Detection

- Door sensors counting more people than badge events (`PEOPLE_MISMATCH`)
- A badge entering twice without leaving (`ANTI_PASSBACK`) or at two doors too quickly (`IMPOSSIBLE_TRAVEL`)
- Doors forced or held open; after-hours entries; repeated denials followed by a grant
- `tailgating_log_analyzer.py` finds all of these in an access-control CSV

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Mantraps or turnstiles at sensitive entrances
2. Anti-passback and door-held-open alarms in the access-control system
3. Visible staff badges; visitors escorted and issued a different badge
4. A culture and a script that makes challenging politely normal: "Can I see your badge?"
5. Cameras at doors, reviewed when the analyzer flags an event

## Scripts in this topic

- [tailgating_log_analyzer.py](./detection/tailgating_log_analyzer.py): access-log rules
- [sample_access_log.csv](./detection/sample_access_log.csv): test data

## Common mistakes

- Relying on a badge reader alone: it authenticates one person, not the people behind them
- Leaving alarms off because they cause false positives instead of tuning them
- Training only reception staff

## Test it safely

Use the provided `sample_access_log.csv`, which contains one planted example of each rule. Physical penetration tests need written authorisation.

## References

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) control PE-3
