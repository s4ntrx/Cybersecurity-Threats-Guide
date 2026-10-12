# Baiting

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | not applicable |
| MITRE ATT&CK (v19) | Initial Access / T1091 Replication Through Removable Media; T1200 Hardware Additions |
| CWE | not applicable |
| CAPEC | not applicable |
| Example CVE | not applicable |

## What it is

Baiting leaves something tempting, usually a USB drive labelled "Payroll" or "Confidential", where a victim will find it. Plugging it in runs malware, or the device pretends to be a keyboard and types attack commands.

## How it works

Two mechanisms are common. Storage media carry files that look like documents but are programs (double extensions such as `invoice.pdf.exe`, autorun files, shortcuts, macros). Programmable USB devices present themselves as a keyboard and send keystrokes faster than a person, opening a shell and downloading malware in seconds.

## Real-world example

In 2008 the US Department of Defense suffered a widely reported compromise by the `agent.btz` worm, spread through removable media, which led to a ban on USB drives across military networks. Add a primary source when expanding this section.

## Detection

- Inspect the drive without opening anything: autorun files, executables in the root, double extensions, macro documents (`usb_bait_scanner.py`)
- A "storage" device that also presents a keyboard interface (keystroke-injection signature)
- Endpoint alerts for new USB device classes; logs of newly attached devices

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Disable autorun and autoplay; block unknown removable storage with device control (allow-list approved devices)
2. Block USB HID devices from unmanaged storage-class devices where possible
3. Teach staff: never plug in found media; hand it to IT
4. Give IT a sacrificial or kiosk machine that mounts media read-only (`mount -o ro,noexec,nosuid,nodev`)
5. Keep endpoint protection current and restrict macros in Office documents

## Scripts in this topic

- [usb_bait_scanner.py](./detection/usb_bait_scanner.py): read-only folder and USB descriptor checks

## Common mistakes

- Believing a drive is safe because it looks new or sealed
- Scanning with antivirus after opening the files
- Treating only storage devices as a risk: charging cables and keyboards can also be implants

## Test it safely

Use an empty folder or a throwaway virtual machine. Never test with real malware.

## References

- [MITRE ATT&CK T1091](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK T1200](https://attack.mitre.org/techniques/T1200/)
