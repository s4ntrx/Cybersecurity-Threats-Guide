#!/usr/bin/env python3
"""
USB baiting scanner
Location: 04-social-engineering/baiting/detection/usb_bait_scanner.py

Baiting leaves infected or malicious media where a curious person will plug it in. Two read-only checks:

  1. scan_directory(): inspect a mounted drive WITHOUT opening anything on it
       autorun.inf; executables and scripts (.exe .scr .bat .ps1 .vbs .js .jar .lnk .hta .msi ...);
       DOUBLE extensions such as invoice.pdf.exe; macro-enabled Office files; hidden files at the top
       level; very long names with padding spaces that hide the real extension
  2. inspect_usb_devices(): look at the USB descriptors on Linux. A "flash drive" that ALSO presents a
       HID keyboard interface is the signature of keystroke-injection devices (Rubber Ducky, BadUSB)

Never double-click files from found media. Mount it read-only (mount -o ro,noexec,nosuid,nodev) or use a
sacrificial machine. Exit codes: 0 = clean, 1 = findings, 2 = input problem.
"""

import argparse
import json
import os
import re
import sys

EXECUTABLE = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".jar", ".lnk",
              ".hta", ".msi", ".dll", ".sh", ".desktop", ".command", ".app", ".apk", ".reg", ".cpl"}
DOCUMENT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rtf"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def scan_directory(root, max_files=20000):
    findings, count = [], 0
    root = os.path.abspath(root)
    for folder, _dirs, files in os.walk(root):
        for name in files:
            count += 1
            if count > max_files:
                findings.append({"severity": "LOW", "file": root, "issue": f"stopped after {max_files} files"})
                return findings
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            lower = name.lower()
            stem, ext = os.path.splitext(lower)
            inner_ext = os.path.splitext(stem)[1]

            if lower == "autorun.inf":
                findings.append({"severity": "HIGH", "file": rel, "issue": "autorun.inf (tries to launch code when the drive is inserted)"})
            if ext in EXECUTABLE and inner_ext in DOCUMENT:
                findings.append({"severity": "HIGH", "file": rel, "issue": f"double extension '{inner_ext}{ext}': an executable disguised as a document"})
            elif ext in EXECUTABLE:
                top_level = os.path.dirname(rel) == ""
                findings.append({"severity": "HIGH" if top_level else "MEDIUM", "file": rel,
                                 "issue": f"executable or script type ({ext})" + (" in the drive root" if top_level else "")})
            if ext in MACRO:
                findings.append({"severity": "MEDIUM", "file": rel, "issue": "macro-enabled Office document"})
            if re.search(r"\s{5,}\.\w+$", name):
                findings.append({"severity": "HIGH", "file": rel, "issue": "padding spaces before the extension hide the real file type"})
            if name.startswith(".") and os.path.dirname(rel) == "" and lower not in {".ds_store", ".trashes", ".fseventsd"}:
                findings.append({"severity": "LOW", "file": rel, "issue": "hidden file in the drive root"})
    return findings


def read(path):
    try:
        return open(path).read().strip()
    except OSError:
        return ""


def inspect_usb_devices(sysfs="/sys/bus/usb/devices"):
    """Flag devices exposing more than one interface class where HID keyboard is mixed with storage."""
    findings = []
    if not os.path.isdir(sysfs):
        return findings
    devices = {}
    for entry in os.listdir(sysfs):
        device_id = entry.split(":")[0]
        iface = os.path.join(sysfs, entry)
        cls = read(os.path.join(iface, "bInterfaceClass"))
        if cls:
            proto = read(os.path.join(iface, "bInterfaceProtocol"))
            devices.setdefault(device_id, []).append((cls.lower(), proto))
    for device_id, interfaces in devices.items():
        classes = {c for c, _ in interfaces}
        keyboard = any(c == "03" and p == "01" for c, p in interfaces)
        product = read(os.path.join(sysfs, device_id, "product")) or "unknown device"
        if keyboard and "08" in classes:
            findings.append({"severity": "HIGH", "file": device_id,
                             "issue": f"'{product}' is a storage device that ALSO acts as a keyboard (keystroke-injection signature)"})
        elif keyboard and len(classes) > 1:
            findings.append({"severity": "MEDIUM", "file": device_id,
                             "issue": f"'{product}' is a keyboard with extra interfaces ({', '.join(sorted(classes))}); verify it is a genuine device"})
    return findings


def main():
    parser = argparse.ArgumentParser(description="USB baiting scanner (read-only)")
    parser.add_argument("path", nargs="?", help="mounted drive or folder to inspect")
    parser.add_argument("--check-usb", action="store_true", help="also inspect attached USB devices (Linux)")
    parser.add_argument("--sysfs", default="/sys/bus/usb/devices", help=argparse.SUPPRESS)
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    if not args.path and not args.check_usb:
        parser.error("give a path to scan and/or --check-usb")
    findings = []
    if args.path:
        if not os.path.isdir(args.path):
            print(f"[x] Not a directory: {args.path}")
            return 2
        findings += scan_directory(args.path)
    if args.check_usb:
        findings += inspect_usb_devices(args.sysfs)
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    for f in findings:
        print(f"  [{f['severity']}] {f['file']}: {f['issue']}")
    print("[+] Nothing suspicious found. Still mount unknown media read-only." if not findings else f"[!] {len(findings)} finding(s): do NOT open files from this media")
    if args.output:
        json.dump(findings, open(args.output, "w"), indent=2)
    return 1 if [f for f in findings if f["severity"] != "LOW"] else 0


if __name__ == "__main__":
    sys.exit(main())
