#!/usr/bin/env python3
"""
Safe file access: stop path traversal and file inclusion
Location: 02-web-application-security/file-inclusion/prevention/safe_file_access.py

Three layers, strongest first:

  1. allowlist_lookup(): never build a path from user input. Map a short key ("terms") to a fixed
     file and reject everything else.
  2. safe_join(): when a user-supplied name is unavoidable, resolve the final real path (following
     symlinks and ../ ) and require it to stay inside the base directory.
  3. allowed extensions and null-byte rejection.

Checking for the text "../" is NOT a defence: attackers use ..%2f, ....//, backslashes and
double encoding. Always resolve the path and compare it to the base directory.
"""

import os


class UnsafePath(ValueError):
    pass


def allowlist_lookup(key, mapping):
    """mapping example: {"terms": "/srv/app/pages/terms.html", "privacy": "/srv/app/pages/privacy.html"}"""
    try:
        return mapping[key]
    except (KeyError, TypeError):
        raise UnsafePath(f"unknown resource: {key!r}")


def safe_join(base_dir, user_path, allowed_extensions=None):
    if "\x00" in user_path:
        raise UnsafePath("null byte in path")
    if os.path.isabs(user_path) or user_path.startswith(("\\", "/")) or (len(user_path) > 1 and user_path[1] == ":"):
        raise UnsafePath("absolute paths are not allowed")
    base = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base, user_path))   # resolves .., symlinks
    if os.path.commonpath([base, candidate]) != base:
        raise UnsafePath("path escapes the base directory")
    if allowed_extensions and os.path.splitext(candidate)[1].lower() not in allowed_extensions:
        raise UnsafePath("file type not allowed")
    return candidate


def read_file(base_dir, user_path, allowed_extensions=(".txt", ".html", ".md")):
    path = safe_join(base_dir, user_path, allowed_extensions)
    with open(path, "rb") as handle:
        return handle.read()


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as base:
        open(os.path.join(base, "report.txt"), "w").write("quarterly report")
        for attempt in ["report.txt", "../etc/passwd", "/etc/passwd", "report.txt\x00.png", "sub/../report.txt", "..%2f..%2fetc/passwd"]:
            try:
                print(f"{attempt!r:34} -> OK, read {len(read_file(base, attempt))} bytes")
            except UnsafePath as exc:
                print(f"{attempt!r:34} -> blocked: {exc}")
            except OSError as exc:
                print(f"{attempt!r:34} -> not found")
