#!/usr/bin/env python3
"""
Minimal key manager: envelope encryption, rotation and an audit trail
Location: 05-cryptography/key-management/key_manager.py

A teaching implementation of the key lifecycle from NIST SP 800-57: generate, use, rotate,
retire, destroy.

  * A master key is derived from a passphrase with scrypt (never stored).
  * Every data key is random (32 bytes) and stored only WRAPPED (AES-256-GCM) under the master key.
  * Rotation creates version N+1 for new encryption; older versions stay readable until retired.
  * Destroyed keys have their wrapped material removed, so data encrypted under them is unrecoverable.
  * Every action is appended to a hash-chained audit log (editing history breaks the chain).

For production use a KMS or HSM (AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault).
Never hard-code keys in source files (CWE-321).
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

b64 = lambda raw: base64.b64encode(raw).decode()
unb64 = lambda text: base64.b64decode(text)
now = lambda: datetime.now(timezone.utc)


class KeyStoreError(Exception):
    pass


class KeyStore:
    def __init__(self, directory, passphrase):
        self.dir = directory
        self.store_path = os.path.join(directory, "keystore.json")
        self.audit_path = os.path.join(directory, "audit.log")
        self.passphrase = passphrase.encode()
        self.data = None
        self.master = None

    # ----------------------------------------------------------- persistence
    def _derive(self, salt):
        return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(self.passphrase)

    def _save(self):
        tmp = self.store_path + ".tmp"
        with open(tmp, "w") as handle:
            json.dump(self.data, handle, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.store_path)                 # atomic: no half-written keystore

    def init(self):
        if os.path.exists(self.store_path):
            raise KeyStoreError("keystore already exists")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        salt = os.urandom(16)
        self.master = self._derive(salt)
        nonce = os.urandom(12)
        # A known plaintext lets us detect a wrong passphrase instead of failing later.
        check = AESGCM(self.master).encrypt(nonce, b"keystore-v1", None)
        self.data = {"version": 1, "salt": b64(salt), "check": b64(nonce + check), "keys": {}}
        self._save()
        self._audit("init", "-")

    def open(self):
        if not os.path.exists(self.store_path):
            raise KeyStoreError("no keystore here; run init first")
        with open(self.store_path) as handle:
            self.data = json.load(handle)
        self.master = self._derive(unb64(self.data["salt"]))
        blob = unb64(self.data["check"])
        try:
            AESGCM(self.master).decrypt(blob[:12], blob[12:], None)
        except InvalidTag:
            raise KeyStoreError("wrong passphrase")

    # ----------------------------------------------------------- audit trail
    def _audit(self, action, key_id):
        previous = "0" * 64
        if os.path.exists(self.audit_path):
            lines = open(self.audit_path).read().splitlines()
            if lines:
                previous = json.loads(lines[-1])["hash"]
        entry = {"time": now().isoformat(timespec="seconds"), "action": action, "key": key_id, "prev": previous}
        entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        with open(self.audit_path, "a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def verify_audit(self):
        previous = "0" * 64
        for number, line in enumerate(open(self.audit_path).read().splitlines(), 1):
            entry = json.loads(line)
            claimed = entry.pop("hash")
            if entry["prev"] != previous or hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest() != claimed:
                return False, number
            previous = claimed
        return True, None

    # ----------------------------------------------------------- key lifecycle
    def _wrap(self, key_id, raw):
        nonce = os.urandom(12)
        return b64(nonce + AESGCM(self.master).encrypt(nonce, raw, key_id.encode()))   # key id is authenticated

    def _unwrap(self, key_id, wrapped):
        blob = unb64(wrapped)
        return AESGCM(self.master).decrypt(blob[:12], blob[12:], key_id.encode())

    def create(self, name, valid_days=90):
        version = 1 + max((k["version"] for k in self.data["keys"].values() if k["name"] == name), default=0)
        key_id = f"{name}-v{version}"
        self.data["keys"][key_id] = {
            "name": name, "version": version, "status": "active",
            "created": now().isoformat(timespec="seconds"),
            "expires": (now() + timedelta(days=valid_days)).isoformat(timespec="seconds"),
            "wrapped": self._wrap(key_id, os.urandom(32)),
        }
        self._save()
        self._audit("create", key_id)
        return key_id

    def rotate(self, name):
        """New version for new encryption; the previous active version becomes 'decrypt-only'."""
        for key_id, meta in self.data["keys"].items():
            if meta["name"] == name and meta["status"] == "active":
                meta["status"] = "decrypt-only"
                self._audit("rotate-out", key_id)
        return self.create(name)

    def set_status(self, key_id, status):
        meta = self._meta(key_id)
        if status == "destroyed":
            meta["wrapped"] = None
        meta["status"] = status
        self._save()
        self._audit(status, key_id)

    def _meta(self, key_id):
        if key_id not in self.data["keys"]:
            raise KeyStoreError(f"unknown key {key_id}")
        return self.data["keys"][key_id]

    def _raw(self, key_id, need):
        meta = self._meta(key_id)
        if meta["status"] == "destroyed" or not meta["wrapped"]:
            raise KeyStoreError(f"{key_id} has been destroyed")
        if need == "encrypt" and meta["status"] != "active":
            raise KeyStoreError(f"{key_id} is {meta['status']} and cannot be used to encrypt")
        if need == "encrypt" and datetime.fromisoformat(meta["expires"]) < now():
            raise KeyStoreError(f"{key_id} has expired; rotate it")
        return self._unwrap(key_id, meta["wrapped"])

    def active_key_id(self, name):
        for key_id, meta in self.data["keys"].items():
            if meta["name"] == name and meta["status"] == "active":
                return key_id
        raise KeyStoreError(f"no active key named {name}")

    def encrypt(self, name, plaintext: bytes) -> dict:
        key_id = self.active_key_id(name)
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._raw(key_id, "encrypt")).encrypt(nonce, plaintext, key_id.encode())
        self._audit("encrypt", key_id)
        return {"key_id": key_id, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}

    def decrypt(self, blob: dict) -> bytes:
        key_id = blob["key_id"]
        plaintext = AESGCM(self._raw(key_id, "decrypt")).decrypt(unb64(blob["nonce"]), unb64(blob["ciphertext"]), key_id.encode())
        self._audit("decrypt", key_id)
        return plaintext

    def listing(self):
        rows = []
        for key_id, meta in sorted(self.data["keys"].items()):
            expired = datetime.fromisoformat(meta["expires"]) < now()
            rows.append((key_id, "expired" if expired and meta["status"] == "active" else meta["status"], meta["created"], meta["expires"]))
        return rows


def open_store(args):
    passphrase = os.environ.get(args.passphrase_env) or getpass.getpass("Keystore passphrase: ")
    store = KeyStore(args.dir, passphrase)
    return store


def main():
    parser = argparse.ArgumentParser(description="Teaching key manager (envelope encryption + rotation + audit log)")
    parser.add_argument("--dir", default="keystore", help="keystore directory")
    parser.add_argument("--passphrase-env", default="KEYSTORE_PASSPHRASE", help="env var holding the passphrase")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    c = sub.add_parser("create"); c.add_argument("name"); c.add_argument("--days", type=int, default=90)
    r = sub.add_parser("rotate"); r.add_argument("name")
    sub.add_parser("list")
    for name in ("retire", "destroy"):
        d = sub.add_parser(name); d.add_argument("key_id")
    sub.add_parser("audit")
    e = sub.add_parser("encrypt"); e.add_argument("name"); e.add_argument("infile"); e.add_argument("outfile")
    d = sub.add_parser("decrypt"); d.add_argument("infile"); d.add_argument("outfile")
    args = parser.parse_args()

    try:
        store = open_store(args)
        if args.cmd == "init":
            store.init(); print(f"[+] Keystore created in {args.dir}")
            return 0
        store.open()
        if args.cmd == "create":
            print("[+] Created", store.create(args.name, args.days))
        elif args.cmd == "rotate":
            print("[+] New active key", store.rotate(args.name))
        elif args.cmd == "list":
            for row in store.listing():
                print("%-22s %-13s created %s  expires %s" % row)
        elif args.cmd in ("retire", "destroy"):
            store.set_status(args.key_id, "retired" if args.cmd == "retire" else "destroyed")
            print(f"[+] {args.key_id}: {args.cmd}")
        elif args.cmd == "audit":
            ok, line = store.verify_audit()
            print("[+] Audit log intact" if ok else f"[x] Audit log tampered at line {line}")
            return 0 if ok else 1
        elif args.cmd == "encrypt":
            json.dump(store.encrypt(args.name, open(args.infile, "rb").read()), open(args.outfile, "w"))
            print(f"[+] Encrypted to {args.outfile}")
        elif args.cmd == "decrypt":
            open(args.outfile, "wb").write(store.decrypt(json.load(open(args.infile))))
            print(f"[+] Decrypted to {args.outfile}")
    except (KeyStoreError, InvalidTag) as exc:
        print(f"[x] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
