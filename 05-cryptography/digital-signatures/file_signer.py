#!/usr/bin/env python3
"""
File signing and verification with Ed25519
Location: 05-cryptography/digital-signatures/file_signer.py

  keygen   create a password-protected Ed25519 key pair
  sign     write <file>.sig (detached signature with the file's SHA-256 and the key id)
  verify   check a file against its .sig and a public key

Ed25519 is fast, has no parameters to get wrong, and produces 64-byte signatures.
Verification failing for ANY reason (wrong key, edited file, malformed .sig) returns exit code 1,
and a signature is only trusted when the key id in the .sig matches the public key you supplied.
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def passphrase_from(env_name):
    value = os.environ.get(env_name) if env_name else None
    return (value or getpass.getpass("Key passphrase: ")).encode()


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_keys(private_path, public_path, passphrase):
    key = Ed25519PrivateKey.generate()
    with open(private_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(passphrase)))
    os.chmod(private_path, 0o600)
    with open(public_path, "wb") as handle:
        handle.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_id(key.public_key())


def sign_file(path, private_path, passphrase, sig_path=None):
    with open(private_path, "rb") as handle:
        private_key = serialization.load_pem_private_key(handle.read(), password=passphrase)
    digest = sha256_file(path)
    record = {
        "algorithm": "Ed25519", "file": os.path.basename(path), "sha256": digest,
        "key_id": key_id(private_key.public_key()),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # The signature covers the digest AND the metadata, so none of it can be edited undetected.
    payload = json.dumps(record, sort_keys=True).encode()
    record["signature"] = base64.b64encode(private_key.sign(payload)).decode()
    sig_path = sig_path or path + ".sig"
    with open(sig_path, "w") as handle:
        json.dump(record, handle, indent=2)
    return sig_path, record


def verify_file(path, public_path, sig_path=None):
    """Return (ok, reason)."""
    sig_path = sig_path or path + ".sig"
    try:
        with open(public_path, "rb") as handle:
            public_key = serialization.load_pem_public_key(handle.read())
        record = json.load(open(sig_path))
        signature = base64.b64decode(record.pop("signature"))
    except (OSError, ValueError, KeyError) as exc:
        return False, f"cannot read key or signature: {exc}"

    if not isinstance(public_key, Ed25519PublicKey):
        return False, "public key is not an Ed25519 key"
    if record.get("key_id") != key_id(public_key):
        return False, "signature was made by a different key"
    try:
        public_key.verify(signature, json.dumps(record, sort_keys=True).encode())
    except InvalidSignature:
        return False, "signature does not match (record was altered or wrong key)"
    if sha256_file(path) != record.get("sha256"):
        return False, "file content has changed since it was signed"
    return True, f"valid signature by key {record['key_id']} at {record['signed_at']}"


def main():
    parser = argparse.ArgumentParser(description="Ed25519 file signer")
    parser.add_argument("--passphrase-env", help="environment variable holding the key passphrase")
    sub = parser.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", default="signing_private.pem")
    k.add_argument("--public", default="signing_public.pem")
    s = sub.add_parser("sign")
    s.add_argument("file")
    s.add_argument("--key", required=True, help="private key")
    v = sub.add_parser("verify")
    v.add_argument("file")
    v.add_argument("--key", required=True, help="public key")
    v.add_argument("--sig", help="signature file (default: <file>.sig)")
    args = parser.parse_args()

    if args.cmd == "keygen":
        kid = generate_keys(args.private, args.public, passphrase_from(args.passphrase_env))
        print(f"[+] Key id {kid}: wrote {args.private} (encrypted, mode 600) and {args.public}")
    elif args.cmd == "sign":
        path, record = sign_file(args.file, args.key, passphrase_from(args.passphrase_env))
        print(f"[+] Wrote {path} (key {record['key_id']})")
    else:
        ok, reason = verify_file(args.file, args.key, args.sig)
        print(("[+] VALID: " if ok else "[x] INVALID: ") + reason)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
