#!/usr/bin/env python3
"""
RSA encryption and signatures (OAEP and PSS)
Location: 05-cryptography/encryption/asymmetric/rsa_example.py

  gen      create a password-protected RSA key pair (3072-bit by default)
  encrypt  RSA-OAEP (SHA-256) encrypt a SHORT message with the public key
  decrypt  decrypt with the private key
  sign     RSA-PSS (SHA-256) signature over a file
  verify   check a signature

RSA can only encrypt a few hundred bytes. For real data use hybrid encryption (a random AES key
encrypted with RSA), as in ../symmetric/aes_example.py.

Never use PKCS#1 v1.5 padding for new encryption: it is vulnerable to padding-oracle attacks.
"""

import argparse
import base64
import getpass
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def passphrase_from(env_name):
    value = os.environ.get(env_name) if env_name else None
    return (value or getpass.getpass("Key passphrase: ")).encode()


def generate_keypair(private_path, public_path, passphrase, bits=3072):
    if bits < 2048:
        raise ValueError("RSA keys below 2048 bits are not secure")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    with open(private_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(passphrase)))
    os.chmod(private_path, 0o600)
    with open(public_path, "wb") as handle:
        handle.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def load_private(path, passphrase):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=passphrase)


def load_public(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_public_key(handle.read())


def encrypt(public_key, message: bytes) -> bytes:
    return public_key.encrypt(message, OAEP)


def decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, OAEP)


def sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data, PSS, hashes.SHA256())


def verify(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def main():
    parser = argparse.ArgumentParser(description="RSA-OAEP encryption and RSA-PSS signatures")
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate a key pair")
    g.add_argument("--private", default="rsa_private.pem")
    g.add_argument("--public", default="rsa_public.pem")
    g.add_argument("--bits", type=int, default=3072)

    for name in ("encrypt", "decrypt", "sign", "verify"):
        c = sub.add_parser(name)
        c.add_argument("--key", required=True, help="public key (encrypt/verify) or private key (decrypt/sign)")
        c.add_argument("--in", dest="infile", required=True, help="input file")
        c.add_argument("--out", help="output file (default: input + .enc/.sig)")
        if name == "verify":
            c.add_argument("--sig", required=True, help="signature file")
    parser.add_argument("--passphrase-env", help="environment variable holding the key passphrase")
    args = parser.parse_args()

    if args.cmd == "gen":
        generate_keypair(args.private, args.public, passphrase_from(args.passphrase_env), args.bits)
        print(f"[+] Wrote {args.private} (encrypted, mode 600) and {args.public}")
        return 0

    data = open(args.infile, "rb").read()
    if args.cmd == "encrypt":
        out = args.out or args.infile + ".enc"
        open(out, "wb").write(encrypt(load_public(args.key), data))
        print(f"[+] Encrypted to {out}")
    elif args.cmd == "decrypt":
        out = args.out or args.infile + ".dec"
        open(out, "wb").write(decrypt(load_private(args.key, passphrase_from(args.passphrase_env)), data))
        print(f"[+] Decrypted to {out}")
    elif args.cmd == "sign":
        out = args.out or args.infile + ".sig"
        open(out, "wb").write(sign(load_private(args.key, passphrase_from(args.passphrase_env)), data))
        print(f"[+] Signature written to {out}")
    elif args.cmd == "verify":
        ok = verify(load_public(args.key), open(args.sig, "rb").read(), data)
        print("[+] Signature VALID" if ok else "[x] Signature INVALID")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
