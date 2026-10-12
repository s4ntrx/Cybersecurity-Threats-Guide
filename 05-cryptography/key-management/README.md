# Key Management

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | Cryptographic Failures |
| MITRE ATT&CK (v19) | Related: Credential Access / T1552 Unsecured Credentials |
| CWE | CWE-321 Use of Hard-coded Cryptographic Key |
| CAPEC | not applicable |
| Guidance | NIST SP 800-57 Part 1 (key management lifecycle) |

## What it is

Key management is everything that happens to a cryptographic key after you choose an algorithm: generation, storage, distribution, use, rotation, retirement and destruction. Strong encryption with badly handled keys offers little protection.

## How it works

A key that is hard-coded, shared widely, never rotated, or stored next to the data it protects is effectively public. The lifecycle limits the damage: short-lived keys, a separate key per purpose, an audit trail, and the ability to destroy a key and so render the data under it unrecoverable.

## Real-world example

In 2023 an acquired Microsoft consumer signing key was used by attackers to forge authentication tokens for cloud email accounts (Microsoft's incident write-up and the US Cyber Safety Review Board's 2024 report describe it). The failure was in how a high-value key was protected and accounted for.

## Detection

- Search code and repositories for hard-coded keys and secrets (secret scanning)
- Audit key use and age: unused keys, keys past expiry, keys shared across systems
- Alert on decrypt or sign operations from unexpected identities

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Use a managed service or HSM (cloud KMS, HashiCorp Vault) rather than keys in files
2. Envelope encryption: protect data keys with a master key that is never stored in plaintext
3. One key per purpose, with an expiry; rotate on a schedule and after any suspected exposure
4. Keep old versions decrypt-only until data is re-encrypted, then retire and destroy them
5. Keep a tamper-evident audit log of every key operation
6. Never put keys in source code, images or chat

## Scripts in this topic

- [key_manager.py](./key_manager.py): teaching key store with envelope encryption, rotation, destruction and a hash-chained audit log

## Common mistakes

- Rotating by overwriting the key and losing the ability to decrypt old data
- Keeping the master key in the same place as the wrapped keys
- Skipping an audit trail
- Using one key for everything

## Test it safely

Run `key_manager.py init`, create a key, encrypt a file, rotate, then destroy the old version and confirm old ciphertext can no longer be decrypted.

## References

- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CWE-321](https://cwe.mitre.org/data/definitions/321.html)
