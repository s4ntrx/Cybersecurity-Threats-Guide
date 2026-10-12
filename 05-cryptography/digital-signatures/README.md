# Digital Signatures

> **Last reviewed:** 2026-10-11 | **Status:** Draft (new topic; scripts tested against local lab targets, references not yet independently re-verified)

## Standards mapping

| Framework | Reference |
|---|---|
| OWASP Top 10:2025 | Software or Data Integrity Failures; Cryptographic Failures |
| MITRE ATT&CK (v19) | Related: Defense Evasion code-signing abuse (T1553.002) |
| CWE | CWE-347 Improper Verification of Cryptographic Signature |
| CAPEC | not applicable |
| Example | Flame malware forged a Microsoft code-signing certificate (2012) |

## What it is

A digital signature proves that data came from the holder of a private key and has not been changed since. Anyone with the public key can check it. It provides integrity and authenticity, and non-repudiation when the key is controlled by one party.

## How it works

The signer hashes the data and transforms the hash with the private key. The verifier recomputes the hash and checks it against the signature with the public key. Any change to the data, the signature or the signed metadata makes verification fail. The weak points are usually key theft, weak hash functions and verifiers that skip or mishandle the check.

## Real-world example

The Flame malware (2012) used a chosen-prefix collision against the MD5 hash to forge a certificate chaining to Microsoft's, letting malicious code appear to be signed by Microsoft. Microsoft revoked the affected certificates (Security Advisory 2718704).

## Detection

- Find unsigned artifacts that should be signed (packages, releases, containers, firmware)
- Alert on signature verification failures instead of logging and continuing
- Monitor certificate transparency logs and code-signing key usage

## Prevention

In order of strength. The first items fix the cause; the rest reduce risk.

1. Use modern algorithms: Ed25519 or ECDSA P-256, or RSA-PSS with 3072-bit keys; never MD5 or SHA-1
2. Verify before use, fail closed, and check that the signing key is the one you expect (pin the key id)
3. Protect signing keys in an HSM or a managed key service; separate build and signing duties
4. Sign metadata together with the file hash so none of it can be swapped
5. Plan revocation and key rotation before you need them

## Scripts in this topic

- [file_signer.py](./file_signer.py): Ed25519 key generation, detached signatures, strict verification

## Common mistakes

- Verifying that a signature is well-formed but not who made it
- Trusting a signature when the public key came from the same download
- Signing only the file name or a timestamp, not the content hash
- Treating a valid signature as proof the software is safe: it proves origin only

## Test it safely

Use `file_signer.py` in a scratch folder: sign a file, change one byte, and watch verification fail.

## References

- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) Edwards-Curve Digital Signature Algorithm (EdDSA)
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- [MITRE ATT&CK T1553.002](https://attack.mitre.org/techniques/T1553/002/)
