# 🔐 Cryptography

[Back to Main](../README.md)

## 📖 Overview
Cryptography is the practice and study of techniques for secure communication in the presence of adversaries. This section covers encryption algorithms, hashing functions, digital signatures, and key management practices essential for protecting data.

## 📋 Categories Covered

1. Symmetric Encryption - Same key for encryption/decryption *(planned)*
2. [Asymmetric Encryption](./encryption/asymmetric/README.md) - Public/private key pairs
3. [Hashing Functions](./hashing/README.md) - One-way cryptographic hashes
4. [Digital Signatures](./digital-signatures/README.md) - Message authentication and non-repudiation
5. [Key Management](./key-management/README.md) - Generation, storage, and rotation

## 🛡️ Cryptographic Primitives

| Type | Algorithms | Use Cases |
|------|------------|-----------|
| **Symmetric** | AES, DES, 3DES, ChaCha20 | Data at rest, File encryption |
| **Asymmetric** | RSA, ECC, Diffie-Hellman | Key exchange, Digital signatures |
| **Hashing** | SHA-2, SHA-3, MD5 (insecure) | Password storage, Integrity checks |
| **MAC** | HMAC, CMAC | Message authentication |

## 🚀 Quick Start

```bash
# Navigate to encryption examples
cd 05-cryptography/encryption/symmetric/
python aes_example.py --encrypt --file secret.txt --key mykey.key

# Try hashing
cd ../hashing/
python password_hashing.py --hash "MySecurePassword123!"
python integrity_checker.py --verify-file important.doc
```

## ⚠️ Security Warnings (Cryptography Best Practices)

- 🔐 **Never roll your own crypto**  
  Use established, peer-reviewed cryptographic libraries.

- 🗝️ **Keep keys secure**  
  Use Hardware Security Modules (HSMs) in production environments.

- 🧮 **Use modern algorithms**  
  Avoid outdated or broken algorithms such as **MD5, SHA1, and DES**.

- 🔄 **Implement Perfect Forward Secrecy (PFS)**  
  Use ephemeral keys to protect past sessions if long-term keys are compromised.

- 🔁 **Regular key rotation**  
  Change encryption keys periodically according to your security policy.

---

### ✅ Best Practice Reminder

- Prefer well-vetted standards (e.g., AES-256, RSA-2048+, ECC, SHA-256+).  
- Follow industry guidance from NIST and OWASP.  
- Conduct regular security reviews and cryptographic audits.


### `05-cryptography/encryption/README.md`

# 🔑 Encryption

## 📖 Overview
Encryption transforms readable data (plaintext) into an unreadable format (ciphertext) using an algorithm and key. Only those with the correct key can decrypt and read the data.

## 🎯 Types of Encryption

### 1. Symmetric Encryption
- Same key for encryption and decryption
- Fast and efficient for large data
- Challenge: Secure key distribution

**Algorithms:**
- **AES** (Advanced Encryption Standard) - Current standard
- **ChaCha20** - Fast stream cipher
- **3DES** - Legacy, avoid if possible

### 2. Asymmetric Encryption
- Different keys for encryption (public) and decryption (private)
- Slower but solves key distribution
- Used for key exchange and digital signatures

**Algorithms:**
- **RSA** - Most common, based on prime factorization
- **ECC** (Elliptic Curve Cryptography) - Smaller keys, same security
- **ElGamal** - Based on discrete logarithm

## 📊 Encryption Comparison

| Algorithm | Key Size | Speed | Security | Use Case |
|-----------|----------|-------|----------|----------|
| AES-256 | 256 bits | Fast | Excellent | File/disk encryption |
| ChaCha20 | 256 bits | Very Fast | Excellent | Mobile/embedded |
| RSA-2048 | 2048 bits | Slow | Good | Key exchange |
| ECC-256 | 256 bits | Moderate | Excellent | Modern applications |

## 💡 Best Practices

1. **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)
2. **Generate keys properly** - Use CSPRNG
3. **Store keys securely** - Never hardcode
4. **Rotate keys regularly**
5. **Use different keys for different purposes**
