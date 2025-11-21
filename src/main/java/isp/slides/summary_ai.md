# Information Security & Privacy — Comprehensive Summary (Weeks 1–4)

This document summarizes all topics from the first four weeks of the course, including confidentiality, integrity, authenticated encryption, public-key cryptography, key exchange, signatures, and KDFs. It captures all key definitions, constructions, and security notions.

---

# 1. Confidentiality (Secrecy)

Confidentiality ensures that only authorized parties can read a message. It is achieved using either symmetric or asymmetric (public-key) encryption.

---

## 1.1 Perfect Secrecy

A cipher has perfect secrecy when the ciphertext reveals *no information* about the plaintext.

### One-Time Pad (OTP)
- Encryption: `c = m XOR k`
- Key must be:
  - Truly random
  - As long as the message
  - Used only once
- Key reuse completely breaks security (two-time pad attack).

Perfect secrecy is not achievable for practical multi-use systems.

---

## 1.2 Stream Ciphers & PRGs

Stream ciphers use a **Pseudorandom Generator (PRG)** to expand a short key into a long pseudorandom stream:
```
c = m XOR G(k)
```

### PRG Security
- **Indistinguishability:** Output looks random.
- **Unpredictability:** Next bit cannot be predicted.

Stream ciphers are **malleable**: flipping a ciphertext bit flips plaintext.

Key or nonce reuse is catastrophic.

---

## 1.3 Block Ciphers and Modes

Block ciphers (e.g., AES) behave like:
- **PRP:** Pseudorandom permutation
- **PRF:** Pseudorandom function

### Modes of Operation
| Mode | Secure? | Notes |
|------|---------|-------|
| ECB | ❌ No | Reveals patterns |
| CBC | ✔ Yes | Requires random IV |
| CTR | ✔ Yes | Requires unique nonces |

CPA-security requires randomized or nonce-based encryption.

---

# 2. Integrity

Integrity ensures messages are not tampered with.

Main tool: **Message Authentication Code (MAC)**.

---

## 2.1 MACs & Security

MAC provides:
- Tag generation: `t = S(k, m)`
- Verification: `V(k, m, t)`

Security notion: **EUF-CMA** (Existential Unforgeability under Chosen-Message Attack).

---

## 2.2 MAC Constructions

### PRF-based MAC
`S(k, m) = F(k, m)` is secure if F is a secure PRF.

### CBC-MAC
For block ciphers; requires careful handling for variable-length messages.

### HMAC
```
HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
```

Secure even if underlying hash has limited weaknesses.

---

## 2.3 Hash Functions

Properties:
- Preimage resistance
- Second-preimage resistance
- Collision resistance (hard to find x ≠ y with H(x) = H(y))

Collision attacks take ~2^(n/2) operations.

Merkle–Damgård construction underlies many hashes.

---

# 3. Authenticated Encryption (AE)

AE combines:
1. Confidentiality (CPA-security)
2. Integrity (ciphertext integrity)

AE ⇒ CCA-security.

---

## 3.1 AE Compositions

| Construction | Secure? | Notes |
|--------------|---------|-------|
| Encrypt-then-MAC | ✔ | Always secure (IPsec) |
| MAC-then-Encrypt | ⚠️ | Potentially insecure (TLS 1.2) |
| Encrypt-and-MAC | ❌ | Not always secure (SSH) |

### AEAD Modes
- AES-GCM
- AES-CCM
- EAX

Support **Authenticated Associated Data (AAD)**.

---

# 4. Public-Key Encryption (PKE)

Consists of:
- KeyGen → (pk, sk)
- Encrypt(pk, m) → c
- Decrypt(sk, c) → m or ⊥

Must be randomized to achieve CPA-security.

---

## 4.1 IND-CPA & IND-CCA

### IND-CPA
Adversary chooses (m0, m1) and receives encryption of one; must guess which.

### IND-CCA
Adversary additionally has a decryption oracle (except challenge ciphertext).

---

# 5. Trapdoor Functions (TDF)

A TDF is:
- Easy to compute forward
- Hard to invert without trapdoor
- Easy to invert with secret key

Basis for public-key cryptography.

---

# 6. RSA

### Construction
- N = p·q
- Choose e
- Compute d = e⁻¹ mod φ(N)

### RSA Problems
- Textbook RSA is deterministic ⇒ not CPA-secure
- Malleable ⇒ attacker can modify ciphertext predictably

### Practical Schemes
- **PKCS#1 v1.5:** deterministic, outdated but widely deployed
- **RSA-OAEP:** randomized, IND-CCA secure

---

# 7. Digital Signatures

Provide:
- Integrity
- Authentication
- Non-repudiation

Security: **EUF-CMA**.

### Hash-and-Sign Paradigm
Signatures applied to hashed message; requires collision-resistant hash.

### RSA Signatures
- **FDH:** sign H(m)
- **RSA-PSS:** salted, randomized, provably secure

### DSA / ECDSA
- Based on discrete log
- Require fresh nonce; nonce reuse leaks private key

---

# 8. Key Exchange

### TTP-Based
Each user shares key with TTP; TTP distributes session keys.

Weakness: TTP learns all keys.

### Diffie–Hellman (DH)
Shared secret = g^(ab) mod p.

Secure against eavesdroppers, vulnerable to MITM.

### PKE Key Transport
Encrypt random key under receiver’s public key.

Still MITM-vulnerable unless keys are authenticated.

---

# 9. Key Derivation Functions (KDFs)

Used to derive multiple keys from a single source key (SK).

### Case 1 — SK is Uniform
Use PRF:
```
k_i = PRF(SK, context || i)
```

### Case 2 — SK is Non-Uniform (HKDF)
1. Extract: `PRK = HMAC(salt, SK)`
2. Expand: derive keys with HMAC

### Case 3 — Passwords
Use slow, salted functions:
- PBKDF2
- bcrypt
- scrypt
- Argon2

---

# Final Guidelines
- Do not design your own crypto
- Use AEAD modes (AES-GCM)
- Never reuse nonces or keys
- Authenticate public keys to prevent MITM

