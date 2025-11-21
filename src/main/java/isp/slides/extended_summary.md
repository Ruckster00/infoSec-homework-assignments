# Information Security & Privacy — Full Detailed Summary (Matched Exactly to Slides)

---

# 1. Secrecy
Confidentiality ensures that only intended recipients can read messages. Implemented via **symmetric** or **asymmetric** encryption.

A cipher is secure if the ciphertext reveals **no information** about the plaintext.

---

## 1.1 Perfect Secrecy
A cipher achieves perfect secrecy if for all messages m₀, m₁ and ciphertext c:

\[ P[E(k,m_0)=c] = P[E(k,m_1)=c] \]

This means: given c, an adversary cannot determine which of two messages was encrypted.

---

## 1.2 One-Time Pad (OTP)
Vernam cipher:
- M = C = K = {0,1}ⁿ
- \(E(k, m) = k ⊕ m\)
- \(D(k, c) = k ⊕ c\)

Properties:
- Perfect secrecy if key is **truly random**, **as long as message**, and **never reused**.
- Key reuse breaks security: **two-time pad attack**.
- Impractical because keys must be as long as messages.

---

## 1.3 Pseudorandom Generator (PRG) & Stream Ciphers
To avoid long keys, replace random pad with pseudorandom one.

PRG:
- Deterministic function: \(G: {0,1}^s → {0,1}^n\) with n≫s.

Stream cipher:
- E(k, m) = m ⊕ G(k)
- D(k, c) = c ⊕ G(k)

Stream ciphers cannot be perfectly secret because seed < message length.

### Security Notions
**Secure PRG:** output indistinguishable from random.
**Unpredictable PRG:** attacker cannot predict next bit.
**Theorem:** PRG is secure ⇔ unpredictable.

### Attacks
- **Two-time pad:** key reuse reveals m₁ ⊕ m₂.
- **Malleability:** attacker can flip bits in ciphertext → predictable plaintext changes.

---

## 1.4 Block Ciphers
Block ciphers:
- Input: n-bit block, output: n-bit block
- Determined by key k
- Behave like PRPs (pseudorandom permutations)
- PRP ⊂ PRF

Secure PRF: indistinguishable from a random function.
Secure PRP: indistinguishable from random permutation.

---

## 1.5 Modes of Operation
### ECB (Electronic Codebook)
- Each block encrypted independently.
- Identical plaintext blocks → identical ciphertext blocks.
- **NOT semantically secure.**

### CTR (Counter Mode)
- Turns PRF into stream cipher.
- Requires **unique (key, nonce)** pair.
- Secure for single messages.

### CBC (Cipher Block Chaining)
- Uses random IV for first block.
- IV must be **unpredictable and fresh**.
- CPA-secure.
- Sequential processing.

---

# 2. Integrity
Integrity ensures data has not been altered. Achieved via **Message Authentication Codes (MACs)**.

---

## 2.1 Message Authentication Codes (MACs)
A MAC consists of signing and verification algorithms:
- S: K × M → T
- V: K × M × T → {0,1}

Correctness: V(k, m, S(k,m)) = 1

### Security: EUF-CMA
- AP: chosen-message attack (attacker obtains tags for chosen messages)
- AG: produce a valid (m, t) not previously queried

If F is secure PRF and |Y| is large, S(k,m)=F(k,m) is secure MAC.

---

## 2.2 MACs for Long Messages
### CBC/ECBC-MAC
- Uses PRP repeatedly.
- Correct only for fixed-length messages unless extended (ECBC).

### Hash-Based MACs
To MAC long messages efficiently:
- Use collision-resistant hash to compress message.
- Merkle–Damgård lifts collision resistance from compression function.

If I is a secure MAC and H is CR, then Iᴮᴵᴳ is a secure MAC.

### HMAC
\(HMAC(k,m) = H((k⊕opad) || H((k⊕ipad)||m))\)
- Secure even when hash function is slightly weakened.
- Treats hash as PRF.
- Widely used.

---

## 2.3 Hash Function Properties
- **Preimage resistance**: given H(m), find m.
- **Second-preimage resistance**: given m₁, find m₂ ≠ m₁ with same hash.
- **Collision resistance**: find m₁ ≠ m₂ with same hash.

Birthday bound: ~2^(n/2) operations.

---

# 3. Authenticated Encryption (AE)
AE = **CPA security + ciphertext integrity (INT-CTXT)**.

Cipher that provides AE ⇒ Cipher is CCA-security.

## Implications
1. Authenticity
2. Security against chosen ciphertext attack
3. Provides confidentiality against an active adversary that can decrypt some ciphertext

---

## 3.1 AE Constructions
| Scheme | Secure? | Notes |
|--------|---------|-------|
| Encrypt-then-MAC | ✔ | Always secure (IPsec) |
| MAC-then-Encrypt | ⚠ | Can be insecure (TLS 1.2 issues) |
| Encrypt-and-MAC | ❌ | Not secure in general (SSH) |

### AEAD Modes
- AES-GCM (CTR + GHASH)
- AES-CCM (CTR + CBC-MAC)
- ChaCha20-Poly1305

Nonce uniqueness is critical.

---

# 4. Public-Key Encryption (PKE)
Triple of algorithms:
- KeyGen → (pk, sk)
- Encrypt(pk,m) → c
- Decrypt(sk,c) → m or ⊥

Must be **randomized** to achieve CPA security.

---

## 4.1 Security Notions
### IND-CPA
Adversary:
- picks messages (m₀, m₁)
- receives c = E(pk, m_b)
- must guess b

### IND-CCA
As above, plus decryption oracle except for challenge ciphertext.
Stronger than CPA.

---

# 5. Trapdoor Functions (TDFs)
A TDF satisfies:
- easy forward computation y=f(pk,x)
- hard to invert without trapdoor
- easy with sk

Trapdoor permutations are bijective TDFs.

Foundation of RSA.

---

# 6. RSA
## 6.1 Construction
- Pick primes p,q
- N=pq
- φ(N)=(p−1)(q−1)
- Choose e with gcd(e,φ(N))=1
- Compute d=e⁻¹ mod φ(N)

Encrypt: c=m^e mod N
Decrypt: m=c^d mod N

---

## 6.2 Security and Issues
**Textbook RSA is insecure:**
- deterministic → breaks CPA-security
- malleable → attacker can scale plaintext
- vulnerable to CCA attacks

---

## 6.3 RSA in Practice
### PKCS#1 v1.5
- Deterministic padding
- Susceptible to padding oracle attacks
- Still widely deployed

### RSA-OAEP
- Randomized
- IND-CCA secure in ROM
- Modern standard

---

# 7. Digital Signatures
Provide:
- Integrity
- Authentication
- Non-repudiation

Components:
- KeyGen → (pk, sk)
- Sign(sk,m) → σ
- Verify(pk,m,σ) → {0,1}

Security: **EUF-CMA**.

---

## 7.1 Hash-and-Sign
Sign H(m) instead of m.
Security requires collision-resistant hash.

---

## 7.2 Signature Schemes
### RSA-FDH
- σ = F⁻¹(sk, H(m))
- Verified by checking F(pk,σ)=H(m)
- Proven secure in ROM.

### RSA-PSS
- Randomized (salt)
- Provably secure
- Modern recommended scheme.

### PKCS#1 v1.5 Signatures
- Deterministic
- Practical but lacks formal security proof.

### DSA / ECDSA
- Based on discrete logarithm.
- Require **fresh random nonce**.
- Nonce reuse → full private key recovery.
- ECDSA more efficient.

---

# 8. Key Exchange
## 8.1 TTP-Based Key Exchange
- Each user shares a key with TTP.
- TTP generates session key.
- Issues: replay attacks, TTP learns all keys, single point of failure.

---

## 8.2 Diffie–Hellman (DH)
- Public parameters: p, g
- Exchange A=g^a, B=g^b
- Shared secret: g^(ab)

Security: CDH assumption.
Not authenticated → MITM attacks.

---

## 8.3 PKE-Based Key Transport
Alice encrypts random session key under Bob's pk.
MITM still possible unless pk is authenticated.

---

# 9. Key Derivation Functions

