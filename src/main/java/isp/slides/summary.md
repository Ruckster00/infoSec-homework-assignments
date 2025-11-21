
# Secrecy
Confidentiality ensures only intended recipients can read messages. Implemented using symmetric or asymmetric encryption.

**Secure Cipher** Cipher text should reveal no information about the plain text.

## Perfect Secrecy
Given cipher text c, one cannot tell whether c is a cryptogram of m_0 or m_1 where k is randomly chosen. So following probibilty equation must hold: P[E(k,m_0)=c] = P[E(k,m_1)=c]

## One Time Pad
**Vernam** 
M=C=K={0,1}^n; E(k,m) = k xor m; D(k,c) = k xor c
- given a truly random key, OTP has perfect secrecy
- key has to be random and it must be used only once
- BUT: perfect secrecy requires key to be at least as long as the plain text

## Pseudo Random Generator (PRG)
Idea: replace and random with a pseudorandom key
PRG is a deterministic function G that maps seed space to random looking key space: {0,1}^s -> {0,1}^n where n>>s

Stream ciphers
- E(k,m) := m xor G(k)
- D(k,c) := c xor G(k)
- stream ciphers cannot have perfect secrecy because keys (seeds) are shorter than messages

**Def. Secure PRG** For all efficient statistical tests A: Adv_PRG[A,G] is negligible (<2^-80).

**Def. Unpredictable PRG** Given an initial sequence of bits (a prefix), one cannot efficiently predict the next bit (p > 0,5 + number).

**Thm. Secure PRG** A PRG is secure iff. it is unpredictable.

## Threat model
Idea: Basis for reasoning about security
- **Adversary's power** what can she do?
- **Adversary's goal** what is she trying to achieve?
### Def. Semantic Security
**One-Time Semantic Security**

- AP: observer one ciphertext
  - every message is encrypted with its own key; a particular key is used only once
- AG: learn about the plaintext

**Many-Time Semantic Security (CPA-Security)**

- AP: chosen-PT attack
  - can obtain the encryption of any message of her choice
- AG: break semantic security
  - learn about the PT from the CT
  
A cipher has semantic security if given only cipher text, an attacker cannot practically derive any information about the plain text

**Thm.** Given a secure PRG, derived stream cipher is semantically secure.

## Attacks
- **Two-time pad attack** Never use stream-cipher key to encrypt more than one message
  **Look at code example!!!**

- **Malleability attack** Modifications to CT are not detected and have predicatble impact on the plain text

## Block Ciphers
- work on data blocks of fixed sizes (length n) with key of fixed size k produce a ciphertext of n length
- built by iteration
- behave like PRps (pseudorandom permutations F: K x X -> X)
- PRPs are a subset of PRFs (pseudorandom function E: K x X -> Y)
  - E(k,-) has an inverse
  - we have an efficient inversion algorithm D(k,x)
  
**Secure PRF** random function in Funs[X,Y] is indistinguishable from a random function in S_F which is a subset of all functions from X to Y
- definitions of secure PRFs and PRPs

### Modes of Operation
**Electronic Code Book (ECB)**

- split data into blocks and if needed extend the last block with padding bits
- independently encrypt each block 
- PROBLEM: If two plaintext blocks are the same, so are the corresponding ciphertexts blocks
- not semantically secure!! When sending two messages to the challenger you can find out which of the two messages was encryted by choosing m_1 and m_0 correctly

**Deterministic Counter Mode (CTR)**

- creates a stream cipher from a PRF
- secure (but only for encrypting a single message)
- requires unique (key,nonce) pair
- nonce is a counter

**Cipher Block Chaining (CBC)**

- randomize encryption with an initialization vector (IV)
  - sent unencrypted
  - requires new unpredictable IV per message
- forces encryption to be sequential
- secure under CPA

# Integrity
Integrity ensures data has not been altered. Detection is usually sufficient achieved through Message Authentication Codes (MACs).

## Message Authentication Code
Pair (S,V) of signing and verification algorithm:
- S: K x M -> T
- V: K x M x T -> {0,1}
- consistency requirement: V(k,m,S(k,m)) = 1
  
## Secure MAC

- AP: Chosen message attack
  - for any message the attacker is given a corresponding valid tag
- AG: Existential forgery
  - produce a new valid (m,t) pair
- Turn secure PRF F:K x X -> Y into **secure MAC** I_F = (S,V):
  - S(k,m) := F(k,m)
  - V(k,m,t) := if t = F(k,m) ? 1 : 0 
  - if F is a a secure PRF and |Y| is sufficiently large, then I_F is a secure MAC

## MACs for Long Messages
**CBC-/ECBC-MAC**

- uses block cipher PRP repeatedly
- msut use fixed-length messages or fix construction (ECBC)

**Hash-based MACs**

- must be collision resistant (advantage is negligible)
- Merkle-Damgard constructions: given a CR function for short messages (compression fucntion), construct CR function for long messages

**MAC from CR**
If I is a secure MAC and H is collision resistant, then I^BIG is a secure MAC

**HMAC (Hash-based MAC)**
```
HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
```
- remains secure even if underlying hash function has minor weaknesses
- treats hash as a PRF
- widely used in practice (TLS, IPsec)

## Hash Functions
**Properties:**
- **Preimage resistance:** given H(m), hard to find m
- **Second-preimage resistance:** given m1, hard to find m2 ≠ m1 where H(m1) = H(m2)
- **Collision resistance:** hard to find any m1 ≠ m2 where H(m1) = H(m2)

**Birthday Attack:** Finding collisions takes ~2^(n/2) operations for n-bit hash

**Merkle-Damgård Construction:** builds CR hash for long messages from CR compression function for short messages

## Authenticated Encryption (AE)
**Goal:** Provide both confidentiality and integrity

**AE = CPA-security + Ciphertext Integrity (INT-CTXT)**

AE implies CCA-security (can resist chosen-ciphertext attacks)

### AE Compositions
| Construction | Secure? | Used In |
|--------------|---------|---------|
| **Encrypt-then-MAC** | ✔ Always secure | IPsec |
| **MAC-then-Encrypt** | ⚠️ Sometimes insecure | TLS 1.2 |
| **Encrypt-and-MAC** | ❌ Not always secure | SSH |

**Encrypt-then-MAC:** 
- Encrypt plaintext: c = E(k_E, m)
- MAC the ciphertext: t = S(k_M, c)
- Send (c, t)
- Always provides AE if encryption is CPA-secure and MAC is secure
- Uses separate keys for encryption and MAC

### AEAD (Authenticated Encryption with Associated Data)
**Modern AE Modes:**
- **AES-GCM** (Galois/Counter Mode)
- **AES-CCM** (Counter with CBC-MAC)
- **ChaCha20-Poly1305**

**AAD:** Additional data authenticated but not encrypted (e.g., packet headers)

**GCM Mode:**
- CTR mode for encryption
- GHASH for authentication
- Single-pass, parallelizable
- Nonce must never repeat

# Public-key Encryption
## Public-key cryptography: overview, usages and definitions
**Components:**
- KeyGen() → (pk, sk)
- Encrypt(pk, m) → c
- Decrypt(sk, c) → m or ⊥

**Key Properties:**
- Each party uses a key pair: public key (known) and private key (secret)
- Public key encryption **must be randomized** to achieve CPA-security
- Long-lived keys compared to symmetric keys

**Usage:**
- Communication session set-up: establish shared secrets
- Non-interactive applications: encrypt to someone without prior contact
- Digital signatures

### Security Notions

**IND-CPA (Indistinguishability under Chosen-Plaintext Attack):**
- Adversary chooses two messages (m₀, m₁)
- Receives encryption of one: c = E(pk, m_b) for random b
- Must guess which message was encrypted
- PKE must be randomized to achieve CPA-security

**IND-CCA (Indistinguishability under Chosen-Ciphertext Attack):**
- Adversary has CPA capabilities plus decryption oracle
- Cannot query decryption of challenge ciphertext
- Stronger security notion than CPA
- Authenticated Encryption provides CCA-security

## Trapdoor Functions and Permutations

**Trapdoor Function (TDF):**
- Easy to compute: y = f(pk, x)
- Hard to invert without secret: x = f⁻¹(?, y) is hard
- Easy to invert with trapdoor: x = f⁻¹(sk, y)

**Trapdoor Permutation:** TDF that is also a permutation (bijection)

Used as foundation for public-key cryptography (RSA, etc.)

## RSA Construction

**Key Generation:**
1. Choose large primes p, q
2. Compute N = p·q
3. Compute φ(N) = (p-1)(q-1)
4. Choose e with gcd(e, φ(N)) = 1
5. Compute d = e⁻¹ mod φ(N)
6. pk = (N, e), sk = (N, d)

**Encryption/Decryption:**
- Encrypt: c = m^e mod N
- Decrypt: m = c^d mod N

**Security Basis:** RSA assumption (factoring N is hard)

## RSA in Practice

**Textbook RSA Problems:**
- Deterministic → not CPA-secure
- Malleable: given c = m^e, can create c' = (2m)^e
- Vulnerable to chosen-ciphertext attacks

**Practical RSA Schemes:**

**PKCS#1 v1.5:**
- Adds padding before encryption
- Deterministic padding
- Vulnerable to padding oracle attacks
- Legacy, still widely deployed

**RSA-OAEP (Optimal Asymmetric Encryption Padding):**
- Randomized padding scheme
- IND-CCA secure
- Uses hash functions and randomness
- Modern standard for RSA encryption

# Digital Signatures

**Purpose:**
- **Integrity:** detect modifications
- **Authentication:** verify sender identity
- **Non-repudiation:** signer cannot deny signing
- **Publicly verifiable** anyone with PK can verify the signature

**Components:**
- KeyGen() → (pk, sk)
- Sign(sk, m) → σ
- Verify(pk, m, σ) → {0, 1}

**Security:** EUF-CMA (Existential Unforgeability under Chosen-Message Attack)
- Adversary can request signatures on any messages
- Goal: forge signature on new message

## Hash-and-Sign Paradigm

Sign H(m) instead of m directly
- Requires **collision-resistant hash**
- If attacker finds m, m' with H(m) = H(m'), signature on m is valid for m'

## RSA Signatures

**Full Domain Hash (FDH):**
- Sign: S(sk,m) := F^-1(sk,H(m))
- Verify: V(sk,m,z) := H(m)=F(pk,z) ? 1 : 0
- Requires hash output to match RSA modulus size
- Provably secure with random oracle
- produces unique signatures: every message has its own signature

**RSA-PSS (Probabilistic Signature Scheme):**
- Randomized (includes salt) by using mask genrating function that extends the hash size to the full modulus size
- Provably secure in random oracle model
- Preferred modern standard
- Not deterministic like PKCS#1 v1.5

**PKCS#1 v1.5 Signatures:**
- Deterministic
- Widely deployed but has theoretical weaknesses
- Being phased out
- has reserver place for digest info which encodes the name of the used hash function
- partial domain hash -> no proof that this is secure, but no known substantial attack

## DSA / ECDSA

**Based on discrete logarithm problem**

**Critical Requirement:** Fresh random nonce per signature
- **Nonce reuse leaks private key!**
- Deterministic variants (RFC 6979) avoid this risk

**ECDSA:** Elliptic curve variant
- Smaller keys than RSA for same security
- Faster operations
- Widely used (Bitcoin, TLS)

## Hashing is required for security
**Zero-message attack**\
- create existential forgery by picking a random signature and creating a message from it by applying the trapdorr function with the known public key
- defeats security because you can easily create a valid message signature pair without having to know any messages
**Multiplicative-property attack**\
- ask for signatures on two messages m1,m2
- output existential forgery z3=z1*z2, m3=m1*m2

# Key Exchange Protocols

## Key Exchange Problem and TTPs

**Goal:** Two parties establish shared secret over insecure channel

**Trusted Third Party (TTP) Approach:**
- Each user shares long-term key with TTP
- TTP generates and distributes session keys
- Scales as O(n), not O(n²)

**Weaknesses:**
- TTP learns all session keys
- Single point of failure
- Requires TTP to be online (in basic version)
- Vulnerable to replay attacks without proper timestamps/nonces

## Diffie-Hellman Protocol

**Setup:** Public parameters p (prime), g (generator)

**Protocol:**
1. Alice chooses random a, sends A = g^a mod p
2. Bob chooses random b, sends B = g^b mod p
3. Both compute shared secret: K = g^(ab) mod p
   - Alice: K = B^a mod p
   - Bob: K = A^b mod p

**Security:**
- Secure against passive eavesdroppers (DH assumption)
- **Vulnerable to Man-in-the-Middle (MITM) attacks**
- Requires authentication of exchanged values

**Variants:**
- **ECDH:** Elliptic curve DH (smaller keys)
- **DHE:** Ephemeral DH (forward secrecy)

## Key Exchange with Public-Key Cryptography

**Key Transport:**
1. Alice generates random session key K
2. Alice encrypts: c = E(pk_Bob, K)
3. Alice sends c to Bob
4. Bob decrypts: K = D(sk_Bob, c)

**Still vulnerable to MITM unless public keys are authenticated**

**Solutions:**
- PKI (Public Key Infrastructure) with certificates
- Pre-shared authenticated public keys
- Authenticated DH (combining DH with signatures)

## Digital Signatures

**Purpose:**
- **Integrity:** detect modifications
- **Authentication:** verify sender identity
- **Non-repudiation:** signer cannot deny signing
- **Publicly verifiable** anyone with PK can verify the signature

**Components:**
- KeyGen() → (pk, sk)
- Sign(sk, m) → σ
- Verify(pk, m, σ) → {0, 1}

**Security:** EUF-CMA (Existential Unforgeability under Chosen-Message Attack)
- Adversary can request signatures on any messages
- Goal: forge signature on new message

### Hash-and-Sign Paradigm

Sign H(m) instead of m directly
- Requires **collision-resistant hash**
- If attacker finds m, m' with H(m) = H(m'), signature on m is valid for m'

### RSA Signatures

**Full Domain Hash (FDH):**
- Sign: S(sk,m) := F^-1(sk,H(m))
- Verify: V(sk,m,z) := H(m)=F(pk,z) ? 1 : 0
- Requires hash output to match RSA modulus size
- Provably secure with random oracle
- produces unique signatures: every message has its own signature

**RSA-PSS (Probabilistic Signature Scheme):**
- Randomized (includes salt) by using mask genrating function that extends the hash size to the full modulus size
- Provably secure in random oracle model
- Preferred modern standard
- Not deterministic like PKCS#1 v1.5

**PKCS#1 v1.5 Signatures:**
- Deterministic
- Widely deployed but has theoretical weaknesses
- Being phased out
- has reserver place for digest info which encodes the name of the used hash function
- partial domain hash -> no proof that this is secure, but no known substantial attack

### DSA / ECDSA

**Based on discrete logarithm problem**

**Critical Requirement:** Fresh random nonce per signature
- **Nonce reuse leaks private key!**
- Deterministic variants (RFC 6979) avoid this risk

**ECDSA:** Elliptic curve variant
- Smaller keys than RSA for same security
- Faster operations
- Widely used (Bitcoin, TLS)

### Hashing is required for security
**Zero-message attack**\
- create existential forgery by picking a random signature and creating a message from it by applying the trapdorr function with the known public key
- defeats security because you can easily create a valid message signature pair without having to know any messages
**Multiplicative-property attack**\
- ask for signatures on two messages m1,m2
- output existential forgery z3=z1*z2, m3=m1*m2


## Key Derivation Functions (KDFs)

**Purpose:** Derive one or more keys from source keying material

### Case 1: Uniform Source Key

**When:** SK is already uniformly random

**Method:** Use PRF
```
KDF(sk,ctx,l) := PRF(SK, context || 0) || PRF(SK, context || 1) || ... || PRF(SK, context || l)
```
- ctx: a string unique to every application
  - assures that two applications derive indepenedent keys even if they sample the same source key

Example contexts: "encryption", "MAC", "key-0001"

### Case 2: Non-Uniform Source Key (HKDF)

**When:** SK has good entropy but may be biased (e.g., DH shared secret)

**HKDF (HMAC-based KDF):**

**Extract Phase:**
```
PRK = HMAC(salt, SK)
```
- Removes bias and structure from SK
- Salt can be public, random, or fixed

**Expand Phase:**
```
k_i = HMAC(PRK, context || i)
```
- Derives multiple independent keys
- Context binding prevents key misuse

**Standard in:** TLS 1.3, Signal, WireGuard

### Case 3: Password-Based KDFs

**Challenge:** Passwords have low entropy (HKDF unsuitable)
- Derived keys will be vulnerable to dictionary attack

**Idea** Increase entropy ba adding salt and slowing down the hashing

**Requirements:**
- Slow (resist brute-force)
- Memory-hard (resist hardware attacks)
- Salted (prevent rainbow tables)

**Algorithms:**
- **PBKDF2:**IterationCount × HMAC
- **bcrypt:** Designed for passwords
- **scrypt:** Memory-hard
- **Argon2:** Modern, winner of password hashing competition

**Never use fast hashes (SHA256) directly on passwords!**

---

## Security Principles Summary

**Never:**
- Reuse keys/nonces in stream ciphers or CTR mode
- Use ECB mode
- Design your own crypto
- Use textbook RSA
- Reuse ECDSA nonces
- Use MAC-then-Encrypt without careful analysis
- Hash passwords with fast hashes

**Always:**
- Use AEAD modes (AES-GCM, ChaCha20-Poly1305)
- Randomize public-key encryption
- Use separate keys for encryption and MAC
- Authenticate Diffie-Hellman exchanges
- Use strong KDFs for passwords
- Prefer Encrypt-then-MAC if composing manually
- Use collision-resistant hashes for signatures

