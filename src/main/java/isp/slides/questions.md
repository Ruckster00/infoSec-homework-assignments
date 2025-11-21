# Practice Questions (Multiple Choice + Short Answer)

This document contains exam-oriented questions based on the full course content: secrecy, integrity, authenticated encryption, public-key cryptography, key exchange, signatures, and KDFs.

---

# Multiple Choice Questions

### **1. ECB mode is insecure because:**

A. It uses too much randomness\
B. It leaks block equality patterns\
C. It is too slow\
D. It produces tags too short

**Correct:** B

---

### **2. Stream ciphers become insecure if:**

A. PRG output is longer than message\
B. Key is reused for two messages\
C. Ciphertext is too short\
D. Plaintext contains zeros

**Correct:** B

---

### **3. A secure MAC must satisfy:**

A. Preimage resistance\
B. EUF-CMA security\
C. Chosen-ciphertext security\
D. Trapdoor inversion

**Correct:** B

---

### **4. HMAC is secure because:**

A. It uses AES internally\
B. It adds extra random bits\
C. It treats the hash as a PRF\
D. It avoids using keys entirely

**Correct:** C

---

### **5. Diffie–Hellman without authentication is vulnerable to:**

A. Chosen-message attacks\
B. MAN-in-the-middle attacks\
C. Hash-collision attacks\
D. Padding oracle attacks

**Correct:** B

---

### **6. Authenticated Encryption (AE) provides:**

A. Confidentiality only\
B. Integrity only\
C. Confidentiality + Integrity\
D. Authentication only

**Correct:** C

---

### **7. Encrypt-then-MAC is:**

A. Always secure\
B. Never secure\
C. Secure only for single messages\
D. Worse than Encrypt-and-MAC

**Correct:** A

---

### **8. RSA-OAEP is designed to be:**

A. CPA-secure only\
B. CCA-secure\
C. Deterministic\
D. A PRF

**Correct:** B

---

### **9. Full Domain Hash (FDH) signatures require:**

A. Trapdoor permutations and collision-resistant hash\
B. Stream ciphers\
C. Public-key MACs\
D. Block ciphers

**Correct:** A

---

### **10. Nonces in CTR mode must:**

A. Be predictable\
B. Be reused for efficiency\
C. Never repeat under same key\
D. Match message length

**Correct:** C

---

### **11. HKDF is used when:**

A. Key is uniform\
B. Key is non-uniform or biased\
C. Key is stored in hardware\
D. Message is short\

**Correct:** B

---

### **12. DSA/ECDSA requires:**

A. Fixed salt\
B. Fresh random nonce per signature\
C. Deterministic encryption\
D. Large block cipher

**Correct:** B

---

# Short Answer Questions

### **1. Why must public-key encryption be randomized to achieve CPA security?**

**Answer:** If public-key encryption is deterministic, an attacker can encrypt candidate messages using the public key and compare the results to the ciphertext. Since the public key is available to everyone, this allows the attacker to identify which message was encrypted, breaking CPA security. Randomization ensures that each encryption of the same message produces a different ciphertext.

---

### **2. Explain why HMAC remains secure even if the hash function has minor weaknesses.**

**Answer:** HMAC treats the hash function as a PRF (pseudorandom function) rather than relying on its collision resistance. The nested structure with two separate key-derived values (ipad and opad) provides additional security layers. Even if the underlying hash has some weaknesses, the keyed construction prevents attackers from exploiting them without knowing the secret key.

---

### **3. Describe the difference between collision resistance and second-preimage resistance.**

**Answer:** 
- **Collision resistance:** Hard to find ANY two different messages m₁ ≠ m₂ such that H(m₁) = H(m₂)
- **Second-preimage resistance:** Given a specific message m₁, hard to find a different m₂ ≠ m₁ such that H(m₁) = H(m₂)

Collision resistance is stronger because the attacker can choose both messages, while second-preimage resistance fixes one message.

---

### **4. Why is Encrypt-then-MAC always secure, while MAC-then-Encrypt may not be?**

**Answer:** In Encrypt-then-MAC, the MAC covers the entire ciphertext, so any tampering is detected before decryption occurs. This guarantees ciphertext integrity. In MAC-then-Encrypt, the MAC is encrypted, and decryption must happen before verification. This can leak information through padding oracles or timing attacks, potentially breaking security.

---

### **5. Describe a man-in-the-middle attack on Diffie–Hellman key exchange.**

**Answer:** The attacker intercepts messages between Alice and Bob:
1. Alice sends g^a → Attacker intercepts and sends g^e to Bob
2. Bob sends g^b → Attacker intercepts and sends g^f to Alice
3. Alice computes K₁ = (g^f)^a, Bob computes K₂ = (g^e)^b
4. Attacker shares K₁ with Alice and K₂ with Bob, acting as a relay

The attacker can decrypt, read, modify, and re-encrypt all messages without Alice or Bob detecting it.

---

### **6. Why must nonces in CTR mode never repeat? Explain consequences.**

**Answer:** CTR mode generates a keystream by encrypting nonce||counter values. If the same nonce is reused with the same key, the same keystream is generated. This leads to a two-time pad scenario: c₁ ⊕ c₂ = m₁ ⊕ m₂, which leaks information about both plaintexts and allows attackers to decrypt messages or inject malicious content.

---

### **7. Explain what EUF-CMA security for signatures means in simple terms.**

**Answer:** EUF-CMA (Existential Unforgeability under Chosen-Message Attack) means that even if an attacker can request valid signatures on any messages of their choice, they still cannot forge a valid signature on any new message they haven't seen signed. This ensures signatures cannot be fabricated without the private key.

---

### **8. Give two reasons why textbook RSA is insecure.**

**Answer:**
1. **Deterministic:** Same plaintext always produces the same ciphertext, breaking CPA security. Attacker can encrypt candidate messages and compare.
2. **Malleable:** Given c = m^e, attacker can create c' = (2^e)·c = (2m)^e, which decrypts to 2m. This allows predictable ciphertext modifications without knowing the plaintext.

---

### **9. Why is RSA-PSS preferred over PKCS#1 v1.5 signatures?**

**Answer:** RSA-PSS includes randomization (salt) making signatures non-deterministic and provably secure in the random oracle model. PKCS#1 v1.5 uses deterministic padding and has known theoretical vulnerabilities. RSA-PSS provides stronger security guarantees and is the modern standard.

---

### **10. What is the purpose of applying a KDF after performing Diffie–Hellman?**

**Answer:** The DH shared secret g^(ab) may have structure or bias (e.g., leading zeros, non-uniform distribution). A KDF (especially HKDF) removes this bias and derives multiple independent keys for different purposes (encryption, MAC, IVs). This ensures the derived keys are uniformly random and suitable for cryptographic use.

---

### **11. Explain how collision resistance is used in hash-and-sign schemes.**

**Answer:** In hash-and-sign, the signature is computed on H(m) rather than m directly. If an attacker finds m' ≠ m with H(m) = H(m'), then a signature valid for m is also valid for m', allowing forgery. Collision resistance prevents attackers from finding such pairs, ensuring one signature corresponds to one message.

---

### **12. Why is a TTP-based key exchange system not scalable for large networks?**

**Answer:** While TTP scales better than pairwise keys (O(n) vs O(n²)), it has critical limitations:
- TTP must be online and available for every key exchange
- TTP learns all session keys (privacy concern)
- Single point of failure and bottleneck
- Does not scale to internet-size networks with millions of users
Decentralized solutions like authenticated DH are more practical.

# Additional Multiple Choice Questions

### **13. Which property is *required* for a cryptographic PRG?**

A. Deterministic and predictable\
B. Indistinguishable from random\
C. Must use a block cipher internally\
D. Requires a trapdoor

**Correct:** B

---

### **14. CBC mode is CPA-secure only if:**

A. Key is changed every message\
B. Block size is 512 bits\
C. IV is random and unpredictable\
D. Message is hashed before encryption

**Correct:** C

---

### **15. A MAC built from a collision-resistant hash fails when:**

A. Hash is too long\
B. Collisions become easy to find\
C. Keys are not public\
D. Tags are padded

**Correct:** B

---

### **16. Which scheme achieves ciphertext integrity?**

A. AES-CTR\
B. AES-CBC\
C. AES-GCM\
D. Stream cipher XOR

**Correct:** C

---

### **17. Public-key encryption schemes must:**

A. Use AES\
B. Be deterministic\
C. Use fresh randomness for each encryption\
D. Only encrypt short messages

**Correct:** C

---

### **18. The main purpose of digital signatures is:**

A. Key generation
B. Confidentiality
C. Integrity + Authentication + Non-repudiation
D. Increasing block size

**Correct:** C

---

### **19. In RSA, ciphertext malleability means:**

A. Keys are too large
B. Plaintext cannot be recovered
C. Ciphertexts can be algorithmically modified to change plaintext
D. Modulus is too small

**Correct:** C

---

### **20. DSA becomes completely insecure if:**

A. Hash function output is too long
B. Nonce is reused
C. Messages are too short
D. Key is 2048 bits

**Correct:** B

---

### **21. A KDF using a PRF ensures that:**

A. Keys are longer than plaintext
B. Derived keys are pseudorandom and independent
C. Original key is erased
D. All keys are public

**Correct:** B

---

### **22. HKDF's Extract step removes:**

A. Randomness
B. Entropy
C. Bias and structure from SK
D. Keys from memory

**Correct:** C

---

### **23. A TTP-based key exchange system requires:**

A. Each pair of users to share a unique key
B. Each user to share a key with the TTP only
C. RSA encryption for each message
D. Perfect secrecy

**Correct:** B

---

### **24. In Diffie–Hellman, the shared secret is:**

A. g^(a+b)
B. (g^a * g^b) mod p
C. g^(ab) mod p
D. H(a‖b)

**Correct:** C

---

### **25. RSA-PSS includes a random salt to:**

A. Reduce key size
B. Make encryption faster
C. Prevent deterministic signatures
D. Remove need for hashing

**Correct:** C

---

# Additional Short Answer Questions

### **13. Why does Encrypt-and-MAC fail to guarantee authenticated encryption in general?**

**Answer:** In Encrypt-and-MAC, the MAC is computed on the plaintext and sent alongside the ciphertext: (E(k₁, m), MAC(k₂, m)). The MAC reveals information about the plaintext (e.g., if the same plaintext is sent twice, the MAC will be identical). Additionally, the ciphertext itself is not authenticated, so modifications to it may not be detected before decryption attempts.

---

### **14. Explain how a padding oracle attack works against improperly implemented RSA or AES-CBC.**

**Answer:** A padding oracle attack exploits systems that reveal whether padding is valid or invalid through error messages, timing, or behavior differences. An attacker sends modified ciphertexts and observes the responses. By analyzing which modifications produce valid padding, the attacker can decrypt the ciphertext byte-by-byte without knowing the key.

---

### **15. Why is IND-CCA stronger than IND-CPA?**

**Answer:** IND-CCA (Chosen-Ciphertext Attack) allows the adversary to decrypt arbitrary ciphertexts of their choice (except the challenge), in addition to encrypting chosen plaintexts. This models real-world scenarios where attackers can observe decryption behavior. CPA only allows chosen plaintexts. Since CCA adversaries have more power, achieving IND-CCA security is harder and provides stronger guarantees.

---

### **16. Describe how collision resistance relates to the security of HMAC.**

**Answer:** While HMAC's primary security relies on treating the hash as a PRF, collision resistance provides additional protection. If collisions in the hash function become easy to find, certain attacks become possible. However, HMAC's nested structure (with keyed inputs) makes it significantly more resistant to collision-based attacks than simple hash-based MACs like H(k||m).

---

### **17. What is the difference between FDH (Full Domain Hash) and RSA-PSS?**

**Answer:**
- **FDH:** Deterministic; signs H(m) directly where H maps to the full RSA domain. Provably secure in random oracle model.
- **RSA-PSS:** Randomized; includes a salt making each signature different. Provides stronger security guarantees and prevents deterministic signature attacks.

Both are provably secure, but RSA-PSS is preferred for its randomization.

---

### **18. Why does DH require authentication for secure use?**

**Answer:** Pure Diffie-Hellman is vulnerable to man-in-the-middle attacks because parties don't verify who they're exchanging keys with. An attacker can establish separate DH exchanges with both parties. Authentication (via signatures, certificates, or pre-shared authenticated keys) ensures that the received g^a or g^b values actually come from the intended party.

---

### **19. What role does a KDF play in transforming a DH shared secret into usable keys?**

**Answer:** The DH shared secret g^(ab) is:
1. **Not uniformly random** (has bias/structure)
2. **Single value** (need multiple keys for encryption, MAC, IVs)

A KDF (like HKDF) extracts randomness to remove bias, then expands it to derive multiple independent, uniformly random keys for different cryptographic purposes.

---

### **20. Why is a random IV essential in CBC mode?**

**Answer:** The IV ensures that encrypting the same plaintext twice produces different ciphertexts (CPA security). If the IV is predictable, an attacker can choose plaintexts that cancel out with the IV, revealing patterns. If the IV is reused, identical plaintext blocks at the start will produce identical ciphertext blocks, leaking information.

---

### **21. What is ciphertext integrity (INT-CTXT)?**

**Answer:** INT-CTXT means an attacker cannot create a new valid ciphertext that will be accepted by the decryption algorithm. Even with access to encryptions of chosen plaintexts, the attacker cannot forge or modify ciphertexts without detection. This property is essential for authenticated encryption.

---

### **22. Why must keys used for MAC and encryption be distinct in Encrypt-then-MAC?**

**Answer:** Using the same key for different cryptographic primitives can lead to unexpected interactions and vulnerabilities. Separate keys ensure security independence: even if one primitive has weaknesses or the key is compromised in one context, the other remains secure. This follows the principle of key separation.

---

### **23. Describe why Textbook RSA is vulnerable to chosen-ciphertext attacks.**

**Answer:** Due to RSA's multiplicative property: given c₁ = m₁^e and c₂ = m₂^e, an attacker can create c₃ = c₁·c₂ = (m₁·m₂)^e. The attacker can request decryption of c₃ to get m₁·m₂, then compute m₁ or m₂. This allows decrypting target ciphertexts indirectly. RSA-OAEP prevents this by adding randomized padding.

---

### **24. Explain why ECDSA requires strong randomness for each signature.**

**Answer:** The signature includes k·G (where k is the random nonce). If k is reused for two messages, an attacker can set up equations and solve for the private key algebraically. Even partial information about k can leak the private key. This is why deterministic variants (RFC 6979) that derive k from the message and key are preferred.

---

### **25. In a TTP-based key exchange, how can replay attacks occur and how are they prevented?**

**Answer:** An attacker can capture and replay old session key distribution messages from the TTP, tricking parties into using compromised keys. Prevention methods include:
- **Timestamps:** Only accept recent messages within a time window
- **Nonces:** Include fresh random values that must be different each session
- **Sequence numbers:** Track message ordering and reject duplicates

---

# Additional Multiple Choice Questions (Extended)

### **26. Which property is NOT required for perfect secrecy?**

A. Key is truly random\
B. Key is at least as long as message\
C. Key is used only once\
D. Encryption is performed in blocks

**Correct:** D

---

### **27. The main advantage of ECDH over traditional DH is:**

A. No MITM vulnerability\
B. Smaller key sizes for equivalent security\
C. Does not require random nonces\
D. Works without modular arithmetic

**Correct:** B

---

### **28. Collision resistance is essential for:**

A. Stream ciphers\
B. Block cipher modes\
C. Hash-and-sign paradigm\
D. Key derivation from uniform sources

**Correct:** C

---

### **29. AES-GCM provides:**

A. Confidentiality only\
B. Integrity only\
C. Both confidentiality and integrity in single pass\
D. Neither confidentiality nor integrity

**Correct:** C

---

### **30. The birthday attack on hash functions has complexity:**

A. 2^n\
B. 2^(n/2)\
C. n^2\
D. log(n)

**Correct:** B

---

### **31. In CBC mode, the IV must be:**

A. Secret and reusable\
B. Unpredictable and unique per message\
C. Derived from the key\
D. The same for all messages

**Correct:** B

---

### **32. Textbook RSA is malleable because:**

A. Keys are too short\
B. E(m₁) · E(m₂) = E(m₁ · m₂)\
C. It uses random padding\
D. Factoring is easy

**Correct:** B

---

### **33. The Extract phase in HKDF:**

A. Expands the key material\
B. Removes bias from source key\
C. Generates random nonces\
D. Encrypts the derived keys

**Correct:** B

---

### **34. Forward secrecy is achieved by:**

A. Using long-lived keys\
B. Ephemeral session keys\
C. Stronger hash functions\
D. Longer ciphertexts

**Correct:** B

---

### **35. A PRF differs from a PRP in that:**

A. PRF must be invertible\
B. PRP must be invertible\
C. PRF is always faster\
D. PRP produces longer output

**Correct:** B

---

### **36. The main security property of HMAC is:**

A. It requires two different keys\
B. It remains secure despite minor hash weaknesses\
C. It is faster than all other MACs\
D. It provides encryption

**Correct:** B

---

### **37. CTR mode becomes insecure when:**

A. Messages are too long\
B. Same (key, nonce) pair is reused\
C. IV is too short\
D. Block cipher is too fast

**Correct:** B

---

### **38. AAD in AEAD modes is:**

A. Encrypted but not authenticated\
B. Authenticated but not encrypted\
C. Both encrypted and authenticated\
D. Neither encrypted nor authenticated

**Correct:** B

---

### **39. The security of RSA relies on:**

A. Discrete logarithm problem\
B. Integer factorization problem\
C. Hash collision resistance\
D. Linear algebra

**Correct:** B

---

### **40. Deterministic public-key encryption cannot achieve:**

A. Correctness\
B. CPA-security\
C. Efficiency\
D. Key generation

**Correct:** B

---

### **41. PBKDF2 is slow because:**

A. It uses large keys\
B. It iterates HMAC many times\
C. It requires hardware support\
D. It generates long outputs

**Correct:** B

---

### **42. The Merkle-Damgård construction:**

A. Builds hash for long messages from compression function\
B. Constructs MACs from ciphers\
C. Creates PRGs from PRFs\
D. Derives keys from passwords

**Correct:** A

---

### **43. EUF-CMA security means:**

A. Encryption is indistinguishable\
B. Cannot forge signatures on new messages\
C. Keys cannot be recovered\
D. Hashes are collision-resistant

**Correct:** B

---

### **44. The main weakness of MAC-then-Encrypt is:**

A. Always insecure\
B. May leak information through padding oracle\
C. Too slow\
D. Requires three keys

**Correct:** B

---

### **45. In RSA-PSS, the salt ensures:**

A. Deterministic signatures\
B. Signatures are randomized\
C. Smaller signature size\
D. Faster verification

**Correct:** B

---

### **46. A padding oracle attack exploits:**

A. Timing information about padding validity\
B. Short keys\
C. Weak hash functions\
D. Reused nonces

**Correct:** A

---

### **47. The discrete logarithm problem is the basis for:**

A. RSA\
B. AES\
C. Diffie-Hellman and DSA\
D. SHA-256

**Correct:** C

---

### **48. INT-CTXT (ciphertext integrity) means:**

A. Plaintext cannot be modified\
B. Attacker cannot create new valid ciphertext\
C. Keys are secret\
D. Encryption is fast

**Correct:** B

---

### **49. ECDSA signature generation requires:**

A. Same nonce every time\
B. Fresh random nonce per signature\
C. No randomness\
D. Symmetric key

**Correct:** B

---

### **50. The main purpose of using separate keys for MAC and encryption is:**

A. Faster computation\
B. Security separation and independence\
C. Smaller key size\
D. Backward compatibility

**Correct:** B

---

# Additional Short Answer Questions (Extended)

### **26. Why is ECB mode considered insecure even when using strong block ciphers like AES?**

**Answer:** ECB encrypts each block independently with the same key, so identical plaintext blocks produce identical ciphertext blocks. This leaks patterns in the data (e.g., repeating data, images show recognizable patterns). It's deterministic, so it cannot achieve CPA security. The block cipher's strength doesn't help because the mode of operation is fundamentally flawed.

---

### **27. Explain the difference between a PRF and a PRP.**

**Answer:**
- **PRF (Pseudorandom Function):** A function F: K × X → Y where outputs look random. Not necessarily invertible.
- **PRP (Pseudorandom Permutation):** A function that is also a permutation (bijection), meaning it's invertible with D(k, F(k, x)) = x.

All PRPs are PRFs, but not all PRFs are PRPs. Block ciphers are PRPs because they have decryption.

---

### **28. What is the purpose of the salt in HKDF Extract phase?**

**Answer:** The salt (which can be random, fixed, or public) is used as the HMAC key to extract a pseudorandom key (PRK) from the potentially biased source material. The salt helps ensure that even if the source key has structure or low entropy in some contexts, the PRK is uniformly random and suitable for key derivation.

---

### **29. Why does authenticated encryption (AE) imply CCA-security?**

**Answer:** AE provides ciphertext integrity (INT-CTXT), meaning attackers cannot create valid new ciphertexts. In a CCA attack, the adversary tries to learn information by getting decryptions of modified ciphertexts. With AE, all such modified ciphertexts will be rejected before decryption, preventing the attack. Thus AE automatically provides CCA security.

---

### **30. Explain why stream cipher key reuse is catastrophic.**

**Answer:** Stream cipher: c = m ⊕ G(k). If the same key encrypts m₁ and m₂:
- c₁ = m₁ ⊕ G(k)
- c₂ = m₂ ⊕ G(k)
- c₁ ⊕ c₂ = m₁ ⊕ m₂

The keystream cancels out, directly revealing the XOR of plaintexts. With known plaintext or language patterns, attackers can recover both messages completely.

---

### **31. What is forward secrecy and why is it important?**

**Answer:** Forward secrecy ensures that compromise of long-term keys does not compromise past session keys. This is achieved using ephemeral (temporary) keys for each session. If an attacker later obtains the private key, they cannot decrypt previously recorded traffic. This is critical for protecting historical communications from future compromises.

---

### **32. Describe the malleability problem in textbook RSA.**

**Answer:** RSA has the property that E(m₁) · E(m₂) = E(m₁ · m₂). Given a ciphertext c = m^e, an attacker can compute c' = c · 2^e = (2m)^e without knowing m. When decrypted, c' yields 2m. This allows predictable modifications to plaintexts without decryption, breaking integrity and enabling chosen-ciphertext attacks.

---

### **33. Why must digital signatures use collision-resistant hash functions?**

**Answer:** Signatures are computed on H(m). If an attacker finds m' ≠ m with H(m) = H(m'), a signature on m is also valid for m'. For example, sign a legitimate contract m, then claim you signed a fraudulent version m' with the same hash. Collision resistance prevents finding such pairs.

---

### **34. Explain the difference between preimage resistance and collision resistance.**

**Answer:**
- **Preimage resistance:** Given y = H(x), hard to find any x. (One-wayness)
- **Collision resistance:** Hard to find any x₁ ≠ x₂ with H(x₁) = H(x₂). (No two inputs hash to same output)

Collision resistance is stronger and harder to achieve. Birthday attacks make collisions easier to find (~2^(n/2)) than preimages (~2^n).

---

### **35. How does HMAC remain secure even if the underlying hash has weaknesses?**

**Answer:** HMAC uses a nested construction: H((k ⊕ opad) || H((k ⊕ ipad) || m)). The key is involved twice in different ways. Even if the hash has some collision vulnerabilities, an attacker without the key cannot exploit them in the keyed setting. HMAC's security relies on the hash behaving as a PRF when keyed, not on full collision resistance.

---

### **36. Why is CTR mode considered a stream cipher mode?**

**Answer:** CTR mode encrypts counter values (nonce||counter) to generate a keystream, then XORs this with the plaintext: c = m ⊕ E(k, nonce||ctr). This is functionally identical to a stream cipher c = m ⊕ G(k, nonce), where the block cipher acts as a PRG. Like stream ciphers, it requires unique nonces.

---

### **37. What is the role of AAD in AEAD schemes?**

**Answer:** AAD (Additional Authenticated Data) is data that must be authenticated but not encrypted. Examples include packet headers, protocol metadata, or addresses. AAD is included in the authentication tag computation but sent in plaintext. This ensures integrity of both encrypted payload and unencrypted metadata.

---

### **38. Explain why the IV in CBC mode must be unpredictable.**

**Answer:** If the IV is predictable, an attacker can choose plaintexts that, when XORed with the known IV, reveal information. For example, if encrypting the same message with a predictable IV sequence, the first ciphertext block becomes predictable. Unpredictability (randomness) ensures that even identical plaintexts produce completely different ciphertexts, maintaining CPA security.

---

### **39. What makes password-based KDFs different from regular KDFs?**

**Answer:** Passwords have low entropy (humans choose weak passwords). Password-based KDFs must:
- Be **slow** (high iteration count) to make brute-force expensive
- Be **memory-hard** (resist hardware/GPU attacks)
- Use **salt** to prevent rainbow tables

Regular KDFs assume high-entropy sources and focus on extraction/expansion rather than slowing down attacks.

---

### **40. Why is ECDSA completely broken if the nonce is reused?**

**Answer:** ECDSA signature contains (r, s) where s = k⁻¹(H(m) + r·d) and k is the nonce. With two signatures using the same k:
- s₁ = k⁻¹(H(m₁) + r·d)
- s₂ = k⁻¹(H(m₂) + r·d)

Solving these equations reveals k, and then the private key d can be calculated. This has happened in practice (PlayStation 3, blockchain wallets).

---

### **41. Describe the two phases of HKDF and their purposes.**

**Answer:**
- **Extract Phase:** PRK = HMAC(salt, source_key). Removes bias and structure from the potentially non-uniform source key, producing a pseudorandom key.
- **Expand Phase:** Derive multiple keys = HMAC(PRK, context||counter). Generates multiple independent keys from the PRK for different purposes (encryption, MAC, IVs, etc.).

---

### **42. What is the birthday bound and why does it matter for hash functions?**

**Answer:** The birthday bound states that in a set of ~2^(n/2) random values from an n-bit space, there's a high probability of finding a collision. For hash functions, this means collisions can be found in ~2^(n/2) operations, not 2^n. This is why 128-bit hashes offer only ~64-bit collision resistance, insufficient for modern security (256-bit hashes preferred).

---

### **43. Explain why public-key encryption must be randomized.**

**Answer:** With a public key available, anyone can encrypt messages. If encryption is deterministic, an attacker can encrypt candidate messages and compare with the target ciphertext, identifying the plaintext. Randomization ensures each encryption produces a different ciphertext, making this attack impossible and achieving CPA security.

---

### **44. What is non-repudiation in the context of digital signatures?**

**Answer:** Non-repudiation means the signer cannot later deny having signed a message. Since only the holder of the private key can generate a valid signature, a valid signature proves the signer's intent. This is legally binding in many contexts, unlike MACs where both parties share the key.

---

### **45. How does Encrypt-then-MAC composition guarantee authenticated encryption?**

**Answer:** The MAC is computed over the entire ciphertext: (c = E(k₁, m), t = MAC(k₂, c)). Any modification to the ciphertext changes the MAC, which is verified before decryption. This provides:
- **Integrity:** Modifications are detected
- **CPA security:** From the encryption
- Together these provide full AE and CCA security

---

### **46. Why is TTP-based key exchange not scalable for the internet?**

**Answer:** Internet scale (billions of users) makes TTP impractical:
- TTP must be online for every key exchange (availability bottleneck)
- Single point of failure affecting all users
- Privacy concern: TTP knows all session keys
- Geographic distribution and latency issues
- Trust model doesn't work across organizational boundaries

Decentralized public-key solutions are necessary.

---

### **47. What is the difference between IND-CPA and IND-CCA security?**

**Answer:**
- **IND-CPA:** Adversary can encrypt chosen plaintexts. Models passive attacks and chosen-plaintext scenarios.
- **IND-CCA:** Adversary can additionally decrypt chosen ciphertexts (except the challenge). Models active attacks where adversary can observe decryption behavior.

CCA is strictly stronger; AE provides CCA security.

---

### **48. Explain why RSA-OAEP is preferred over PKCS#1 v1.5 for encryption.**

**Answer:** PKCS#1 v1.5 has deterministic padding and is vulnerable to padding oracle attacks (Bleichenbacher's attack), where timing/error differences leak information enabling decryption. RSA-OAEP uses randomized padding with provable security in the random oracle model, achieving IND-CCA security. It's the modern standard for RSA encryption.

---

### **49. What makes Argon2 better than PBKDF2 for password hashing?**

**Answer:** Argon2 is:
- **Memory-hard:** Requires significant RAM, making GPU/ASIC attacks expensive
- **Configurable:** Tune time, memory, and parallelism
- **Modern design:** Won the Password Hashing Competition (2015)

PBKDF2 is only time-hard (iterations), easily parallelized on GPUs. Argon2 provides much better protection against hardware-based attacks.

---

### **50. Describe how a two-time pad attack works.**

**Answer:** If a stream cipher key is reused:
1. c₁ = m₁ ⊕ k, c₂ = m₂ ⊕ k
2. Attacker computes c₁ ⊕ c₂ = m₁ ⊕ m₂ (key cancels)
3. Using frequency analysis, known plaintext, or language patterns, recover m₁ and m₂
4. Once either message is found, the key k is revealed

Historical example: Soviet spy messages were broken this way when one-time pads were reused.
