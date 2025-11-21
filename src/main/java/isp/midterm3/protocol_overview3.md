# Protocol Overview - Secure Multi-Factor Document Signing System

## Background
A company implements a secure document signing system where employees can digitally sign important documents using multi-factor authentication. The system ensures that only authorized employees can sign documents, and that signed documents cannot be repudiated or tampered with. The system consists of three entities: an Employee (Alice), an Authentication Server, and a Document Repository. Due to compliance requirements, the system must maintain an immutable audit trail and ensure forward secrecy.

## Security Requirements
1. **Mutual Authentication**: Both the Employee and Authentication Server must verify each other's identities
2. **Forward Secrecy**: Past communications remain secure even if long-term keys are compromised
3. **Multi-Factor Authentication**: Employee must prove possession of both a private key and knowledge of a PIN
4. **Document Integrity**: Signed documents cannot be altered without detection
5. **Non-Repudiation**: Employee cannot deny having signed a document
6. **Replay Protection**: Old authentication tokens cannot be reused
7. **Confidentiality**: Documents are encrypted during transmission

## System Components

### Initial Setup
- **Employee (Alice)**: Has an RSA key pair (pkAlice, skAlice) and a 6-digit PIN
- **Authentication Server**: Has an RSA key pair (pkServer, skServer) and stores a hash of Alice's PIN
- **Document Repository**: Stores signed documents and maintains an audit log
- All public keys are known to relevant parties
- Define key pairs and PIN hash globally in the main method

## Protocol Flow

### Phase 1: Mutual Authentication with Forward Secrecy (Alice ↔ Server)

1. **Alice initiates the connection**:
   - Generates ECDH key pair: secret value `a` and public value `A = g^a`
   - Creates a timestamp `ts1` (current time in milliseconds)
   - Signs the concatenation: `sig_A = Sign(skAlice, A || ts1)`
   - Sends: `{A, ts1, sig_A}`

2. **Server responds**:
   - Receives and verifies `sig_A` using `pkAlice`
   - Checks that `ts1` is recent (within 30 seconds) to prevent replay attacks
   - Generates its own ECDH key pair: secret `b` and public `B = g^b`
   - Creates timestamp `ts2`
   - Computes shared secret: `ss = H(B^a) = H(A^b)` using SHA-256
   - Derives session key: `k_session = PBKDF2(ss, salt, 10000 iterations)` where salt is a random 16-byte value
   - Signs: `sig_S = Sign(skServer, B || A || ts2)`
   - Encrypts the salt: `C_salt = AES-GCM-encrypt(k_temp, salt)` where `k_temp = first_16_bytes(H(ss))`
   - Sends: `{B, ts2, sig_S, C_salt, salt_iv, salt_tag}`

3. **Alice completes key agreement**:
   - Verifies `sig_S` using `pkServer`
   - Checks timestamp `ts2`
   - Computes shared secret: `ss = H(A^b)`
   - Derives temporary key: `k_temp = first_16_bytes(H(ss))`
   - Decrypts to recover salt: `salt = AES-GCM-decrypt(k_temp, C_salt, salt_iv, salt_tag)`
   - Derives the same session key: `k_session = PBKDF2(ss, salt, 10000 iterations)`

### Phase 2: PIN-Based Challenge-Response (Server → Alice)

1. **Server issues PIN challenge**:
   - Generates random 32-byte challenge: `nonce`
   - Encrypts challenge: `C_nonce = AES-GCM-encrypt(k_session, nonce)`
   - Sends: `{C_nonce, nonce_iv, nonce_tag}`

2. **Alice responds to challenge**:
   - Decrypts: `nonce = AES-GCM-decrypt(k_session, C_nonce, nonce_iv, nonce_tag)`
   - Computes response: `resp = H(PIN || nonce)` using SHA-256
   - Encrypts response: `C_resp = AES-GCM-encrypt(k_session, resp)`
   - Sends: `{C_resp, resp_iv, resp_tag}`

3. **Server verifies PIN**:
   - Decrypts: `resp = AES-GCM-decrypt(k_session, C_resp, resp_iv, resp_tag)`
   - Computes expected: `expected = H(stored_PIN || nonce)`
   - Compares `resp` with `expected`
   - If match: authentication succeeds; otherwise: protocol aborts

### Phase 3: Document Signing and Submission (Alice → Repository via Server)

1. **Alice prepares document**:
   - Has a document as a byte array: `doc`
   - Computes document hash: `doc_hash = SHA-256(doc)`
   - Creates a timestamp: `ts_sign`
   - Signs the document hash and timestamp: `doc_sig = Sign(skAlice, doc_hash || ts_sign)`
   - Computes MAC over the signature for integrity: `mac = HMAC-SHA256(k_session, doc_sig || ts_sign)`
   
2. **Alice encrypts and sends**:
   - Creates envelope: `envelope = doc || doc_hash || ts_sign || doc_sig || mac`
   - Encrypts envelope: `C_envelope = AES-GCM-encrypt(k_session, envelope)`
   - Sends to Server: `{C_envelope, env_iv, env_tag}`

3. **Server processes and forwards to Repository**:
   - Decrypts: `envelope = AES-GCM-decrypt(k_session, C_envelope, env_iv, env_tag)`
   - Extracts: `doc, doc_hash, ts_sign, doc_sig, mac`
   - Verifies MAC: `HMAC-SHA256-verify(k_session, doc_sig || ts_sign, mac)`
   - Verifies document hash: `SHA-256(doc) == doc_hash`
   - Verifies signature: `Verify(pkAlice, doc_hash || ts_sign, doc_sig)`
   - If all checks pass, creates audit entry: `audit = {Alice_ID, doc_hash, ts_sign, doc_sig}`
   - Forwards to Repository via secure channel (out-of-band or another authenticated connection)

4. **Repository stores document**:
   - Receives audit entry from Server
   - Performs final verification of `doc_sig` using `pkAlice`
   - Stores: `{doc, doc_hash, ts_sign, doc_sig, Alice_ID}` in permanent storage
   - Prints: "SUCCESS - Document signed and stored" or "FAILURE - Verification failed"

## Programming Assignment Tasks

### Task 1: Implement Mutual Authentication with Forward Secrecy
Implement the ECDH-based key exchange between Alice and Server with RSA signature verification. Both parties must:
- Generate ephemeral ECDH key pairs
- Sign their public values and timestamps
- Verify the peer's signature
- Derive a shared session key using PBKDF2
- Handle timestamp verification to prevent replay attacks

### Task 2: Implement PIN-Based Multi-Factor Authentication
After establishing the secure channel, implement the challenge-response protocol:
- Server generates a random challenge
- Alice proves knowledge of her PIN by correctly responding
- All communications use AES-GCM encryption with the session key

### Task 3: Implement Document Signing and Verification
Implement the complete document signing workflow:
- Alice signs a document (use a simple text file or byte array)
- Compute cryptographic hash of the document
- Create RSA signature over the hash
- Add HMAC for transport integrity
- Encrypt the entire envelope with AES-GCM

### Task 4: Implement Server-Side Validation
The Server must validate all cryptographic components:
- Decrypt the envelope
- Verify the HMAC tag
- Verify the document hash matches the document content
- Verify the RSA signature
- Forward to Repository only if all checks pass

### Task 5: Implement Repository Storage and Audit
The Repository must:
- Receive the validated document from Server
- Perform final signature verification (defense in depth)
- Store the document with its signature and metadata
- Print success/failure message

## Auxiliary Functions to Implement

```java
// Task 1
byte[] deriveSessionKey(byte[] sharedSecret, byte[] salt, int iterations)
boolean verifyTimestamp(long timestamp, int maxAgeSeconds)

// Task 2
byte[] hashPinWithNonce(String pin, byte[] nonce)

// Task 3
byte[] computeDocumentHash(byte[] document)
byte[] signDocument(PrivateKey sk, byte[] documentHash, long timestamp)
byte[] computeEnvelopeMAC(SecretKey sessionKey, byte[] data)

// Task 4
boolean verifyEnvelopeMAC(SecretKey sessionKey, byte[] data, byte[] mac)
boolean verifyDocumentSignature(PublicKey pk, byte[] docHash, long timestamp, byte[] signature)

// Task 5
void storeDocument(byte[] doc, byte[] docHash, long timestamp, byte[] signature, String employeeId)
```

## Security Analysis Questions (Answer in comments)

1. **Forward Secrecy**: Explain why this protocol provides forward secrecy even though RSA keys are used for authentication.

2. **Replay Protection**: Identify all mechanisms that prevent replay attacks in this protocol.

3. **Defense in Depth**: Why does the Repository verify the signature again even though the Server already verified it?

4. **Key Separation**: Why do we use HMAC with the session key in addition to the RSA signature?

5. **Timestamp Binding**: Why is the timestamp included in the signature instead of just signing the document hash alone?

## Testing Requirements

Your implementation should demonstrate:
1. Successful complete protocol execution (all phases work correctly)
2. Rejection of replayed messages (test with old timestamps)
3. Rejection of modified documents (tamper with document after signing)
4. Rejection of incorrect PIN (test with wrong PIN)
5. Rejection of invalid signatures (test with corrupted signature bytes)

## Bonus Task (Optional)
Implement a token revocation mechanism: After a successful document signing, generate a one-time revocation token that Alice can use to revoke her signature within a 5-minute window. The token should be based on HMAC and include a timestamp to prevent misuse after the revocation window expires.

---

**Note**: This assignment tests your understanding of:
- Asymmetric cryptography (RSA for signatures and authentication)
- Symmetric cryptography (AES-GCM for confidentiality and integrity)
- Key agreement (ECDH for forward secrecy)
- Key derivation (PBKDF2)
- Hash functions (SHA-256 for document integrity and key derivation)
- MACs (HMAC for transport integrity)
- Digital signatures (RSA signatures for non-repudiation)
- Timestamp-based replay protection
- Multi-factor authentication concepts
- Defense in depth principles
