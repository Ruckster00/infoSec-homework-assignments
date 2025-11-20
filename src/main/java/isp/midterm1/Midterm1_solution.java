package isp.midterm1;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class Midterm1_solution {
    public static void main(String[] args) throws Exception {
        // Global key pairs for Alice and Server (known to each other)
        final KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        final KeyPair aliceKP = rsaKpg.generateKeyPair();
        final KeyPair serverKP = rsaKpg.generateKeyPair();

        // Shared password between Server and Lock
        final String sharedPassword = "SecurePassword123!";

        Environment env = new Environment();

        env.add(new Agent("alice") {
            public void task() throws Exception {
                // ===== STEP 1: Mutual authentication and key agreement with Server =====
                
                // Generate ephemeral DH key pair for forward secrecy
                final KeyPairGenerator dhKpg = KeyPairGenerator.getInstance("DH");
                dhKpg.initialize(2048);
                final KeyPair aliceDHKP = dhKpg.generateKeyPair();
                
                // Sign Alice's DH public key with her RSA private key (authentication)
                final Signature aliceSigner = Signature.getInstance("SHA256withRSA");
                aliceSigner.initSign(aliceKP.getPrivate());
                aliceSigner.update(aliceDHKP.getPublic().getEncoded());
                final byte[] aliceDHSignature = aliceSigner.sign();
                
                // Send Alice's DH public key and signature to Server
                send("server", aliceDHKP.getPublic().getEncoded());
                send("server", aliceDHSignature);
                
                print("Alice: Sent signed DH public key to Server");
                
                // Receive Server's DH public key and signature
                final byte[] serverDHPubKeyBytes = receive("server");
                final byte[] serverDHSignature = receive("server");
                
                // Verify Server's signature using Server's RSA public key
                final Signature serverVerifier = Signature.getInstance("SHA256withRSA");
                serverVerifier.initVerify(serverKP.getPublic());
                serverVerifier.update(serverDHPubKeyBytes);
                
                if (!serverVerifier.verify(serverDHSignature)) {
                    print("Alice: FAILED to verify Server's signature!");
                    return;
                }
                print("Alice: Successfully verified Server's identity");
                
                // Reconstruct Server's DH public key
                final X509EncodedKeySpec serverDHKeySpec = new X509EncodedKeySpec(serverDHPubKeyBytes);
                final DHPublicKey serverDHPubKey = 
                    (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(serverDHKeySpec);
                
                // Perform DH key agreement
                final KeyAgreement aliceDH = KeyAgreement.getInstance("DH");
                aliceDH.init(aliceDHKP.getPrivate());
                aliceDH.doPhase(serverDHPubKey, true);
                final byte[] sharedSecret = aliceDH.generateSecret();
                
                // Derive AES key from shared secret (use first 16 bytes for AES-128)
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                print("Alice: Established shared secret with Server");
                
                // ===== STEP 2: Generate tokens and send last token over secured channel =====
                
                // Generate secret for Lamport's scheme
                final SecureRandom random = new SecureRandom();
                final byte[] secret = new byte[32];
                random.nextBytes(secret);
                
                // Generate 1000 tokens by hashing the secret 1000 times
                final int NUM_TOKENS = 1000;
                final byte[] lastToken = hash(NUM_TOKENS, secret);
                
                print("Alice: Generated %d tokens, last token: %s", NUM_TOKENS, hex(lastToken));
                
                // Encrypt the last token with AES-GCM for confidentiality and integrity
                final Cipher aesEnc = Cipher.getInstance("AES/GCM/NoPadding");
                aesEnc.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] encryptedToken = aesEnc.doFinal(lastToken);
                final byte[] iv = aesEnc.getIV();
                
                // Send encrypted token and IV to Server
                send("server", encryptedToken);
                send("server", iv);
                
                print("Alice: Sent encrypted token to Server");
                
                // ===== STEP 4: Try to open the lock by sending tokens =====
                
                // Wait for lock to be ready
                Thread.sleep(200);
                
                // Attempt to open the lock 3 times using decreasing token indices
                for (int attempt = 0; attempt < 3; attempt++) {
                    // Calculate which token to use (999, 998, 997...)
                    int tokenIndex = NUM_TOKENS - 1 - attempt;
                    final byte[] currentToken = hash(tokenIndex, secret);
                    
                    print("\nAlice: Attempting to open lock (attempt %d) with token t=%d", 
                          attempt + 1, tokenIndex);
                    
                    send("lock", currentToken);
                    
                    // Wait for lock response
                    Thread.sleep(100);
                }
            }
        });

        env.add(new Agent("server") {
            public void task() throws Exception {
                // ===== STEP 1: Mutual authentication and key agreement with Alice =====
                
                // Receive Alice's DH public key and signature
                final byte[] aliceDHPubKeyBytes = receive("alice");
                final byte[] aliceDHSignature = receive("alice");
                
                // Verify Alice's signature using Alice's RSA public key
                final Signature aliceVerifier = Signature.getInstance("SHA256withRSA");
                aliceVerifier.initVerify(aliceKP.getPublic());
                aliceVerifier.update(aliceDHPubKeyBytes);
                
                if (!aliceVerifier.verify(aliceDHSignature)) {
                    print("Server: FAILED to verify Alice's signature!");
                    return;
                }
                print("Server: Successfully verified Alice's identity");
                
                // Reconstruct Alice's DH public key
                final X509EncodedKeySpec aliceDHKeySpec = new X509EncodedKeySpec(aliceDHPubKeyBytes);
                final DHPublicKey aliceDHPubKey = 
                    (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(aliceDHKeySpec);
                
                // Get DH parameters from Alice's public key
                final javax.crypto.spec.DHParameterSpec dhParams = aliceDHPubKey.getParams();
                
                // Generate Server's ephemeral DH key pair
                final KeyPairGenerator dhKpg = KeyPairGenerator.getInstance("DH");
                dhKpg.initialize(dhParams);
                final KeyPair serverDHKP = dhKpg.generateKeyPair();
                
                // Sign Server's DH public key with Server's RSA private key
                final Signature serverSigner = Signature.getInstance("SHA256withRSA");
                serverSigner.initSign(serverKP.getPrivate());
                serverSigner.update(serverDHKP.getPublic().getEncoded());
                final byte[] serverDHSignature = serverSigner.sign();
                
                // Send Server's DH public key and signature to Alice
                send("alice", serverDHKP.getPublic().getEncoded());
                send("alice", serverDHSignature);
                
                print("Server: Sent signed DH public key to Alice");
                
                // Perform DH key agreement
                final KeyAgreement serverDH = KeyAgreement.getInstance("DH");
                serverDH.init(serverDHKP.getPrivate());
                serverDH.doPhase(aliceDHPubKey, true);
                final byte[] sharedSecret = serverDH.generateSecret();
                
                // Derive AES key from shared secret
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                print("Server: Established shared secret with Alice");
                
                // ===== STEP 2: Receive encrypted token from Alice =====
                
                final byte[] encryptedToken = receive("alice");
                final byte[] iv = receive("alice");
                
                // Decrypt the token with AES-GCM
                final Cipher aesDec = Cipher.getInstance("AES/GCM/NoPadding");
                aesDec.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] lastToken = aesDec.doFinal(encryptedToken);
                
                print("Server: Received and decrypted token from Alice: %s", hex(lastToken));
                
                // ===== STEP 3: Transfer token to Lock with MAC =====
                
                // Generate random salt for PBKDF2
                final SecureRandom random = new SecureRandom();
                final byte[] salt = new byte[16];
                random.nextBytes(salt);
                
                // Compute MAC tag over the token
                final byte[] tag = mac(lastToken, sharedPassword, salt);
                
                print("Server: Computed MAC tag: %s", hex(tag));
                
                // Send token, tag, and salt to Lock
                send("lock", lastToken);
                send("lock", tag);
                send("lock", salt);
                
                print("Server: Sent token with MAC to Lock");
            }
        });

        env.add(new Agent("lock") {
            public void task() throws Exception {
                // ===== STEP 3: Receive token from Server and verify MAC =====
                
                final byte[] receivedToken = receive("server");
                final byte[] receivedTag = receive("server");
                final byte[] salt = receive("server");
                
                print("Lock: Received token from Server");
                
                // Verify the MAC tag
                if (!verify(receivedToken, receivedTag, sharedPassword, salt)) {
                    print("Lock: MAC verification FAILED! Rejecting token.");
                    return;
                }
                
                print("Lock: MAC verification successful");
                
                // Store the token (this is SHA256^1000(s))
                byte[] storedToken = receivedToken;
                print("Lock: Stored token: %s", hex(storedToken));
                
                // ===== STEP 4: Verify tokens from Alice =====
                
                // Wait for Alice to start sending tokens
                Thread.sleep(250);
                
                // Process multiple access attempts
                for (int attempt = 0; attempt < 3; attempt++) {
                    final byte[] incomingToken = receive("alice");
                    
                    print("\nLock: Received token from Alice: %s", hex(incomingToken));
                    
                    // Hash the incoming token once
                    final byte[] hashedToken = hash(1, incomingToken);
                    
                    print("Lock: Hashed received token: %s", hex(hashedToken));
                    print("Lock: Stored token:         %s", hex(storedToken));
                    
                    // Compare with stored token
                    if (MessageDigest.isEqual(hashedToken, storedToken)) {
                        print("Lock: SUCCESS - Access granted (attempt %d)", attempt + 1);
                        // Update stored token with the received one
                        storedToken = incomingToken;
                        print("Lock: Updated stored token to: %s", hex(storedToken));
                    } else {
                        print("Lock: FAILURE - Access denied (attempt %d)", attempt + 1);
                    }
                }
            }
        });

        // Connect the agents
        env.connect("alice", "server");
        env.connect("server", "lock");
        env.connect("alice", "lock");
        
        env.start();
    }

    /**
     * Hashes the given payload multiple times using SHA-256.
     * 
     * @param times   number of times to apply the hash function
     * @param payload the initial payload to hash
     * @return the final hash value after applying SHA-256 'times' times
     */
    public static byte[] hash(int times, byte[] payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] result = payload;
            
            for (int i = 0; i < times; i++) {
                result = digest.digest(result);
            }
            
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Error during hashing", e);
        }
    }

    /**
     * Computes the MAC tag over the message using HMAC-SHA256.
     * The key is derived from the password and salt using PBKDF2.
     * 
     * @param payload  the message to authenticate
     * @param password the password from which to derive the key
     * @param salt     the salt used to strengthen the key derivation
     * @return the computed MAC tag
     */
    public static byte[] mac(byte[] payload, String password, byte[] salt) {
        try {
            // Derive key from password using PBKDF2 with HMAC-SHA256
            final int iterations = 1000;
            final int keyLength = 256; // 256 bits for HMAC-SHA256
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derivedKey = factory.generateSecret(spec).getEncoded();
            
            // Create HMAC-SHA256 key
            SecretKeySpec hmacKey = new SecretKeySpec(derivedKey, "HmacSHA256");
            
            // Compute MAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return mac.doFinal(payload);
            
        } catch (Exception e) {
            throw new RuntimeException("Error during MAC computation", e);
        }
    }

    /**
     * Verifies the MAC tag using constant-time comparison.
     * 
     * @param payload  the message to verify
     * @param tag      the MAC tag to verify
     * @param password the password used for key derivation
     * @param salt     the salt used for key derivation
     * @return true if the tag is valid, false otherwise
     */
    public static boolean verify(byte[] payload, byte[] tag, String password, byte[] salt) {
        try {
            // Recompute the MAC tag
            byte[] computedTag = mac(payload, password, salt);
            
            // Use constant-time comparison to prevent timing attacks
            return MessageDigest.isEqual(tag, computedTag);
            
        } catch (Exception e) {
            throw new RuntimeException("Error during MAC verification", e);
        }
    }
}
