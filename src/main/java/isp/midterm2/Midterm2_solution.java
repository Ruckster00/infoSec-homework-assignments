package isp.midterm2;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * One-sided authenticated key-exchange protocol (simplified TLS 1.3 handshake variant)
 * 
 * PROTOCOL FLOW:
 * 1. Alice sends A = g^a (ECDH public key)
 * 2. Server sends B = g^b, σ = Sign(sk, A||B), E(k, chall)
 * 3. Alice verifies σ, decrypts chall, sends E(k, H(pwd||chall))
 * 4. Server verifies response and authenticates Alice
 * 
 * SECURITY PROPERTIES:
 * - Server authentication via RSA signature
 * - Client authentication via password-based challenge-response
 * - Forward secrecy via ephemeral ECDH
 * - Confidentiality and integrity via AES-GCM
 */
public class Midterm2_solution {
    public static void main(String[] args) throws Exception {
        Environment env = new Environment();
        
        // Server's RSA key pair (known public key to Alice)
        final KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        final KeyPair serverKP = rsaKpg.generateKeyPair();
        
        // Alice's password (known to both Alice and Server)
        final String pwd = "Alice123";

        env.add(new Agent("alice") {
            public void task() throws Exception {
                // ===== STEP 1: Alice initiates ECDH key exchange =====
                
                print("Alice: Initiating ECDH key exchange");
                
                // Generate Alice's ephemeral EC key pair
                final KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
                ecKpg.initialize(256);
                final KeyPair aliceECKP = ecKpg.generateKeyPair();
                final PrivateKey a = aliceECKP.getPrivate();  // Alice's secret value
                final PublicKey A = aliceECKP.getPublic();     // Alice's public value
                
                // Send public value A to server
                send("server", A.getEncoded());
                print("Alice: Sent public value A to server");
                
                // ===== STEP 3: Alice receives and processes server's response =====
                
                // Receive server's public value B and signature σ
                final byte[] BEncoded = receive("server");
                final byte[] signature = receive("server");
                
                print("Alice: Received server's public value B and signature");
                
                // Verify the signature σ = Sign(sk, A||B)
                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(serverKP.getPublic());
                
                // Reconstruct what was signed: A||B
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(A.getEncoded());
                digest.update(BEncoded);
                final byte[] concatenated = digest.digest();
                
                verifier.update(concatenated);
                
                if (!verifier.verify(signature)) {
                    print("Alice: FAILED to verify server's signature! Aborting.");
                    return;
                }
                
                print("Alice: Successfully verified server's signature");
                
                // Reconstruct server's public key B
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(BEncoded);
                final ECPublicKey B = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                
                // Perform ECDH key agreement: shared secret = B^a
                final KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
                ecdh.init(a);
                ecdh.doPhase(B, true);
                final byte[] sharedSecret = ecdh.generateSecret();
                
                print("Alice: Computed shared secret: %s", hex(sharedSecret));
                
                // Derive AES key: k = H(shared secret), take first 16 bytes
                digest.reset();
                final byte[] sharedSecretHash = digest.digest(sharedSecret);
                final byte[] k = Arrays.copyOfRange(sharedSecretHash, 0, 16);
                final SecretKeySpec aesKey = new SecretKeySpec(k, "AES");
                
                print("Alice: Derived AES key from shared secret");
                
                // Receive and decrypt the challenge from server
                final byte[] encryptedChallenge = receive("server");
                final byte[] ivChallenge = receive("server");
                
                print("Alice: Received encrypted challenge from server");
                
                final Cipher aesDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
                aesDecrypt.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivChallenge));
                final byte[] challenge = aesDecrypt.doFinal(encryptedChallenge);
                
                print("Alice: Decrypted challenge: %s", hex(challenge));
                
                // Create response: resp = H(pwd || chall)
                digest.reset();
                digest.update(pwd.getBytes());
                digest.update(challenge);
                final byte[] response = digest.digest();
                
                print("Alice: Computed response: %s", hex(response));
                
                // Encrypt the response and send to server
                final Cipher aesEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
                aesEncrypt.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] encryptedResponse = aesEncrypt.doFinal(response);
                final byte[] ivResponse = aesEncrypt.getIV();
                
                send("server", encryptedResponse);
                send("server", ivResponse);
                
                print("Alice: Sent encrypted response to server");
                print("Alice: Protocol completed successfully!");
            }
        });
        
        env.add(new Agent("server") {
            public void task() throws Exception {
                // ===== STEP 2: Server receives Alice's public value and responds =====
                
                // Receive Alice's public value A
                final byte[] AEncoded = receive("alice");
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(AEncoded);
                final ECPublicKey A = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                
                print("Server: Received Alice's public value A");
                
                // Generate server's ephemeral EC key pair with same parameters as Alice
                final KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
                ecKpg.initialize(256);
                final KeyPair serverECKP = ecKpg.generateKeyPair();
                final PrivateKey b = serverECKP.getPrivate();  // Server's secret value
                final PublicKey B = serverECKP.getPublic();     // Server's public value
                
                print("Server: Generated ephemeral EC key pair");
                
                // Perform ECDH key agreement: shared secret = A^b
                final KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
                ecdh.init(b);
                ecdh.doPhase(A, true);
                final byte[] sharedSecret = ecdh.generateSecret();
                
                print("Server: Computed shared secret: %s", hex(sharedSecret));
                
                // Derive AES key: k = H(shared secret), take first 16 bytes
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                final byte[] sharedSecretHash = digest.digest(sharedSecret);
                final byte[] k = Arrays.copyOfRange(sharedSecretHash, 0, 16);
                final SecretKeySpec aesKey = new SecretKeySpec(k, "AES");
                
                print("Server: Derived AES key from shared secret");
                
                // Sign A||B with server's RSA private key: σ = Sign(sk, A||B)
                digest.reset();
                digest.update(AEncoded);
                digest.update(B.getEncoded());
                final byte[] concatenated = digest.digest();
                
                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(serverKP.getPrivate());
                signer.update(concatenated);
                final byte[] signature = signer.sign();
                
                print("Server: Signed A||B with RSA private key");
                
                // Generate random challenge (32 bytes)
                final byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);
                
                print("Server: Generated challenge: %s", hex(challenge));
                
                // Encrypt challenge with AES-GCM
                final Cipher aesEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
                aesEncrypt.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] encryptedChallenge = aesEncrypt.doFinal(challenge);
                final byte[] ivChallenge = aesEncrypt.getIV();
                
                // Send B, signature, and encrypted challenge to Alice
                send("alice", B.getEncoded());
                send("alice", signature);
                send("alice", encryptedChallenge);
                send("alice", ivChallenge);
                
                print("Server: Sent B, signature, and encrypted challenge to Alice");
                
                // ===== STEP 4: Server verifies Alice's response =====
                
                // Receive Alice's encrypted response
                final byte[] encryptedResponse = receive("alice");
                final byte[] ivResponse = receive("alice");
                
                print("Server: Received encrypted response from Alice");
                
                // Decrypt Alice's response
                final Cipher aesDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
                aesDecrypt.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivResponse));
                final byte[] receivedResponse = aesDecrypt.doFinal(encryptedResponse);
                
                print("Server: Decrypted response: %s", hex(receivedResponse));
                
                // Compute expected response: H(pwd || chall)
                digest.reset();
                digest.update(pwd.getBytes());
                digest.update(challenge);
                final byte[] expectedResponse = digest.digest();
                
                print("Server: Expected response: %s", hex(expectedResponse));
                
                // Verify the response using constant-time comparison
                if (MessageDigest.isEqual(receivedResponse, expectedResponse)) {
                    print("Server: ✓ Alice is authenticated successfully!");
                    print("Server: Secure channel established with shared key k");
                } else {
                    print("Server: ✗ Authentication FAILED! Connection aborted.");
                }
            }
        });

        env.connect("alice", "server");
        env.start();
    }
}