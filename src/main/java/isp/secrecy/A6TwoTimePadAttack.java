package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * LEARNING OBJECTIVES:
 * - Understand why reusing the same IV/nonce with CTR mode is catastrophic
 * - Demonstrate the two-time pad attack (key stream reuse)
 * - Learn how XOR properties allow plaintext recovery when key streams are reused
 * 
 * THE SETTING:
 * Alice is sending encrypted messages to Bob using AES in CTR mode. Unfortunately, Alice's
 * implementation has a critical bug: she reuses the same IV (nonce) for multiple messages.
 * This means the same key stream is used to encrypt different plaintexts.
 * 
 * You are an attacker who can intercept the ciphertexts. You know that:
 * 1. The same IV is being reused (you can see the IV in the traffic)
 * 2. You have some knowledge about the structure of the messages
 * 3. One of the messages starts with "Message from Alice: "
 * 
 * THE VULNERABILITY:
 * In CTR mode: CT = PT ⊕ KeyStream
 * If the same IV is reused with the same key, the KeyStream is identical.
 * 
 * For two messages encrypted with the same key stream:
 * CT1 = PT1 ⊕ KeyStream
 * CT2 = PT2 ⊕ KeyStream
 * 
 * Therefore: CT1 ⊕ CT2 = (PT1 ⊕ KeyStream) ⊕ (PT2 ⊕ KeyStream) = PT1 ⊕ PT2
 * 
 * If we know (or can guess) PT1, we can recover PT2:
 * PT2 = PT1 ⊕ CT1 ⊕ CT2
 * 
 * THE TASK:
 * As an attacker, intercept two messages that were encrypted with the same IV.
 * Using the known plaintext from the first message, recover the second message.
 */
public class A6TwoTimePadAttack {
    public static void main(String[] args) throws Exception {
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        // Alice sends two messages, but mistakenly uses the same IV for both
        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // First message
                final String message1 = "Message from Alice: The exam is on Monday at 10 AM.";
                
                final Cipher aes1 = Cipher.getInstance("AES/CTR/NoPadding");
                aes1.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct1 = aes1.doFinal(message1.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes1.getIV();  // Save the IV
                
                print("Sending message 1: '%s'", message1);
                print("CT1: %s", hex(ct1));
                print("IV:  %s", hex(iv));
                
                send("bob", ct1);
                send("bob", iv);
                
                // Small delay between messages
                Thread.sleep(100);
                
                // Second message - CRITICAL BUG: Reusing the same IV!
                final String message2 = "Secret exam question: What is the main weakness of ECB mode?";
                
                final Cipher aes2 = Cipher.getInstance("AES/CTR/NoPadding");
                // VULNERABILITY: Using the same IV as before
                aes2.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] ct2 = aes2.doFinal(message2.getBytes(StandardCharsets.UTF_8));
                
                print("Sending message 2: '%s'", message2);
                print("CT2: %s", hex(ct2));
                
                send("bob", ct2);
                send("bob", iv);  // Same IV - this is the vulnerability!
            }
        });

        env.add(new Agent("attacker") {
            @Override
            public void task() throws Exception {
                // Intercept both messages
                final byte[] ct1 = receive("alice");
                final byte[] iv1 = receive("alice");
                
                print("Intercepted CT1: %s", hex(ct1));
                print("Intercepted IV1: %s", hex(iv1));
                
                // Forward to Bob (we're passive for now)
                send("bob", ct1);
                send("bob", iv1);
                
                Thread.sleep(150);
                
                final byte[] ct2 = receive("alice");
                final byte[] iv2 = receive("alice");
                
                print("Intercepted CT2: %s", hex(ct2));
                print("Intercepted IV2: %s", hex(iv2));
                
                // Check if IVs are the same - TWO-TIME PAD DETECTED!
                boolean sameIV = java.util.Arrays.equals(iv1, iv2);
                print("IV reuse detected: %s", sameIV);
                
                if (sameIV) {
                    print("\n=== LAUNCHING TWO-TIME PAD ATTACK ===");
                    
                    // Known plaintext: We know the first message starts with this
                    final String knownPlaintext = "Message from Alice: ";
                    final byte[] knownPT = knownPlaintext.getBytes(StandardCharsets.UTF_8);
                    
                    // Recover the beginning of message 2
                    // PT2 = PT1 ⊕ CT1 ⊕ CT2
                    final int recoveryLength = Math.min(Math.min(knownPT.length, ct1.length), ct2.length);
                    final byte[] recoveredPT2 = new byte[recoveryLength];
                    
                    for (int i = 0; i < recoveryLength; i++) {
                        recoveredPT2[i] = (byte) (knownPT[i] ^ ct1[i] ^ ct2[i]);
                    }
                    
                    final String recovered = new String(recoveredPT2, StandardCharsets.UTF_8);
                    print("Recovered beginning of message 2: '%s'", recovered);
                    
                    // Advanced attack: Try to recover more by guessing common words
                    // This demonstrates that even partial knowledge allows further recovery
                    print("\n=== ATTEMPTING FULL RECOVERY ===");
                    
                    // If we can guess that message 2 might contain "Secret exam question: "
                    // we can verify our guess and potentially recover more
                    final String guessedPrefix = "Secret exam question: ";
                    final byte[] guessedPT2 = guessedPrefix.getBytes(StandardCharsets.UTF_8);
                    
                    if (guessedPT2.length <= ct2.length) {
                        // Verify the guess by recovering PT1 and checking if it makes sense
                        final byte[] verifyPT1 = new byte[guessedPT2.length];
                        for (int i = 0; i < guessedPT2.length; i++) {
                            verifyPT1[i] = (byte) (guessedPT2[i] ^ ct1[i] ^ ct2[i]);
                        }
                        
                        final String verifiedPT1 = new String(verifyPT1, StandardCharsets.UTF_8);
                        print("If message 2 starts with '%s', then message 1 starts with: '%s'", 
                              guessedPrefix, verifiedPT1);
                        
                        // This matches our known plaintext, confirming the guess!
                        if (verifiedPT1.equals("Message from Alice: ")) {
                            print("GUESS CONFIRMED! Both messages partially recovered.");
                            
                            // Now we can try to recover the full second message
                            // by using the full first message (if we can guess/obtain it)
                            final String fullMessage1 = "Message from Alice: The exam is on Monday at 10 AM.";
                            final byte[] fullPT1 = fullMessage1.getBytes(StandardCharsets.UTF_8);
                            
                            final int fullLength = Math.min(Math.min(fullPT1.length, ct1.length), ct2.length);
                            final byte[] fullRecoveredPT2 = new byte[fullLength];
                            
                            for (int i = 0; i < fullLength; i++) {
                                fullRecoveredPT2[i] = (byte) (fullPT1[i] ^ ct1[i] ^ ct2[i]);
                            }
                            
                            final String fullyRecovered = new String(fullRecoveredPT2, StandardCharsets.UTF_8);
                            print("\nFULLY RECOVERED MESSAGE 2: '%s'", fullyRecovered);
                        }
                    }
                }
                
                // Forward to Bob
                send("bob", ct2);
                send("bob", iv2);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Bob receives and decrypts both messages normally
                for (int i = 1; i <= 2; i++) {
                    final byte[] ct = receive("alice");
                    final byte[] iv = receive("alice");
                    
                    final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                    aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    final byte[] pt = aes.doFinal(ct);
                    final String message = new String(pt, StandardCharsets.UTF_8);
                    
                    print("Bob received message %d: '%s'", i, message);
                }
            }
        });

        env.mitm("alice", "bob", "attacker");
        env.start();
    }
}

/*
 * QUESTIONS TO ANSWER AFTER RUNNING THE EXERCISE:
 * 
 * 1. Why is IV reuse catastrophic in CTR mode?
 *    - The same key stream is generated, allowing XOR relationships between plaintexts
 * 
 * 2. What is the mathematical property that makes this attack possible?
 *    - XOR is self-inverse: A ⊕ B ⊕ B = A
 *    - CT1 ⊕ CT2 = PT1 ⊕ PT2 (the key stream cancels out)
 * 
 * 3. How much plaintext knowledge is needed?
 *    - Even partial knowledge of one message allows partial recovery of others
 *    - Common patterns (headers, protocols) make attacks practical
 * 
 * 4. Does this attack work on CBC mode?
 *    - No! In CBC, IV reuse leaks if messages start identically, but doesn't allow full recovery
 *    - Each block depends on the previous ciphertext, breaking the simple XOR relationship
 * 
 * 5. How can this vulnerability be prevented?
 *    - NEVER reuse an IV/nonce with the same key in CTR mode
 *    - Use a counter, random nonce, or timestamp to ensure uniqueness
 *    - Better: use AEAD modes like GCM that handle nonces properly
 * 
 * 6. Is this related to the "one-time pad"?
 *    - Yes! One-time pad is perfectly secure IF the pad is used only once
 *    - Reusing the pad (two-time pad) completely breaks security
 *    - CTR mode generates a pseudo-random pad from IV+key; reuse has the same effect
 * 
 * REAL-WORLD EXAMPLES:
 * - Microsoft's PPTP VPN had this vulnerability
 * - Some WEP implementations reused IVs
 * - Various TLS implementations had nonce-reuse bugs
 * 
 * BONUS CHALLENGE:
 * - Modify the code to recover the FULL message 2 using crib-dragging
 *   (trying common words/phrases at different positions)
 * - Implement a statistical attack using character frequency analysis
 */
