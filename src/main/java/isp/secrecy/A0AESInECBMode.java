package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import java.security.Key;

/**
 * PRACTICE ASSIGNMENT:
 * Assuming Alice and Bob know a shared secret key in advance, secure the
 * channel using AES in ECB mode. Then exchange ten messages between Alice and Bob.
 * 
 * LEARNING OBJECTIVES:
 * - Understand why ECB mode is insecure for most applications
 * - Observe that ECB does not require an IV (deterministic encryption)
 * - Notice that identical plaintext blocks produce identical ciphertext blocks
 * - Compare with CBC mode to understand the importance of randomized encryption
 * 
 * TASK:
 * 1. Implement message exchange using AES/ECB/PKCS5Padding
 * 2. Send the same message twice and observe the ciphertext
 * 3. Answer: Why is this a security problem?
 * 
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A0AESInECBMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Exchange 10 messages with Bob
                for (int i = 1; i <= 10; i++) {
                    /*
                     * STEP 3:
                     * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                     * Such exchange repeats 10 times.
                     *
                     * NOTE: In ECB mode, you do NOT need to send an IV because ECB is deterministic.
                     * Each block is encrypted independently with the same key.
                     * 
                     * TODO: Implement encryption using "AES/ECB/PKCS5Padding"
                     * - Initialize cipher in ENCRYPT_MODE with the shared key
                     * - Encrypt the plaintext
                     * - Send only the ciphertext (no IV needed)
                     */
                    final String message = "Message " + i + " from Alice to Bob. Hello Bob!";
                    print("Sending: '%s'", message);

                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = encrypt.doFinal(pt);

                    send("bob", ct);

                    // Wait for Bob's reply (except for the last message)
                    if (i < 10) {
                        final byte[] bobCt = receive("bob");

                        final Cipher decrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        decrypt.init(Cipher.DECRYPT_MODE, key);
                        final byte[] bobPt = decrypt.doFinal(bobCt);
                        print("Got reply '%s', converted to string: '%s'", hex(bobCt), new String(bobPt));
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive 10 messages from Alice and reply to 9 of them
                for (int i = 1; i <= 10; i++) {
                    /*
                     * STEP 4:
                     * Bob receives, decrypts and displays a message.
                     * 
                     * NOTE: ECB mode does not use an IV, so you only receive the ciphertext.
                     * 
                     * TODO: Implement decryption using "AES/ECB/PKCS5Padding"
                     * - Receive the ciphertext
                     * - Initialize cipher in DECRYPT_MODE with the shared key
                     * - Decrypt and display the message
                     */
                    
                    final byte[] ct = receive("alice");

                    final Cipher decrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    decrypt.init(Cipher.DECRYPT_MODE, key);
                    final byte[] dt = decrypt.doFinal(ct);
                    print("Got message '%s', converted to string: '%s'", hex(ct), new String(dt));

                    // Reply to Alice's message (except for the last one)
                    if (i < 10) {
                        final String replyMessage = "Reply " + i + " from Bob to Alice. Hi Alice!";
                        print("Sending: '%s'", replyMessage);

                        final byte[] replyPt = replyMessage.getBytes();

                        final Cipher encrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        encrypt.init(Cipher.ENCRYPT_MODE, key);
                        final byte[] replyCt = encrypt.doFinal(replyPt);

                        send("alice", replyCt);
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}

/*
 * QUESTIONS TO ANSWER AFTER COMPLETING THE EXERCISE:
 * 
 * 1. What happens if you encrypt the same message twice?
 *    - Modify the code to send "Hello Bob!" twice and compare the ciphertexts
 *    - Are they identical? Why is this a problem?
 * 
 * 2. Why is ECB mode considered insecure?
 *    - Think about what information an attacker can learn from observing ciphertexts
 *    - Consider the famous "ECB penguin" example
 * 
 * 3. What are the main differences between ECB and CBC modes?
 *    - Does ECB use an IV? Does CBC?
 *    - Is ECB randomized or deterministic?
 *    - Which one reveals patterns in the plaintext?
 * 
 * 4. When (if ever) might ECB mode be acceptable?
 *    - Hint: Think about encrypting single blocks of random data (e.g., keys)
 * 
 * BONUS CHALLENGE:
 * - Send two messages that have the same first 16 bytes (one AES block)
 * - Observe that the first block of ciphertext is identical
 * - This demonstrates the block-independence property of ECB
 */
