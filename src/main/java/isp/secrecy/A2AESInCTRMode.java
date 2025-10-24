package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the
 * channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
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
                    /* STEP 3:
                     * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                     * Such exchange repeats 10 times.
                     *
                     * Do not forget: In CBC (and CTR mode), you have to also
                     * send the IV. The IV can be accessed via the
                     * cipher.getIV() call
                     */
                    final String message = "Message " + i + " from Alice to Bob. Hello Bob!";
                    print("Sending: '%s'", message);

                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    
                    // Generate a random nonce (initial counter value) for CTR mode
                    final byte[] nonce = new byte[16]; // 128-bit nonce for AES
                    new SecureRandom().nextBytes(nonce);
                    
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
                    final byte[] ct = encrypt.doFinal(pt);

                    // send both cipher text and nonce to bob
                    send("bob", ct);
                    send("bob", nonce);

             

                    // Wait for Bob's reply (except for the last message)
                    if (i < 10) {
                        final byte[] bobCt = receive("bob");
                        final byte[] bobNonce = receive("bob");
                        
                        // Decrypt Bob's message using the nonce
                        final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                        decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(bobNonce));
                        final byte[] bobPt = decrypt.doFinal(bobCt);
                        print("Got '%s'", new String(bobPt));
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive 10 messages from Alice and reply to 9 of them
                for (int i = 1; i <= 10; i++) {
                    /* STEP 4
                     * Bob receives, decrypts and displays a message.
                     * Once you obtain the byte[] representation of cipher parameters,
                     * you can load them with:
                     *
                     *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                     *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                     *
                     * You then pass this object to the cipher init() method call.*
                     */
                    final byte[] ct = receive("alice");
                    final byte[] nonce = receive("alice");

                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
                    final byte[] dt = decrypt.doFinal(ct);
                    print("Got '%s'", new String(dt));

                    // Reply to Alice's message (except for the last one)
                    if (i < 10) {
                        final String replyMessage = "Reply " + i + " from Bob to Alice. Hi Alice!";
                        print("Sending: '%s'", replyMessage);
                        
                        final byte[] replyPt = replyMessage.getBytes();
                        
                        // Encrypt the reply
                        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                        
                        // Generate a random nonce for the reply
                        final byte[] replyNonce = new byte[16];
                        new SecureRandom().nextBytes(replyNonce);
                        
                        encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(replyNonce));
                        final byte[] replyCt = encrypt.doFinal(replyPt);
                        
                        // Send reply to Alice
                        send("alice", replyCt);
                        send("alice", replyNonce);
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
