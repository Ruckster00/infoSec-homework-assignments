package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import java.nio.charset.StandardCharsets;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        // final Key key = KeyGenerator.getInstance("AES").generateKey();
        final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 1; i <= 10; i++) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, sharedKey);
                    final byte[] ct = encrypt.doFinal(pt);
                    final byte[] iv = encrypt.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    if (i < 10) {
                        final byte[] bobCt = receive("bob");
                        final byte[] bobIv = receive("bob");
                        final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                        decrypt.init(Cipher.DECRYPT_MODE, sharedKey, new GCMParameterSpec(128, bobIv));
                        final byte[] bobPt = decrypt.doFinal(bobCt);
                        print("Got reply '%s', converted to string: '%s'", hex(bobCt), new String(bobPt));
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 1; i <= 10; i++) {
                    final byte[] ct = receive("alice");
                    final byte[] iv = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, sharedKey, new GCMParameterSpec(128, iv));
                    final byte[] pt = decrypt.doFinal(ct);
                    print("Got message '%s', converted to string: '%s'", hex(ct), new String(pt));

                    if (i < 10) {
                        final String reply = "Thank you for your message! Kisses, Bob. xoxo";
                        final byte[] replyPt = reply.getBytes(StandardCharsets.UTF_8);
                        final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                        encrypt.init(Cipher.ENCRYPT_MODE, sharedKey);
                        final byte[] replyCt = encrypt.doFinal(replyPt);
                        final byte[] replyIv = encrypt.getIV();
                        send("alice", replyCt);
                        send("alice", replyIv);
                    }
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
