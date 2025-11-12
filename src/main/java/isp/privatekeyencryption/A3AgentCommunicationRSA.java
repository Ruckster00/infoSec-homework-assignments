package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                for (int i = 1; i <= 10; i++) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final Cipher encrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                    final byte[] ct = encrypt.doFinal(pt);
                    send("bob", ct);

                    if (i < 10) {
                        final byte[] bobCt = receive("bob");
                        final Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                        decrypt.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                        final byte[] bobPt = decrypt.doFinal(bobCt);
                        print("Got reply '%s', converted to string: '%s'", hex(bobCt), new String(bobPt));
                    }
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */

                for (int i = 1; i <= 10; i++) {
                    final byte[] ct = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] pt = decrypt.doFinal(ct);
                    print("Got message '%s', converted to string: '%s'", hex(ct), new String(pt));

                    if (i < 10) {
                        final String reply = "Thank you for your message! Kisses, Bob. xoxo";
                        final byte[] replyPt = reply.getBytes(StandardCharsets.UTF_8);
                        final Cipher encrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                        encrypt.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
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
