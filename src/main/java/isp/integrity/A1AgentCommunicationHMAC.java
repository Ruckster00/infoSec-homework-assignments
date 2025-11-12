package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);
                
                for (int i = 1; i <= 10; i++) {
                    final String text = "Message " + i + ": I hope you get this message intact. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final byte[] tag = mac.doFinal(pt);
                    final byte[] messageWithTag = new byte[pt.length + tag.length];
                    System.arraycopy(pt, 0, messageWithTag, 0, pt.length);
                    System.arraycopy(tag, 0, messageWithTag, pt.length, tag.length);
                    
                    send("bob", messageWithTag);
                    print("Alice sent message " + i + " with HMAC: " + hex(tag));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);

                for (int i = 1; i <= 10; i++) {
                    final byte[] messageWithTag = receive("alice");
                    final int tagSize = 32;
                    final int messageSize = messageWithTag.length - tagSize;
                    final byte[] receivedMessage = new byte[messageSize];
                    final byte[] receivedTag = new byte[tagSize];
                    
                    System.arraycopy(messageWithTag, 0, receivedMessage, 0, messageSize);
                    System.arraycopy(messageWithTag, messageSize, receivedTag, 0, tagSize);

                    final byte[] computedTag = mac.doFinal(receivedMessage);

                    final boolean isValid = MessageDigest.isEqual(receivedTag, computedTag);
                    
                    if (isValid) {
                        final String messageText = new String(receivedMessage, StandardCharsets.UTF_8);
                        print("Bob received valid message " + i + ": " + messageText);
                    } else {
                        print("Tags are not equal. Message " + i + " has been modified!");
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
