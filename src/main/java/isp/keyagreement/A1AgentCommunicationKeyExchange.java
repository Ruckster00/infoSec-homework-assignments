package isp.keyagreement;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Hey bob, what's up? Did you get my message?";
                final byte[] bobPkBytes = receive("bob");
                final PublicKey bobPublicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(bobPkBytes));

                final KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                final byte[] sharedSecret = kg.generateKey().getEncoded();
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, "AES");

                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.ENCRYPT_MODE, bobPublicKey);
                final byte[] wrappedKey = rsa.doFinal(sharedSecret);

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", wrappedKey);
                send("bob", iv);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                final KeyPair rsaKp = kpg.generateKeyPair();
                send("alice", rsaKp.getPublic().getEncoded());
                print("Sent RSA public key");

                final byte[] wrappedKey = receive("alice");
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.DECRYPT_MODE, rsaKp.getPrivate());
                final byte[] sharedSecret = rsa.doFinal(wrappedKey); // unwrap shared secret
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}