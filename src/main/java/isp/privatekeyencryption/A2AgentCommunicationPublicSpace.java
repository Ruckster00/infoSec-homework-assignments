package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();
        final SecretKey sharedKeyChaCha = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey sharedKeyAES = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);
                send("bob", data);
                MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed = digestAlgorithm.digest(data);
                Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");
                encrypt.init(Cipher.ENCRYPT_MODE, sharedKeyChaCha);
                final byte[] encryptedHash = encrypt.doFinal(hashed);
                send("public-space", encryptedHash);
                final byte[] iv = encrypt.getIV();
                send("public-space", iv);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                final byte[] encryptedDigestChaCha = receive("alice");
                final byte[] ivChaCha = receive("alice");
                Cipher chaCha = Cipher.getInstance("ChaCha20-Poly1305");
                chaCha.init(Cipher.DECRYPT_MODE, sharedKeyChaCha, new IvParameterSpec(ivChaCha));
                final byte[] decryptedDigestChaCha = chaCha.doFinal(encryptedDigestChaCha);
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, sharedKeyAES);
                final byte[] encryptedDigestAES = aes.doFinal(decryptedDigestChaCha);
                send("bob", encryptedDigestAES);
                final byte[] iv = aes.getIV();
                send("bob",iv);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] data = receive("alice");
                MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed = digestAlgorithm.digest(data);
                Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] encryptedDigest = receive("public-space");
                final byte[] iv = receive("public-space");
                decrypt.init(Cipher.DECRYPT_MODE, sharedKeyAES, new GCMParameterSpec(128, iv));
                final byte[] decryptedDigest = decrypt.doFinal(encryptedDigest);
                final boolean isValid = MessageDigest.isEqual(hashed, decryptedDigest);

                if (isValid) {
                    print("Integrity maintained. Data was not changed during exchange.");
                } else {
                    print("Data was changed during exchange.");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
