package isp.midterm2;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import fri.isp.Agent;
import fri.isp.Environment;

public class Midterm2 {
    public static void main(String[] args) throws Exception {
        Environment env = new Environment();
        final KeyPair serverKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final String pwd = "Alice123";

        env.add(new Agent("alice") {
            public void task() throws Exception {
                // Step 1: Alice create secrete and public value and sends public value to
                // server
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                final PublicKey A = keyPair.getPublic();
                final PrivateKey a = keyPair.getPrivate();
                send("server", A.getEncoded());

                final byte[] B = receive("server");
                final byte[] o = receive("server");
                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(serverKP.getPublic());
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                digestAlgorithm.update(A.getEncoded());
                digestAlgorithm.update(B);
                verifier.update(digestAlgorithm.digest());
                if (verifier.verify(o)) {
                    print("Valid signature.");
                    final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                    dh.init(a);
                    dh.doPhase((ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(B)),
                            true);
                    final byte[] sharedSecret = dh.generateSecret();
                    digestAlgorithm.reset();
                    final byte[] sharedSecretHash = digestAlgorithm.digest(sharedSecret);
                    final byte[] k = Arrays.copyOfRange(sharedSecretHash, 0, 16);
                    final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                    final byte[] challEncrypted = receive("server");
                    final byte[] iv = receive("server");
                    aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, iv));
                    final byte[] challDecrypted = aes.doFinal(challEncrypted);
                    digestAlgorithm.reset();
                    digestAlgorithm.update(pwd.getBytes());
                    digestAlgorithm.update(challDecrypted);
                    final byte[] resp = digestAlgorithm.digest();
                    aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
                    send("server", aes.doFinal(resp));
                    send("server", aes.getIV());
                } else
                    print("Invalid signature.");

            }
        });
        env.add(new Agent("server") {
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.genKeyPair();
                final PrivateKey b = keyPair.getPrivate();
                final PublicKey B = keyPair.getPublic();

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey A = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(A, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                // Step 2: Hash shared secret to derive AES symmetric key
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                final byte[] sharedSecretHash = digest.digest(sharedSecret);
                final byte[] k = Arrays.copyOfRange(sharedSecretHash, 0, 16);
                digest.reset();
                digest.update(A.getEncoded());
                digest.update(B.getEncoded());
                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(serverKP.getPrivate());
                signer.update(digest.digest());
                final byte[] o = signer.sign();
                send("alice", B.getEncoded());
                send("alice", o);
                final byte[] chall = new byte[32];
                new Random().nextBytes(chall);
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
                final byte[] ct = aes.doFinal(chall);
                final byte[] iv = aes.getIV();
                send("alice", ct);
                send("alice", iv);

                final byte[] ctResp = receive("alice");
                final byte[] ivResp = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, ivResp));
                digest.reset();
                digest.update(pwd.getBytes());
                digest.update(chall);
                final byte[] concat = digest.digest();
                final byte[] ptResp = aes.doFinal(ctResp);

                if (MessageDigest.isEqual(ptResp, concat)) {
                    print("Alice is authenticated");
                } else {
                    print("Connection couldn't be established.");
                }

            }
        });

        env.connect("alice", "server");
        env.start();
    }
}