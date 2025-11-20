package isp.signatures;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();
        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";
        // Create key pairs
        final KeyPair aliceKP = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 1; i <= 10; i++) {
                    final String message = i + "Hello bob, whats up?";
                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(aliceKP.getPrivate());
                    signer.update(message.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();
                    send("bob", message.getBytes(StandardCharsets.UTF_8));
                    send("bob", signature);
                    if (i < 10) {
                        final byte[] reply = receive("bob");
                        final byte[] replySignature = receive("bob");
                        final Signature verifier = Signature.getInstance(signingAlgorithm);
                        verifier.initVerify(bobKP.getPublic());
                        verifier.update(reply);
                        if (verifier.verify(replySignature))
                            print("Valid signature for reply from bob.");
                        else
                            print("Invalid signature for reply from bob.");

                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 1; i <= 10; i++) {
                    final byte[] message = receive("alice");
                    final byte[] signature = receive("alice");
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(aliceKP.getPublic());
                    verifier.update(message);
                    if (verifier.verify(signature))
                        print("Valid signature for message from alice.");
                    else
                        print("Invalid signature for message from alice.");

                    if (i < 10) {
                        final String reply = i + "Hey, not much. Hope you're doing well!";
                        final Signature signer = Signature.getInstance(signingAlgorithm);
                        signer.initSign(bobKP.getPrivate());
                        signer.update(reply.getBytes(StandardCharsets.UTF_8));
                        final byte[] replySignature = signer.sign();
                        send("alice", reply.getBytes(StandardCharsets.UTF_8));
                        send("alice", replySignature);
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}