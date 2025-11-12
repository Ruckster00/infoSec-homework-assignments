package isp;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import fri.isp.Agent;

public class ChaChaExample {
    public static void main(String[] args) throws Exception {
        // shared key
        final SecretKey sharedKey = KeyGenerator.getInstance("ChaCha20").generateKey();

        // the payload
        final String message = "this is my message";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.printf("MSG: %s%n", message);
        System.out.printf("PT:  %s%n", Agent.hex(pt));

        // encrypt
        final Cipher alice = Cipher.getInstance("ChaCha20-Poly1305");
        alice.init(Cipher.ENCRYPT_MODE, sharedKey);
        final byte[] ct = alice.doFinal(pt);
        System.out.printf("CT:  %s%n", Agent.hex(ct));

        // send IV
        final byte[] iv = alice.getIV();
        System.out.printf("IV:  %s%n", Agent.hex(iv));

        // decrypt
        final Cipher bob = Cipher.getInstance("ChaCha20-Poly1305");
        // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
        // the default is 128 bits
        bob.init(Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(iv));
        final byte[] pt2 = bob.doFinal(ct);
        System.out.printf("PT:  %s%n", Agent.hex(pt2));
        System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
    }
    
}
