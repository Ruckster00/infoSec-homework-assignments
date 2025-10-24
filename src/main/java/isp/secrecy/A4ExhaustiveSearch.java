package isp.secrecy;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import fri.isp.Agent;

/**
 * Implement a brute force key search (exhaustive key search) if you know that
 * the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last
 * three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class
 * {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        byte[] secretKey = new byte[8];
        SecureRandom random = new SecureRandom();
        secretKey[5] = (byte) random.nextInt(256);
        secretKey[6] = (byte) random.nextInt(256);
        secretKey[7] = (byte) random.nextInt(256);
        
        System.out.println("[SECRET KEY] " + Agent.hex(secretKey));
        
        Key key = new SecretKeySpec(secretKey, "DES");
        Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = encrypt.doFinal(message.getBytes());
        
        System.out.println("[CIPHERTEXT] " + Agent.hex(cipherText));
        
        System.out.println("\n--- Starting Brute Force Attack ---");        
        byte[] foundKey = bruteForceKey(cipherText, message);
        
        if (foundKey != null) {
            System.out.println("[FOUND KEY] " + Agent.hex(foundKey));
        } else {
            System.out.println("Failed to find the key.");
        }
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        byte[] possibleKey = new byte[8];        
        int attempts = 0;

        for (int i = 0; i < (1 << 24); i++) { // 2^24 combinations
            attempts++;
            possibleKey[5] = (byte) ((i >> 16) & 0xFF);
            possibleKey[6] = (byte) ((i >> 8) & 0xFF);
            possibleKey[7] = (byte) (i & 0xFF);
            
            try {
                Key key = new SecretKeySpec(possibleKey, "DES");
                Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                decrypt.init(Cipher.DECRYPT_MODE, key);
                final byte[] pt = decrypt.doFinal(ct);
                String plainMessage = new String(pt);
                
                if (plainMessage.equals(message)) {
                    return possibleKey;
                }
                
            } catch (Exception e) {
                continue;
            }
        }
        
        System.out.println("Key not found after trying all " + attempts + " possibilities");
        return null;
    }
}
