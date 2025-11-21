package isp.concepts_summarized;

import fri.isp.Agent;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Demonstrates all three cases of Key Derivation:
 * 1. Case 1: Uniform Source Key (using PRF)
 * 2. Case 2: Non-Uniform Source Key (using HKDF)
 * 3. Case 3: Password-Based KDF (using PBKDF2)
 */
public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        System.out.println("=== KEY DERIVATION EXAMPLES ===\n");
        
        case1_UniformSourceKey();
        System.out.println("\n" + "=".repeat(50) + "\n");
        
        case2_NonUniformSourceKey_HKDF();
        System.out.println("\n" + "=".repeat(50) + "\n");
        
        case3_PasswordBased_PBKDF2();
    }

    // Case 1: Uniform Source Key - use PRF
    private static void case1_UniformSourceKey() throws Exception {
        System.out.println("CASE 1: Uniform Source Key (PRF-based KDF)");

        // Generate uniform random key
        final SecretKey uniformSourceKey = KeyGenerator.getInstance("AES").generateKey();
        System.out.printf("Source Key: %s%n", Agent.hex(uniformSourceKey.getEncoded()));

        // Derive keys using HMAC as PRF with different contexts
        final Mac hmacPRF = Mac.getInstance("HmacSHA256");
        
        hmacPRF.init(new SecretKeySpec(uniformSourceKey.getEncoded(), "HmacSHA256"));
        final byte[] encKey = hmacPRF.doFinal("encryption".getBytes());
        System.out.printf("Encryption Key: %s%n", Agent.hex(Arrays.copyOf(encKey, 16)));

        hmacPRF.init(new SecretKeySpec(uniformSourceKey.getEncoded(), "HmacSHA256"));
        final byte[] macKey = hmacPRF.doFinal("mac".getBytes());
        System.out.printf("MAC Key: %s%n", Agent.hex(Arrays.copyOf(macKey, 16)));
    }

    // Case 2: Non-Uniform Source Key - use HKDF (Extract-then-Expand)
    private static void case2_NonUniformSourceKey_HKDF() throws Exception {
        System.out.println("CASE 2: Non-Uniform Source Key (HKDF)");

        // Simulate DH shared secret
        final byte[] dhSharedSecret = new byte[32];
        new SecureRandom().nextBytes(dhSharedSecret);
        System.out.printf("DH Shared Secret: %s%n", Agent.hex(dhSharedSecret));

        // HKDF Extract: PRK = HMAC(salt, SK)
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        final Mac hmacExtract = Mac.getInstance("HmacSHA256");
        hmacExtract.init(new SecretKeySpec(salt, "HmacSHA256"));
        final byte[] prk = hmacExtract.doFinal(dhSharedSecret);
        System.out.printf("PRK (Extract): %s%n", Agent.hex(prk));

        // HKDF Expand: derive keys from PRK
        final Mac hmacExpand = Mac.getInstance("HmacSHA256");
        
        hmacExpand.init(new SecretKeySpec(prk, "HmacSHA256"));
        final byte[] encKey = hmacExpand.doFinal("encryption".getBytes());
        System.out.printf("Encryption Key: %s%n", Agent.hex(Arrays.copyOf(encKey, 16)));

        hmacExpand.init(new SecretKeySpec(prk, "HmacSHA256"));
        final byte[] macKey = hmacExpand.doFinal("mac".getBytes());
        System.out.printf("MAC Key: %s%n", Agent.hex(Arrays.copyOf(macKey, 16)));
    }

    // Case 3: Password-Based KDF - use PBKDF2 (slow, salted)
    private static void case3_PasswordBased_PBKDF2() throws Exception {
        System.out.println("CASE 3: Password-Based KDF (PBKDF2)");

        final String password = "hunter2";
        final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);

        // PBKDF2 with high iteration count
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        final SecretKey derivedKey = pbkdf.generateSecret(specs);

        System.out.printf("Password: %s%n", password);
        System.out.printf("Salt: %s%n", Agent.hex(salt));
        System.out.printf("Derived Key: %s%n", Agent.hex(derivedKey.getEncoded()));

        // Example usage with HMAC
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(derivedKey.getEncoded(), "HmacSHA256"));
        System.out.printf("HMAC[Hello World!] = %s%n", Agent.hex(hmac.doFinal("Hello World!".getBytes())));
    }
}
