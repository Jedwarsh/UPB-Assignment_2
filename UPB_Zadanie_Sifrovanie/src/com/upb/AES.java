package com.upb;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES {

    // Getter for IvParameterSpec
    public static IvParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    // Setter for IvParameterSpec
    public static void setParameterSpec(IvParameterSpec parameterSpec) {
        AES.parameterSpec = parameterSpec;
    }

    // Global IvParameterSpec variable
    private static IvParameterSpec parameterSpec;

    // Getter for original message
    public static String getMessage() {
        return message;
    }

    // Setter for original message
    public static void setMessage(String message) {
        AES.message = message;
    }

    // Original message stored as a global variable
    private static String message;

    // Getter for decrypted message
    public static String getDecrypted() {
        return decrypted;
    }

    // Setter for decrypted message
    public static void setDecrypted(String decrypted) {
        AES.decrypted = decrypted;
    }

    // Decrypted message stored as a global variable
    private static String decrypted;

    // Method that is capable of decrypting messages with a secret key and measures the elapsed time during the method
    public static String Decrypt(SecretKey secretKey, byte[] encryptedMessageBytes) throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        long start = System.nanoTime();
        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE,secretKey,parameterSpec);
        byte[] decryptedMessageBytes =
                decryptionCipher.doFinal(encryptedMessageBytes);
        setDecrypted(new String(decryptedMessageBytes));
        System.out.println("Decrypted message = "+decrypted);
        long end = System.nanoTime();
        long duration = end - start;
        double durationInSeconds = (double) duration/ 1_000_000_000;
        System.out.println("Decryption took " + durationInSeconds + " seconds");
        return decrypted;
    }

    // Method that is capable of encrypting messages with a secret key and measures the elapsed time during the method
    public static byte[] Encrypt(SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long start = System.nanoTime();
        Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        byte[] InitVectorBytes = keyGenerator.generateKey().getEncoded();
        parameterSpec = new IvParameterSpec(InitVectorBytes);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key,parameterSpec);
        setMessage("Hello World");
        byte[] encryptedMessageBytes =
                encryptionCipher.doFinal(message.getBytes());
        String encryptedMessage =
                Base64.getEncoder().encodeToString(encryptedMessageBytes);
        System.out.println("Original message = "+ message);
        System.out.println("Encrypted message = "+ encryptedMessage);
        long end = System.nanoTime();
        long duration = end - start;
        double durationInSeconds = (double) duration/ 1_000_000_000;
        System.out.println("Encryption took " + durationInSeconds + " seconds");
        return encryptedMessageBytes;
    }

    // Method that creates a secret key
    public static SecretKey createKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        String secretKeyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Secret key = " + secretKeyString);
        return secretKey;
    }

    // Method that compares the original message and the decrypted message
    public static void checkMessages(){
        String original = getMessage();
        String decrypted = getDecrypted();
        if (original.equals(decrypted)) {
            System.out.println("The strings match");
        }
        else {
            System.out.println("The strings don't match");
        }
    }
}
