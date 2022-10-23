package com.upb;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void init() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception ignored) {

        }
    }

    public void initFromString(String privateKey){
        try{
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(privateKey));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            this.privateKey = keyFactory.generatePrivate(keySpecPrivate);
        }catch( Exception ignored){}
    }


    public String getPrivateKey() {
        return encode(privateKey.getEncoded());
    }

    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);

    }
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public String decrypt(String encryptedMessage) throws Exception{
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage,"UTF8");
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args){
        RSA rsa = new RSA();
        try{
            String encryptedMessage = rsa.encrypt("Hello World");
            String decryptrdMessage = rsa.decrypt(encryptedMessage);

            System.err.println("Encrypted: " + encryptedMessage);
            System.err.println("Decrypted: " + decryptrdMessage);
        }catch (Exception ignored){}
    }
}
