package com.upb;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class Main {

    public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (args.length == 3 && args[0].equals("D")) {
            File encrypted = new File(args[2]);
            File decrypted = new File("decrypted");
            BufferedReader bf = new BufferedReader(new FileReader(args[1]));
            String keyLine = bf.readLine();
            encryptDecrypt(keyLine, Cipher.DECRYPT_MODE, encrypted, decrypted);
        } else if (args.length == 2 && args[0].equals("E")) {
            System.out.println(System.getProperty("user.dir"));
            File plaintext = new File(args[1]);
            File encrypted = new File("encrypted");
            String key = createRandomKey();
            encryptDecrypt(key, Cipher.ENCRYPT_MODE, plaintext, encrypted);
        } else {
            System.out.println("Wrong number or usage of arguments.");
        }
    }

    private  static String createRandomKey(){
        Random rnd = new Random();
        int n = 10000000 + rnd.nextInt(90000000);
        return String.valueOf(n);
    }

    public static void encryptDecrypt(String key, int cipherMode, File in, File output) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(output);

        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());

        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = skf.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        byte[] ivBytes = new byte[8];
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        if(cipherMode == Cipher.ENCRYPT_MODE) {
            long start = System.nanoTime();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv, SecureRandom.getInstance("SHA1PRNG"));
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            write(cis, fos);
            PrintWriter out = new PrintWriter("key");
            out.println(key);
            out.close();
            long end = System.nanoTime();
            long duration = end - start;
            double durationInSeconds = (double) duration/ 1_000_000_000;
            System.out.println("Encryption took " + durationInSeconds + " seconds");
        } else if(cipherMode == Cipher.DECRYPT_MODE) {
            long start = System.nanoTime();
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv, SecureRandom.getInstance("SHA1PRNG"));
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            write(fis,cos);
            long end = System.nanoTime();
            long duration = end - start;
            double durationInSeconds = (double) duration/ 1_000_000_000;
            System.out.println("Decryption took " + durationInSeconds + " seconds");
        }
    }

    private static void write(InputStream in, OutputStream out) throws IOException {
        in.transferTo(out);
    }
}