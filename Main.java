package com.upb;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Random;

public class Main {

    public static void main(String[] args) throws Exception {

        if (args.length == 3 && args[0].equals("D")) {
            File encrypted = new File(args[2]);
            File decrypted = new File("decrypted");
            BufferedReader bf = new BufferedReader(new FileReader(args[1]));
            String encryptedKey = bf.readLine();
            String privateLine = bf.readLine();
            String originalSum = bf.readLine();
            RSA rsa = new RSA();
            MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
            String checksum = getFileChecksum(shaDigest,encrypted);
            if(!checksum.equals(originalSum)) {
                System.out.println("The encrypted file was tampered");
                return;
            }
            rsa.initFromString(privateLine);
            String decryptedKey = rsa.decrypt(encryptedKey);
            encryptDecrypt(decryptedKey, Cipher.DECRYPT_MODE, encrypted, decrypted);
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

    private static String getFileChecksum(MessageDigest digest, File file) throws IOException
    {
        FileInputStream fis = new FileInputStream(file);

        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        };

        fis.close();

        byte[] bytes = digest.digest();

        StringBuilder sb = new StringBuilder();
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    private  static String createRandomKey(){
        Random rnd = new Random();
        int n = 10000000 + rnd.nextInt(90000000);
        return String.valueOf(n);
    }

    public static void encryptDecrypt(String key, int cipherMode, File in, File output) throws Exception {
        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(output);
        RSA rsa = new RSA();
        rsa.init();
        String encryptedKey = rsa.encrypt(key);
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
            out.println(encryptedKey);
            out.println(rsa.getPrivateKey());

            MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
            String shaChecksum = getFileChecksum(shaDigest,output);
            out.println(shaChecksum);
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

    private void write(InputStream in, OutputStream out) throws IOException {
        in.transferTo(out);
    }
}