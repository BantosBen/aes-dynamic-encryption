package com.sanj;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AESDynamicEncryption {
    public String encrypt(String plainText)
            throws Exception {
        Cipher cipher;
        cipher = Cipher.getInstance("AES");

        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        String salt = trimString(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        byte[] plainTextByte = plainText.getBytes();
        //System.out.println(Arrays.toString(plainTextByte));
//        byte[] plainTextByt=plainTextByte;
//        Arrays.sort(plainTextByt);
//        System.out.println(new String(plainTextByt));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        return salt + trimString(encoder.encodeToString(encryptedByte));
    }

    public String decrypt(String encryptedText)
            throws Exception {
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        StringBuilder encodedKey = new StringBuilder();
        StringBuilder encryption = new StringBuilder();
        System.out.println(encryptedText.length());
        for (int i = 0; i < encryptedText.length(); i++) {
            if (i < 22) {
                encodedKey.append(encryptedText.charAt(i));
            } else {
                encryption.append(encryptedText.charAt(i));
            }

        }
        encodedKey.append("==");
        encryption.append("==");

        double division= (double) encryption.toString().length();
        System.out.println(division);

        byte[] decodedKey = Base64.getDecoder().decode(encodedKey.toString());
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryption.toString());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
        return new String(decryptedByte);
    }

    public boolean verifyEncryption(String encryptedText, String plainText)
            throws Exception {
        boolean valid = false;
        String decryptedText = decrypt(encryptedText);
        if (decryptedText.equals(plainText)) {
            valid = true;
        }

        return valid;
    }

    private String trimString(String hex) {
        StringBuilder decimal = new StringBuilder();
        for (int i = 0; i < hex.length() - 2; i++) {

            char c = hex.charAt(i);
            decimal.append(c);
        }

        return decimal.toString();
    }
}
