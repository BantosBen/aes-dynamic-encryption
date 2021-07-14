package com.sanj.lib;

// Java program to implement the
// encryption and decryption


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;


// Creating the symmetric class which implements the symmetric

public class EncryptionAlgorithm {

    private static final String AES = "AES";
    // We are using a Block cipher(CBC mode)
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

    public static SecretKey createAESecretKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);
        keygenerator.init(securerandom);
        return keygenerator.generateKey();
    }

    // Function to initialize a vector with an arbitrary value
    public static byte[] createInitializationVector() {
        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }


    // This function takes plaintext,the key with an initialization,vector to convert plainText into CipherText.
    private static byte[] processEncryption(String plainText, SecretKey secretKey, byte[] initializationVector) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    // This function performs the reverse operation of the do_AESEncryption function. It converts ciphertext to the plaintext using the key.
    private static String processDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    public String encrypt(String plainText) {
        try {
            SecretKey secretKey = createAESecretKey();
            String secretKeyString = DatatypeConverter.printHexBinary(secretKey.getEncoded());
            byte[] initializationVector = createInitializationVector();
            String initializationVectorString = DatatypeConverter.printHexBinary(initializationVector);
            byte[] encryptedText = processEncryption(plainText, secretKey, initializationVector);
            String encryptedTextString = DatatypeConverter.printHexBinary(encryptedText);

            return secretKeyString + initializationVectorString + encryptedTextString;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String encryptedText) {
        try {
            StringBuilder secretKeyString = new StringBuilder();
            StringBuilder initializationVectorString = new StringBuilder();
            StringBuilder encryptedTextString = new StringBuilder();

            for (int i = 0; i < encryptedText.length(); i++) {
                if (i < 32) {
                    secretKeyString.append(encryptedText.charAt(i));
                } else if (i < 64) {
                    initializationVectorString.append(encryptedText.charAt(i));
                }else {
                    encryptedTextString.append(encryptedText.charAt(i));
                }
            }
            byte[] secretKeyByte= DatatypeConverter.parseHexBinary(secretKeyString.toString());
            SecretKey secretKey = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, AES);
            byte[] initializationVector=DatatypeConverter.parseHexBinary(initializationVectorString.toString());
            byte[] encryptedTextByte=DatatypeConverter.parseHexBinary(encryptedTextString.toString());

            return processDecryption(encryptedTextByte,secretKey,initializationVector);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    // Driver code
//
//    public static void main(String args[])throws Exception {
//
//        SecretKey Symmetrickey = createAESKey();
//        String SymmetrickeyString= DatatypeConverter.printHexBinary(Symmetrickey.getEncoded());
//        System.out.println( "The Symmetric Key is :"+ SymmetrickeyString.length());
//        byte[] initializationVector= createInitializationVector();
//        String initializationVectorString=DatatypeConverter.printHexBinary(initializationVector);
//        System.out.println("initializationVector:"+initializationVectorString.length());
//        byte[] decodedKey= DatatypeConverter.parseHexBinary(SymmetrickeyString);
//        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, AES);
//        System.out.println(secretKey.equals(Symmetrickey));
//        //System.out.println(Arrays.equals(DatatypeConverter.parseHexBinary(initializationVectorString), initializationVector));
//        String plainText= "This is the message I want To Encrypt.";
//
//        // Encrypting the message using the symmetric key
//        byte[] cipherText = do_AESEncryption(plainText,Symmetrickey,initializationVector);
//        System.out.println("The ciphertext or Encrypted Message is: "+ DatatypeConverter.printHexBinary(cipherText));
//
//        // Decrypting the encrypted message
//        String decryptedText= do_AESDecryption(cipherText,Symmetrickey,initializationVector);
//        System.out.println( "Your original message is: "+ decryptedText);
//
//    }
}