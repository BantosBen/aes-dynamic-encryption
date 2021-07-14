package com.sanj;

import com.github.cliftonlabs.json_simple.JsonArray;
import com.github.cliftonlabs.json_simple.JsonObject;
import com.sanj.lib.EncryptionAlgorithm;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class Main {
    public static void main(String[] args) throws Exception {
//        System.out.println(new AESDynamicEncryption().decrypt("ZId/oPPvTbfYVZV6XSlRRgAtOLQUTJGqe3+etxY6KkyOsRKE0fwHft/F+7++d4oMmFJEbGGRdpj+DWxcJRn8FugpAi1kdmuX1B\\nDzEaezq2o6qX36Qc2gnJHc9ZoDMvf7MxMlExL0NIea12sGjSmQPt1Q2V9w2Jp9XizK7d+Vi0M3V8\\n6iY8mOY6Ex9KlIJkgMM2eyyTvraV/G2LT/lZFtThrqdbKGVxQjrLDuk04Edhvc9yovISMVRyoRVD\\nTeTWPF17PBBrLzQ9RRIAiR17zbEXdun1jAPGR4rThkQtOU33MQ7sF5WbkoP3+lb7wjFPHn"));
        //System.out.println(new AESDynamicEncryption().encrypt("{\"responseCode\":\"1\",\"responseData\":[{\"message_id\":\"1\",\"category\":\"Students\",\"message\":\"The End Of Term Exams Shall Be Administered As From 11\\/12\\/2020\",\"date_posted\":\"2020-06-25\"}]}\n"));

        JSONArray smartContractJsonArray = new JSONArray();
        JSONObject smartContractJsonObject =new JSONObject();
        smartContractJsonObject.put("sellerPublicKey", String.valueOf(System.currentTimeMillis()));
        smartContractJsonObject.put("buyerPublicKey", String.valueOf(System.currentTimeMillis()));
        smartContractJsonObject.put("sellerPhone", String.valueOf(new Random().nextInt(1000000000)));
        smartContractJsonObject.put("buyerPhone", String.valueOf(new Random().nextInt(1000000000)));
        smartContractJsonObject.put("amount", String.valueOf(new Random().nextInt(100)));
        smartContractJsonObject.put("matureDays", String.valueOf(new Random().nextInt(10)));
        smartContractJsonObject.put("validation", false);
        smartContractJsonObject.put("buyerConfirmation", false);
        smartContractJsonObject.put("terminated", false);
        smartContractJsonArray.add(smartContractJsonObject);

        String plainText= smartContractJsonArray.toJSONString();
        String encryptedPlainText=new EncryptionAlgorithm().encrypt(plainText);
        System.out.println(encryptedPlainText);
        System.out.println("ENCRYPTION SIZE: "+encryptedPlainText.length());
        String decryptedPlainText=new EncryptionAlgorithm().decrypt(encryptedPlainText);
        System.out.println(decryptedPlainText);
        smartContractJsonArray= (JSONArray) new JSONParser().parse(decryptedPlainText);
        smartContractJsonObject= (JSONObject) smartContractJsonArray.get(0);
        System.out.println(smartContractJsonObject.get("amount"));


    }
}
