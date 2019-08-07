package com.zhuguang.zhou.utils;

import it.sauronsoftware.base64.Base64;
import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


/**
 * 自己定义的数据加密和解密
 */
public class PKCS8Prod {
    private static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY ="publicKey";
    private static final String PRIVATE_KEY ="privateKey";


    public static void main(String[] args) throws Exception{
        Map<String,String> keyMap = genKey();
        RSAPublicKey publicKey = getPublicKey(keyMap.get(PUBLIC_KEY));
        RSAPrivateKey privateKey = getPrivateKey(keyMap.get(PRIVATE_KEY));
        String info ="明文123456";
        //加密
        byte[] bytes = encrypt(info.getBytes("utf-8"),publicKey);
        System.out.println("加密后的数据:" + new String(bytes));
        //解密
         String by = decrypt(bytes, privateKey);
        System.out.println("解密后的数据" + by);

    }

    private static String decrypt(byte[] bytes, RSAPrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher pircipher = Cipher.getInstance(keyFactory.getAlgorithm());
        pircipher.init(Cipher.DECRYPT_MODE,privateKey );
        byte[] doFinal = pircipher.doFinal(bytes);
        String stringresult = new String(doFinal,"UTF-8");
        System.out.println(stringresult);
        return stringresult;
    }

    private static byte[] encrypt(byte[] bytes, RSAPublicKey publicKey) throws Exception {
        //加密数据
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] datas =  cipher.doFinal(bytes);
        return datas;
    }

    public static Map<String,String> genKey() throws Exception {
        Map<String,String> keyMap = new HashMap<String,String>();
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = new SecureRandom("CGWS@Login@Pad1258693wq^cczj%zhou".getBytes());
        // random.setSeed(keyInfo.getBytes());
        // 初始加密，512位已被破解，用1024位,最好用2048位
        keygen.initialize(2048, random);
        // 取得密钥对
        KeyPair kp = keygen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
        String privateKeyString = new String(Base64.encode(privateKey.getEncoded()),"UTF-8");
        RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
        String publicKeyString = new String(Base64.encode(publicKey.getEncoded()),"UTF-8");
        keyMap.put(PUBLIC_KEY, publicKeyString);
        keyMap.put(PRIVATE_KEY, privateKeyString);
        return keyMap;
    }

    public static RSAPublicKey getPublicKey(String publicKey) throws Exception{
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    public static RSAPrivateKey getPrivateKey(String privateKey) throws Exception{
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

}
