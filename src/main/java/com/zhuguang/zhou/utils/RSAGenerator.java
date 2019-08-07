package com.zhuguang.zhou.utils;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 百度RSA不对称加密算法工具类： 1、生成私钥公钥对
 * 2、使用公钥对数据加密，使用私钥对数据解密
 * 3、使用私钥生成数字签名和使用公钥验证数字签名，
 * 
 */
public class RSAGenerator {

	// public static String zx_privateKey =
	// "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKkvruEOS5HvHpccZkutQyaRdCrPLMsQUu9i10CyTxb96wTstYHBji3t6uDctqppJGOyEMT/5RMe24zIp67S6u6tEEY7BymMxzuVXtXfHakTWTffvHLV9sRF9pn/CkV0R8lXmgUCmvjW3ujshb/nyQc6gvF4X2o0dF/a8JX7RcErAgMBAAECgYAJEvijM3wUIKoYWrqV1n4ihGyhmykA3yhDlJ6M5sNdLVM8mWGGyxXQGtGdK9lUPH1qJ3PEzSDBLMeDvoNX2hIlkpzWJOtXrDiJlnNSwXZG0y1eHYoOeGVPnkSXYVvsKQpbhb4ZUglrXjnYCJsSe//1ThgvSQiWreXRfXWxksLP6QJBAN6GW+vwIymKuSXFAx0KmiJWhLb2kO6/+R5BY3ojIrUVIGDCsOhmlSuCYCRJRHsTvMtW/miyrfBaN0ObfXtbi8UCQQDCozSKjqSI8ocGcJYIbTOwGrZxhLK/rtFNtdI8H3gIysMtDgUSNlOG25riX/GyTVbPyEoT+x9Hx8I+ZIiNlDgvAkAD5d6eV2qGQ8PSgYz4aUMh7toMSm1ngT1f5k1TymHFQkV67G4k5Acg5/u/JvloHoRkG3YBZ3/cgfgN2x9rlcLxAkARdDtA9ZuxoDYVkMETjl9lOnAD7AdvgwjH9DcfJx9Hgo9QGgLAaFjDLixMgpgVCjRvu6FQ+2MJt9MmbzODprgHAkEAqaH2mCcIF/mF3e3NTh6RG8AW/4Xug2I8pKMWHSEVVB8C/jm/wWf1zjhZlKUB0IjOnoqRnh4nlWtN84R/WdX5Dg==";
	// public static String zx_publicKey =
	// "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpL67hDkuR7x6XHGZLrUMmkXQqzyzLEFLvYtdAsk8W/esE7LWBwY4t7erg3LaqaSRjshDE/+UTHtuMyKeu0ururRBGOwcpjMc7lV7V3x2pE1k337xy1fbERfaZ/wpFdEfJV5oFApr41t7o7IW/58kHOoLxeF9qNHRf2vCV+0XBKwIDAQAB";
	//public static String zx_privateKey = "4D494943646749424144414E42676B71686B6947397730424151454641415343416D417767674A6341674541416F4742414B6B767275454F53354876487063635A6B757451796152644372504C4D735155753969313043795478623936775473745948426A69337436754463747170704A474F79454D542F35524D6532347A4970363753367536744545593742796D4D787A75565874586648616B545754666676484C563973524639706E2F436B563052386C586D6755436D766A5733756A7368622F6E795163366776463458326F3064462F61384A58375263457241674D42414145436759414A4576696A4D337755494B6F5957727156316E3469684779686D796B41337968446C4A364D35734E644C564D386D57474779785851477447644B396C55504831714A3350457A5344424C4D6544766F4E583268496C6B707A574A4F74587244694A6C6E4E5377585A473079316548596F4F654756506E6B5358595676734B5170626862345A55676C72586A6E59434A7353652F2F31546867765351695772655852665857786B734C5036514A42414E3647572B767749796D4B755358464178304B6D694A57684C62326B4F362F2B52354259336F6A4972555649474443734F686D6C5375435943524A52487354764D74572F6D6979726642614E304F626658746269385543515144436F7A534B6A715349386F6347634A594962544F7747725A78684C4B2F7274464E746449384833674979734D74446755534E6C4F4732357269582F47795456625079456F542B7839487838492B5A49694E6C446776416B414435643665563271475138505367597A3461554D6837746F4D536D316E67543166356B3154796D4846516B56363747346B35416367352F752F4A766C6F486F526B473359425A332F636766674E327839726C634C78416B415264447441395A75786F4459566B4D45546A6C396C4F6E41443741647667776A48394463664A783948676F395147674C4161466A444C69784D67706756436A5276753646512B324D4A74394D6D627A4F4470726748416B4541716148326D436349462F6D463365334E54683652473841572F34587567324938704B4D5748534556564238432F6A6D2F775766317A6A685A6C4B554230496A4F6E6F71526E68346E6C57744E3834522F5764583544673D3D";
	//public static String zx_publicKey = "4D4947664D413047435371475349623344514542415155414134474E4144434269514B42675143704C363768446B75523778365848475A4C72554D6D6B5851717A797A4C45464C7659746441736B38572F657345374C57427759347437657267334C61716153526A736844452F2B55544874754D794B657530757275725242474F7763706A4D63376C5637563378327045316B3333377879316662455266615A2F7770466445664A56356F46417072343174376F3749572F35386B484F6F4C78654639714E485266327643562B3058424B77494441514142";


	public static String zx_publicKey = "4D4947664D413047435371475349623344514542415155414134474E4144434269514B42675143704C363768446B75523778365848475A4C72554D6D6B5851717A797A4C45464C7659746441736B38572F657345374C57427759347437657267334C61716153526A736844452F2B55544874754D794B657530757275725242474F7763706A4D63376C5637563378327045316B3333377879316662455266615A2F7770466445664A56356F46417072343174376F3749572F35386B484F6F4C78654639714E485266327643562B3058424B77494441514142";

	public static String zx_privateKey = "4D45494943646749424144414E42676B71686B6947397730424151454641415343416D417767674A6341674541416F4742414B6B767275454F53354876487063635A6B757451796152644372504C4D735155753969313043795478623936775473745948426A69337436754463747170704A474F79454D542F35524D6532347A4970363753367536744545593742796D4D787A75565874586648616B545754666676484C563973524639706E2F436B563052386C586D6755436D766A5733756A7368622F6E795163366776463458326F3064462F61384A58375263457241674D42414145436759414A4576696A4D337755494B6F5957727156316E3469684779686D796B41337968446C4A364D35734E644C564D386D57474779785851477447644B396C55504831714A3350457A5344424C4D6544766F4E583268496C6B707A574A4F74587244694A6C6E4E5377585A473079316548596F4F654756506E6B5358595676734B5170626862345A55676C72586A6E59434A7353652F2F31546867765351695772655852665857786B734C5036514A42414E3647572B767749796D4B755358464178304B6D694A57684C62326B4F362F2B52354259336F6A4972555649474443734F686D6C5375435943524A52487354764D74572F6D6979726642614E304F626658746269385543515144436F7A534B6A715349386F6347634A594962544F7747725A78684C4B2F7274464E746449384833674979734D74446755534E6C4F4732357269582F47795456625079456F542B7839487838492B5A49694E6C446776416B414435643665563271475138505367597A3461554D6837746F4D536D316E67543166356B3154796D4846516B56363747346B35416367352F752F4A766C6F486F526B473359425A332F636766674E327839726C634C78416B415264447441395A75786F4459566B4D45546A6C396C4F6E41443741647667776A48394463664A783948676F395147674C4161466A444C69784D67706756436A5276753646512B324D4A74394D6D627A4F4470726748416B4541716148326D436349462F6D463365334E54683652473841572F34587567324938704B4D5748534556564238432F6A6D2F775766317A6A685A6C4B554230496A4F6E6F71526E68346E6C57744E3834522F5764583544673D3D";


	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";
	public static final String DIGEST_ALGORITHM = "SHA-512";

	/** */
	/**
	 * RSA最大加密明文大小
	 */
	private static final int MAX_ENCRYPT_BLOCK = 245;

	/** */
	/**
	 * RSA最大解密密文大小
	 */
	private static final int MAX_DECRYPT_BLOCK = 256;

	/** */
	/**
	 * 获取公钥的key
	 */
	private static final String PUBLIC_KEY = "RSAPublicKey";

	/** */
	/**
	 * 获取私钥的key
	 */
	private static final String PRIVATE_KEY = "RSAPrivateKey";
	private static final String BDPUBLIC_KEY = "BDRSAPublicKey";

	/**
	 * BASE64解密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */

	/** */
	/**
	 * <p>
	 * 根据字符串生成密钥对(公钥和私钥)
	 * </p>
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKeyPair() throws Exception {
		byte[] buffer = Base64Utils.decode(hexStringToString(zx_publicKey));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

		buffer = Base64Utils.decode(hexStringToString(zx_privateKey));
		PKCS8EncodedKeySpec pkkeySpec = new PKCS8EncodedKeySpec(buffer);
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkkeySpec); // (RSAPrivateKey)
																							// keyPair.getPrivate();

		Map<String, Object> keyMap = new HashMap<String, Object>(3);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/** */
	/**
	 * <p>
	 * 生成密钥对(公钥和私钥)
	 * </p>
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> genKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(2048);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	public static byte[] decryptBASE64(String key) throws Exception {
		return Base64Utils.decode(key);
	}

	/**
	 * BASE64加密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptBASE64(byte[] key) throws Exception {
		return Base64Utils.encode(key);
	}

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加签数据
	 * @param privateKey
	 *            私钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {

		// 计算明文摘要
		byte[] digestData = digest(data).getBytes("utf-8");
		// 解密由base64编码的私钥
		byte[] keyBytes = decryptBASE64(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(digestData);

		return encryptBASE64(signature.sign());
	}

	/** */
	/**
	 * <p>
	 * 公钥加密
	 * </p>
	 * 
	 * @param data
	 *            源数据
	 * @param publicKey
	 *            公钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
		byte[] keyBytes = Base64Utils.decode(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	/** */
	/**
	 * <P>
	 * 私钥解密
	 * </p>
	 * 
	 * @param encryptedData
	 *            已加密数据
	 * @param privateKey
	 *            私钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
		byte[] keyBytes = Base64Utils.decode(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 用SHA-512算法计算摘要
	 * 
	 * @param contents
	 * @return
	 * @throws Exception
	 */
	private static String digest(byte[] contents) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
		byte[] digestbyte = messageDigest.digest(contents);
		return new String(Hex.encodeHex(digestbyte));
	}

	/**
	 * 校验数字签名
	 * 
	 * @param data
	 *            加签数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

		// 计算出明文的摘要
		byte[] digestData = digest(data).getBytes("utf-8");

		// 解密由base64编码的公钥
		byte[] keyBytes = decryptBASE64(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(digestData);

		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	/**
	 * 
	 * 从文件读取秘钥
	 * 
	 * @param filePath
	 * @return
	 * @throws Exception
	 * 
	 */
	public static String getKeyFromFile(String filePath) throws Exception {
		File f = new File(filePath);
		InputStream ins = new FileInputStream(f);
		BufferedReader br = new BufferedReader(new InputStreamReader(ins));
		String readLine = null;
		StringBuffer sb = new StringBuffer();
		while ((readLine = br.readLine()) != null) {
			sb.append(readLine);
		}
		br.close();
		ins.close();
		return new String(sb);
	}

	public static String unicodeConver(String str) {
		char[] c = str.toCharArray();
		String resultStr = "";
		for (int i = 0; i < c.length; i++)
			resultStr += String.valueOf(c[i]);
		return resultStr;

	}

	/** */
	/**
	 * <p>
	 * 获取私钥
	 * </p>
	 * 
	 * @param keyMap
	 *            密钥对
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return Base64Utils.encode(key.getEncoded());
	}

	public static String getBDPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(BDPUBLIC_KEY);
		return Base64Utils.encode(key.getEncoded());
	}

	/**
	 * <p>
	 * 获取公钥
	 * </p>
	 * 
	 * @param keyMap
	 *            密钥对
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return Base64Utils.encode(key.getEncoded());
	}

	/**
	 * 字符串转化成为16进制字符串
	 * 
	 * @param s
	 * @return
	 */
	public static String strToHexString(String s) {
		String str = "";
		for (int i = 0; i < s.length(); i++) {
			int ch = (int) s.charAt(i);
			String s4 = Integer.toHexString(ch);
			str = str + s4;
		}
		return str.toUpperCase();
	}

	/**
	 * 16进制转换成为string类型字符串
	 * 
	 * @param s
	 * @return
	 */
	public static String hexStringToString(String s) {
		if (s == null || s.equals("")) {
			return null;
		}
		s = s.replace(" ", "");
		byte[] baKeyword = new byte[s.length() / 2];
		for (int i = 0; i < baKeyword.length; i++) {
			try {
				baKeyword[i] = (byte) (0xff & Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		try {
			s = new String(baKeyword, "UTF-8");
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		return s;
	}

	public static void main(String[] args) {
		System.out.println(strToHexString(zx_publicKey));
		System.out.println(hexStringToString(strToHexString(zx_publicKey)));
	}
}
