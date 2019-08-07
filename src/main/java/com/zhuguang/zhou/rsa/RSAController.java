
package com.zhuguang.zhou.rsa;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.zhuguang.zhou.utils.Base64Utils;
import com.zhuguang.zhou.utils.RSAGenerator;
import com.zhuguang.zhou.vo.RestResultVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

/**
 * RSA 加密解密
 * 
 *
 */
public class RSAController {
	private Logger logger = LoggerFactory.getLogger(RSAController.class);

	private static String publicKey;
	private static String privateKey;

	public static String getPublicKey() {
		return publicKey;
	}

	public static void setPublicKey(String publicKey) {
		RSAController.publicKey = publicKey;
	}

	public static String getPrivateKey() {
		return privateKey;
	}

	public static void setPrivateKey(String privateKey) {
		RSAController.privateKey = privateKey;
	}

	static {
		try {
			Map<String, Object> keyMap = RSAGenerator.initKeyPair();
			publicKey = RSAGenerator.getPublicKey(keyMap);
			privateKey = RSAGenerator.getPrivateKey(keyMap);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 公钥加密
	 * 
	 * @param source
	 * @param publicKey
	 * @return
	 */

	public String encrypt(String request) {
		RequestparamEncrypt requestparamEncrypt = JSON.parseObject(request, RequestparamEncrypt.class);
		String source = requestparamEncrypt.getSource();
		String publicKey = requestparamEncrypt.getPublicKey();
		RestResultVo result = new RestResultVo();
		if (source == null || publicKey == null) {
			result.setStatus("0");
			result.setMessage("字符信息为空或数据绑定失败");
			return JSONObject.toJSONString(result);
		}
		try {
			byte[] data = source.getBytes("UTF-8");
			byte[] encodedData = RSAGenerator.encryptByPublicKey(data, publicKey);
			result.setData(Base64Utils.encode(encodedData));
			result.setMessage("字符信息加密成功");
			logger.info("字符信息加密成功");
		} catch (Exception e) {
			logger.warn("字符加密失败");
			result.setStatus("0");
			result.setMessage("字符加密失败");
		}
		return JSONObject.toJSONString(result);
	}

	/**
	 * 私钥解密
	 * 
	 * @param encodedData
	 * @return
	 */

	public String decrypt( String encodedData) {
		System.out.println(encodedData);
		RestResultVo result = new RestResultVo();
		if (encodedData == null) {
			result.setStatus("0");
			result.setMessage("字符信息为空或数据绑定失败");
			return JSONObject.toJSONString(result);
		}
		try {
			String bString = encodedData.replace(" ", "+");
			byte[] decodedData = RSAGenerator.decryptByPrivateKey(Base64Utils.decode(bString), privateKey);
			String target = new String(decodedData, "UTF-8");
			try {
				JSONObject object = JSON.parseObject(target);
			    result.setData(object);
			} catch (Exception e){
				result.setData(target);
			}
			result.setMessage("字符信息解密成功");
			logger.info("字符信息解密成功");
		} catch (Exception e) {
			logger.warn("字符信息解密失败");
			result.setStatus("0");
			result.setMessage("字符信息解密失败");
		}
		return JSONObject.toJSONString(result);
	}

	// public static void main(String[] args) throws Exception {
	// RSAContraller rsaContraller = new RSAContraller();
	// System.out.println(rsaContraller.encrypt("我是工程师",RSAGenerator.strToHexString(publicKey)
	// ));
	// System.out.println(rsaContraller.decrypt(rsaContraller.encrypt("我是工程师",
	// RSAGenerator.strToHexString(publicKey))));
	// }

}
