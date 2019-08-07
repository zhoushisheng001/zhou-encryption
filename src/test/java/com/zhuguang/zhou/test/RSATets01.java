package com.zhuguang.zhou.test;

import com.alibaba.fastjson.JSON;
import com.zhuguang.zhou.rsa.RSAController;
import com.zhuguang.zhou.vo.RestResultVo;
import org.junit.Test;

public class RSATets01 {

    @Test
    public void test01 () {
        RSAController rsaController = new RSAController();
        String publicKey = rsaController.getPublicKey();
        String request = "{\"source\":\"美好的一天\",\"publicKey\"" + ":\"" + publicKey +  "\"}";
        //String request = "{\"source\":\"123456\",\"publicKey\" :\"1254\"}";
        System.out.println("request:" + request);
        String encrypt = rsaController.encrypt(request);
        System.out.println("加密后的数据encrypt:" + encrypt);
        System.out.println("==============================开始解密=========================================");
        RestResultVo res = JSON.parseObject(encrypt, RestResultVo.class);
        System.out.println("data：" + res.getData());
        RSATets01 rsaTets01 = new RSATets01();
        rsaTets01.test02(res.getData().toString());

    }

    public void test02 (String data) {
        RSAController rsaController = new RSAController();
        //String request = "gM9cON8zlC7QS81rf685ergLp6n8h7cJTc28FlK4z6Y1yixiDWgR52748w+pth1ZhFrnzQh2VXsf7+dmPIRM2zSG8w7/mIBJy9QtzpwX3YatCXyBgDs04OmvZPqlZJeh7unH3IQDGTkDrB7PiY7BooEBxnAic/eaO3RWhjjGE2A=";
        System.out.println("request:" + data);
        String encrypt = rsaController.decrypt(data);
        System.out.println("加密后的数据encrypt:" + encrypt);
    }

}
