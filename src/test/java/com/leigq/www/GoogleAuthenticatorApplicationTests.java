package com.leigq.www;

import com.leigq.www.util.GoogleAuthenticator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class GoogleAuthenticatorApplicationTests {

    @Test
    public void genSecretTest() {
        String secret = GoogleAuthenticator.generateSecretKey();
        String qrCode = GoogleAuthenticator.getQRBarcodeURL("username", secret);
        System.out.println("二维码地址:" + qrCode);
        System.out.println("密钥:" + secret);
    }

    @Test
    public void verifyTest() {
        // 上面生成的密钥
        String secret = "SE637UUCE3UUV5A7";
        // Google验证器动态验证码
        String randomCode = "892895";
        long code = Long.parseLong(randomCode);
        boolean result = GoogleAuthenticator.checkCode(secret, code, System.currentTimeMillis());
        System.out.println("动态验证码是否正确：" + result);
    }

}
