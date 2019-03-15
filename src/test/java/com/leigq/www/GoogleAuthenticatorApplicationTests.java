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
        // 生成密码
        String secret = GoogleAuthenticator.generateSecretKey();
        // 生成二维码地址
        // 帐户名建议使用自己 APP名称+APP账户(手机/邮箱)， 例如：WeChat-185882334545
        // host 域名
        String qrcode = GoogleAuthenticator.getQRBarcodeURL(
                "这里是帐户名", "baidu.com", secret);
        System.out.println("二维码地址:" + qrcode);
        System.out.println("密钥:" + secret);
    }

    @Test
    public void verifyTest() {
        // 上面生成的密钥
        String secret = "4GGGUPMHAZHJRPGF";
        // Google验证器动态验证码
        long code = 388012;
        GoogleAuthenticator ga = new GoogleAuthenticator();
        boolean r = ga.checkCode(secret, code, System.currentTimeMillis());
        System.out.println("动态验证码是否正确：" + r);
    }

}
