package com.auth.www;

import com.auth.www.util.MultiFactorAuthenticator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class MultiFactorAuthenticatorApplicationTests {

    @Test
    public void genSecretTest() {
        String secret = MultiFactorAuthenticator.generateSecretKey();
        String qrCode = MultiFactorAuthenticator.getQRBarcodeURL("username", secret);
        System.out.println("secret = " + secret);
        System.out.println("qrCode = " + qrCode);
    }

    @Test
    public void verifyTest() {
        String secret = "ABCDEFGHIJKLMN";
        String randomCode = "012345";
        long code = Long.parseLong(randomCode);
        boolean result = MultiFactorAuthenticator.checkCode(secret, code, System.currentTimeMillis());
        System.out.println(result);
    }

}
