package com.leigq.www.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * GoogleAuthenticator
 * 参考：
 * <a href='https://blog.csdn.net/lizhengjava/article/details/76947962'>Google Authenticator 原理及Java实现<a/>
 * <br/>
 * <a href='https://blog.csdn.net/youanyyou/article/details/81937753'>两步验证杀手锏：Java 接入 Google 身份验证器实战<a/>
 * <p>
 * 自从google出了双重身份验证后，就方便了大家，等同于有了google一个级别的安全，但是我们该怎么使用google authenticator (双重身份验证)，
 * 下面是java的算法，这样大家都可以得到根据key得到公共的秘钥了,直接复制，记得导入JAR包：
 * commons-codec-1.8.jar
 * junit-4.10.jar
 * 创建人：LeiGQ <br>
 * 创建时间：2019-03-15 16:15 <br>
 * <p>
 * 修改人： <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * </p>
 */
@Slf4j
public class GoogleAuthenticator {

    // taken from Google pam docs - we probably don't need to mess with these
    private static final int SECRET_SIZE = 10;

    // 种子， 有点像加盐
    private static final String SEED = "g8GjEvTbW5oVSV7avLBdwIHqGlUYNzKFI7izOF8GwLDVKs2m0QN7vxRs2im5MDaNCWGmcD2rvcZx";

    // 随机数字算法
    private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

    private int window_size = 3; // default 3 - max 17 (from google docs)最多可偏移的时间

    private void setWindowSize(int s) {
        if (s >= 1 && s <= 17)
            window_size = s;
    }

    /**
     * 生成密钥
     * <br>创建人： leiGQ
     * <br>创建时间： 2019-03-15 16:27
     * <p>
     * 修改人： <br>
     * 修改时间： <br>
     * 修改备注： <br>
     * </p>
     * <br>
     */
    public static String generateSecretKey() {
        try {
            SecureRandom sr = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
            sr.setSeed(Base64.decodeBase64(SEED));
            byte[] buffer = sr.generateSeed(SECRET_SIZE);
            Base32 codec = new Base32();
            byte[] bEncodedKey = codec.encode(buffer);
            return new String(bEncodedKey);
        }catch (NoSuchAlgorithmException e) {
            log.error("生成密钥异常：", e);
        }
        return null;
    }


    /**
     * 获取QR条形码URL, 用这个生成二维码，给Google验证器扫
     * <br>创建人： leiGQ
     * <br>创建时间： 2019-03-15 16:29
     * <p>
     * 修改人： <br>
     * 修改时间： <br>
     * 修改备注： <br>
     * </p>
     * <br>
     */
    public static String getQRBarcodeURL(String user, String host, String secret) {
        String format = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";
        return String.format(format, user, host, secret);
    }

    /**
     * 验证码动态验证码
     * <br>创建人： leiGQ
     * <br>创建时间： 2019-03-15 16:31
     * <p>
     * 修改人： <br>
     * 修改时间： <br>
     * 修改备注： <br>
     * </p>
     * <br>
     * @param secret 密码，上面方法生成的
     * @param code 动态验证码
     * @param timeMsec 毫秒时间搓 System.currentTimeMillis()
     */
    public boolean checkCode(String secret, long code, long timeMsec) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        // convert unix msec time into a 30 second "window"
        // this is per the TOTP spec (see the RFC for details)
        long t = (timeMsec / 1000L) / 30L;
        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.
        for (int i = -window_size; i <= window_size; ++i) {
            long hash;
            try {
                hash = verifyCode(decodedKey, t + i);
            }catch (Exception e) {
                // Yes, this is bad form - but
                // the exceptions thrown would be rare and a static configuration problem
                e.printStackTrace();
                throw new RuntimeException(e.getMessage());
                //return false;
            }
            if (hash == code) {
                return true;
            }
        }
        // The validation code is invalid.
        return false;
    }


    private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);
        int offset = hash[20 - 1] & 0xF;
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return (int) truncatedHash;
    }
}
