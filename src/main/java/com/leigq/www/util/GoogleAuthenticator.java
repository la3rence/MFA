package com.leigq.www.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Slf4j
public class GoogleAuthenticator {
    private static final String ISSUER = "Hello";
    private static final String IMAGE_QR_CODE_API = "https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=";
    private static final String SEED = "thisisgoogleauthenticator";
    // taken from Google pam docs - we probably don't need to mess with these
    private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    private static final int SECRET_SIZE = 10;
    private static final int WINDOW_SIZE = 1;

    /**
     * 生成密钥
     */
    public static String generateSecretKey() {
        try {
            SecureRandom sr = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
            sr.setSeed(Base64.decodeBase64(SEED));
            byte[] buffer = sr.generateSeed(SECRET_SIZE);
            Base32 codec = new Base32();
            byte[] bEncodedKey = codec.encode(buffer);
            return new String(bEncodedKey);
        } catch (NoSuchAlgorithmException e) {
            log.error("生成密钥异常：", e);
        }
        return null;
    }

    /**
     * 获取 QR Code
     */
    public static String getQRBarcodeURL(String user, String host, String secret) {
        String format = IMAGE_QR_CODE_API + "otpauth://totp/%s@%s?secret=%s%%26issuer=%s";
        String imageUrl = String.format(format, user, host, secret, ISSUER);
        log.info(imageUrl);
        return imageUrl;
    }

    /**
     * 验证码动态验证码
     *
     * @param secret 密码，上面方法生成的
     * @param code   动态验证码
     * @param time   毫秒时间戳
     */
    public static boolean checkCode(String secret, long code, long time) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        // convert unix msec time into a 30 second "window"
        // this is per the TOTP spec (see the RFC for details)
        long t = (time / 1000L) / 30L;
        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash;
            try {
                hash = verifyCode(decodedKey, t + i);
            } catch (Exception e) {
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

    private GoogleAuthenticator() {
    }
}
