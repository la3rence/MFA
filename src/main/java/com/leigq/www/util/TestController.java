package com.leigq.www.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Google Authenticator 接口。
 *
 * @author Lawrence
 * @date 2020/8/5
 */
@Slf4j
@RestController
public class TestController {

    /**
     * 我们用一个内存 Map 来模拟数据库
     */
    protected Map<String, String> userSecret = new ConcurrentHashMap<>();

    @GetMapping("/bind")
    public Map<String, String> bind(@RequestParam String username,
                                    @RequestParam(required = false, defaultValue = "example.com") String host) {
        HashMap<String, String> json = new HashMap<>(4);
        // 首先判断用户有没有绑定
        if (userSecret.containsKey(username)) {
            String secret = userSecret.get(username);
            String qrCodeLink = GoogleAuthenticator.getQRBarcodeURL(username, host, secret);
            json.put("qrCodeLink", qrCodeLink);
            json.put("user", username);
            json.put("host", host);
            json.put("secret", secret);
            log.info(userSecret.toString());
            return json;
        }
        String secret = GoogleAuthenticator.generateSecretKey();
        String qrCodeLink = GoogleAuthenticator.getQRBarcodeURL(username, host, secret);
        json.put("qrCodeLink", qrCodeLink);
        json.put("user", username);
        json.put("host", host);
        json.put("secret", secret);
        // 将 user 和 secret 一对一保存, 不让同一用户生成新的 secret
        userSecret.put(username, secret);
        log.info(userSecret.toString());
        return json;
    }

    @GetMapping("/check")
    public Map<String, Object> check(@RequestParam String username, @RequestParam String codeInput) {
        HashMap<String, Object> json = new HashMap<>(4);
        String secret = userSecret.get(username);
        if (null != codeInput && codeInput.length() == 6 && null != secret) {
            long code = Long.parseLong(codeInput);
            boolean result = GoogleAuthenticator.checkCode(secret, code, System.currentTimeMillis());
            json.put("pass", result);
        } else {
            json.put("pass", false);
        }
        json.put("codeInput", codeInput);
        log.info(userSecret.toString());
        return json;
    }
}
