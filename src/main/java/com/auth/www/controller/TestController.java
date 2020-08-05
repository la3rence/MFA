package com.auth.www.controller;

import com.auth.www.util.MultiFactorAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authentication Bind / Check Interface
 *
 * @author Lawrence
 */
@Slf4j
@RestController
public class TestController {

    /**
     * We can use a Map to simulate the database.
     */
    protected Map<String, String> userSecret = new ConcurrentHashMap<>();

    /**
     * Bind user to the secret.
     *
     * @param username username
     * @return qr code
     */
    @GetMapping("/bind")
    public Map<String, String> bind(@RequestParam String username) {
        HashMap<String, String> json = new HashMap<>(4);
        if (userSecret.containsKey(username)) {
            String secret = userSecret.get(username);
            String qrCodeLink = MultiFactorAuthenticator.getQRBarcodeURL(username, secret);
            json.put("qrCodeLink", qrCodeLink);
            json.put("user", username);
            json.put("secret", secret);
            log.info(userSecret.toString());
            return json;
        }
        String secret = MultiFactorAuthenticator.generateSecretKey();
        String qrCodeLink = MultiFactorAuthenticator.getQRBarcodeURL(username, secret);
        json.put("qrCodeLink", qrCodeLink);
        json.put("user", username);
        json.put("secret", secret);
        userSecret.put(username, secret);
        log.info(userSecret.toString());
        return json;
    }

    /**
     * check user's code
     *
     * @param username  user name
     * @param codeInput input from user
     * @return right or not
     */
    @GetMapping("/check")
    public Map<String, Object> check(@RequestParam String username, @RequestParam String codeInput) {
        HashMap<String, Object> json = new HashMap<>(2);
        String secret = userSecret.get(username);
        if (null != codeInput && codeInput.length() == 6 && null != secret) {
            long code = Long.parseLong(codeInput);
            boolean result = MultiFactorAuthenticator.checkCode(secret, code, System.currentTimeMillis());
            json.put("pass", result);
        } else {
            json.put("pass", false);
        }
        log.info(userSecret.toString());
        return json;
    }
}
