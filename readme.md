# 使用 Java/Spring 接入身份验证器

# Multi-Factor Authentication by Java with Spring
多因素认证 ｜ 多因子认证 ｜ Google Authenticator ｜ 2FA ｜ MFA | 时间戳同步 ｜ Java实现 | Spring后端

## 工具类

[MultiFactorAuthenticator](src/main/java/com/auth/www/util/MultiFactorAuthenticator.java)

## 接入自己的用户体系

[TestController](src/main/java/com/auth/www/controller/TestController.java)

## 客户端

- [Google Authenticator](https://apps.apple.com/app/google-authenticator/id388497605)
- [Authy](https://authy.com/)
- [Step Two](https://steptwo.app/) 

## 注意

- 服务端时间必须与客户端一致。
- 接入自己的用户系统时，可以设计一个 user - secret 一一映射的表用来绑定身份验证。
本案例偷懒了，直接放内存里的。
- 二维码的展示放在了 JSON 中，使用了国内可以访问的一个 API，可能会失效。

## 快速开始
启动此服务。
用户下载、安装好客户端应用后，尝试发出此请求。
```shell script
curl -XGET localhost:8080/bind?username=test
```
将返回 JSON 中的二维码地址通过浏览器打开，或者使用 wget 等客户端下载到本地。
使用客户端导入此二维码，或者填写密文导入。导入成功后，应用会出现相应的 6 位数验证码。
将验证码作为以下 HTTP 请求的 codeInput 字段内容。
```shell script
curl -XGET localhost:8080/check?username=test&codeInput={codeInput}
```
返回的结果为 true 则验证成功。
