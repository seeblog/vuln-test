package com.test;

import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    /**
     * 完整复现 NotifyServiceImpl.java:150-154 的漏洞路径：
     *
     *   DecodedJWT decodedJWT = JWT.decode(body.getSignedPayload());
     *   String header = new String(Base64.getDecoder().decode(decodedJWT.getHeader()));
     *   String x5c = JSONObject.parseObject(header).getJSONArray("x5c").getString(0);
     *
     * 无数据库依赖，可独立运行。
     */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        String signedPayload = body.get("signedPayload");
        try {
            // 行150: JWT.decode 仅 Base64 分割，不验签
            DecodedJWT decodedJWT = JWT.decode(signedPayload);

            // 行153: getHeader() 返回原始 Base64url 字符串（第一段），用 BASIC 解码器解码
            String header = new String(Base64.getDecoder().decode(decodedJWT.getHeader()));

            // 行154: fastjson 解析攻击者控制的 header JSON —— gadget chain 在此触发
            JSONObject parsed = JSONObject.parseObject(header);

            // 行154 续: 正常业务取 x5c，若不存在则 NPE（被全局异常处理器捕获）
            String x5c = parsed.getJSONArray("x5c").getString(0);

            return Map.of("code", 200, "x5c_len", x5c.length());

        } catch (NullPointerException e) {
            // 对应 GlobalExceptionHandler 行143 捕获 NPE → 返回 500
            // 此时 parseObject 已执行完毕，gadget side-effect 已发生
            return Map.of("code", 500, "msg", "internal error");
        } catch (Exception e) {
            return Map.of("code", 500, "msg", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
