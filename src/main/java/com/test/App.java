package com.test;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        // 故意不开启 autoTypeSupport，测试 expectClass 绕过路径（CVE-2022-25845 的真实机制）
        log.info("[BOOT] fastjson version check, AutoType = {}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        SpringApplication.run(App.class, args);
    }

    /**
     * 精确复现 NotifyServiceImpl.java:150-154
     * JWT header -> Base64.getDecoder() -> JSONObject.parseObject()
     */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            DecodedJWT jwt = JWT.decode(body.get("signedPayload"));
            log.info("[V2-1] JWT.decode OK");

            String header = new String(Base64.getDecoder().decode(jwt.getHeader()), StandardCharsets.UTF_8);
            log.info("[V2-2] header decoded len={} preview={}", header.length(),
                    header.substring(0, Math.min(80, header.length())));

            log.info("[V2-3] calling parseObject...");
            JSONObject parsed = JSONObject.parseObject(header);
            log.info("[V2-4] parseObject OK keys={}", parsed.keySet());

            parsed.getJSONArray("x5c").getString(0); // 触发 NPE（正常业务）
            result.put("code", 200);

        } catch (NullPointerException e) {
            log.warn("[V2-NPE] {} at {}", e.getMessage(), e.getStackTrace()[0]);
            result.put("code", 500);
            result.put("msg", "NPE-parseObject已执行完毕");
        } catch (Exception e) {
            log.error("[V2-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            result.put("code", 500);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /**
     * 直接接收 fastjson payload（text/plain），跳过 JWT 包装。
     * 用于独立验证 fastjson JSON 语法和 gadget chain，与 JWT 编码问题解耦。
     *
     * Python 端用法：
     *   curl -X POST http://host:12300/raw \
     *        -H 'Content-Type: text/plain' \
     *        --data-binary @step2.json
     */
    @PostMapping(value = "/raw", consumes = {"text/plain", "application/octet-stream", "*/*"})
    public Map<String, Object> raw(HttpServletRequest request) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            byte[] bytes = request.getInputStream().readAllBytes();
            String json = new String(bytes, StandardCharsets.UTF_8);
            log.info("[RAW] len={} preview={}", json.length(),
                    json.substring(0, Math.min(100, json.length())));

            JSONObject.parseObject(json);

            result.put("ok", true);
            result.put("msg", "parseObject completed");
            result.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());

        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            result.put("ok", false);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /** 验证 Java 进程的文件写入权限，与 fastjson 无关 */
    @PostMapping("/diag/write")
    public Map<String, Object> diagWrite(@RequestBody Map<String, String> body) {
        String file = body.getOrDefault("file", "/tmp/diag_test");
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write("java-write-ok\n".getBytes(StandardCharsets.UTF_8));
            }
            result.put("ok", true);
            result.put("file", file);
        } catch (Exception e) {
            result.put("ok", false);
            result.put("msg", e.getMessage());
        }
        return result;
    }
}
