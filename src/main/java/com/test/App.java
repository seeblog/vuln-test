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
        // 开启 autoType，先验证 gadget chain 本身是否有效
        // 结论确认后再测试 autoType=false 下的 Step1 类缓存污染绕过
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        log.info("[BOOT] fastjson AutoType = {}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        SpringApplication.run(App.class, args);
    }

    /** 复现 NotifyServiceImpl.java:150-154 */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            DecodedJWT jwt = JWT.decode(body.get("signedPayload"));
            String header = new String(Base64.getDecoder().decode(jwt.getHeader()), StandardCharsets.UTF_8);
            log.info("[V2] header preview={}", header.substring(0, Math.min(80, header.length())));
            JSONObject.parseObject(header);
            result.put("code", 500);
            result.put("msg", "NPE-parseObject已执行");
        } catch (NullPointerException e) {
            result.put("code", 500);
            result.put("msg", "NPE-parseObject已执行");
        } catch (Exception e) {
            log.error("[V2-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            result.put("code", 500);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /**
     * 直接接收 fastjson JSON（text/plain），绕过 JWT 包装。
     * autoType 状态跟随 main() 的设置。
     */
    @PostMapping(value = "/raw", consumes = {"text/plain", "application/octet-stream", "*/*"})
    public Map<String, Object> raw(HttpServletRequest request) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            byte[] bytes = request.getInputStream().readAllBytes();
            String json = new String(bytes, StandardCharsets.UTF_8);
            log.info("[RAW] len={} autoType={} preview={}",
                    json.length(),
                    ParserConfig.getGlobalInstance().isAutoTypeSupport(),
                    json.substring(0, Math.min(100, json.length())));

            JSONObject.parseObject(json);

            result.put("ok", true);
            result.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            result.put("ok", false);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /** 验证 Java 进程写文件权限，与 fastjson 无关 */
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
