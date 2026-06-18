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

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        // ── 诊断1：打印 fastjson 默认 AutoType 状态 ──
        boolean autoType = ParserConfig.getGlobalInstance().isAutoTypeSupport();
        System.out.println("[DIAG] fastjson AutoType default = " + autoType);

        // ── 诊断2：强制开启 AutoType，验证 gadget 是否因此触发 ──
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        System.out.println("[DIAG] fastjson AutoType forced ON");

        SpringApplication.run(App.class, args);
    }

    /**
     * /notify/v2  ——  精确复现 NotifyServiceImpl.java:150-154
     *
     * 新增：
     *   - 打印完整异常类型和消息（帮助区分 NPE / JSONException / IllegalArgumentException）
     *   - 在 parseObject 前后各打一条日志，确认执行到了哪一步
     */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        String signedPayload = body.get("signedPayload");
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            // step1: JWT.decode — 不验签，仅 split + Base64 解码
            DecodedJWT decodedJWT = JWT.decode(signedPayload);
            log.info("[STEP1] JWT.decode OK, header(raw)={}", decodedJWT.getHeader().substring(0, Math.min(40, decodedJWT.getHeader().length())));

            // step2: BASIC Base64 解码 header（对应 NotifyServiceImpl:153）
            byte[] headerBytes = Base64.getDecoder().decode(decodedJWT.getHeader());
            String header = new String(headerBytes);
            log.info("[STEP2] Base64.decode OK, header len={}", header.length());

            // step3: fastjson parseObject（gadget 触发点）
            log.info("[STEP3] calling JSONObject.parseObject ...");
            JSONObject parsed = JSONObject.parseObject(header);
            log.info("[STEP3] parseObject returned, keys={}", parsed.keySet());

            // step4: 取 x5c（正常业务），无此 key 则 NPE
            String x5c = parsed.getJSONArray("x5c").getString(0);
            result.put("code", 200);
            result.put("x5c_len", x5c.length());

        } catch (NullPointerException e) {
            log.warn("[NPE] at: {}", e.getStackTrace()[0]);
            result.put("code", 500);
            result.put("msg", "NPE: parseObject 执行完毕，x5c 为 null（正常，gadget 应已触发）");
        } catch (Exception e) {
            // 关键：打印完整异常，帮助定位是哪一步失败
            log.error("[ERR] {} : {}", e.getClass().getName(), e.getMessage());
            result.put("code", 500);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /**
     * /diag/fastjson  ——  用最简单的 payload 验证 fastjson @type 处理是否生效
     * 直接 POST JSON body: {"json": "...fastjson payload..."}
     */
    @PostMapping("/diag/fastjson")
    public Map<String, Object> diagFastjson(@RequestBody Map<String, String> body) {
        String json = body.get("json");
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            log.info("[DIAG] parseObject input={}", json.substring(0, Math.min(80, json.length())));
            JSONObject parsed = JSONObject.parseObject(json);
            result.put("ok", true);
            result.put("keys", parsed.keySet().toString());
            result.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        } catch (Exception e) {
            log.error("[DIAG ERR] {} : {}", e.getClass().getName(), e.getMessage());
            result.put("ok", false);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }
}
