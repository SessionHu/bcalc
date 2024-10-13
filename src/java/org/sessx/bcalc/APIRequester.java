package org.sessx.bcalc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class APIRequester {

    private HttpURLConnection conn;

    private static final String UA_LINUX_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

    public APIRequester(String method, String url) throws java.net.URISyntaxException, IOException {
        this.conn = (HttpURLConnection) new URI(url).toURL().openConnection();
        this.conn.setRequestMethod(method);
        this.conn.setRequestProperty("User-Agent", UA_LINUX_FIREFOX);
        this.conn.setRequestProperty("Accept", "application/json, text/plain, */*");
        this.conn.setRequestProperty("Referer", "https://www.bilibili.com/");
        this.conn.setRequestProperty("DNT", "1");
        this.conn.setRequestProperty("Cookie", getCookie());
    }

    public String getTextResponse() throws IOException {
        this.conn.connect();
        boolean success = this.conn.getResponseCode() / 100 == 2;
        String charset; {
            String[] cta = this.conn.getContentType().split(";\\s*");
            if (cta.length == 2 && cta[1].matches("^charset=.+$")) {
                charset = cta[1].replace("charset=", "");
            } else {
                charset = "UTF-8";
            }
        }
        InputStreamReader in = new InputStreamReader(success ? this.conn.getInputStream() : this.conn.getErrorStream(), charset);
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            sb.append((char) b);
        }
        in.close();
        return sb.toString();
    }

    private static final String EXAMPLE_BUVID3 = "B5A1A156-5875-4B91-4B81-E4F925B1DE9566475infoc";
    private static final String EXAMPLE_BUVID4 = "22BC0A2F-0797-8001-5979-20351ECA502266475-024101310-h4eVT1ZiF3kVzN6KKW0X3A==";

    private static HashMap<String, String> cookie = new HashMap<>();

    private static final String REST_BILI_SPI = "https://api.bilibili.com/x/frontend/finger/spi";

    private static String getCookie() throws IOException {
        syncCookieLocal();
        // if cookie is empty, get from spi
        boolean isEmpty;
        synchronized (cookie) {
            isEmpty = cookie.isEmpty();
        }
        if (isEmpty) {
            synchronized (cookie) {
                cookie.put("buvid3", EXAMPLE_BUVID3);
                cookie.put("buvid4", EXAMPLE_BUVID4);
            }
            JsonObject data = get(REST_BILI_SPI).get("data").getAsJsonObject();
            synchronized (cookie) {
                cookie.put("buvid3", data.get("b_3").getAsString());
                cookie.put("buvid4", data.get("b_4").getAsString());
            }
        }
        // then return cookie normally
        StringJoiner sj = new StringJoiner("; ");
        synchronized (cookie) {
            for (Map.Entry<String, String> e : cookie.entrySet()) {
                sj.add(urlencode(e.getKey()) + '=' + urlencode(e.getValue()));
            }
        }
        // return
        return sj.toString();
    }

    private static final File FILE_SINO_COOKIE = new File(System.getProperty("user.home") + "/.sessx/sinobili/cookie.json");

    private static void syncCookieLocal() throws IOException {
        JsonObject json;
        long lastmod;
        // load from file
        try (InputStreamReader in = new InputStreamReader(new FileInputStream(FILE_SINO_COOKIE), StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            int b;
            while ((b = in.read()) != -1) {
                sb.append((char) b);
            }
            json = GSON.fromJson(sb.toString(), JsonObject.class);
            lastmod = FILE_SINO_COOKIE.lastModified() / 1000L; // unit: second
        }
        synchronized (cookie) {
            // main sync
            for (Map.Entry<String, JsonElement> e : json.entrySet()) {
                String local = urldecode(e.getValue().getAsString());
                String mem = cookie.get(e.getKey());
                if (!local.equals(mem)) {
                    if (lastmod > lastsyncookie) {
                        cookie.put(e.getKey(), local);
                    } else {
                        if (mem != null) {
                            json.addProperty(e.getKey(), mem);
                        } else {
                            json.remove(e.getKey());
                        }
                    }
                }
            }
            for (Map.Entry<String, String> e : cookie.entrySet()) {
                String mem = e.getValue();
                String local = json.has(e.getKey()) ? json.get(e.getKey()).getAsString() : null;
                if (!mem.equals(local)) {
                    json.addProperty(e.getKey(), mem);
                }
            }
            // save to file
            try (FileOutputStream out = new FileOutputStream(FILE_SINO_COOKIE)) {
                out.write(GSON.toJson(json).getBytes(StandardCharsets.UTF_8));
            }
            // update time
            lastsyncookie = System.currentTimeMillis() / 1000L; // unit: second
        }
    }

    private static long lastsyncookie = 0;

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public APIRequester write(byte[] data, int offset, int length) throws IOException {
        OutputStream out = this.conn.getOutputStream();
        out.write(data, offset, length);
        out.close();
        return this;
    }

    private static String urlencode(String str) {
        try {
            return URLEncoder.encode(str, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static String urldecode(String str) {
        try {
            return URLDecoder.decode(str, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static JsonObject get(String url, JsonObject param, boolean wbi) throws IOException {
        if (wbi) {
            param = wbiSign(param);
        }
        url += "?" + encodeParams(param);
        try {
            return GSON.fromJson(new APIRequester("GET", url).getTextResponse(), JsonObject.class);
        } catch (java.net.URISyntaxException e) {
            throw new IOException(e);
        }
    }

    public static JsonObject get(String url, JsonObject param) throws IOException {
        return get(url, param, false);
    }

    public static JsonObject get(String url) throws IOException {
        return get(url, new JsonObject(), false);
    }

    public static JsonObject post(String url, JsonObject param, byte[] data, int offset, int length, boolean wbi) throws IOException {
        if (wbi) {
            param = wbiSign(param);
        }
        url += "?" + encodeParams(param);
        try {
            if (data == null) {
                data = new byte[0];
            }
            return GSON.fromJson(new APIRequester("POST", url).write(data, offset, length).getTextResponse(), JsonObject.class);
        } catch (java.net.URISyntaxException e) {
            throw new IOException(e);
        }
    }

    private static String encodeParams(JsonObject param) {
        StringJoiner sj = new StringJoiner("&");
        for (Map.Entry<String, JsonElement> e : param.entrySet()) {
            sj.add(urlencode(e.getKey()) + "=" + urlencode(e.getValue().getAsString()));
        }
        return sj.toString();
    }

    private static final byte[] MIXIN_KEY_ENC_TAB = {
        46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49,
        33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40,
        61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11,
        36, 20, 34, 44, 52
    };


    private static JsonObject wbiSign(JsonObject param) throws IOException {
        long wts;
        // mixin
        String mixinKey = getMixinKey();
        Map<String, String> map = new TreeMap<>();
        for (Map.Entry<String, JsonElement> e : param.entrySet()) {
            if (!e.getKey().matches("^(w_rid|wts)$")) {
                map.put(e.getKey(), urldecode(e.getValue().getAsString()));
            }
        }
        wts = System.currentTimeMillis() / 1000L; // unit: second
        map.put("wts", String.valueOf(wts));
        StringJoiner sj = new StringJoiner("&");
        for (Map.Entry<String, String> e : map.entrySet()) {
            sj.add(urlencode(e.getKey()) + "=" + urlencode(e.getValue()));
        }
        String s = sj.toString().replace("+", "%20") + mixinKey;
        // md5
        String hex;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            hex = bytesToHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        // return
        JsonObject f = new JsonObject();
        for (Map.Entry<String, String> e : map.entrySet()) {
            f.addProperty(e.getKey(), e.getValue());
        }
        f.addProperty("w_rid", hex);
        return f;
    }

    private static String getMixinKey() throws IOException {
        if (lastmixinkeyts + 28800L > System.currentTimeMillis() / 1000L) {
            return mixinkeycache;
        }
        // biliticket
        long ts = System.currentTimeMillis() / 1000L; // unit: second
        String hexSign = hmacSha256("XgwSnGZ1p", "ts" + ts);
        JsonObject param = new JsonObject();
        param.addProperty("key_id", "ec02");
        param.addProperty("hexsign", hexSign);
        param.addProperty("context[ts]=", ts);
        synchronized (cookie) {
            param.addProperty("csrf", cookie.getOrDefault("bili_jct", ""));
        }
        JsonObject data = post(REST_BILI_GEN_WEB_TICKET, param, null, 0, 0, false).get("data").getAsJsonObject();
        synchronized (cookie) {
            cookie.put("bili_ticket", data.get("ticket").getAsString());
            cookie.put("bili_ticket_expires", String.valueOf(data.get("created_at").getAsLong() + data.get("ttl").getAsLong()));
        }
        // wbi
        JsonObject wbiImg = data.get("nav").getAsJsonObject();
        String imgUrl = wbiImg.get("img_url").getAsString();
        String imgKey = imgUrl.substring(imgUrl.lastIndexOf("/") + 1, imgUrl.lastIndexOf("."));
        String subUrl = wbiImg.get("sub_url").getAsString();
        String subKey = subUrl.substring(subUrl.lastIndexOf("/") + 1, subUrl.lastIndexOf("."));
        String s = imgKey + subKey;
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            key.append(s.charAt(MIXIN_KEY_ENC_TAB[i]));
        }
        // return
        lastmixinkeyts = System.currentTimeMillis() / 1000L; // unit: second
        return mixinkeycache = key.toString();
    }

    private static String mixinkeycache;
    private static long lastmixinkeyts = 0;

    private static final String REST_BILI_GEN_WEB_TICKET = "https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket";

    /**
     * Convert a byte array to a hex string.
     * 
     * @param bytes The byte array to convert.
     * @return The hex string representation of the given byte array.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * Generate a HMAC-SHA256 hash of the given message string using the given key
     * string.
     * 
     * @param key     The key string to use for the HMAC-SHA256 hash.
     * @param message The message string to hash.
     * @return The HMAC-SHA256 hash of the given message string using the given key
     *         string.
     */
    private static String hmacSha256(String key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void clearCache() {
        synchronized (cookie) {
            cookie.remove("bili_ticket");
            cookie.remove("bili_ticket_expires");
        }
        try {
            syncCookieLocal();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        lastmixinkeyts = 0;
    }

    public static void addCookie(JsonObject nc) {
        synchronized (cookie) {
            for (Map.Entry<String, JsonElement> e : nc.entrySet()) {
                cookie.put(e.getKey(), e.getValue().getAsString());
            }
        }
    }

}