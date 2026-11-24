package org.visadahyu.datapavan.proxyfixture;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * W8 part 2a's proxy fixture (scripts/verify-proxies.sh, ADR 0052): one action per start, by the extra "action", to
 * the proxy lab at the extras "host" and "port", with "user", "password" and "secret" where the action needs them.
 * Each logs "ACTION ok WHAT" or "ACTION failed WHY" under the tag DatapavanProxyFixture, then "done", and never a
 * credential. Its bytes are what apps with built-in proxies send:
 *
 * <ul>
 *   <li>{@code socks5}: RFC 1928 with RFC 1929's user name and password, CONNECT inner.proxylab.test:443, then a TLS
 *       hello for that name, which the lab's target echoes;</li>
 *   <li>{@code connect}: an HTTP CONNECT with Basic credentials, then the same hello;</li>
 *   <li>{@code forward}: a plain request to the proxy, its target in absolute form, with Basic credentials;</li>
 *   <li>{@code setting}: a plain request through Android's proxy setting, which HttpURLConnection follows;</li>
 *   <li>{@code obfuscated}: the 64 bytes that start Telegram's obfuscated transport, by its documented rules;</li>
 *   <li>{@code faketls}: a fake-TLS hello for the MTProto secret, made as TDLib makes it, which mtg answers;</li>
 *   <li>{@code whatsapp}: WhatsApp's clear header and a frame, which the target echoes;</li>
 *   <li>{@code hello}: a TLS hello for the extra "name", which the target echoes.</li>
 * </ul>
 *
 * <p>For the proxy record's measurements 7.1 and 7.2 (scripts/measure-proxy-settings.sh), which set Android's own
 * proxy settings and look at what an ordinary app does with them:
 *
 * <ul>
 *   <li>{@code read}: what this app is told: {@code getDefaultProxy()}, each network's own proxy, the proxy system
 *       properties Android set in this process, and what its {@code ProxySelector} picks for two URLs;</li>
 *   <li>{@code get}: an {@code HttpURLConnection} GET of the extra "url", which follows Android's setting as apps do:
 *       the status, or the exception's class;</li>
 *   <li>{@code property}: a plain request for "url" by a socket of its own to the proxy the system properties name,
 *       as an app that reads them itself does (under a PAC, the framework's handler on the phone's loopback);</li>
 *   <li>{@code webview}: a WebView, Chromium's network stack in this app's process, loads "url".</li>
 * </ul>
 */
public class ProxyActivity extends Activity {
    private static final String TAG = "DatapavanProxyFixture";
    private static final String INNER = "inner.proxylab.test";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        final String action = String.valueOf(getIntent().getStringExtra("action"));
        if (action.equals("webview")) {
            webview(extra("url"));
            return;
        }
        new Thread(() -> {
            try {
                Log.i(TAG, action + " ok " + run(action));
            } catch (Exception e) {
                // The exception's class only: its message could carry what was sent.
                Log.i(TAG, action + " failed " + e.getClass().getSimpleName());
            }
            Log.i(TAG, "done");
            runOnUiThread(this::finish);
        }).start();
    }

    private String extra(String name) {
        String value = getIntent().getStringExtra(name);
        return value == null ? "" : value;
    }

    private Socket open() throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(extra("host"), Integer.parseInt(extra("port"))), 10_000);
        socket.setSoTimeout(10_000);
        return socket;
    }

    private String run(String action) throws Exception {
        switch (action) {
            case "socks5": return socks5();
            case "connect": return connect();
            case "forward": return forward();
            case "setting": return setting();
            case "obfuscated": return obfuscated();
            case "faketls": return fakeTls();
            case "whatsapp": return whatsapp();
            case "hello": return hello(extra("name"));
            case "lookup": return lookup(extra("name"));
            case "read": return read();
            case "get": return get(extra("url"));
            case "property": return property(extra("url"));
            default: throw new IllegalArgumentException();
        }
    }

    /** A proxy as one word: none, HOST:PORT, or pac:URL@PORT (the port of the handler on the phone's loopback). */
    private static String describe(android.net.ProxyInfo proxy) {
        if (proxy == null) return "none";
        android.net.Uri pac = proxy.getPacFileUrl();
        if (pac != null && !android.net.Uri.EMPTY.equals(pac)) return "pac:" + pac + "@" + proxy.getHost() + ":" + proxy.getPort();
        return proxy.getHost() + ":" + proxy.getPort();
    }

    private static String selected(java.net.ProxySelector selector, String uri) {
        StringBuilder picked = new StringBuilder();
        try {
            for (java.net.Proxy proxy : selector.select(new java.net.URI(uri))) {
                if (picked.length() > 0) picked.append(',');
                picked.append(proxy.type() == java.net.Proxy.Type.DIRECT ? "DIRECT" : proxy.type() + "@" + proxy.address());
            }
        } catch (Exception e) {
            return "failed-" + e.getClass().getSimpleName();
        }
        return picked.toString();
    }

    /** What Android tells this app of its proxy settings, in one line of NAME=VALUE words. */
    @SuppressWarnings("deprecation")
    private String read() {
        android.net.ConnectivityManager connectivity = getSystemService(android.net.ConnectivityManager.class);
        StringBuilder line = new StringBuilder("default=").append(describe(connectivity.getDefaultProxy()));
        android.net.Network active = connectivity.getActiveNetwork();
        for (android.net.Network network : connectivity.getAllNetworks()) {
            android.net.NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            android.net.LinkProperties link = connectivity.getLinkProperties(network);
            String kind = caps == null ? "unknown"
                : caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) ? "vpn"
                : caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) ? "wifi"
                : caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) ? "mobile" : "other";
            line.append(' ').append(kind).append(network.equals(active) ? "(active)" : "").append('=')
                .append(link == null ? "unknown" : describe(link.getHttpProxy()));
        }
        for (String property : new String[] {"http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"}) {
            line.append(' ').append(property).append('=').append(System.getProperty(property, "-"));
        }
        java.net.ProxySelector selector = java.net.ProxySelector.getDefault();
        line.append(" selector=").append(selector == null ? "none" : selector.getClass().getSimpleName());
        if (selector != null) {
            line.append(" select-http=").append(selected(selector, "http://" + INNER + "/"));
            line.append(" select-https=").append(selected(selector, "https://" + INNER + "/"));
        }
        return line.toString();
    }

    private static String get(String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        connection.setUseCaches(false);
        try {
            return String.valueOf(connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    private static String property(String url) throws Exception {
        String host = System.getProperty("http.proxyHost");
        String port = System.getProperty("http.proxyPort");
        if (host == null || host.isEmpty() || port == null) return "no-property";
        // A PAC on a network's own setting names the handler's host with no port (-1): nothing to connect to.
        if (Integer.parseInt(port) <= 0) return "port " + port;
        URL target = new URL(url);
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, Integer.parseInt(port)), 10_000);
            s.setSoTimeout(10_000);
            String request = "GET " + url + " HTTP/1.1\r\nHost: " + target.getAuthority() + "\r\nConnection: close\r\n\r\n";
            s.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            String head = head(s.getInputStream());
            String[] status = head.split(" ", 3);
            return status.length > 1 ? status[1] : "no-status";
        }
    }

    /** Loads [url] in a WebView on the main thread, and logs how it ended within 20 s: "finished", or the error. */
    private void webview(String url) {
        final android.webkit.WebView view = new android.webkit.WebView(this);
        setContentView(view);
        final boolean[] ended = {false};
        final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
        final Runnable end = () -> {
            Log.i(TAG, "done");
            view.destroy();
            finish();
        };
        view.setWebViewClient(new android.webkit.WebViewClient() {
            @Override
            public void onReceivedError(android.webkit.WebView v, android.webkit.WebResourceRequest request,
                    android.webkit.WebResourceError error) {
                if (ended[0] || !request.isForMainFrame()) return;
                ended[0] = true;
                Log.i(TAG, "webview failed " + error.getErrorCode() + " " + error.getDescription());
                main.post(end);
            }

            @Override
            public void onReceivedHttpError(android.webkit.WebView v, android.webkit.WebResourceRequest request,
                    android.webkit.WebResourceResponse response) {
                if (ended[0] || !request.isForMainFrame()) return;
                ended[0] = true;
                Log.i(TAG, "webview failed http-" + response.getStatusCode());
                main.post(end);
            }

            @Override
            public void onPageFinished(android.webkit.WebView v, String finished) {
                if (ended[0]) return;
                ended[0] = true;
                Log.i(TAG, "webview ok finished");
                main.post(end);
            }
        });
        main.postDelayed(() -> {
            if (ended[0]) return;
            ended[0] = true;
            Log.i(TAG, "webview failed timeout");
            end.run();
        }, 20_000);
        view.loadUrl(url);
    }

    /**
     * A lookup through Android's resolver, which the network part passes on: a messenger's lookups seen through the
     * network part make a hello no DNS answer tied to its address evidence of its proxy (ADR 0052, fix round). The
     * answer may be none.
     */
    private String lookup(String name) {
        try {
            java.net.InetAddress.getAllByName(name);
        } catch (java.net.UnknownHostException e) {
            // No such name: the lookup was made all the same.
        }
        return "asked";
    }

    private String socks5() throws Exception {
        try (Socket s = open()) {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            out.write(new byte[] {5, 1, 2});
            expect(read(in, 2), new byte[] {5, 2});
            byte[] user = extra("user").getBytes(StandardCharsets.UTF_8);
            byte[] password = extra("password").getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream auth = new ByteArrayOutputStream();
            auth.write(1);
            auth.write(user.length);
            auth.write(user);
            auth.write(password.length);
            auth.write(password);
            out.write(auth.toByteArray());
            expect(read(in, 2), new byte[] {1, 0});
            byte[] name = INNER.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            request.write(new byte[] {5, 1, 0, 3, (byte) name.length});
            request.write(name);
            request.write(new byte[] {1, (byte) 187});
            out.write(request.toByteArray());
            byte[] reply = read(in, 4);
            if (reply[1] != 0) throw new IOException();
            read(in, reply[3] == 4 ? 18 : 6);
            return echoed(s, clientHello(INNER, new byte[32], new byte[32]));
        }
    }

    private String basic() {
        String pair = extra("user") + ":" + extra("password");
        return "Proxy-Authorization: Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8)) + "\r\n";
    }

    private String connect() throws Exception {
        try (Socket s = open()) {
            String request = "CONNECT " + INNER + ":443 HTTP/1.1\r\nHost: " + INNER + ":443\r\n" + basic() + "\r\n";
            s.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            String head = head(s.getInputStream());
            if (!head.startsWith("HTTP/1.1 200") && !head.startsWith("HTTP/1.0 200")) throw new IOException();
            return echoed(s, clientHello(INNER, new byte[32], new byte[32]));
        }
    }

    private String forward() throws Exception {
        try (Socket s = open()) {
            String request = "GET http://" + INNER + "/fixture HTTP/1.1\r\nHost: " + INNER + "\r\n" + basic() + "Connection: close\r\n\r\n";
            s.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            String head = head(s.getInputStream());
            if (!head.contains(" 204 ")) throw new IOException();
            return "204";
        }
    }

    private String setting() throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://" + INNER + "/setting").openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        try {
            return String.valueOf(connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    /** 64 random bytes by Telegram's rules for the obfuscated transport's start (core.telegram.org/mtproto/mtproto-transports). */
    private String obfuscated() throws Exception {
        byte[] start = new byte[64];
        while (true) {
            RANDOM.nextBytes(start);
            int first = ByteBuffer.wrap(start, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int second = ByteBuffer.wrap(start, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if ((start[0] & 0xff) == 0xef || second == 0) continue;
            if (first == 0x44414548 || first == 0x54534f50 || first == 0x20544547 || first == 0x4954504f
                || first == 0x02010316 || first == 0xdddddddd || first == 0xeeeeeeee) continue;
            break;
        }
        // The protocol tag of the padded intermediate transport, as the client sets it before encrypting.
        start[56] = start[57] = start[58] = start[59] = (byte) 0xdd;
        try (Socket s = open()) {
            s.getOutputStream().write(start);
            s.getOutputStream().flush();
            // mtg takes it for no fake TLS and closes; the bytes went.
            try {
                s.getInputStream().read();
            } catch (IOException e) {
                // Closed or reset: either way the start was sent.
            }
            return "sent";
        }
    }

    /** A fake-TLS hello for the secret ee + 16-byte key + cover name: TDLib's TlsInit.cpp, as mtg's client_side.go checks it. */
    private String fakeTls() throws Exception {
        byte[] secret = hex(extra("secret").substring(2));
        byte[] key = Arrays.copyOf(secret, 16);
        String cover = new String(secret, 16, secret.length - 16, StandardCharsets.US_ASCII);
        byte[] session = new byte[32];
        RANDOM.nextBytes(session);
        byte[] record = clientHello(cover, session, new byte[32]);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] digest = mac.doFinal(record);
        byte[] stamp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) (System.currentTimeMillis() / 1000)).array();
        for (int i = 0; i < 4; i++) digest[28 + i] ^= stamp[i];
        System.arraycopy(digest, 0, record, 11, 32);
        try (Socket s = open()) {
            s.getOutputStream().write(record);
            byte[] answer = read(s.getInputStream(), 3);
            if (answer[0] != 0x16 || answer[1] != 3 || answer[2] != 3) throw new IOException();
            return "accepted";
        }
    }

    private String whatsapp() throws Exception {
        byte[] frame = new byte[] {'W', 'A', 6, 3, 0, 0, 4, 1, 2, 3, 4};
        try (Socket s = open()) {
            return echoed(s, frame);
        }
    }

    private String hello(String name) throws Exception {
        try (Socket s = open()) {
            return echoed(s, clientHello(name, new byte[32], new byte[32]));
        }
    }

    /** Sends [bytes] and reads them back, as the lab's target echoes them. */
    private static String echoed(Socket s, byte[] bytes) throws IOException {
        s.getOutputStream().write(bytes);
        expect(read(s.getInputStream(), bytes.length), bytes);
        return "echoed";
    }

    /** A small TLS 1.3 ClientHello record for [name], with [session] as its session ID and [random]. */
    static byte[] clientHello(String name, byte[] session, byte[] random) throws IOException {
        byte[] host = name.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        extensions.write(new byte[] {0, 0});
        writeShort(extensions, host.length + 5);
        writeShort(extensions, host.length + 3);
        extensions.write(0);
        writeShort(extensions, host.length);
        extensions.write(host);
        extensions.write(new byte[] {0, 43, 0, 3, 2, 3, 4});
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(new byte[] {3, 3});
        body.write(random);
        body.write(session.length);
        body.write(session);
        body.write(new byte[] {0, 2, 0x13, 0x01, 1, 0});
        writeShort(body, extensions.size());
        body.write(extensions.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(new byte[] {0x16, 3, 1});
        writeShort(record, body.size() + 4);
        record.write(1);
        record.write(0);
        writeShort(record, body.size());
        record.write(body.toByteArray());
        return record.toByteArray();
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static byte[] read(InputStream in, int n) throws IOException {
        byte[] bytes = new byte[n];
        int at = 0;
        while (at < n) {
            int read = in.read(bytes, at, n - at);
            if (read < 0) throw new IOException();
            at += read;
        }
        return bytes;
    }

    private static void expect(byte[] got, byte[] wanted) throws IOException {
        if (!Arrays.equals(got, wanted)) throw new IOException();
    }

    private static String head(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        while (!head.toString("US-ASCII").endsWith("\r\n\r\n")) {
            int b = in.read();
            if (b < 0) break;
            head.write(b);
        }
        return head.toString("US-ASCII");
    }

    private static byte[] hex(String text) {
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        return bytes;
    }
}
