/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.web;

import android.content.Context;
import android.net.Uri;

import org.grove.guard.Prefs;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Receives website history from the Groveguard browser extension on this phone.
 * Listens only on 127.0.0.1 (not reachable from the network), only while a pairing code is set, and only accepts
 * visits sent with that code. It never sends anything back but "ok".
 */
public final class ExtSync {
    private ExtSync() { }

    public static final int PORT = 47913;
    private static final String KEY = "ext_sync_key";
    private static final int MAX_BODY = 2 * 1024 * 1024;
    private static volatile ServerSocket server;
    private static volatile long lastReceived;
    private static volatile String lastBrowser = "";

    /** Name of the browser that last sent something, e.g. "Grove Browser" or "Firefox". */
    public static String lastBrowser() { return lastBrowser; }

    public static String code(Context c) { return Prefs.str(c, KEY, ""); }
    public static boolean running() { return server != null; }
    public static long lastReceived() { return lastReceived; }

    /** Makes a new pairing code (the old one stops working) and starts listening. */
    public static String newCode(Context c) {
        String abc = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        SecureRandom r = new SecureRandom();
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 10; i++) b.append(abc.charAt(r.nextInt(abc.length())));
        Prefs.set(c, KEY, b.toString());
        start(c);
        return b.toString();
    }

    public static void unlink(Context c) {
        Prefs.set(c, KEY, "");
        stop();
    }

    public static synchronized void start(final Context ctx) {
        final Context c = ctx.getApplicationContext();
        if (server != null || code(c).isEmpty()) return;
        try {
            final ServerSocket ss = new ServerSocket(PORT, 8, InetAddress.getByName("127.0.0.1"));
            server = ss;
            Thread t = new Thread(new Runnable() {
                @Override public void run() {
                    while (!ss.isClosed()) {
                        try (Socket s = ss.accept()) {
                            s.setSoTimeout(5000);
                            handle(c, s);
                        } catch (Exception ignored) { }
                    }
                }
            }, "ext-sync");
            t.setDaemon(true);
            t.start();
        } catch (Exception e) { server = null; }
    }

    public static synchronized void stop() {
        ServerSocket s = server;
        server = null;
        if (s != null) try { s.close(); } catch (Exception ignored) { }
    }

    private static String line(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int ch;
        while ((ch = in.read()) != -1 && ch != '\n') { if (b.size() > 8192) throw new java.io.IOException("line too long"); if (ch != '\r') b.write(ch); }
        return b.toString("UTF-8");
    }

    private static void handle(Context c, Socket s) throws Exception {
        if (!s.getInetAddress().isLoopbackAddress()) return;
        InputStream in = new BufferedInputStream(s.getInputStream());
        OutputStream out = s.getOutputStream();
        String[] req = line(in).split(" ");
        int len = 0;
        String key = "", browser = "";
        String h;
        int headers = 0;
        while (!(h = line(in)).isEmpty()) {
            if (++headers > 64) return;
            int i = h.indexOf(':');
            if (i < 0) continue;
            String name = h.substring(0, i).trim().toLowerCase(Locale.ROOT), val = h.substring(i + 1).trim();
            if (name.equals("content-length")) len = Integer.parseInt(val);
            else if (name.equals("x-groveguard-key")) key = val;
            else if (name.equals("x-groveguard-browser")) browser = val.replaceAll("[^A-Za-z ]", "");
        }
        if (req.length < 2) return;
        if ("OPTIONS".equals(req[0])) { reply(out, 204, ""); return; }
        String path = req[1];
        boolean get = "GET".equals(req[0]) && "/v1/settings".equals(path);
        if (!get && !("POST".equals(req[0]) && ("/v1/visits".equals(path) || "/v1/log".equals(path) || "/v1/set".equals(path)))) { reply(out, 404, "not found"); return; }
        String want = code(c);
        if (want.isEmpty() || !MessageDigest.isEqual(want.getBytes(StandardCharsets.UTF_8), key.toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8))) {
            reply(out, 403, "wrong code"); return;
        }
        lastReceived = System.currentTimeMillis();
        if (!browser.isEmpty()) lastBrowser = browser.length() > 20 ? browser.substring(0, 20) : browser;
        if (get) { reply(out, 200, settings(c).toString()); return; }
        if (len <= 0 || len > MAX_BODY) { reply(out, 413, "too big"); return; }
        byte[] body = new byte[len];
        int got = 0;
        while (got < len) { int n = in.read(body, got, len - got); if (n < 0) break; got += n; }
        String text = new String(body, 0, got, StandardCharsets.UTF_8);
        String app0 = (browser.isEmpty() ? "Browser" : browser.length() > 20 ? browser.substring(0, 20) : browser) + " (extension)";
        if ("/v1/set".equals(path)) { set(c, new JSONObject(text)); reply(out, 200, settings(c).toString()); return; }
        if ("/v1/log".equals(path)) { addLog(new JSONArray(text), app0); reply(out, 200, "ok"); return; }
        JSONArray arr = new JSONArray(text);
        String app = (browser.isEmpty() ? "Browser" : browser.length() > 20 ? browser.substring(0, 20) : browser) + " (extension)";
        long now = System.currentTimeMillis();
        List<WebHistory.Visit> list = new ArrayList<>();
        for (int i = 0; i < arr.length() && i < 1000; i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o == null) continue;
            String url = o.optString("u");
            if (url.length() > 2000) url = url.substring(0, 2000);
            String host = Uri.parse(url).getHost();
            if (host == null || host.isEmpty() || host.length() > 253) continue;
            long t = o.optLong("t", now);
            if (t > now + 60000 || t < 0) t = now;
            String why = o.optString("w");
            if (why.length() > 100) why = why.substring(0, 100);
            list.add(new WebHistory.Visit(t, host.toLowerCase(Locale.ROOT), url, o.optBoolean("b"), why, app));
        }
        WebHistory.addMany(c, list);
        lastReceived = now;
        reply(out, 200, "ok");
    }

    /** What the extension should use: the app's switches, lists and your rules (the app is in charge). */
    static JSONObject settings(Context c) throws Exception {
        JSONObject o = new JSONObject();
        o.put("blocking", WebFilter.enabled(c));
        JSONObject l = new JSONObject();
        for (WebFilter.ListInfo i : WebFilter.LISTS) l.put(i.id, WebFilter.listOn(c, i));
        o.put("lists", l);
        o.put("myBlock", new JSONArray(WebFilter.myBlock(c)));
        o.put("myAllow", new JSONArray(WebFilter.myAllow(c)));
        o.put("paused", new JSONArray(new java.util.TreeSet<>(Prefs.set(c, WebFilter.PAUSED))));
        return o;
    }

    /** A change made in the extension (always block/allow, a list switch, pause) — saved in the app. */
    private static void set(final Context c, JSONObject o) {
        final JSONObject f = o;
        org.grove.guard.App.MAIN.post(new Runnable() {
            @Override public void run() {
                try {
                    JSONObject r = f.optJSONObject("rule");
                    if (r != null) WebFilter.setRule(c, r.optString("host"), r.optString("list"));
                    JSONObject l = f.optJSONObject("list");
                    if (l != null) { WebFilter.ListInfo i = WebFilter.find(l.optString("id")); if (i != null) WebFilter.setList(c, i, l.optBoolean("on")); }
                    JSONObject p = f.optJSONObject("pause");
                    if (p != null && !p.optString("host").isEmpty()) WebFilter.setPaused(c, p.optString("host"), p.optBoolean("on"));
                    if (f.has("blocking")) Prefs.set(c, WebFilter.ENABLED, f.optBoolean("blocking"));
                    WebFilter.changed();
                } catch (Exception ignored) { }
            }
        });
    }

    /** Pages and blocked requests from the extension, shown in the web tab's log. */
    private static void addLog(JSONArray a, String app) {
        long now = System.currentTimeMillis();
        for (int i = 0; i < a.length() && i < 1000; i++) {
            JSONObject o = a.optJSONObject(i);
            if (o == null) continue;
            String host = o.optString("h"), url = o.optString("u");
            if (host.isEmpty() || host.length() > 253) continue;
            long t = o.optLong("t", now);
            if (t > now + 60000 || t < 0) t = now;
            String type = o.optString("type", "request");
            if (type.length() > 20) type = type.substring(0, 20);
            String page = o.optString("page"), why = o.optString("w");
            WebFilter.log(new WebFilter.Entry(t, type, host.toLowerCase(Locale.ROOT), url.length() > 2000 ? url.substring(0, 2000) : url,
                    page.length() > 253 ? "" : page, o.optBoolean("b"), why.length() > 100 ? why.substring(0, 100) : why, app));
        }
        WebFilter.changed();
    }

    private static void reply(OutputStream out, int code, String text) throws java.io.IOException {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        String st = code == 200 ? "OK" : code == 204 ? "No Content" : code == 403 ? "Forbidden" : code == 404 ? "Not Found" : "Error";
        out.write(("HTTP/1.1 " + code + " " + st + "\r\nContent-Type: text/plain\r\nContent-Length: " + b.length
                + "\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type, X-Groveguard-Key, X-Groveguard-Browser\r\n"
                + "Access-Control-Allow-Methods: POST\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(b);
        out.flush();
    }
}
