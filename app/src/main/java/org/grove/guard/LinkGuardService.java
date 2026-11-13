/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * Idea from Hypatia's LinkScannerService (Copyright (C) 2017-2018 Divested Computing Group), rewritten.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.accessibilityservice.AccessibilityService;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.Rect;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Toast;

import org.grove.guard.scan.Detect;
import org.grove.guard.scan.Sigs;
import org.grove.guard.scan.WebCheck;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Web protection. Reads the address bar of Firefox (and its forks) and other browsers, and warns — or takes you
 * back — when you open a site on the dangerous-domain list. Optionally checks web addresses shown in any app.
 * Also hosts the realtime file scanner, so that runs without a notification.
 *
 * Nothing it reads is stored or sent anywhere; only the host names of matches go into the Activity list.
 *
 * Why Hypatia's link scanner didn't work in Firefox: it cast every on-screen text to a plain String, but browsers
 * (Firefox's address bar especially) use styled text, so the cast failed and the text was silently skipped; it only
 * looked at the view that changed rather than the address bar; and its host-name pattern only matched texts that
 * were nothing but a host name, so a full address like "https://bad.example/page" was never checked.
 */
public class LinkGuardService extends AccessibilityService {
    private static volatile LinkGuardService instance;

    /** Browser package → address bar view ids (without the "package:id/" prefix). */
    private static final Map<String, String[]> BROWSERS = new HashMap<>();

    static {
        String[] gecko = {"mozac_browser_toolbar_url_view", "url_bar_title", "mozac_browser_toolbar_edit_url_view", "display_url"};
        for (String p : new String[]{"org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.fennec_fdroid",
                "org.mozilla.fennec_aurora", "org.mozilla.focus", "org.mozilla.klar", "org.mozilla.focus.beta", "org.mozilla.reference.browser",
                "io.github.forkmaintainers.iceraven", "us.spotco.fennec_dos", "org.ironfoxoss.ironfox", "org.ironfoxoss.ironfox.nightly",
                "org.torproject.torbrowser", "org.torproject.torbrowser_alpha", "net.waterfox.android.release", "org.gnu.icecat",
                "com.mull", "us.spotco.mulch", "app.fennec.fdroid"}) BROWSERS.put(p, gecko);
        String[] chromium = {"url_bar", "location_bar_edit_text", "url_field", "omnibarTextInput", "search_box_text", "url"};
        for (String p : new String[]{"com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.brave.browser", "com.brave.browser_beta",
                "com.vivaldi.browser", "com.kiwibrowser.browser", "org.bromite.bromite", "org.cromite.cromite", "com.microsoft.emmx",
                "com.sec.android.app.sbrowser", "com.opera.browser", "com.opera.mini.native", "com.duckduckgo.mobile.android",
                "org.chromium.chrome", "com.ecosia.android", "us.spotco.mulch_wv", "com.yandex.browser", "mark.via.gp", "mark.via"}) BROWSERS.put(p, chromium);
        // Grove Launcher's feed browser (it can also ask Grove Guard directly before loading a page)
        BROWSERS.put(Trust.LAUNCHER, new String[]{"url_bar", "address", "url", "web_address", "address_box", "web_url"});
    }

    private final Map<String, Long> lastLook = new HashMap<>();
    private final Map<String, Long> alerted = new HashMap<>();
    private String lastHost = "";

    public static boolean isRunning() { return instance != null; }

    /** Whether Android's accessibility settings have this service switched on. */
    public static boolean enabledInSettings(Context c) {
        String s = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        if (s == null) return false;
        ComponentName me = new ComponentName(c, LinkGuardService.class);
        for (String part : s.split(":")) {
            ComponentName cn = ComponentName.unflattenFromString(part);
            if (me.equals(cn)) return true;
        }
        return false;
    }

    public static boolean isBrowser(String pkg) { return BROWSERS.containsKey(pkg); }

    @Override protected void onServiceConnected() {
        instance = this;
        if (!Prefs.on(this, Prefs.WEB, false)) Prefs.set(this, Prefs.WEB, true); // turning the service on means you want it
        Sigs.ensureLoaded(this);
        if (!Sigs.domainsLoaded() && !new java.io.File(Sigs.dir(this), Sigs.DOMAINS).exists()) {
            Events.add(Events.WEB, "Web protection is on — the website list isn't downloaded yet", "Update the database in Grove Guard.");
            if (Sigs.networkOk(this, false)) Sigs.update(this, false, null);
        }
        Events.add(Events.WEB, "Web protection on", "Checking Firefox and other browsers");
        RealtimeService.sync(this);
        StatusProvider.changed(this);
    }

    @Override public boolean onUnbind(Intent intent) {
        shutdown();
        return super.onUnbind(intent);
    }

    @Override public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    private void shutdown() {
        if (instance != this) return;
        instance = null;
        // move the realtime scanner back to its own service
        if ("accessibility".equals(org.grove.guard.scan.Watcher.host())) {
            org.grove.guard.scan.Watcher.stop();
            RealtimeService.sync(getApplicationContext());
        }
        StatusProvider.changed(getApplicationContext());
    }

    @Override public void onInterrupt() { }

    @Override public void onAccessibilityEvent(AccessibilityEvent e) {
        if (e == null || e.getPackageName() == null || Sigs.domains == null) return;
        String pkg = e.getPackageName().toString();
        if (pkg.equals(getPackageName())) return;
        boolean browser = BROWSERS.containsKey(pkg);
        if (!browser && !Prefs.on(this, Prefs.WEB_ALL_APPS, false)) return;
        long now = System.currentTimeMillis();
        Long prev = lastLook.get(pkg);
        if (prev != null && now - prev < (browser ? 350 : 1500)) return;
        lastLook.put(pkg, now);
        try {
            if (browser) checkBrowser(pkg);
            else if (e.getSource() != null) checkTexts(pkg, e.getSource());
        } catch (Exception ignored) {
            // windows can disappear while we look at them
        }
    }

    private void checkBrowser(String pkg) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null || root.getPackageName() == null || !pkg.equals(root.getPackageName().toString())) return;
        String addr = null;
        for (String id : BROWSERS.get(pkg)) {
            List<AccessibilityNodeInfo> l = root.findAccessibilityNodeInfosByViewId(pkg + ":id/" + id);
            if (l == null) continue;
            for (AccessibilityNodeInfo n : l) {
                if (n.isFocused() && n.isEditable()) return; // you're typing; check once you've gone to the page
                CharSequence t = n.getText();
                if (!TextUtils.isEmpty(t)) { addr = t.toString(); break; }
            }
            if (addr != null) break;
        }
        if (addr == null) addr = findAddressHeuristically(root, Trust.LAUNCHER.equals(pkg));
        String host = WebCheck.hostOfAddress(addr);
        if (host == null || host.equals(lastHost)) return;
        lastHost = host;
        WebCheck.Hit hit = WebCheck.check(this, host);
        if (hit != null) onDangerous(pkg, hit, true);
    }

    /**
     * Newer browser versions draw the toolbar without view ids. Look for something address-like near the top of
     * the screen: a view whose id mentions url/address/location/omnibox, or a short host-like text in the top fifth.
     */
    private String findAddressHeuristically(AccessibilityNodeInfo root, boolean strict) {
        Rect screen = new Rect();
        root.getBoundsInScreen(screen);
        int topLimit = screen.top + Math.max(1, screen.height() / 5);
        int bottomBar = screen.bottom - Math.max(1, screen.height() / 6); // Firefox can put the toolbar at the bottom
        ArrayDeque<AccessibilityNodeInfo> q = new ArrayDeque<>();
        q.add(root);
        int seen = 0;
        String best = null;
        Rect r = new Rect();
        while (!q.isEmpty() && seen < 400) {
            AccessibilityNodeInfo n = q.poll();
            seen++;
            String id = n.getViewIdResourceName();
            CharSequence t = n.getText();
            if (t == null) t = n.getContentDescription();
            if (t != null && t.length() > 3 && t.length() < 2048) {
                String s = t.toString();
                if (id != null) {
                    String li = id.toLowerCase(java.util.Locale.ROOT);
                    if ((li.contains("url") || li.contains("address") || li.contains("location") || li.contains("omnibox") || li.contains("toolbar"))
                            && WebCheck.hostOfAddress(s) != null) {
                        if (n.isFocused() && n.isEditable()) return null;
                        return s;
                    }
                }
                // the launcher shows lots of other text (app names, widgets): only trust its address box there
                if (strict && n.isEditable() && !n.isFocused() && WebCheck.hostOfAddress(s) != null) return s;
                if (!strict && best == null && WebCheck.hostOfAddress(s) != null) {
                    n.getBoundsInScreen(r);
                    if ((r.bottom <= topLimit || r.top >= bottomBar) && !(n.isEditable() && n.isFocused())) best = s;
                }
            }
            for (int i = 0; i < n.getChildCount(); i++) {
                AccessibilityNodeInfo k = n.getChild(i);
                if (k != null) q.add(k);
            }
        }
        return best;
    }

    /** Hypatia-style check of texts in any app (off by default; the list also contains many ad domains). */
    private void checkTexts(String pkg, AccessibilityNodeInfo src) {
        ArrayDeque<AccessibilityNodeInfo> q = new ArrayDeque<>();
        q.add(src);
        int seen = 0;
        while (!q.isEmpty() && seen < 300) {
            AccessibilityNodeInfo n = q.poll();
            seen++;
            CharSequence t = n.getText();
            if (t != null && t.length() > 3 && t.length() < 10000 && t.toString().indexOf('.') > 0 && !(n.isEditable() && n.isFocused())) {
                for (String h : WebCheck.hosts(t.toString())) {
                    WebCheck.Hit hit = WebCheck.check(this, h);
                    if (hit != null) { onDangerous(pkg, hit, false); return; }
                }
            }
            for (int i = 0; i < n.getChildCount(); i++) {
                AccessibilityNodeInfo k = n.getChild(i);
                if (k != null) q.add(k);
            }
        }
    }

    private void onDangerous(String pkg, WebCheck.Hit hit, boolean opened) {
        long now = System.currentTimeMillis();
        Long prev = alerted.get(hit.host);
        if (prev != null && now - prev < 60000) return;
        alerted.put(hit.host, now);
        if (alerted.size() > 500) alerted.clear();
        String app = Detect.appName(this, pkg);
        boolean leave = opened && Prefs.on(this, Prefs.WEB_AUTO_BACK, false);
        if (leave) {
            performGlobalAction(GLOBAL_ACTION_BACK);
            Toast.makeText(this, "Grove Guard: left dangerous site " + WebCheck.defang(hit.host), Toast.LENGTH_LONG).show();
        }
        Events.add(Events.WEB, (opened ? "Dangerous site opened in " : "Dangerous address shown in ") + app + ": " + WebCheck.defang(hit.host),
                (hit.listed.equals(hit.host) ? "" : "Listed as " + WebCheck.defang(hit.listed) + " · ") + (leave ? "Went back automatically" : "Warned"));
        int id = 0x6000 + (Math.abs(hit.host.hashCode()) % 100000);
        Notification.Builder b = new Notification.Builder(this, App.CH_ALERTS)
                .setSmallIcon(R.drawable.ic_stat)
                .setColor(0xFFC0392B)
                .setContentTitle(leave ? "Left a dangerous site" : "Dangerous site: " + WebCheck.defang(hit.host))
                .setContentText((leave ? WebCheck.defang(hit.host) + " · " : "") + "On Grove Guard's list of malware, phishing, tracker and ad domains")
                .setStyle(new Notification.BigTextStyle().bigText(WebCheck.defang(hit.host) + " in " + app
                        + (hit.listed.equals(hit.host) ? "" : "\nListed domain: " + WebCheck.defang(hit.listed))
                        + "\nOn Grove Guard's list of malware, phishing, tracker and ad domains."))
                .setCategory(Notification.CATEGORY_ERROR)
                .setTimeoutAfter(10 * 60 * 1000L)
                .setAutoCancel(true);
        if (opened && !leave) b.addAction(new Notification.Action.Builder(null, "Go back", actionIntent(ActionReceiver.BACK, hit.host, id, 1)).build());
        b.addAction(new Notification.Action.Builder(null, "Allow this site", actionIntent(ActionReceiver.ALLOW, hit.listed, id, 2)).build());
        getSystemService(NotificationManager.class).notify(id, b.build());
    }

    private PendingIntent actionIntent(String action, String host, int notifId, int n) {
        Intent i = new Intent(this, ActionReceiver.class).setAction(action).putExtra("host", host).putExtra("nid", notifId);
        return PendingIntent.getBroadcast(this, notifId * 4 + n, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    /** Handles the alert's buttons. Not exported: only our own notifications can call it. */
    public static class ActionReceiver extends BroadcastReceiver {
        static final String BACK = "org.grove.guard.web.BACK", ALLOW = "org.grove.guard.web.ALLOW";

        @Override public void onReceive(Context c, Intent i) {
            String host = i.getStringExtra("host");
            c.getSystemService(NotificationManager.class).cancel(i.getIntExtra("nid", 0));
            if (BACK.equals(i.getAction())) {
                final LinkGuardService s = instance;
                if (s != null) {
                    // the button is pressed in the notification shade: close it first, then go back in the browser
                    if (android.os.Build.VERSION.SDK_INT >= 31) s.performGlobalAction(GLOBAL_ACTION_DISMISS_NOTIFICATION_SHADE);
                    App.MAIN.postDelayed(new Runnable() { @Override public void run() { s.performGlobalAction(GLOBAL_ACTION_BACK); } }, 450);
                }
            } else if (ALLOW.equals(i.getAction()) && host != null) {
                Set<String> allow = Prefs.set(c, Prefs.WEB_ALLOW);
                allow.add(host);
                Prefs.set(c, Prefs.WEB_ALLOW, allow);
                Events.add(Events.WEB, "Allowed " + WebCheck.defang(host), "You can remove it in Settings > Web protection.");
                Toast.makeText(c, "Allowed " + host, Toast.LENGTH_SHORT).show();
            }
        }
    }
}
