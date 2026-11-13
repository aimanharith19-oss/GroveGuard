/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import org.grove.guard.fw.Firewall;
import org.grove.guard.fw.Shizuku;
import org.grove.guard.scan.Detect;
import org.grove.guard.scan.Scanner;
import org.grove.guard.scan.Sigs;
import org.grove.guard.scan.Watcher;
import org.grove.guard.ui.FirewallPage;
import org.grove.guard.ui.SettingsPage;
import org.grove.guard.ui.Ui;

import java.text.NumberFormat;
import java.util.List;

/** The app: Protect, Firewall, Activity and Settings tabs. */
public class MainActivity extends Activity implements Sigs.Listener, Scanner.Listener, Events.Listener, Firewall.Listener, Shizuku.Listener {
    private static final String[] TABS = {"Protect", "Firewall", "Background", "Apps", "Activity"};
    private static final int[] TAB_ICONS = {R.drawable.ic_shield, R.drawable.ic_wall, R.drawable.ic_sleep, R.drawable.ic_apps, R.drawable.ic_list};
    static final int TAB_SETTINGS = 5;

    private Ui.Pal p;
    private FrameLayout content;
    private LinearLayout nav;
    private int tab;
    private FirewallPage firewallPage;
    private org.grove.guard.ui.BackgroundPage backgroundPage;
    private org.grove.guard.ui.AppsPage appsPage;
    private int lastTab;
    private SettingsPage settingsPage;
    // live views on the Protect tab
    private ProgressBar scanBar;
    private TextView scanFile, scanCount;
    private final StringBuilder updateLog = new StringBuilder();

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        p = Ui.pal(this);
        LinearLayout root = Ui.col(this);
        root.setBackgroundColor(p.bg);
        content = new FrameLayout(this);
        root.addView(content, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        nav = Ui.row(this);
        nav.setBackgroundColor(p.card);
        nav.setPadding(Ui.dp(this, 8), Ui.dp(this, 6), Ui.dp(this, 8), Ui.dp(this, 6));
        root.addView(nav, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setFilterTouchesWhenObscured(true); // ignore taps while another app draws over us (tapjacking)
        setContentView(root);
        getWindow().setNavigationBarColor(p.card);
        tab = b != null ? b.getInt("tab", 0) : getIntent().getIntExtra("tab", 0);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && !Prefs.on(this, "asked_notif", false)) {
            Prefs.set(this, "asked_notif", true);
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
        if (!Prefs.sp(this).contains(Prefs.AUTO_UPDATE)) Prefs.set(this, Prefs.AUTO_UPDATE, true);
        Jobs.schedule(this);
    }

    @Override protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        if (i.hasExtra("tab")) { tab = i.getIntExtra("tab", 0); show(); }
    }

    @Override protected void onSaveInstanceState(Bundle out) { super.onSaveInstanceState(out); out.putInt("tab", tab); }

    @Override protected void onResume() {
        super.onResume();
        Sigs.addListener(this); Scanner.addListener(this); Events.addListener(this); Firewall.addListener(this); Shizuku.addListener(this);
        App.IO.execute(new Runnable() { @Override public void run() { Detect.prune(getApplicationContext()); } });
        Sigs.ensureLoaded(this);
        RealtimeService.sync(this);
        secureWindow();
        if (org.grove.guard.ui.Lock.needsAuth(this)) {
            content.setVisibility(View.INVISIBLE);
            nav.setVisibility(View.INVISIBLE);
            if (authing) return;
            authing = true;
            org.grove.guard.ui.Lock.authenticate(this, "Fingerprint or screen lock", new org.grove.guard.ui.Lock.Result() {
                @Override public void done(boolean ok) {
                    authing = false;
                    if (!ok) { finish(); return; }
                    content.setVisibility(View.VISIBLE);
                    nav.setVisibility(View.VISIBLE);
                    show();
                }
            });
            return;
        }
        content.setVisibility(View.VISIBLE);
        nav.setVisibility(View.VISIBLE);
        show();
    }

    private boolean authing;

    /** Hide the screen from screenshots and the recent-apps preview while the app lock is on. */
    public void secureWindow() {
        if (org.grove.guard.ui.Lock.enabled(this)) getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        else getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
    }

    @Override protected void onStop() {
        org.grove.guard.ui.Lock.onLeave();
        super.onStop();
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        if (!org.grove.guard.ui.Lock.onResult(req, res)) super.onActivityResult(req, res, data);
    }

    @Override protected void onPause() {
        Sigs.removeListener(this); Scanner.removeListener(this); Events.removeListener(this); Firewall.removeListener(this); Shizuku.removeListener(this);
        super.onPause();
    }

    // ---------------------------------------------------------------- listeners

    @Override public void onSigsChanged() { if (tab == 0 || tab == TAB_SETTINGS) show(); }

    @Override public void onProgress(int done, int total, String current) {
        if (tab != 0) return;
        if (scanBar == null) { show(); return; }
        scanBar.setIndeterminate(total == 0);
        if (total > 0) { scanBar.setMax(total); scanBar.setProgress(done); }
        scanFile.setText(current);
        scanCount.setText(total > 0 ? NumberFormat.getInstance().format(done) + " of " + NumberFormat.getInstance().format(total) + " files" : "");
    }

    @Override public void onFinished(Scanner.Result r) { if (tab == 0) show(); }

    @Override public void onEvent(Events.Event e) { if (tab == 4 || (tab == 0 && e != null && (Events.THREAT.equals(e.kind)))) show(); }

    @Override public void onFirewallChanged() { if (tab == 1 && firewallPage != null) firewallPage.refreshHeader(); }

    @Override public void onShizukuChanged() {
        if (tab == 1 && firewallPage != null) firewallPage.refreshHeader();
        else if (tab == 2 && backgroundPage != null) backgroundPage.reload();
        else if (tab == 3 && appsPage != null) appsPage.refreshHeader();
        else if (tab == 0 || tab == TAB_SETTINGS) show();
    }

    public void openTab(int t) { if (t != tab) { if (t == TAB_SETTINGS) lastTab = tab; tab = t; show(); } }

    @Override public void onBackPressed() {
        if (tab == TAB_SETTINGS) { tab = lastTab; show(); return; }
        super.onBackPressed();
    }

    /** Page title with the settings button on the right (all tabs). */
    public static View pageHeader(final Activity a, String title, String subtitle) {
        Ui.Pal p = Ui.pal(a);
        LinearLayout h = Ui.row(a);
        h.setPadding(Ui.dp(a, 22), Ui.dp(a, 22), Ui.dp(a, 12), Ui.dp(a, 10));
        LinearLayout t = Ui.col(a);
        t.addView(Ui.title(a, title, 24));
        t.addView(Ui.text(a, subtitle, 13, p.sub));
        h.addView(t, Ui.lpW(1));
        if (a instanceof MainActivity && ((MainActivity) a).tab != TAB_SETTINGS) {
            FrameLayout g = new FrameLayout(a);
            g.addView(Ui.icon(a, R.drawable.ic_settings, p.sub, 24), new FrameLayout.LayoutParams(Ui.dp(a, 24), Ui.dp(a, 24), Gravity.CENTER));
            g.setBackground(Ui.ripple(a, 0, Ui.dp(a, 24)));
            g.setContentDescription("Settings");
            g.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { ((MainActivity) a).openTab(TAB_SETTINGS); } });
            h.addView(g, new LinearLayout.LayoutParams(Ui.dp(a, 48), Ui.dp(a, 48)));
        }
        return h;
    }

    // ---------------------------------------------------------------- tabs

    private void buildNav() {
        nav.removeAllViews();
        for (int i = 0; i < TABS.length; i++) {
            final int idx = i;
            boolean on = i == tab;
            LinearLayout b = Ui.col(this);
            b.setGravity(Gravity.CENTER);
            b.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
            FrameLayout pill = new FrameLayout(this);
            pill.setBackground(Ui.round(on ? p.container : 0, Ui.dp(this, 16)));
            ImageView ic = Ui.icon(this, TAB_ICONS[i], on ? p.onContainer : p.sub, 22);
            FrameLayout.LayoutParams il = new FrameLayout.LayoutParams(Ui.dp(this, 22), Ui.dp(this, 22), Gravity.CENTER);
            pill.addView(ic, il);
            LinearLayout.LayoutParams pl = new LinearLayout.LayoutParams(Ui.dp(this, 56), Ui.dp(this, 32));
            pl.gravity = Gravity.CENTER_HORIZONTAL;
            b.addView(pill, pl);
            TextView t = Ui.text(this, TABS[i], 11.5f, on ? p.text : p.sub);
            if (on) t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            t.setPadding(0, Ui.dp(this, 4), 0, 0);
            t.setGravity(Gravity.CENTER_HORIZONTAL);
            t.setSingleLine();
            LinearLayout.LayoutParams tl = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tl.gravity = Gravity.CENTER_HORIZONTAL;
            b.addView(t, tl);
            b.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { if (tab != idx) { tab = idx; show(); } } });
            b.setContentDescription(TABS[i]);
            b.setBackground(Ui.ripple(this, 0, Ui.dp(this, 16)));
            nav.addView(b, Ui.lpW(1));
        }
    }

    public void recreateTab() { show(); }

    void show() {
        buildNav();
        scanBar = null;
        if (tab == 1) {
            if (firewallPage == null) firewallPage = new FirewallPage(this);
            if (firewallPage.view().getParent() != content) { content.removeAllViews(); content.addView(firewallPage.view()); }
            firewallPage.refreshHeader();
            return;
        }
        if (tab == 2) {
            if (backgroundPage == null) backgroundPage = new org.grove.guard.ui.BackgroundPage(this);
            else if (backgroundPage.view().getParent() != content) backgroundPage.reload();
            if (backgroundPage.view().getParent() != content) { content.removeAllViews(); content.addView(backgroundPage.view()); }
            return;
        }
        if (tab == 3) {
            if (appsPage == null) appsPage = new org.grove.guard.ui.AppsPage(this);
            else if (appsPage.view().getParent() != content) appsPage.reload();
            if (appsPage.view().getParent() != content) { content.removeAllViews(); content.addView(appsPage.view()); }
            return;
        }
        final ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        LinearLayout col = Ui.col(this);
        col.setPadding(0, 0, 0, Ui.dp(this, 24));
        sv.addView(col);
        int keepScroll = 0;
        if (content.getChildCount() > 0 && content.getChildAt(0) instanceof ScrollView && content.getChildAt(0).getTag() != null
                && content.getChildAt(0).getTag().equals(tab)) keepScroll = content.getChildAt(0).getScrollY();
        sv.setTag(tab);
        if (tab == 0) buildProtect(col);
        else if (tab == 4) buildActivity(col);
        else { if (settingsPage == null) settingsPage = new SettingsPage(this); settingsPage.build(col); }
        content.removeAllViews();
        content.addView(sv);
        final int y = keepScroll;
        if (y > 0) sv.post(new Runnable() { @Override public void run() { sv.scrollTo(0, y); } });
    }

    private View header(String subtitle) {
        LinearLayout h = (LinearLayout) pageHeader(this, "Grove Guard", subtitle);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.mipmap.ic_launcher);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(Ui.dp(this, 44), Ui.dp(this, 44));
        lp.rightMargin = Ui.dp(this, 12);
        h.addView(logo, 0, lp);
        return h;
    }

    // ---------------------------------------------------------------- Protect

    private void buildProtect(LinearLayout col) {
        col.addView(header("Malware scanner · web protection · firewall"));
        List<Detect.Threat> threats = Detect.all();
        boolean scanning = Scanner.running(), db = Sigs.downloaded(this), loaded = Sigs.loaded();
        boolean rt = Prefs.on(this, Prefs.REALTIME, false);

        // hero
        LinearLayout hero = Ui.card(this);
        hero.setPadding(Ui.dp(this, 20), Ui.dp(this, 22), Ui.dp(this, 20), Ui.dp(this, 18));
        LinearLayout top = Ui.row(this);
        int icon, fg, bg;
        String title, sub;
        if (!threats.isEmpty()) {
            icon = R.drawable.ic_warning; fg = p.danger; bg = p.dangerBg;
            title = threats.size() == 1 ? "1 threat found" : threats.size() + " threats found";
            sub = "Review them below";
        } else if (scanning) {
            icon = R.drawable.ic_search; fg = p.primary; bg = p.container;
            title = "Scanning…"; sub = "You can leave this screen";
        } else if (!db) {
            icon = R.drawable.ic_shield; fg = p.warn; bg = p.warnBg;
            title = "Set up protection"; sub = Sigs.updating() ? "Downloading the signature database…" : "Download the signature database to start";
        } else if (!rt) {
            icon = R.drawable.ic_shield; fg = p.warn; bg = p.warnBg;
            title = "Realtime scanning is off"; sub = "Files are only checked when you scan";
        } else {
            icon = R.drawable.ic_shield_check; fg = p.primary; bg = p.container;
            title = "You're protected"; sub = "New files and apps are checked as they arrive";
        }
        top.addView(Ui.badge(this, icon, fg, bg, 64));
        LinearLayout tt = Ui.col(this);
        tt.setPadding(Ui.dp(this, 16), 0, 0, 0);
        tt.addView(Ui.title(this, title, 22));
        TextView st = Ui.text(this, sub, 14, p.sub);
        st.setPadding(0, Ui.dp(this, 2), 0, 0);
        tt.addView(st);
        top.addView(tt, Ui.lpW(1));
        hero.addView(top);

        // database line
        String dbLine;
        if (Sigs.updating()) dbLine = "Updating the database…";
        else if (Sigs.loading()) dbLine = "Loading signatures…";
        else if (loaded) dbLine = shortCount(Sigs.count()) + " signatures · updated " + Events.ago(this, Sigs.lastUpdate(this));
        else if (db) dbLine = "Database downloaded · not loaded yet";
        else dbLine = "No signature database yet (~" + Sigs.downloadSizeMb(this) + " MB)";
        TextView dbt = Ui.text(this, dbLine, 13, p.sub);
        dbt.setPadding(0, Ui.dp(this, 14), 0, 0);
        hero.addView(dbt);
        if (updateLog.length() > 0 && Sigs.updating()) {
            TextView ul = Ui.text(this, updateLog.toString().trim(), 12, p.sub);
            ul.setPadding(0, Ui.dp(this, 6), 0, 0);
            hero.addView(ul);
        }

        if (scanning) {
            scanBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
            scanBar.setProgressTintList(android.content.res.ColorStateList.valueOf(p.primary));
            scanBar.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(p.primary));
            LinearLayout.LayoutParams bl = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 10));
            bl.topMargin = Ui.dp(this, 14);
            hero.addView(scanBar, bl);
            scanCount = Ui.text(this, "", 13, p.text);
            scanCount.setPadding(0, Ui.dp(this, 6), 0, 0);
            hero.addView(scanCount);
            scanFile = Ui.text(this, "", 12, p.sub);
            scanFile.setSingleLine();
            scanFile.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
            hero.addView(scanFile);
            onProgress(Scanner.progressDone(), Scanner.progressTotal(), Scanner.progressFile());
            hero.addView(spacedRow(Ui.button(this, "Stop scan", 1, new View.OnClickListener() {
                @Override public void onClick(View v) { Scanner.cancel(); Ui.toast(MainActivity.this, "Stopping…"); }
            }), null));
        } else {
            View scanBtn = Ui.bigButton(this, R.drawable.ic_search, "Scan now", 0, new View.OnClickListener() {
                @Override public void onClick(View v) { startScan(); }
            });
            View upd = Ui.bigButton(this, R.drawable.ic_refresh, Sigs.updating() ? "Updating…" : db ? "Update database" : "Download database", db ? 1 : 0,
                    new View.OnClickListener() {
                        @Override public void onClick(View v) { update(); }
                    });
            if (db) { hero.addView(stacked(scanBtn, 16)); hero.addView(stacked(upd, 10)); }
            else hero.addView(stacked(upd, 16));
            Scanner.Result r = Scanner.lastResult();
            if (r != null && db) {
                TextView lr = Ui.text(this, "Last scan: " + (r.cancelled ? "stopped" : r.matches > 0 ? r.matches + " found" : "nothing found")
                        + " · " + NumberFormat.getInstance().format(r.files) + " files in " + (r.millis / 1000) + " s", 12, p.sub);
                lr.setPadding(0, Ui.dp(this, 10), 0, 0);
                hero.addView(lr);
            }
        }
        col.addView(hero);

        // threats
        if (!threats.isEmpty()) {
            col.addView(Ui.section(this, "Threats"));
            LinearLayout tc = Ui.card(this);
            for (int i = 0; i < threats.size(); i++) {
                if (i > 0) tc.addView(Ui.divider(this));
                tc.addView(threatRow(threats.get(i)));
            }
            col.addView(tc);
        }

        // setup needs
        boolean files = App.hasFileAccess(this);
        boolean notif = Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
        if (!files || !notif) {
            col.addView(Ui.section(this, "Needs your permission"));
            LinearLayout pc = Ui.card(this);
            if (org.grove.guard.fw.Shell.backend(this) != null) pc.addView(Ui.item(this, R.drawable.ic_bolt, "Set up with Shizuku", "One tap: file access, alerts and no battery limits", null,
                    new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            App.IO.execute(new Runnable() {
                                @Override public void run() {
                                    final String err = org.grove.guard.fw.Setup.grantBasics(MainActivity.this);
                                    runOnUiThread(new Runnable() { @Override public void run() { Ui.toast(MainActivity.this, err == null ? "Done" : err); show(); } });
                                }
                            });
                        }
                    }));
            if (!files) pc.addView(Ui.item(this, R.drawable.ic_folder, "Allow file access", "Needed to scan your storage and Downloads", null, new View.OnClickListener() {
                @Override public void onClick(View v) { askFileAccess(); }
            }));
            if (!notif) pc.addView(Ui.item(this, R.drawable.ic_warning, "Allow alerts", "So Grove Guard can tell you when it finds something", null, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    if (Build.VERSION.SDK_INT >= 33) requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
                }
            }));
            col.addView(pc);
        }

        // protection switches
        col.addView(Ui.section(this, "Protection"));
        LinearLayout pc = Ui.card(this);
        String host = Watcher.host();
        String rtSub = !rt ? "Off — also in Quick Settings" : "accessibility".equals(host) ? "On · runs inside Web protection, no notification"
                : "service".equals(host) ? "On · background service" : "On · starting…";
        pc.addView(Ui.item(this, R.drawable.ic_bolt, "Realtime scanning", rtSub, rt, new View.OnClickListener() {
            @Override public void onClick(View v) {
                boolean on = !Prefs.on(MainActivity.this, Prefs.REALTIME, false);
                Prefs.set(MainActivity.this, Prefs.REALTIME, on);
                if (on && !App.hasFileAccess(MainActivity.this)) askFileAccess();
                RealtimeService.sync(MainActivity.this);
                if (on && !Sigs.downloaded(MainActivity.this) && !Sigs.updating()) update();
                show();
            }
        }));
        if (rt && "service".equals(host)) {
            pc.addView(Ui.item(this, 0, "Hide the background notification", "Turn off its notification category; scanning keeps running. Or turn on Web protection.", null,
                    new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            try {
                                startActivity(new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                                        .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()).putExtra(Settings.EXTRA_CHANNEL_ID, App.CH_BACKGROUND));
                            } catch (Exception e) { Ui.toast(MainActivity.this, "Open Android's notification settings for Grove Guard"); }
                        }
                    }));
        }
        boolean web = LinkGuardService.enabledInSettings(this);
        String webSub = !web ? "Warns when Firefox or another browser opens a dangerous site"
                : !Sigs.domainsLoaded() ? (Sigs.busy() ? "On · loading the website list…" : "On · website list missing — update the database")
                : Prefs.on(this, Prefs.WEB_AUTO_BACK, false) ? "On · leaves dangerous sites automatically" : "On · warns about dangerous sites";
        pc.addView(Ui.item(this, R.drawable.ic_globe, "Web protection (Firefox & browsers)", webSub, web, new View.OnClickListener() {
            @Override public void onClick(View v) { toggleWeb(); }
        }));
        pc.addView(Ui.item(this, R.drawable.ic_link, "Check a link", "Or share a page from Firefox to Grove Guard", null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                Ui.input(MainActivity.this, "Check a link", null, "example.com or https://…", "", new Ui.Cb<String>() {
                    @Override public void on(String s) {
                        if (s.isEmpty()) return;
                        startActivity(new Intent(MainActivity.this, CheckActivity.class).setAction(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, s));
                    }
                });
            }
        }));
        col.addView(pc);

        // what to scan
        col.addView(Ui.section(this, "What “Scan now” checks"));
        LinearLayout wc = Ui.card(this);
        LinearLayout chips = new FlowLayout(this);
        chips.addView(scanChip("Apps", Prefs.SCAN_APPS, true));
        chips.addView(scanChip("Storage", Prefs.SCAN_STORAGE, true));
        chips.addView(scanChip("SD cards & USB", Prefs.SCAN_SD, false));
        chips.addView(scanChip("System", Prefs.SCAN_SYSTEM, false));
        chips.addView(scanChip("App data folders (Shizuku)", Prefs.SCAN_APPDATA, false));
        wc.addView(chips);
        TextView note = Ui.text(this, "Signature matching finds known malware. Each file's fingerprint is compared with "
                + shortCount(Math.max(Sigs.count(), 0)) + " known-bad ones, on your phone.", 12, p.sub);
        note.setPadding(0, Ui.dp(this, 6), 0, 0);
        wc.addView(note);
        col.addView(wc);
    }

    private View threatRow(final Detect.Threat t) {
        LinearLayout r = Ui.col(this);
        r.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 6));
        LinearLayout top = Ui.row(this);
        top.addView(Ui.badge(this, R.drawable.ic_bug, p.danger, p.dangerBg, 38));
        LinearLayout tx = Ui.col(this);
        tx.setPadding(Ui.dp(this, 12), 0, 0, 0);
        TextView n = Ui.title(this, t.pkg != null ? Detect.appName(this, t.pkg) : t.name(), 16);
        tx.addView(n);
        TextView pth = Ui.text(this, Scanner.display(new java.io.File(t.path)), 12, p.sub);
        pth.setSingleLine();
        pth.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        tx.addView(pth);
        tx.addView(Ui.text(this, t.type + " match · " + t.origin + " · " + Events.ago(this, t.time), 12, p.sub));
        top.addView(tx, Ui.lpW(1));
        r.addView(top);
        LinearLayout acts = Ui.row(this);
        acts.setGravity(Gravity.END);
        acts.addView(Ui.button(this, "Look up", 2, new View.OnClickListener() {
            @Override public void onClick(View v) { PromptActivity.lookup(MainActivity.this, t, null); }
        }));
        acts.addView(Ui.button(this, "Ignore", 2, new View.OnClickListener() {
            @Override public void onClick(View v) { PromptActivity.ignore(MainActivity.this, t); show(); }
        }));
        if (t.pkg != null) acts.addView(Ui.button(this, "Uninstall", 3, new View.OnClickListener() {
            @Override public void onClick(View v) { PromptActivity.uninstall(MainActivity.this, t); }
        }));
        else acts.addView(Ui.button(this, "Delete", 3, new View.OnClickListener() {
            @Override public void onClick(View v) { PromptActivity.delete(MainActivity.this, t, new Runnable() { @Override public void run() { show(); } }); }
        }));
        r.addView(acts);
        return r;
    }

    private TextView scanChip(String label, final String key, final boolean def) {
        return Ui.chip(this, label, Prefs.on(this, key, def), new View.OnClickListener() {
            @Override public void onClick(View v) { Prefs.set(MainActivity.this, key, !Prefs.on(MainActivity.this, key, def)); show(); }
        });
    }

    private View stacked(View v, int topDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 56));
        lp.topMargin = Ui.dp(this, topDp);
        v.setLayoutParams(lp);
        return v;
    }

    private LinearLayout spacedRow(View a, View b) {
        LinearLayout r = Ui.row(this);
        r.setPadding(0, Ui.dp(this, 16), 0, 0);
        r.addView(a, Ui.lpW(1));
        if (b != null) {
            LinearLayout.LayoutParams lp = Ui.lpW(1);
            lp.leftMargin = Ui.dp(this, 10);
            r.addView(b, lp);
        }
        return r;
    }

    static String shortCount(long n) {
        if (n >= 1_000_000) return String.format(java.util.Locale.getDefault(), "%.1fM", n / 1e6);
        if (n >= 10_000) return (n / 1000) + "k";
        return NumberFormat.getInstance().format(n);
    }

    private void startScan() {
        if (!Sigs.downloaded(this)) { update(); return; }
        if (Sigs.updating()) { Ui.toast(this, "Wait for the update to finish"); return; }
        if (Prefs.on(this, Prefs.SCAN_STORAGE, true) && !App.hasFileAccess(this)) {
            Ui.confirm(this, "Scan without file access?", "Grove Guard can't see your storage yet, so only apps will be scanned.", "Allow access", new Runnable() {
                @Override public void run() { askFileAccess(); }
            });
        }
        Scanner.start(this);
        show();
    }

    void update() {
        if (Sigs.updating()) return;
        if (!Sigs.networkOk(this, true)) { Ui.toast(this, "No internet connection"); return; }
        Runnable go = new Runnable() {
            @Override public void run() {
                updateLog.setLength(0);
                Sigs.update(MainActivity.this, true, new Sigs.Progress() {
                    @Override public void on(final String line) {
                        runOnUiThread(new Runnable() {
                            @Override public void run() {
                                updateLog.append(line).append('\n');
                                String[] lines = updateLog.toString().split("\n");
                                if (lines.length > 6) { updateLog.setLength(0); for (int i = lines.length - 6; i < lines.length; i++) updateLog.append(lines[i]).append('\n'); }
                                if (tab == 0) show();
                            }
                        });
                    }
                });
                show();
            }
        };
        if (Sigs.metered(this) && !Sigs.downloaded(this)) {
            Ui.confirm(this, "Download on mobile data?", "The first download is about " + Sigs.downloadSizeMb(this) + " MB. Later updates only fetch what changed.", "Download", go);
        } else go.run();
    }

    void askFileAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        } else requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, 2);
    }

    void toggleWeb() {
        if (org.grove.guard.fw.Shell.backend(this) != null) {
            final boolean on = !LinkGuardService.enabledInSettings(this);
            Runnable go = new Runnable() {
                @Override public void run() {
                    if (on) Prefs.set(MainActivity.this, Prefs.WEB, true);
                    App.IO.execute(new Runnable() {
                        @Override public void run() {
                            final String err = org.grove.guard.fw.Setup.setWebProtection(MainActivity.this, on);
                            runOnUiThread(new Runnable() {
                                @Override public void run() {
                                    if (err != null) Ui.toast(MainActivity.this, err);
                                    if (on && !new java.io.File(Sigs.dir(MainActivity.this), Sigs.DOMAINS).exists() && Sigs.networkOk(MainActivity.this, true)) update();
                                    App.MAIN.postDelayed(new Runnable() { @Override public void run() { show(); } }, 800);
                                }
                            });
                        }
                    });
                }
            };
            if (on) Ui.confirm(this, "Turn on Web protection?", "Grove Guard reads the address bar of Firefox and other browsers and warns you about dangerous sites. "
                    + "Nothing it reads is stored or sent anywhere. Shizuku switches it on for you.", "Turn on", go);
            else go.run();
            return;
        }
        if (LinkGuardService.enabledInSettings(this)) {
            Ui.confirm(this, "Turn off Web protection?", "Android turns accessibility services off in its own settings. Find Grove Guard web protection there and switch it off."
                    + (Prefs.on(this, Prefs.REALTIME, false) ? "\n\nRealtime scanning will keep running as a background service." : ""), "Open settings", new Runnable() {
                @Override public void run() { openAccessibility(); }
            });
            return;
        }
        Ui.dialog(this).setTitle("Turn on Web protection")
                .setMessage("Grove Guard reads the address bar of Firefox and other browsers, and warns you (or goes back) when a site is on its list of "
                        + "dangerous domains. Nothing it reads is stored or sent anywhere.\n\nOn the next screen, tap “Grove Guard web protection” and switch it on. "
                        + "Some phones ask you to allow restricted settings first (App info → ⋮ → Allow restricted settings).")
                .setPositiveButton("Continue", new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) {
                        Prefs.set(MainActivity.this, Prefs.WEB, true);
                        if (!new java.io.File(Sigs.dir(MainActivity.this), Sigs.DOMAINS).exists() && Sigs.networkOk(MainActivity.this, true)) update();
                        openAccessibility();
                    }
                })
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    private void openAccessibility() {
        try { startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)); } catch (Exception e) { Ui.toast(this, "Open Android Settings > Accessibility"); }
    }

    // ---------------------------------------------------------------- Activity

    private void buildActivity(LinearLayout col) {
        col.addView(pageHeader(this, "Activity", "What Grove Guard has been doing"));
        List<Events.Event> ev = Events.all();
        LinearLayout c = Ui.card(this);
        if (ev.isEmpty()) {
            c.addView(Ui.text(this, "Nothing yet. Scans, updates, alerts and firewall changes will show up here.", 14, p.sub));
        }
        int n = 0;
        for (Events.Event e : ev) {
            if (n++ >= 150) break;
            if (n > 1) c.addView(Ui.divider(this));
            LinearLayout r = Ui.row(this);
            r.setGravity(Gravity.TOP);
            r.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
            int ic = R.drawable.ic_check, fg = p.primary, bg = p.container;
            switch (e.kind) {
                case Events.THREAT: ic = R.drawable.ic_bug; fg = p.danger; bg = p.dangerBg; break;
                case Events.WEB: ic = R.drawable.ic_globe; fg = p.danger; bg = p.dangerBg; break;
                case Events.ERROR: ic = R.drawable.ic_warning; fg = p.warn; bg = p.warnBg; break;
                case Events.FW: ic = R.drawable.ic_wall; break;
                case Events.DB: ic = R.drawable.ic_refresh; break;
                case Events.SCAN: ic = R.drawable.ic_search; break;
                default: ic = R.drawable.ic_check;
            }
            r.addView(Ui.badge(this, ic, fg, bg, 34));
            LinearLayout tx = Ui.col(this);
            tx.setPadding(Ui.dp(this, 12), 0, 0, 0);
            tx.addView(Ui.title(this, e.title, 15));
            if (!e.detail.isEmpty()) tx.addView(Ui.text(this, e.detail, 13, p.sub));
            TextView when = Ui.text(this, Events.ago(this, e.time), 12, p.sub);
            when.setAlpha(0.8f);
            tx.addView(when);
            r.addView(tx, Ui.lpW(1));
            c.addView(r);
        }
        col.addView(c);
        if (!ev.isEmpty()) {
            LinearLayout r = Ui.row(this);
            r.setGravity(Gravity.END);
            r.setPadding(Ui.dp(this, 16), Ui.dp(this, 4), Ui.dp(this, 16), 0);
            r.addView(Ui.button(this, "Clear", 2, new View.OnClickListener() {
                @Override public void onClick(View v) { Events.clear(); show(); }
            }));
            col.addView(r);
        }
    }

    /** Lays out chips in rows that wrap. */
    public static class FlowLayout extends LinearLayout {
        public FlowLayout(android.content.Context c) { super(c); }

        @Override protected void onMeasure(int wSpec, int hSpec) {
            int maxW = MeasureSpec.getSize(wSpec);
            int x = 0, y = 0, rowH = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View ch = getChildAt(i);
                measureChild(ch, MeasureSpec.makeMeasureSpec(maxW, MeasureSpec.AT_MOST), MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED));
                LayoutParams lp = (LayoutParams) ch.getLayoutParams();
                int w = ch.getMeasuredWidth() + lp.leftMargin + lp.rightMargin, h = ch.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
                if (x + w > maxW && x > 0) { x = 0; y += rowH; rowH = 0; }
                x += w;
                rowH = Math.max(rowH, h);
            }
            setMeasuredDimension(maxW, y + rowH);
        }

        @Override protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int maxW = r - l, x = 0, y = 0, rowH = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View ch = getChildAt(i);
                LayoutParams lp = (LayoutParams) ch.getLayoutParams();
                int w = ch.getMeasuredWidth() + lp.leftMargin + lp.rightMargin, h = ch.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
                if (x + w > maxW && x > 0) { x = 0; y += rowH; rowH = 0; }
                ch.layout(x + lp.leftMargin, y + lp.topMargin, x + lp.leftMargin + ch.getMeasuredWidth(), y + lp.topMargin + ch.getMeasuredHeight());
                x += w;
                rowH = Math.max(rowH, h);
            }
        }
    }
}
