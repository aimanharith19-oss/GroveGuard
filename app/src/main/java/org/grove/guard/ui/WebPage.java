/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.grove.guard.Events;
import org.grove.guard.MainActivity;
import org.grove.guard.Prefs;
import org.grove.guard.R;
import org.grove.guard.web.WebFilter;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

/** The web tab: ad/tracker/18+ blocking for Grove Launcher's browser, your own rules, the log, and the filter lists. */
public class WebPage {
    private final Activity a;
    private final Ui.Pal p;
    private String filter = "all";
    private int logScroll; // where you were in the log box (kept when new entries arrive)

    public WebPage(Activity a) { this.a = a; this.p = Ui.pal(a); }

    private void redraw() { ((MainActivity) a).recreateTab(); }

    public void build(LinearLayout col) {
        WebFilter.ensureLoaded(a);
        col.addView(MainActivity.pageHeader(a, "Web", "Ads, trackers, 18+ and dangerous sites — for Grove Browser, Grove Launcher's browser and the extension"));

        // status
        LinearLayout st = Ui.card(a);
        boolean on = WebFilter.enabled(a);
        st.addView(Ui.item(a, R.drawable.ic_globe, "Block ads & trackers", (WebFilter.busy() ? "Updating lists… · " : "")
                + String.format(java.util.Locale.getDefault(), "%,d filters active", WebFilter.activeRules())
                + " · updated " + Events.ago(a, WebFilter.lastUpdate(a)), on, new View.OnClickListener() {
            @Override public void onClick(View v) { Prefs.set(a, WebFilter.ENABLED, !WebFilter.enabled(a)); redraw(); }
        }));
        st.addView(Ui.item(a, R.drawable.ic_refresh, "Update lists now", "Lists also update by themselves every day", null, new View.OnClickListener() {
            @Override public void onClick(View v) { WebFilter.update(a, true); Ui.toast(a, "Updating filter lists…"); redraw(); }
        }));
        int adultN = WebFilter.adultSites(a);
        if (adultN != 0) st.addView(Ui.item(a, R.drawable.ic_shield, "18+ blocking", adultN > 0
                ? String.format(java.util.Locale.getDefault(), "Always on · %,d sites blocked, in Grove Browser, Grove Launcher and the linked extension", adultN)
                : "Switched on, but the list isn't downloaded yet — tap to download", null, new View.OnClickListener() {
            @Override public void onClick(View v) { WebFilter.update(a, true); Ui.toast(a, "Downloading lists…"); redraw(); }
        }));
        String code = org.grove.guard.web.ExtSync.code(a);
        long seen = org.grove.guard.web.ExtSync.lastReceived();
        boolean groveBrowser = false;
        try { a.getPackageManager().getPackageInfo(org.grove.guard.Trust.BROWSER, 0); groveBrowser = true; } catch (Exception ignored) { }
        if (groveBrowser) st.addView(Ui.item(a, R.drawable.ic_globe, "Grove Browser", code.isEmpty()
                ? "Installed · open it once and it links to Groveguard by itself"
                : "Linked by itself · follows this tab's settings" + ("Grove Browser".equals(org.grove.guard.web.ExtSync.lastBrowser()) && seen > 0 ? " · last contact " + Events.ago(a, seen) : ""), null, null));
        st.addView(Ui.item(a, R.drawable.ic_link, "Browser extension", code.isEmpty()
                ? "Not linked · install it in Firefox or Chromium, then link it in the history tab so this tab controls it"
                : "Linked (code " + code + ") · follows this tab's settings · " + (seen > 0 ? "last contact " + Events.ago(a, seen) : "not heard from yet since Groveguard started"),
                null, new View.OnClickListener() {
            @Override public void onClick(View v) { ((MainActivity) a).toggleWeb(); }
        }));
        col.addView(st);

        // your rules
        col.addView(Ui.section(a, "My rules"));
        LinearLayout mr = Ui.card(a);
        TextView note = Ui.text(a, "Your rules win over every list and cover sub-domains (blocking example.com also blocks ads.example.com).", 13, p.sub);
        mr.addView(note);
        final EditText field = Ui.field(a, "example.com", "");
        LinearLayout.LayoutParams flp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        flp.topMargin = Ui.dp(a, 8);
        mr.addView(field, flp);
        LinearLayout btns = Ui.row(a);
        btns.setPadding(0, Ui.dp(a, 8), 0, Ui.dp(a, 4));
        TextView blk = Ui.button(a, "Block", 0, new View.OnClickListener() {
            @Override public void onClick(View v) { add(field.getText().toString(), "block"); }
        });
        TextView alw = Ui.button(a, "Allow", 1, new View.OnClickListener() {
            @Override public void onClick(View v) { add(field.getText().toString(), "allow"); }
        });
        btns.addView(blk, new LinearLayout.LayoutParams(0, Ui.dp(a, 52), 1));
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(0, Ui.dp(a, 52), 1);
        alp.leftMargin = Ui.dp(a, 10);
        btns.addView(alw, alp);
        mr.addView(btns);
        for (final String h : WebFilter.myBlock(a)) mr.addView(ruleRow(h, "Blocked by you"));
        for (final String h : WebFilter.myAllow(a)) mr.addView(ruleRow(h, "Allowed by you"));
        for (final String h : new java.util.TreeSet<>(Prefs.set(a, WebFilter.PAUSED))) mr.addView(Ui.item(a, 0, h, "Paused · nothing blocked on this site · tap to resume", null,
                new View.OnClickListener() { @Override public void onClick(View v) { WebFilter.setPaused(a, h, false); redraw(); } }));
        col.addView(mr);

        // log
        col.addView(Ui.section(a, "Log"));
        LinearLayout lg = Ui.card(a);
        LinearLayout chips = new MainActivity.FlowLayout(a);
        String[] ids = {"all", "blocked", "allowed", "page"}, names = {"All", "Blocked", "Allowed", "Pages"};
        for (int i = 0; i < ids.length; i++) {
            final String id = ids[i];
            chips.addView(Ui.chip(a, names[i], id.equals(filter), new View.OnClickListener() {
                @Override public void onClick(View v) { filter = id; logScroll = 0; redraw(); }
            }));
        }
        chips.addView(Ui.chip(a, "Clear", false, new View.OnClickListener() {
            @Override public void onClick(View v) { WebFilter.clearLog(); redraw(); }
        }));
        lg.addView(chips);
        // the log scrolls inside its own box, so the rest of the tab stays short
        final android.widget.ScrollView box = new android.widget.ScrollView(a);
        box.setVerticalScrollBarEnabled(true);
        box.setScrollbarFadingEnabled(false);
        box.setOverScrollMode(View.OVER_SCROLL_NEVER);
        box.setOnTouchListener(new View.OnTouchListener() {
            @Override public boolean onTouch(View v, android.view.MotionEvent e) {
                // keep the page (and the tab swipe) from stealing the scroll while your finger is in the log
                if (e.getActionMasked() == android.view.MotionEvent.ACTION_DOWN || e.getActionMasked() == android.view.MotionEvent.ACTION_MOVE)
                    v.getParent().requestDisallowInterceptTouchEvent(true);
                return false;
            }
        });
        final LinearLayout inner = Ui.col(a);
        box.addView(inner);
        GradientDrawable bb = new GradientDrawable();
        bb.setColor(Ui.SUBTLE);
        bb.setStroke(Ui.dp(a, 1), Ui.STROKE);
        box.setBackground(new android.graphics.drawable.InsetDrawable(bb, Ui.dp(a, 1)));
        box.setPadding(Ui.dp(a, 8), Ui.dp(a, 4), Ui.dp(a, 8), Ui.dp(a, 4));
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                Math.round(a.getResources().getDisplayMetrics().heightPixels * 0.5f));
        blp.topMargin = Ui.dp(a, 8);
        box.setOnScrollChangeListener(new View.OnScrollChangeListener() {
            @Override public void onScrollChange(View v, int x, int y, int ox, int oy) { logScroll = y; }
        });
        List<WebFilter.Entry> log = WebFilter.log();
        int n = 0;
        DateFormat tf = DateFormat.getTimeInstance(DateFormat.MEDIUM);
        for (final WebFilter.Entry e : log) {
            if ("blocked".equals(filter) && !e.blocked) continue;
            if ("allowed".equals(filter) && e.blocked) continue;
            if ("page".equals(filter) && !"page".equals(e.type)) continue;
            if (++n > 500) break;
            String sub = tf.format(new Date(e.time)) + " · " + e.type + (e.page.isEmpty() ? "" : " on " + e.page) + (e.why.isEmpty() ? "" : " · " + e.why);
            LinearLayout r = Ui.item(a, 0, (e.blocked ? "✕ " : "✓ ") + e.host, sub, null, new View.OnClickListener() {
                @Override public void onClick(View v) { entryMenu(e); }
            });
            TextView title = (TextView) ((LinearLayout) r.getChildAt(0)).getChildAt(0);
            title.setText((e.blocked ? "✕ " : "✓ ") + e.host); // keep the real host spelling
            title.setTextSize(18);
            title.setTextColor(e.blocked ? p.danger : Ui.FG);
            inner.addView(r);
        }
        if (n == 0) {
            TextView empty = Ui.text(a, log.isEmpty() ? "Nothing yet. Pages and requests from Grove Browser (linked by itself), Grove Launcher's browser, and Firefox/Chromium once the extension is linked (history tab) show up here as you browse."
                    : "Nothing matches this filter.", 14, p.sub);
            empty.setPadding(Ui.dp(a, 4), Ui.dp(a, 12), Ui.dp(a, 4), Ui.dp(a, 12));
            inner.addView(empty);
        }
        {
            TextView cnt = Ui.text(a, String.format(java.util.Locale.getDefault(), "%,d shown of %,d saved · newest first · scroll inside the box", Math.min(n, 500), log.size()), 12, p.sub);
            cnt.setPadding(0, Ui.dp(a, 6), 0, 0);
            lg.addView(cnt);
            lg.addView(box, blp);
            final int keep = logScroll;
            if (keep > 0) box.post(new Runnable() { @Override public void run() { box.scrollTo(0, keep); } });
        }
        col.addView(lg);

        // filter lists
        col.addView(Ui.section(a, "Filter lists"));
        LinearLayout fl = Ui.card(a);
        String group = "";
        for (final WebFilter.ListInfo l : WebFilter.LISTS) {
            if (!l.group.equals(group)) {
                group = l.group;
                TextView g = Ui.text(a, group.toUpperCase(java.util.Locale.getDefault()), 12, p.sub);
                g.setPadding(0, Ui.dp(a, 12), 0, Ui.dp(a, 2));
                fl.addView(g);
            }
            boolean lo = WebFilter.listOn(a, l);
            long up = WebFilter.updated(a, l);
            String err = org.grove.guard.Prefs.str(a, "web_err_" + l.id, "");
            String sub = lo && up == 0 && !err.isEmpty() ? "Download failed — " + err + " · tap Update lists now" : up > 0 ? String.format(java.util.Locale.getDefault(), "%,d rules · ", WebFilter.ruleCount(a, l)) + Events.ago(a, up)
                    : lo ? "Not downloaded yet" : "Off";
            if (l.adult) { fl.addView(Ui.item(a, 0, l.name, "Always on · " + sub, null, null)); continue; }
            fl.addView(Ui.item(a, 0, l.name, sub, lo, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    boolean now = !WebFilter.listOn(a, l);
                    WebFilter.setList(a, l, now);
                    Ui.switchOf(v).setChecked(now);
                    if (now) Ui.toast(a, "Downloading " + l.name + "…");
                }
            }));
        }
        TextView lic = Ui.text(a, "Lists © their authors: uBlock Origin uAssets (GPL-3.0), EasyList/EasyPrivacy (CC BY-SA 3.0), AdGuard (CC BY-SA), "
                + "Peter Lowe, malware-filter (CC0), OISD, The Block List Project (Unlicense).", 12, p.sub);
        lic.setPadding(0, Ui.dp(a, 8), 0, 0);
        fl.addView(lic);
        col.addView(fl);
    }

    private View ruleRow(final String h, String label) {
        return Ui.item(a, 0, h, label + " · tap to remove", null, new View.OnClickListener() {
            @Override public void onClick(View v) { WebFilter.setRule(a, h, "none"); redraw(); }
        });
    }

    private void add(String site, String list) {
        if (site.trim().isEmpty()) { Ui.toast(a, "Type a site, e.g. example.com"); return; }
        WebFilter.setRule(a, site, list);
        redraw();
    }

    private void entryMenu(final WebFilter.Entry e) {
        final boolean b = WebFilter.myBlock(a).contains(e.host), al = WebFilter.myAllow(a).contains(e.host);
        final String pageSite = "page".equals(e.type) ? e.host : e.page;
        final boolean ps = !pageSite.isEmpty() && WebFilter.paused(a, pageSite);
        String[] items = {b ? "Remove from my block list" : "Always block " + e.host, al ? "Remove from my allow list" : "Always allow " + e.host,
                pageSite.isEmpty() ? "Pause on this site" : (ps ? "Resume on " : "Pause on ") + pageSite, "Copy address"};
        Ui.dialog(a).setTitle(e.host).setItems(items, new android.content.DialogInterface.OnClickListener() {
            @Override public void onClick(android.content.DialogInterface d, int w) {
                if (w == 0) WebFilter.setRule(a, e.host, b ? "none" : "block");
                else if (w == 1) WebFilter.setRule(a, e.host, al ? "none" : "allow");
                else if (w == 2 && !pageSite.isEmpty()) WebFilter.setPaused(a, pageSite, !ps);
                else if (w == 3) {
                    android.content.ClipboardManager cm = a.getSystemService(android.content.ClipboardManager.class);
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("address", e.url));
                    Ui.toast(a, "Copied");
                }
                redraw();
            }
        }).setNegativeButton(android.R.string.cancel, null).show();
    }
}
