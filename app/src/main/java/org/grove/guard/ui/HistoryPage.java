/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.grove.guard.MainActivity;
import org.grove.guard.web.WebFilter;
import org.grove.guard.web.WebHistory;

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** The history tab: every website opened in Grove Launcher's browser and every link checked, blocked or not. */
public class HistoryPage {
    private final Activity a;
    private final Ui.Pal p;
    private String filter = "all", query = "";
    private int limit = 300;
    private List<WebHistory.Visit> all;
    private LinearLayout list;

    public HistoryPage(Activity a) { this.a = a; this.p = Ui.pal(a); }

    private void redraw() { ((MainActivity) a).recreateTab(); }

    public void build(LinearLayout col) {
        all = WebHistory.all(a);
        int blocked = 0;
        for (WebHistory.Visit v : all) if (v.blocked) blocked++;
        col.addView(MainActivity.pageHeader(a, "History", String.format(Locale.getDefault(),
                "%,d visits · %,d blocked — Grove Launcher, browser extension and checked links · kept only on this phone", all.size(), blocked)));

        LinearLayout top = Ui.card(a);
        final EditText search = Ui.field(a, "Search sites or addresses", query);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int af) { }
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) { }
            @Override public void afterTextChanged(Editable s) { query = s.toString().trim().toLowerCase(Locale.ROOT); limit = 300; fill(); }
        });
        top.addView(search);
        LinearLayout chips = new MainActivity.FlowLayout(a);
        chips.setPadding(0, Ui.dp(a, 8), 0, 0);
        String[] ids = {"all", "blocked", "allowed"}, names = {"All", "Blocked", "Allowed"};
        for (int i = 0; i < ids.length; i++) {
            final String id = ids[i];
            chips.addView(Ui.chip(a, names[i], id.equals(filter), new View.OnClickListener() {
                @Override public void onClick(View v) { filter = id; limit = 300; redraw(); }
            }));
        }
        chips.addView(Ui.chip(a, "Clear…", false, new View.OnClickListener() {
            @Override public void onClick(View v) { clearMenu(); }
        }));
        top.addView(chips);
        col.addView(top);

        final String code = org.grove.guard.web.ExtSync.code(a);
        LinearLayout ex = Ui.card(a);
        long last = org.grove.guard.web.ExtSync.lastReceived();
        ex.addView(Ui.item(a, org.grove.guard.R.drawable.ic_link, "Link browser extension", code.isEmpty()
                ? "Also show history from Firefox or Chromium with the Groveguard extension"
                : "Code " + code + (org.grove.guard.web.ExtSync.running() ? " · listening" : " · not listening")
                + (last > 0 ? " · last visit received " + org.grove.guard.Events.ago(a, last) : ""), null, new View.OnClickListener() {
            @Override public void onClick(View v) { linkMenu(); }
        }));
        col.addView(ex);

        list = Ui.col(a);
        col.addView(list);
        fill();
    }

    private void fill() {
        list.removeAllViews();
        DateFormat tf = DateFormat.getTimeInstance(DateFormat.SHORT), df = DateFormat.getDateInstance(DateFormat.FULL);
        Calendar cal = Calendar.getInstance();
        long today = startOfDay(cal, System.currentTimeMillis()), day = -1;
        LinearLayout card = null;
        int n = 0;
        boolean more = false;
        for (final WebHistory.Visit v : all) {
            if ("blocked".equals(filter) && !v.blocked) continue;
            if ("allowed".equals(filter) && v.blocked) continue;
            if (!query.isEmpty() && !v.url.toLowerCase(Locale.ROOT).contains(query) && !v.host.toLowerCase(Locale.ROOT).contains(query)) continue;
            if (n >= limit) { more = true; break; }
            n++;
            long d = startOfDay(cal, v.time);
            if (d != day || card == null) {
                day = d;
                String label = d == today ? "today" : d == today - 86400000L ? "yesterday" : df.format(new Date(d)).toLowerCase(Locale.getDefault());
                list.addView(Ui.section(a, label));
                card = Ui.card(a);
                list.addView(card);
            }
            String sub = tf.format(new Date(v.time)) + (v.app.isEmpty() ? "" : " · " + v.app) + (v.why.isEmpty() ? "" : " · " + v.why)
                    + (v.url.equals(v.host) ? "" : "\n" + (v.url.length() > 120 ? v.url.substring(0, 120) + "…" : v.url));
            LinearLayout r = Ui.item(a, 0, (v.blocked ? "✕ " : "✓ ") + v.host, sub, null, new View.OnClickListener() {
                @Override public void onClick(View x) { menu(v); }
            });
            TextView title = (TextView) ((LinearLayout) r.getChildAt(0)).getChildAt(0);
            title.setText((v.blocked ? "✕ " : "✓ ") + v.host);
            title.setTextSize(18);
            title.setTextColor(v.blocked ? p.danger : 0xFFFFFFFF);
            card.addView(r);
        }
        if (n == 0) {
            LinearLayout c = Ui.card(a);
            c.addView(Ui.text(a, all.isEmpty() ? "Nothing yet. Every website you open in Grove Launcher's browser, and every link you check, shows up here — blocked or not."
                    : "No visits match.", 14, p.sub));
            list.addView(c);
        }
        if (more) {
            TextView m = Ui.button(a, "Show more", 1, new View.OnClickListener() {
                @Override public void onClick(View v) { limit += 300; fill(); }
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(a, 56));
            lp.setMargins(Ui.dp(a, 16), Ui.dp(a, 12), Ui.dp(a, 16), 0);
            list.addView(m, lp);
        }
    }

    private static long startOfDay(Calendar cal, long t) {
        cal.setTimeInMillis(t);
        cal.set(Calendar.HOUR_OF_DAY, 0); cal.set(Calendar.MINUTE, 0); cal.set(Calendar.SECOND, 0); cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }

    private void menu(final WebHistory.Visit v) {
        final boolean b = WebFilter.myBlock(a).contains(v.host), al = WebFilter.myAllow(a).contains(v.host);
        String[] items = {"Open", b ? "Remove from my block list" : "Always block " + v.host, al ? "Remove from my allow list" : "Always allow " + v.host,
                "Copy address", "Delete from history"};
        Ui.dialog(a).setTitle(v.host).setItems(items, new DialogInterface.OnClickListener() {
            @Override public void onClick(DialogInterface d, int w) {
                if (w == 0) {
                    String u = v.url.contains("://") ? v.url : "https://" + v.url;
                    try { a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(u))); } catch (Exception e) { Ui.toast(a, "No browser found"); }
                    return;
                }
                if (w == 1) WebFilter.setRule(a, v.host, b ? "none" : "block");
                else if (w == 2) WebFilter.setRule(a, v.host, al ? "none" : "allow");
                else if (w == 3) {
                    android.content.ClipboardManager cm = a.getSystemService(android.content.ClipboardManager.class);
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("address", v.url));
                    Ui.toast(a, "Copied");
                    return;
                } else if (w == 4) { WebHistory.delete(a, v); }
                redraw();
            }
        }).setNegativeButton(android.R.string.cancel, null).show();
    }

    private void linkMenu() {
        String code = org.grove.guard.web.ExtSync.code(a);
        if (code.isEmpty()) code = org.grove.guard.web.ExtSync.newCode(a);
        final String fc = code;
        Ui.dialog(a).setTitle("link browser extension")
                .setMessage("In your browser, open the Groveguard extension › history, type this code under \"Groveguard app\" and tap link:\n\n"
                        + fc + "\n\nVisits are sent straight to this app on your phone (127.0.0.1 only, never over the internet). "
                        + "If Groveguard isn't running, the extension keeps them and sends them later.")
                .setPositiveButton("Copy code", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) {
                        android.content.ClipboardManager cm = a.getSystemService(android.content.ClipboardManager.class);
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("code", fc));
                        Ui.toast(a, "Copied");
                        redraw();
                    }
                })
                .setNeutralButton("Unlink", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { org.grove.guard.web.ExtSync.unlink(a); redraw(); }
                })
                .setNegativeButton("New code", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { org.grove.guard.web.ExtSync.newCode(a); linkMenu(); }
                }).show();
    }

    private void clearMenu() {
        final long[] ages = {3600000L, 86400000L, 7 * 86400000L, 30 * 86400000L, 0};
        String[] items = {"Last hour", "Older than 1 day", "Older than 7 days", "Older than 30 days", "Everything"};
        Ui.dialog(a).setTitle("clear history").setItems(items, new DialogInterface.OnClickListener() {
            @Override public void onClick(DialogInterface d, int w) {
                if (w == 0) {
                    long cut = System.currentTimeMillis() - ages[0];
                    for (WebHistory.Visit v : all) { if (v.time < cut) break; WebHistory.delete(a, v); }
                } else WebHistory.clear(a, ages[w]);
                Ui.toast(a, "History cleared");
                redraw();
            }
        }).setNegativeButton(android.R.string.cancel, null).show();
    }
}
