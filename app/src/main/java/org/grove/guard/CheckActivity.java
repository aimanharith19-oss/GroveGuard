/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import org.grove.guard.scan.Scanner;
import org.grove.guard.scan.Sigs;
import org.grove.guard.scan.WebCheck;
import org.grove.guard.ui.Ui;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * "Share → Grove Guard" and "Check with Grove Guard" (text selection menu). Works from Firefox: share a page or a
 * link to check its website, or share a downloaded file to scan it. The result shows right here, in a card,
 * instead of throwing you into the main screen (Hypatia rejected shared links as "not a scannable file", opened
 * the main screen twice, and left copies of shared files in its cache).
 */
public class CheckActivity extends Activity {
    private LinearLayout body;
    private Ui.Pal p;
    private String pendingText;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        p = Ui.pal(this);
        FrameLayout root = new FrameLayout(this);
        root.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { finish(); } });
        LinearLayout card = Ui.col(this);
        card.setBackground(Ui.round(p.card, Ui.dp(this, 28)));
        card.setPadding(Ui.dp(this, 22), Ui.dp(this, 20), Ui.dp(this, 22), Ui.dp(this, 14));
        card.setClickable(true);
        LinearLayout head = Ui.row(this);
        head.addView(Ui.badge(this, R.drawable.ic_shield_check, p.primary, p.container, 40));
        TextView t = Ui.title(this, "Grove Guard", 18);
        t.setPadding(Ui.dp(this, 12), 0, 0, 0);
        head.addView(t, Ui.lpW(1));
        card.addView(head);
        body = Ui.col(this);
        body.setPadding(0, Ui.dp(this, 12), 0, 0);
        ScrollView sv = new ScrollView(this);
        sv.addView(body);
        card.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM);
        lp.setMargins(Ui.dp(this, 12), 0, Ui.dp(this, 12), Ui.dp(this, 24));
        root.addView(card, lp);
        setContentView(root);
        handle(getIntent());
    }

    private void handle(Intent i) {
        String a = i.getAction();
        if (Intent.ACTION_PROCESS_TEXT.equals(a)) {
            CharSequence s = i.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT);
            checkText(s == null ? "" : s.toString());
            return;
        }
        if (Intent.ACTION_SEND.equals(a) || Intent.ACTION_SEND_MULTIPLE.equals(a)) {
            List<Uri> uris = new ArrayList<>();
            if (Intent.ACTION_SEND.equals(a)) {
                Uri u = i.getParcelableExtra(Intent.EXTRA_STREAM);
                if (u != null) uris.add(u);
            } else {
                ArrayList<Uri> l = i.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
                if (l != null) uris.addAll(l);
            }
            if (!uris.isEmpty()) { scanFiles(uris); return; }
            CharSequence text = i.getCharSequenceExtra(Intent.EXTRA_TEXT);
            String subject = i.getStringExtra(Intent.EXTRA_SUBJECT);
            checkText((text == null ? "" : text.toString()) + (subject == null ? "" : " " + subject));
            return;
        }
        if (Intent.ACTION_VIEW.equals(a) && i.getData() != null) { checkText(i.getData().toString()); return; }
        message("Nothing to check.");
        closeButton();
    }

    // ---------------------------------------------------------------- links

    private void checkText(final String text) {
        body.removeAllViews();
        final List<String> hosts = WebCheck.hosts(text);
        if (hosts.isEmpty()) {
            message("No web address found in what you shared.");
            closeButton();
            return;
        }
        if (!Sigs.domainsLoaded()) {
            boolean have = new java.io.File(Sigs.dir(this), Sigs.DOMAINS).exists();
            if (have || Prefs.on(this, Prefs.WEB, false) && Sigs.busy()) {
                busy("Loading the website list…");
                pendingText = text;
                App.IO.execute(new Runnable() {
                    @Override public void run() {
                        if (!Sigs.busy()) Sigs.loadNow(getApplicationContext());
                        else while (Sigs.busy()) try { Thread.sleep(300); } catch (InterruptedException e) { return; }
                        runOnUiThread(new Runnable() { @Override public void run() { if (!isFinishing()) showHosts(hosts); } });
                    }
                });
            } else {
                message("To check websites, Grove Guard needs its list of dangerous domains (about 14 MB, updated with the database).");
                body.addView(spaced(Ui.button(this, "Download the website list", 0, new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        Prefs.set(CheckActivity.this, Prefs.WEB, true);
                        busy("Downloading…");
                        Sigs.update(CheckActivity.this, true, null);
                        waitThenShow(hosts);
                    }
                })));
                closeButton();
            }
            return;
        }
        showHosts(hosts);
    }

    private void waitThenShow(final List<String> hosts) {
        App.IO.execute(new Runnable() {
            @Override public void run() {
                try { Thread.sleep(500); while (Sigs.busy()) Thread.sleep(300); } catch (InterruptedException e) { return; }
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        if (isFinishing()) return;
                        if (Sigs.domainsLoaded()) showHosts(hosts);
                        else { body.removeAllViews(); message("Couldn't download the website list. Check your connection and try again."); closeButton(); }
                    }
                });
            }
        });
    }

    private void showHosts(List<String> hosts) {
        body.removeAllViews();
        int bad = 0;
        final List<String> shown = hosts.size() > 8 ? hosts.subList(0, 8) : hosts;
        for (final String h : shown) {
            WebCheck.Hit hit = WebCheck.check(this, h);
            boolean allowed = Prefs.set(this, Prefs.WEB_ALLOW).contains(h);
            if (hit != null) bad++;
            LinearLayout r = Ui.row(this);
            r.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
            r.addView(Ui.badge(this, hit != null ? R.drawable.ic_warning : R.drawable.ic_check,
                    hit != null ? p.danger : p.primary, hit != null ? p.dangerBg : p.container, 36));
            LinearLayout tx = Ui.col(this);
            tx.setPadding(Ui.dp(this, 12), 0, 0, 0);
            TextView name = Ui.title(this, hit != null ? WebCheck.defang(h) : h, 16);
            tx.addView(name);
            String sub = hit != null ? "On the dangerous-domain list" + (hit.listed.equals(h) ? "" : " (as " + WebCheck.defang(hit.listed) + ")")
                    : allowed ? "You allowed this site" : "Not on the list";
            tx.addView(Ui.text(this, sub, 13, hit != null ? p.danger : p.sub));
            r.addView(tx, Ui.lpW(1));
            TextView more = Ui.button(this, "Look up", 2, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/domain/" + h))); }
                    catch (Exception e) { Ui.toast(CheckActivity.this, "No browser found"); }
                }
            });
            r.addView(more);
            body.addView(r);
        }
        TextView note = Ui.text(this, bad > 0
                ? "Don't enter passwords or payment details there. The list covers malware, phishing, trackers and ads, so some entries are just ad or tracking servers."
                : "Not being on the list doesn't prove a site is safe — it only means it isn't known to be bad.", 13, p.sub);
        note.setPadding(0, Ui.dp(this, 8), 0, 0);
        body.addView(note);
        Events.add(bad > 0 ? Events.WEB : Events.INFO, bad > 0 ? "Checked link: " + bad + " dangerous" : "Checked link: nothing found",
                shown.size() == 1 ? (bad > 0 ? WebCheck.defang(shown.get(0)) : shown.get(0)) : shown.size() + " sites");
        closeButton();
    }

    // ---------------------------------------------------------------- files

    private void scanFiles(final List<Uri> uris) {
        busy(uris.size() == 1 ? "Scanning the file…" : "Scanning " + uris.size() + " files…");
        App.IO.execute(new Runnable() {
            @Override public void run() {
                if (!Sigs.loaded()) Sigs.loadNow(getApplicationContext());
                final List<String[]> res = new ArrayList<>(); // name, verdict, sha256
                final boolean noDb = !Sigs.loaded();
                if (!noDb) for (Uri u : uris) {
                    String name = displayName(u);
                    try (InputStream in = getContentResolver().openInputStream(u)) {
                        if (in == null) throw new Exception("can't open");
                        Scanner.Hashes h = Scanner.hash(in);
                        String type = Scanner.match(h);
                        res.add(new String[]{name, type == null ? "" : type, h.sha256});
                        Events.add(type != null ? Events.THREAT : Events.SCAN, (type != null ? "Shared file is malware: " : "Shared file checked: ") + name,
                                type != null ? "Matched a " + type + " signature" : "No known malware");
                    } catch (Exception e) {
                        res.add(new String[]{name, null, null});
                    }
                }
                runOnUiThread(new Runnable() { @Override public void run() { if (!isFinishing()) showFiles(res, noDb); } });
            }
        });
    }

    private void showFiles(List<String[]> res, boolean noDb) {
        body.removeAllViews();
        if (noDb) {
            message("No signature database yet. Open Grove Guard and update the database first.");
            body.addView(spaced(Ui.button(this, "Open Grove Guard", 1, new View.OnClickListener() {
                @Override public void onClick(View v) { startActivity(new Intent(CheckActivity.this, MainActivity.class)); finish(); }
            })));
            closeButton();
            return;
        }
        for (final String[] r : res) {
            boolean err = r[1] == null, bad = !err && !r[1].isEmpty();
            LinearLayout row = Ui.row(this);
            row.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
            row.addView(Ui.badge(this, bad || err ? R.drawable.ic_warning : R.drawable.ic_check,
                    bad ? p.danger : err ? p.warn : p.primary, bad ? p.dangerBg : err ? p.warnBg : p.container, 36));
            LinearLayout tx = Ui.col(this);
            tx.setPadding(Ui.dp(this, 12), 0, 0, 0);
            TextView n = Ui.title(this, r[0], 16);
            n.setSingleLine();
            n.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
            tx.addView(n);
            tx.addView(Ui.text(this, err ? "Couldn't read this file" : bad ? "Known malware (" + r[1] + " signature match)" : "No known malware", 13, bad ? p.danger : p.sub));
            row.addView(tx, Ui.lpW(1));
            if (!err) row.addView(Ui.button(this, "Look up", 2, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/file/" + r[2]))); }
                    catch (Exception e) { Ui.toast(CheckActivity.this, "No browser found"); }
                }
            }));
            body.addView(row);
        }
        TextView note = Ui.text(this, "Shared files are read directly — no copy is kept.", 13, p.sub);
        note.setPadding(0, Ui.dp(this, 8), 0, 0);
        body.addView(note);
        closeButton();
    }

    private String displayName(Uri u) {
        try (Cursor c = getContentResolver().query(u, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (Exception ignored) { }
        String s = u.getLastPathSegment();
        return s == null ? "file" : s;
    }

    // ---------------------------------------------------------------- bits

    private void busy(String msg) {
        body.removeAllViews();
        LinearLayout r = Ui.row(this);
        r.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 18));
        ProgressBar pb = new ProgressBar(this);
        pb.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(p.primary));
        r.addView(pb, new LinearLayout.LayoutParams(Ui.dp(this, 32), Ui.dp(this, 32)));
        TextView t = Ui.text(this, msg, 15, p.text);
        t.setPadding(Ui.dp(this, 14), 0, 0, 0);
        r.addView(t);
        body.addView(r);
    }

    private void message(String s) {
        TextView t = Ui.text(this, s, 15, p.text);
        t.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 8));
        body.addView(t);
    }

    private View spaced(View v) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Ui.dp(this, 8);
        v.setLayoutParams(lp);
        return v;
    }

    private void closeButton() {
        LinearLayout r = Ui.row(this);
        r.setGravity(Gravity.END);
        r.setPadding(0, Ui.dp(this, 8), 0, 0);
        r.addView(Ui.button(this, "Open app", 2, new View.OnClickListener() {
            @Override public void onClick(View v) { startActivity(new Intent(CheckActivity.this, MainActivity.class).putExtra("tab", 4)); finish(); }
        }));
        r.addView(Ui.button(this, "Done", 1, new View.OnClickListener() { @Override public void onClick(View v) { finish(); } }));
        body.addView(r);
    }
}
