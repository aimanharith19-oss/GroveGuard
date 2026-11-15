/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.LruCache;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;

import org.grove.guard.App;
import org.grove.guard.MainActivity;
import org.grove.guard.Prefs;
import org.grove.guard.R;
import org.grove.guard.fw.Firewall;
import org.grove.guard.fw.Shell;
import org.grove.guard.fw.Shizuku;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Firewall tab: backend, on/off, mode, profiles and the app list. */
public class FirewallPage {
    private final Activity a;
    private final Ui.Pal p;
    private final ListView list;
    private final LinearLayout head;
    private final Adapter adapter = new Adapter();
    private final List<AppRow> all = new ArrayList<>();
    private final List<AppRow> shown = new ArrayList<>();
    private final LruCache<String, Drawable> icons = new LruCache<>(120);
    private String query = "";
    private boolean loading;

    static final class AppRow { String pkg, label; boolean system; }

    public FirewallPage(Activity a) {
        this.a = a;
        this.p = Ui.pal(a);
        list = new ListView(a);
        list.setDivider(null);
        list.setSelector(android.R.color.transparent);
        list.setClipToPadding(false);
        list.setPadding(0, 0, 0, Ui.dp(a, 24));
        head = Ui.col(a);
        list.addHeaderView(head, null, false);
        list.setAdapter(adapter);
        loadApps();
    }

    public View view() { return list; }

    private void loadApps() {
        if (loading) return;
        loading = true;
        final boolean sys = Prefs.on(a, Prefs.FW_SYSTEM, false);
        App.IO.execute(new Runnable() {
            @Override public void run() {
                PackageManager pm = a.getPackageManager();
                final List<AppRow> rows = new ArrayList<>();
                for (ApplicationInfo ai : Firewall.candidates(a, sys)) {
                    AppRow r = new AppRow();
                    r.pkg = ai.packageName;
                    r.label = String.valueOf(pm.getApplicationLabel(ai));
                    r.system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                    rows.add(r);
                }
                Collections.sort(rows, new Comparator<AppRow>() {
                    @Override public int compare(AppRow x, AppRow y) { return x.label.compareToIgnoreCase(y.label); }
                });
                a.runOnUiThread(new Runnable() {
                    @Override public void run() {
                        all.clear();
                        all.addAll(rows);
                        loading = false;
                        filter();
                        refreshHeader();
                    }
                });
            }
        });
    }

    private void filter() {
        shown.clear();
        String q = query.toLowerCase(Locale.ROOT);
        Set<String> sel = Firewall.selected(a);
        List<AppRow> selFirst = new ArrayList<>(), rest = new ArrayList<>();
        for (AppRow r : all) {
            if (!q.isEmpty() && !r.label.toLowerCase(Locale.ROOT).contains(q) && !r.pkg.toLowerCase(Locale.ROOT).contains(q)) continue;
            (sel.contains(r.pkg) ? selFirst : rest).add(r);
        }
        shown.addAll(selFirst);
        shown.addAll(rest);
        adapter.notifyDataSetChanged();
    }

    // ---------------------------------------------------------------- header

    private EditText search;

    public void refreshHeader() {
        boolean hadFocus = search != null && search.hasFocus();
        head.removeAllViews();
        head.addView(MainActivity.pageHeader(a, "Firewall", "Cut apps off the internet — no VPN needed"));

        // backend
        final String backend = Shell.backend(a);
        LinearLayout bc = Ui.card(a);
        View item = Ui.item(a, R.drawable.ic_bolt, backend == null ? "Connect Shizuku or root" : "shizuku".equals(backend) ? "Shizuku connected" : "Root connected",
                Shell.status(a), null, new View.OnClickListener() {
                    @Override public void onClick(View v) { backendAction(); }
                });
        bc.addView(item);
        LinearLayout chips = new MainActivity.FlowLayout(a);
        final String pref = Prefs.str(a, Prefs.FW_BACKEND, "auto");
        String[] ids = {"auto", "shizuku", "root"}, labels = {"Automatic", "Shizuku only", "Root only"};
        for (int i = 0; i < ids.length; i++) {
            final String id = ids[i];
            chips.addView(Ui.chip(a, labels[i], id.equals(pref), new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Prefs.set(a, Prefs.FW_BACKEND, id);
                    if (!"shizuku".equals(id) && !Shell.rootKnownOk() && "root".equals(id)) probeRoot();
                    refreshHeader();
                }
            }));
        }
        bc.addView(chips);
        head.addView(bc);

        // main switch
        LinearLayout mc = Ui.card(a);
        boolean active = Firewall.active(a), wanted = Firewall.wanted(a);
        final View sw = Ui.item(a, R.drawable.ic_wall, "Firewall", Firewall.summary(a), active, new View.OnClickListener() {
            @Override public void onClick(View v) {
                final boolean on = !Firewall.active(a);
                Ui.subOf(v).setText(on ? "Turning on…" : "Turning off…");
                Firewall.setEnabled(a, on, null, new Firewall.Done() {
                    @Override public void done(boolean ok, String message) {
                        if (!ok) Ui.dialog(a).setTitle(on ? "Couldn't turn the firewall on" : "Couldn't turn it off").setMessage(message)
                                .setPositiveButton(android.R.string.ok, null).show();
                        refreshHeader();
                    }
                });
            }
        });
        mc.addView(sw);
        if (wanted && !active) {
            TextView w = Ui.text(a, "Android cleared the rules when the phone restarted. They come back by themselves once Shizuku or root is available.", 13, p.warn);
            w.setPadding(Ui.dp(a, 4), 0, Ui.dp(a, 4), Ui.dp(a, 6));
            mc.addView(w);
        }
        mc.addView(Ui.divider(a));
        TextView ml = Ui.text(a, "Mode", 13, p.sub);
        ml.setPadding(Ui.dp(a, 4), Ui.dp(a, 6), 0, 0);
        mc.addView(ml);
        LinearLayout modes = new MainActivity.FlowLayout(a);
        final boolean allow = Firewall.MODE_ALLOW.equals(Firewall.mode(a));
        modes.addView(Ui.chip(a, "Block the apps I pick", !allow, new View.OnClickListener() {
            @Override public void onClick(View v) { if (allow) { Firewall.setMode(a, Firewall.MODE_BLOCK); filter(); refreshHeader(); } }
        }));
        modes.addView(Ui.chip(a, "Allow only the apps I pick", allow, new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (allow) return;
                Ui.confirm(a, "Allow-list mode", "Every app that isn't ticked loses internet access, including ones you install later — until you tick them. "
                        + "Make sure your browser, messaging apps and Groveguard's updates still work after switching.", "Switch", new Runnable() {
                    @Override public void run() { Firewall.setMode(a, Firewall.MODE_ALLOW); filter(); refreshHeader(); }
                });
            }
        }));
        mc.addView(modes);

        // profiles
        TextView pl = Ui.text(a, "Profiles", 13, p.sub);
        pl.setPadding(Ui.dp(a, 4), Ui.dp(a, 10), 0, 0);
        mc.addView(pl);
        LinearLayout prof = new MainActivity.FlowLayout(a);
        String activeId = Prefs.str(a, Prefs.FW_PROFILE, "");
        for (final Firewall.Profile pr : Firewall.profiles(a)) {
            TextView c = Ui.chip(a, pr.name, pr.id.equals(activeId), new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Firewall.applyProfile(a, pr, false, new Firewall.Done() {
                        @Override public void done(boolean ok, String message) { if (!ok) Ui.toast(a, message); filter(); refreshHeader(); }
                    });
                }
            });
            c.setOnLongClickListener(new View.OnLongClickListener() {
                @Override public boolean onLongClick(View v) { profileMenu(pr); return true; }
            });
            prof.addView(c);
        }
        prof.addView(Ui.chip(a, "+ Save current", false, new View.OnClickListener() {
            @Override public void onClick(View v) {
                Ui.input(a, "Save as profile", "Saves the mode and the ticked apps. Switch profiles here, from Canopy, or with automation.", "Name, e.g. Work",
                        Firewall.activeProfileName(a) == null ? "" : Firewall.activeProfileName(a), new Ui.Cb<String>() {
                            @Override public void on(String s) { if (!s.isEmpty()) { Firewall.saveProfile(a, s); refreshHeader(); } }
                        });
            }
        }));
        mc.addView(prof);
        head.addView(mc);

        // list controls
        LinearLayout lc = Ui.row(a);
        lc.setPadding(Ui.dp(a, 16), Ui.dp(a, 10), Ui.dp(a, 16), Ui.dp(a, 4));
        search = Ui.field(a, "Search apps", query);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int af) { }
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) { }
            @Override public void afterTextChanged(Editable s) { query = s.toString().trim(); filter(); }
        });
        lc.addView(search, Ui.lpW(1));
        final boolean sys = Prefs.on(a, Prefs.FW_SYSTEM, false);
        TextView sc = Ui.chip(a, "System", sys, new View.OnClickListener() {
            @Override public void onClick(View v) { Prefs.set(a, Prefs.FW_SYSTEM, !sys); loadApps(); refreshHeader(); }
        });
        ((LinearLayout.LayoutParams) sc.getLayoutParams()).leftMargin = Ui.dp(a, 8);
        lc.addView(sc);
        head.addView(lc);
        int nSel = Firewall.selected(a).size();
        TextView hint = Ui.text(a, loading ? "Loading apps…" : (allow ? "Ticked apps are allowed online · " : "Ticked apps are blocked — tap \u201CAll networks\u201D to block only Wi-Fi or mobile data · ") + nSel + " ticked · " + all.size() + " apps use the internet", 12, p.sub);
        hint.setPadding(Ui.dp(a, 30), Ui.dp(a, 4), Ui.dp(a, 30), Ui.dp(a, 6));
        head.addView(hint);
        if (hadFocus) { search.requestFocus(); search.setSelection(search.getText().length()); }
    }

    private void backendAction() {
        String pref = Prefs.str(a, Prefs.FW_BACKEND, "auto");
        if (!"root".equals(pref) && Shizuku.running()) {
            if (!Shizuku.granted()) Shizuku.requestPermission(new Runnable() { @Override public void run() { } });
            else Ui.toast(a, "Shizuku is ready");
            return;
        }
        if ("root".equals(pref)) { probeRoot(); return; }
        if (Shizuku.installed(a)) {
            Intent i = a.getPackageManager().getLaunchIntentForPackage(Shizuku.MANAGER);
            if (i != null) a.startActivity(i);
            Ui.toast(a, "Start Shizuku, then come back");
        } else {
            Ui.dialog(a).setTitle("Get Shizuku")
                    .setMessage("The firewall runs Android's own network commands, which need Shizuku (works with Wireless debugging, no root) or root.\n\n"
                            + "After installing, start Shizuku and allow Groveguard when asked. If you have root, pick “Root only” instead.")
                    .setPositiveButton("Download Shizuku", new android.content.DialogInterface.OnClickListener() {
                        @Override public void onClick(android.content.DialogInterface d, int w) {
                            try { a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://shizuku.rikka.app/download/"))); } catch (Exception ignored) { }
                        }
                    })
                    .setNegativeButton(android.R.string.cancel, null).show();
        }
    }

    private void probeRoot() {
        Ui.toast(a, "Asking for root…");
        App.IO.execute(new Runnable() {
            @Override public void run() {
                final boolean ok = Shell.probeRoot(a);
                a.runOnUiThread(new Runnable() {
                    @Override public void run() {
                        Ui.toast(a, ok ? "Root access granted" : "Root access denied");
                        if (ok) Firewall.onBackendReady(a);
                        refreshHeader();
                    }
                });
            }
        });
    }

    private void profileMenu(final Firewall.Profile pr) {
        Ui.dialog(a).setTitle(pr.name)
                .setItems(new String[]{"Turn firewall on with this profile", "Update with current apps", "Automation command", "Delete"},
                        new android.content.DialogInterface.OnClickListener() {
                            @Override public void onClick(android.content.DialogInterface d, int w) {
                                if (w == 0) Firewall.applyProfile(a, pr, true, new Firewall.Done() {
                                    @Override public void done(boolean ok, String m) { if (!ok) Ui.toast(a, m); filter(); refreshHeader(); }
                                });
                                else if (w == 1) { Firewall.saveProfile(a, pr.name); refreshHeader(); }
                                else if (w == 2) {
                                    String cmd = "adb shell am broadcast -a shizuwall.PROFILE -n " + a.getPackageName()
                                            + "/.fw.AutomationReceiver --es profile_id " + pr.id + " --ez force_enable true";
                                    TextView tv = Ui.text(a, cmd, 13, p.text);
                                    tv.setTextIsSelectable(true);
                                    tv.setPadding(Ui.dp(a, 24), Ui.dp(a, 12), Ui.dp(a, 24), 0);
                                    Ui.dialog(a).setTitle("Automation").setView(tv).setPositiveButton(android.R.string.ok, null).show();
                                } else Ui.confirm(a, "Delete profile?", pr.name, "Delete", new Runnable() {
                                    @Override public void run() { Firewall.deleteProfile(a, pr.id); refreshHeader(); }
                                });
                            }
                        }).show();
    }

    // ---------------------------------------------------------------- list

    private final class Adapter extends BaseAdapter {
        @Override public int getCount() { return shown.size(); }
        @Override public Object getItem(int i) { return shown.get(i); }
        @Override public long getItemId(int i) { return i; }

        @Override public View getView(int pos, View v, ViewGroup parent) {
            Holder h;
            if (v == null) {
                h = new Holder();
                LinearLayout r = Ui.row(a);
                r.setPadding(Ui.dp(a, 24), Ui.dp(a, 8), Ui.dp(a, 20), Ui.dp(a, 8));
                r.setMinimumHeight(Ui.dp(a, 60));
                h.icon = new ImageView(a);
                r.addView(h.icon, new LinearLayout.LayoutParams(Ui.dp(a, 40), Ui.dp(a, 40)));
                LinearLayout t = Ui.col(a);
                t.setPadding(Ui.dp(a, 14), 0, Ui.dp(a, 8), 0);
                h.label = Ui.title(a, "", 15);
                h.label.setSingleLine();
                h.pkg = Ui.text(a, "", 12, p.sub);
                h.pkg.setSingleLine();
                t.addView(h.label);
                t.addView(h.pkg);
                r.addView(t, Ui.lpW(1));
                h.net = Ui.chip(a, "", true, null);
                h.net.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12);
                h.net.setPadding(Ui.dp(a, 10), Ui.dp(a, 5), Ui.dp(a, 10), Ui.dp(a, 5));
                r.addView(h.net);
                h.sw = new Switch(a);
                h.sw.setClickable(false);
                h.sw.setFocusable(false);
                Ui.tintSwitch(a, h.sw);
                r.addView(h.sw);
                r.setBackground(Ui.ripple(a, 0, 0));
                r.setLayoutParams(new AbsListView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                v = r;
                v.setTag(h);
            } else h = (Holder) v.getTag();
            final AppRow row = shown.get(pos);
            h.pkgName = row.pkg;
            h.label.setText(row.label);
            boolean sel = Firewall.selected(a).contains(row.pkg);
            boolean allow = Firewall.MODE_ALLOW.equals(Firewall.mode(a));
            boolean blockedNow = Firewall.active(a) && Firewall.applied(a).contains(row.pkg);
            boolean mobileNow = Firewall.mobileBlockedNow(a, row.pkg);
            final String net = Firewall.netMode(a, row.pkg);
            String state = blockedNow ? (Firewall.NET_WIFI.equals(net) ? "No internet on Wi-Fi · " : "No internet · ") : mobileNow ? "No mobile data · "
                    : (sel && !allow && Firewall.NET_WIFI.equals(net) && Firewall.active(a)) ? "Allowed on mobile data · " : "";
            h.pkg.setText(state + (row.system ? "System · " : "") + row.pkg);
            h.pkg.setTextColor(blockedNow || mobileNow ? p.danger : p.sub);
            boolean showNet = sel && !allow;
            h.net.setVisibility(showNet ? View.VISIBLE : View.GONE);
            h.net.setText(Firewall.NET_MOBILE.equals(net) ? "Mobile data" : Firewall.NET_WIFI.equals(net) ? "Wi-Fi" : "All networks");
            h.net.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View view) { chooseNet(row.pkg, row.label, net); } });
            h.sw.setChecked(sel);
            Drawable d = icons.get(row.pkg);
            if (d != null) h.icon.setImageDrawable(d);
            else {
                h.icon.setImageDrawable(null);
                final Holder fh = h;
                App.IO.execute(new Runnable() {
                    @Override public void run() {
                        try {
                            final Drawable ic = a.getPackageManager().getApplicationIcon(row.pkg);
                            icons.put(row.pkg, ic);
                            a.runOnUiThread(new Runnable() { @Override public void run() { if (row.pkg.equals(fh.pkgName)) fh.icon.setImageDrawable(ic); } });
                        } catch (Exception ignored) { }
                    }
                });
            }
            v.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) {
                    boolean now = !Firewall.selected(a).contains(row.pkg);
                    Firewall.setSelected(a, row.pkg, now, new Firewall.Done() {
                        @Override public void done(boolean ok, String message) {
                            if (!ok) Ui.toast(a, row.label + ": " + message);
                            adapter.notifyDataSetChanged();
                        }
                    });
                    notifyDataSetChanged();
                }
            });
            if (allow && !sel && Firewall.active(a)) h.label.setAlpha(0.7f); else h.label.setAlpha(1f);
            return v;
        }
    }

    private static final class Holder { ImageView icon; TextView label, pkg, net; Switch sw; String pkgName; }

    private void chooseNet(final String pkg, final String label, String cur) {
        final String[] ids = {Firewall.NET_ALL, Firewall.NET_MOBILE, Firewall.NET_WIFI};
        String[] names = {"All networks", Firewall.mobileSupported() ? "Mobile data only" : "Mobile data only (needs Android 13+)", "Wi-Fi only"};
        int idx = Firewall.NET_MOBILE.equals(cur) ? 1 : Firewall.NET_WIFI.equals(cur) ? 2 : 0;
        Ui.choose(a, "Block " + label + " on", names, idx, new Ui.Cb<Integer>() {
            @Override public void on(Integer w) {
                if (w == 1 && !Firewall.mobileSupported()) { Ui.toast(a, "Blocking only mobile data needs Android 13 or newer"); return; }
                Firewall.setNetMode(a, pkg, ids[w], new Firewall.Done() {
                    @Override public void done(boolean ok, String message) {
                        if (!ok) Ui.dialog(a).setTitle(label).setMessage(message).setPositiveButton(android.R.string.ok, null).show();
                        adapter.notifyDataSetChanged();
                    }
                });
                adapter.notifyDataSetChanged();
            }
        });
    }
}
