/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.provider.Settings;
import android.view.View;
import android.widget.LinearLayout;

import org.grove.guard.App;
import org.grove.guard.MainActivity;
import org.grove.guard.Prefs;
import org.grove.guard.fw.Apps;
import org.grove.guard.fw.Shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Apps tab: disable, uninstall (system apps too, reversibly) and restore. */
public class AppsPage extends AppListPage {
    private static final String[] FILTERS = {"installed", "system", "disabled", "removed"};
    private static final String[] FILTER_LABELS = {"My apps", "System apps", "Disabled", "Removed"};
    private Set<String> essential = new HashSet<>();
    private final Set<String> busy = new HashSet<>();

    public AppsPage(Activity a) { super(a); reload(); }

    private String filterId() { return Prefs.str(a, "apps_filter", "installed"); }

    @Override protected String title() { return "Apps"; }

    @Override protected String subtitle() { return "Disable or remove apps — system apps too"; }

    @Override protected List<Row> load() {
        PackageManager pm = a.getPackageManager();
        List<Row> rows = new ArrayList<>();
        for (PackageInfo pi : pm.getInstalledPackages(PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null) continue;
            Row r = new Row();
            r.pkg = pi.packageName;
            r.label = String.valueOf(pm.getApplicationLabel(ai));
            r.system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            r.removed = (ai.flags & ApplicationInfo.FLAG_INSTALLED) == 0;
            r.disabled = !r.removed && !ai.enabled;
            rows.add(r);
        }
        Collections.sort(rows, new Comparator<Row>() { @Override public int compare(Row x, Row y) { return x.label.compareToIgnoreCase(y.label); } });
        essential = Apps.essential(a);
        return rows;
    }

    @Override protected void buildTop(LinearLayout head) {
        LinearLayout c = Ui.card(a);
        LinearLayout chips = new MainActivity.FlowLayout(a);
        String cur = filterId();
        for (int i = 0; i < FILTERS.length; i++) {
            final String id = FILTERS[i];
            int n = 0;
            for (Row r : all) if (matches(r, id)) n++;
            chips.addView(Ui.chip(a, FILTER_LABELS[i] + (loading ? "" : " · " + n), id.equals(cur), new View.OnClickListener() {
                @Override public void onClick(View v) { Prefs.set(a, "apps_filter", id); refreshHeader(); }
            }));
        }
        c.addView(chips);
        android.widget.TextView t = Ui.text(a, "Removing a system app only removes it for you — it stays on the phone and can be restored from “Removed”. "
                + "Apps the phone needs to work are protected.", 12, p.sub);
        t.setPadding(Ui.dp(a, 4), Ui.dp(a, 6), Ui.dp(a, 4), 0);
        c.addView(t);
        head.addView(c);
    }

    private static boolean matches(Row r, String f) {
        switch (f) {
            case "system": return r.system && !r.removed;
            case "disabled": return r.disabled;
            case "removed": return r.removed;
            default: return !r.system && !r.removed;
        }
    }

    @Override protected boolean include(Row r) { return matches(r, filterId()); }

    @Override protected String rowSub(Row r) {
        if (busy.contains(r.pkg)) return "Working…";
        String s = r.removed ? "Removed for you · tap to restore" : r.disabled ? "Disabled" : essential.contains(r.pkg) ? "Protected" : r.system ? "System" : "";
        return s.isEmpty() ? r.pkg : s + " · " + r.pkg;
    }

    @Override protected int rowSubColor(Row r) { return r.removed || r.disabled ? p.warn : p.sub; }

    @Override protected Boolean rowSwitch(Row r) { return null; }

    @Override protected String listHint() { return shownCount() + " apps · tap one for options"; }

    @Override protected void onRowClick(final Row r) {
        final List<String> labels = new ArrayList<>();
        final List<String> actions = new ArrayList<>();
        boolean prot = essential.contains(r.pkg);
        if (r.removed) { labels.add("Restore"); actions.add(Apps.RESTORE); }
        else {
            if (r.disabled) { labels.add("Enable"); actions.add(Apps.ENABLE); }
            else if (!prot) { labels.add("Disable"); actions.add(Apps.DISABLE); }
            if (!prot) { labels.add(r.system ? "Remove for me (restorable)" : "Uninstall"); actions.add(Apps.UNINSTALL); }
            if (!r.disabled) { labels.add("Force stop"); actions.add(Apps.STOP); }
            if (!prot) { labels.add("Clear data"); actions.add(Apps.CLEAR); }
            labels.add("App info"); actions.add("info");
        }
        Ui.dialog(a).setTitle(r.label + (prot ? " (protected)" : ""))
                .setItems(labels.toArray(new String[0]), new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { confirm(r, actions.get(w)); }
                }).setNegativeButton(android.R.string.cancel, null).show();
    }

    private void confirm(final Row r, final String action) {
        if ("info".equals(action)) {
            try { a.startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + r.pkg))); } catch (Exception ignored) { }
            return;
        }
        if (Shell.backend(a) == null) { Ui.toast(a, "Connect Shizuku first"); return; }
        String title = null, msg = null, yes = null;
        if (Apps.DISABLE.equals(action)) {
            title = "Disable " + r.label + "?";
            msg = "It disappears and can't run until you enable it again." + (r.system ? "\n\nIt's a system app: disabling the wrong one can break features. Look it up if unsure." : "");
            yes = "Disable";
        } else if (Apps.UNINSTALL.equals(action)) {
            title = (r.system ? "Remove " : "Uninstall ") + r.label + "?";
            msg = r.system ? "It's removed for you (data kept) and can be restored from “Removed”. Removing the wrong system app can break features or "
                    + "stop the phone booting properly — look it up if unsure." : "The app and its data are deleted.";
            yes = r.system ? "Remove" : "Uninstall";
        } else if (Apps.CLEAR.equals(action)) {
            title = "Clear all data of " + r.label + "?";
            msg = "Its accounts, settings and files are deleted, as if it was just installed.";
            yes = "Clear";
        }
        if (title == null) { go(r, action); return; }
        Ui.confirm(a, title, msg, yes, new Runnable() { @Override public void run() { go(r, action); } });
    }

    private void go(final Row r, final String action) {
        busy.add(r.pkg);
        refresh();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                final String err = Apps.run(a, action, r.pkg, r.system);
                a.runOnUiThread(new Runnable() {
                    @Override public void run() {
                        busy.remove(r.pkg);
                        if (err != null) { Ui.dialog(a).setTitle(r.label).setMessage(err).setPositiveButton(android.R.string.ok, null).show(); refresh(); }
                        else {
                            Ui.toast(a, "Done");
                            reload();
                        }
                    }
                });
            }
        });
    }
}
