/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.view.View;
import android.widget.LinearLayout;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.grove.guard.R;
import org.grove.guard.fw.Background;
import org.grove.guard.fw.Shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Background tab: stop apps from running when you're not using them. */
public class BackgroundPage extends AppListPage {
    private Set<String> restricted = new HashSet<>();
    private final Set<String> busy = new HashSet<>();

    public BackgroundPage(Activity a) { super(a); reload(); }

    @Override protected String title() { return "Background"; }

    @Override protected String subtitle() { return "Stop apps running when you're not using them"; }

    @Override protected List<Row> load() {
        PackageManager pm = a.getPackageManager();
        List<Row> rows = new ArrayList<>();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if (ai.packageName.equals(a.getPackageName()) || ai.uid < android.os.Process.FIRST_APPLICATION_UID) continue;
            Row r = new Row();
            r.pkg = ai.packageName;
            r.label = String.valueOf(pm.getApplicationLabel(ai));
            r.system = (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            rows.add(r);
        }
        Collections.sort(rows, new Comparator<Row>() { @Override public int compare(Row x, Row y) { return x.label.compareToIgnoreCase(y.label); } });
        if (Shell.backend(a) != null) restricted = Background.restricted(a);
        else restricted = Prefs.set(a, "bg_restricted");
        return rows;
    }

    @Override protected void buildTop(LinearLayout head) {
        LinearLayout c = Ui.card(a);
        c.addView(Ui.item(a, R.drawable.ic_stop, "Stop restricted apps now", restricted.size() + (restricted.size() == 1 ? " app restricted" : " apps restricted")
                + " · force-stops them", null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                final List<String> l = new ArrayList<>(restricted);
                run(new Job() { @Override public String go() { return Background.forceStop(a, l); } }, "Stopped " + l.size() + " apps");
            }
        }));
        c.addView(Ui.item(a, R.drawable.ic_refresh, "Clear background processes", "Closes every app that's only cached in memory", null, new View.OnClickListener() {
            @Override public void onClick(View v) { run(new Job() { @Override public String go() { return Background.killBackground(a); } }, "Background processes cleared"); }
        }));
        View stop = Ui.item(a, 0, "Also force-stop when restricting", "Otherwise the app stops the next time Android tidies up", Prefs.on(a, "bg_stop", true),
                new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        boolean on = !Prefs.on(a, "bg_stop", true);
                        Prefs.set(a, "bg_stop", on);
                        Ui.switchOf(v).setChecked(on);
                    }
                });
        c.addView(stop);
        LinearLayout chips = new org.grove.guard.MainActivity.FlowLayout(a);
        final boolean sys = Prefs.on(a, "bg_system", false);
        chips.addView(Ui.chip(a, "Show system apps", sys, new View.OnClickListener() {
            @Override public void onClick(View v) { Prefs.set(a, "bg_system", !sys); refreshHeader(); }
        }));
        c.addView(chips);
        head.addView(c);
    }

    @Override protected boolean include(Row r) { return !r.system || Prefs.on(a, "bg_system", false) || restricted.contains(r.pkg); }

    @Override protected String rowSub(Row r) {
        if (busy.contains(r.pkg)) return "Working…";
        if (restricted.contains(r.pkg)) return "Restricted · can't run in the background";
        return (r.system ? "System · " : "") + r.pkg;
    }

    @Override protected int rowSubColor(Row r) { return restricted.contains(r.pkg) ? p.primary : p.sub; }

    @Override protected Boolean rowSwitch(Row r) { return restricted.contains(r.pkg); }

    @Override protected String listHint() { return "Switched on = restricted. Restricted apps may show notifications late (messages, alarms)."; }

    @Override protected void onRowClick(final Row r) {
        if (Shell.backend(a) == null) { Ui.toast(a, "Connect Shizuku first"); return; }
        if (busy.contains(r.pkg)) return;
        final boolean restrict = !restricted.contains(r.pkg);
        if (restrict && !Prefs.on(a, "bg_warned", false)) {
            Prefs.set(a, "bg_warned", true);
            Ui.confirm(a, "Restrict " + r.label + "?", "It won't run in the background: no background syncing, jobs or alarms, and its notifications may arrive late "
                    + "until you open it. Don't restrict apps you rely on for messages or alarms.", "Restrict", new Runnable() {
                @Override public void run() { toggle(r, true); }
            });
            return;
        }
        toggle(r, restrict);
    }

    private void toggle(final Row r, final boolean restrict) {
        busy.add(r.pkg);
        refresh();
        final boolean stop = Prefs.on(a, "bg_stop", true);
        App.IO.execute(new Runnable() {
            @Override public void run() {
                final String err = Background.set(a, Collections.singletonList(r.pkg), restrict, stop);
                if (err == null) Events.add(Events.INFO, (restrict ? "Restricted in background: " : "Allowed in background: ") + r.label, r.pkg);
                a.runOnUiThread(new Runnable() {
                    @Override public void run() {
                        busy.remove(r.pkg);
                        if (err != null) Ui.toast(a, r.label + ": " + err);
                        else if (restrict) restricted.add(r.pkg); else restricted.remove(r.pkg);
                        refreshHeader();
                    }
                });
            }
        });
    }

    private interface Job { String go(); }

    private void run(final Job j, final String okMsg) {
        App.IO.execute(new Runnable() {
            @Override public void run() {
                final String err = j.go();
                a.runOnUiThread(new Runnable() { @Override public void run() { Ui.toast(a, err == null ? okMsg : err); } });
            }
        });
    }
}
