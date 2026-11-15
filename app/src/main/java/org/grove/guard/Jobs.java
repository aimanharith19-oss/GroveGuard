/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;

import org.grove.guard.fw.Firewall;
import org.grove.guard.scan.Sigs;

/**
 * Background jobs: the daily database update (Hypatia only updated when you pressed the button) and a check for
 * apps installed while nothing was running, for the firewall's new-app rule.
 */
public class Jobs extends JobService {
    private static final int UPDATE = 1, PACKAGES = 2;

    public static void schedule(Context c) {
        JobScheduler js = c.getSystemService(JobScheduler.class);
        ComponentName cn = new ComponentName(c, Jobs.class);
        if (Prefs.on(c, Prefs.AUTO_UPDATE, true)) {
            js.schedule(new JobInfo.Builder(UPDATE, cn)
                    .setPeriodic(24 * 60 * 60 * 1000L, 6 * 60 * 60 * 1000L)
                    .setRequiredNetworkType(Prefs.on(c, Prefs.AUTO_UPDATE_ANY_NET, false) ? JobInfo.NETWORK_TYPE_ANY : JobInfo.NETWORK_TYPE_UNMETERED)
                    .setRequiresBatteryNotLow(true)
                    .setPersisted(true)
                    .build());
        } else js.cancel(UPDATE);
        if (Firewall.wanted(c)) {
            js.schedule(new JobInfo.Builder(PACKAGES, cn).setPeriodic(15 * 60 * 1000L).setPersisted(true).build());
        } else js.cancel(PACKAGES);
    }

    @Override public boolean onStartJob(final JobParameters p) {
        if (p.getJobId() == PACKAGES) {
            App.IO.execute(new Runnable() {
                @Override public void run() {
                    try { Firewall.checkChangedPackages(getApplicationContext()); } catch (Exception ignored) { }
                    jobFinished(p, false);
                }
            });
            return true;
        }
        if (p.getJobId() == UPDATE) {
            if (Sigs.updating()) return false;
            Sigs.update(this, false, null);
            org.grove.guard.web.WebFilter.update(this, false); // web filter lists, daily
            // the update runs on its own; give it time, then finish the job
            App.MAIN.postDelayed(new Runnable() {
                int waited;
                @Override public void run() {
                    if (Sigs.updating() && waited++ < 120) App.MAIN.postDelayed(this, 10000);
                    else jobFinished(p, false);
                }
            }, 10000);
            return true;
        }
        return false;
    }

    @Override public boolean onStopJob(JobParameters p) { return false; }
}
