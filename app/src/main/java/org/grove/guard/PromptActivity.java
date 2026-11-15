/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import org.grove.guard.scan.Detect;
import org.grove.guard.ui.Ui;

import java.io.File;

/** Handles the buttons on a threat notification (look up, delete, uninstall, ignore). Not exported. */
public class PromptActivity extends Activity {
    public static final String LOOKUP = "org.grove.guard.LOOKUP", DELETE = "org.grove.guard.DELETE",
            UNINSTALL = "org.grove.guard.UNINSTALL", IGNORE = "org.grove.guard.IGNORE";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Detect.Threat t = Detect.find(String.valueOf(getIntent().getStringExtra("id")));
        String a = getIntent().getAction();
        if (t == null || a == null) { finish(); return; }
        if (org.grove.guard.ui.Lock.needsAuth(this)) {
            final Detect.Threat ft = t;
            final String fa = a;
            org.grove.guard.ui.Lock.authenticate(this, "Confirm to act on this threat", new org.grove.guard.ui.Lock.Result() {
                @Override public void done(boolean ok) { if (ok) act(ft, fa); else finish(); }
            });
            return;
        }
        act(t, a);
    }

    @Override protected void onActivityResult(int req, int res, android.content.Intent data) {
        if (!org.grove.guard.ui.Lock.onResult(req, res)) super.onActivityResult(req, res, data);
    }

    private void act(Detect.Threat t, String a) {
        Runnable done = new Runnable() { @Override public void run() { finish(); } };
        switch (a) {
            case LOOKUP: lookup(this, t, done); break;
            case DELETE: delete(this, t, done); break;
            case UNINSTALL: uninstall(this, t); finish(); break;
            case IGNORE: ignore(this, t); finish(); break;
            default: finish();
        }
    }

    public static void lookup(final Activity a, final Detect.Threat t, final Runnable after) {
        Ui.dialog(a).setTitle("Look up on VirusTotal?")
                .setMessage("Opens virustotal.com in your browser with this file's SHA-256 fingerprint (" + t.sha256.substring(0, 12)
                        + "…). Only the fingerprint is shared, not the file.")
                .setPositiveButton("Open", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) {
                        try { a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/file/" + t.sha256))); }
                        catch (Exception e) { Ui.toast(a, "No browser found"); }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override public void onDismiss(DialogInterface d) { if (after != null) after.run(); }
                }).show();
    }

    public static void delete(final Activity a, final Detect.Threat t, final Runnable after) {
        final File f = new File(t.path);
        Ui.dialog(a).setTitle("Delete this file?")
                .setMessage(t.name() + "\n\nThis can't be undone.")
                .setPositiveButton("Delete", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) {
                        if (!f.exists() || f.delete()) {
                            Detect.remove(a, t.id);
                            Events.add(Events.THREAT, "Deleted " + t.name(), t.path);
                            Ui.toast(a, "Deleted");
                        } else Ui.toast(a, "Couldn't delete it — Groveguard may not have access to that folder");
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override public void onDismiss(DialogInterface d) { if (after != null) after.run(); }
                }).show();
    }

    public static void uninstall(Activity a, Detect.Threat t) {
        if (t.pkg == null) return;
        try {
            a.startActivity(new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + t.pkg)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (Exception e) { Ui.toast(a, "Couldn't open the uninstaller"); }
    }

    public static void ignore(Activity a, Detect.Threat t) {
        Detect.remove(a, t.id);
        Events.add(Events.THREAT, "Ignored " + (t.pkg != null ? Detect.appName(a, t.pkg) : t.name()), "Marked as not a threat");
        Ui.toast(a, "Ignored");
    }
}
