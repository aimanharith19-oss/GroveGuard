/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.os.Environment;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.Jobs;
import org.grove.guard.MainActivity;
import org.grove.guard.Prefs;
import org.grove.guard.R;
import org.grove.guard.fw.Firewall;
import org.grove.guard.scan.PgpVerify;
import org.grove.guard.scan.Sigs;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Settings tab. */
public class SettingsPage {
    private final Activity a;
    private final Ui.Pal p;
    private LinearLayout col;

    public SettingsPage(Activity a) { this.a = a; this.p = Ui.pal(a); }

    private void redraw() { if (a instanceof MainActivity) ((MainActivity) a).recreateTab(); }

    public void build(LinearLayout col) {
        this.col = col;
        col.addView(MainActivity.pageHeader(a, "Settings", "Back returns to where you were"));

        // ---------------- accent colour (Windows Phone accents, as in Grove Music)
        col.addView(Ui.section(a, "Accent colour"));
        LinearLayout grid = Ui.col(a);
        grid.setPadding(Ui.dp(a, 20), Ui.dp(a, 4), Ui.dp(a, 20), Ui.dp(a, 4));
        int curAccent = Ui.accent(a);
        LinearLayout rowL = null;
        for (int i = 0; i < Ui.ACCENTS.length; i++) {
            if (i % 5 == 0) { rowL = Ui.row(a); grid.addView(rowL); }
            final int color = Ui.ACCENTS[i];
            View sw = new View(a);
            android.graphics.drawable.GradientDrawable g = new android.graphics.drawable.GradientDrawable();
            g.setColor(color);
            if (color == curAccent) g.setStroke(Ui.dp(a, 3), 0xFFFFFFFF);
            // drawn inside the box, so no edge of the outline gets cut off
            sw.setBackground(new android.graphics.drawable.InsetDrawable(g, Ui.dp(a, 2)));
            sw.setContentDescription("Accent colour " + (i + 1));
            sw.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { Prefs.sp(a).edit().putInt("accent", color).apply(); a.recreate(); }
            });
            Ui.tilt(sw);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(Ui.dp(a, 56), Ui.dp(a, 56));
            lp.setMargins(0, 0, Ui.dp(a, 8), Ui.dp(a, 8));
            rowL.addView(sw, lp);
        }
        col.addView(grid);

        // ---------------- Shizuku
        col.addView(Ui.section(a, "Shizuku"));
        LinearLayout sz = Ui.card(a);
        final String backend = org.grove.guard.fw.Shell.backend(a);
        sz.addView(Ui.item(a, R.drawable.ic_bolt, backend == null ? "Not connected" : "shizuku".equals(backend) ? "Shizuku connected" : "Root connected",
                org.grove.guard.fw.Shell.status(a), null, new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        if (org.grove.guard.fw.Shizuku.running() && !org.grove.guard.fw.Shizuku.granted())
                            org.grove.guard.fw.Shizuku.requestPermission(new Runnable() { @Override public void run() { } });
                        else ((MainActivity) a).openTab(1);
                    }
                }));
        if (backend != null) sz.addView(Ui.item(a, 0, "Set up Groveguard with " + backend, "Grants file access, alerts and battery exemption in one go", null,
                new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        App.IO.execute(new Runnable() {
                            @Override public void run() {
                                final String err = org.grove.guard.fw.Setup.grantBasics(a);
                                a.runOnUiThread(new Runnable() { @Override public void run() { Ui.toast(a, err == null ? "Done" : err); redraw(); } });
                            }
                        });
                    }
                }));
        TextView szn = Ui.text(a, "With Shizuku, Groveguard runs the firewall, the Background and Apps tabs, and scans app data folders. If Groveguard isn't listed in Shizuku, stop and start Shizuku once.", 12, p.sub);
        szn.setPadding(Ui.dp(a, 4), Ui.dp(a, 6), Ui.dp(a, 4), 0);
        sz.addView(szn);
        col.addView(sz);

        // ---------------- database
        col.addView(Ui.section(a, "Signature database"));
        LinearLayout db = Ui.card(a);
        final Sigs.Source src = Sigs.source(a);
        db.addView(Ui.item(a, R.drawable.ic_refresh, "Database server", src.name, null, new View.OnClickListener() {
            @Override public void onClick(View v) { chooseSource(); }
        }));
        String fp = Sigs.fingerprint(a, src);
        db.addView(Ui.item(a, R.drawable.ic_shield_check, "Signing key", fp.isEmpty() ? "Not pinned yet — pinned on the first update" : group(fp), null, new View.OnClickListener() {
            @Override public void onClick(View v) { editFingerprint(); }
        }));
        db.addView(toggle(R.drawable.ic_search, "Extended signatures", "About 170 MB more to download and ~200 MB of memory. Finds more old malware.",
                Prefs.EXTENDED, false, new Runnable() {
                    @Override public void run() { Ui.toast(a, "Update the database to download the change"); }
                }));
        db.addView(toggle(R.drawable.ic_refresh, "Update automatically", "Once a day, on Wi-Fi, when the battery isn't low", Prefs.AUTO_UPDATE, true, new Runnable() {
            @Override public void run() { Jobs.schedule(a); }
        }));
        db.addView(toggle(0, "Auto-update on mobile data too", null, Prefs.AUTO_UPDATE_ANY_NET, false, new Runnable() {
            @Override public void run() { Jobs.schedule(a); }
        }));
        db.addView(toggle(0, "Download through Tor (Orbot)", "Hides which server you update from. Needs Orbot running.", Prefs.ONION, false, null));
        db.addView(Ui.item(a, 0, "Download everything again", "Deletes the database and fetches a fresh copy", null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                Ui.confirm(a, "Download everything again?", "About " + Sigs.downloadSizeMb(a) + " MB.", "Download", new Runnable() {
                    @Override public void run() {
                        File[] fs = Sigs.dir(a).listFiles();
                        if (fs != null) for (File f : fs) if (!f.getName().equals("gpg.key")) //noinspection ResultOfMethodCallIgnored
                            f.delete();
                        Sigs.md5 = null; Sigs.sha1 = null; Sigs.sha256 = null; Sigs.md5x = null; Sigs.domains = null;
                        Sigs.update(a, true, null);
                        redraw();
                    }
                });
            }
        }));
        db.addView(Ui.item(a, 0, "Test the scanner", "Writes three harmless test files to your storage. Realtime scanning (or a scan) should flag them.", null,
                new View.OnClickListener() {
                    @Override public void onClick(View v) { writeTestFiles(); }
                }));
        col.addView(db);

        // ---------------- web
        col.addView(Ui.section(a, "Web protection"));
        LinearLayout web = Ui.card(a);
        web.addView(Ui.item(a, R.drawable.ic_globe, "Browser extension", "Save the Firefox or Chromium extension and see how to install it", null,
                new View.OnClickListener() { @Override public void onClick(View v) { ((MainActivity) a).toggleWeb(); } }));
        final Set<String> allowed = Prefs.set(a, Prefs.WEB_ALLOW);
        web.addView(Ui.item(a, 0, "Allowed sites", allowed.isEmpty() ? "None" : allowed.size() + (allowed.size() == 1 ? " site" : " sites"), null, new View.OnClickListener() {
            @Override public void onClick(View v) { editAllowed(); }
        }));
        TextView wn = Ui.text(a, "Groveguard has no accessibility service, so banking apps don't flag it. "
                + "\u201CAllowed sites\u201D apply to link checks in the app; the extension keeps its own list. You can also share any page or link to Groveguard, "
                + "or select text and choose \u201CCheck with Groveguard\u201D. Grove Launcher's browser asks Groveguard directly.", 12, p.sub);
        wn.setPadding(Ui.dp(a, 4), Ui.dp(a, 6), Ui.dp(a, 4), 0);
        web.addView(wn);
        col.addView(web);

        // ---------------- firewall
        col.addView(Ui.section(a, "Firewall"));
        LinearLayout fw = Ui.card(a);
        fw.addView(toggle(R.drawable.ic_wall, "Block new apps", "In block mode, apps you install are blocked until you untick them (allow-list mode always does this)",
                Prefs.FW_NEW_APPS, false, null));
        fw.addView(toggle(R.drawable.ic_refresh, "Turn back on after restart", "Android clears the rules on reboot. Re-apply them when Shizuku or root is available.",
                Prefs.FW_REAPPLY, true, null));
        fw.addView(Ui.item(a, 0, "Automation commands", "Copy-paste examples", null, new View.OnClickListener() {
            @Override public void onClick(View v) { automationHelp(); }
        }));
        col.addView(fw);

        // ---------------- VirusTotal
        col.addView(Ui.section(a, "VirusTotal"));
        LinearLayout vt = Ui.card(a);
        final boolean hasKey = org.grove.guard.scan.VirusTotal.configured(a);
        vt.addView(Ui.item(a, R.drawable.ic_search, "API key", hasKey ? "Set · " + Prefs.sp(a).getInt("vt_used", 0) + " lookups used today (500 a day)"
                : "Free key from virustotal.com (sign up, then your profile \u2192 API key)", null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                Ui.input(a, "VirusTotal API key", "Only file fingerprints (SHA-256) are sent to VirusTotal, never the files. Leave empty to turn it off.",
                        "64-character key", Prefs.str(a, org.grove.guard.scan.VirusTotal.KEY, ""), new Ui.Cb<String>() {
                            @Override public void on(String k) { Prefs.set(a, org.grove.guard.scan.VirusTotal.KEY, k.trim()); redraw(); }
                        });
            }
        }));
        if (hasKey) {
            vt.addView(toggle(0, "Check new apps and downloads", "Apps you install and risky files saved to your storage (APK, ZIP, PDF, Office…) "
                    + "that the local database didn't flag", org.grove.guard.scan.VirusTotal.AUTO, true, null));
            final int[] mins = {1, 3, 5, 10};
            int cur = Prefs.sp(a).getInt(org.grove.guard.scan.VirusTotal.MIN, 3), mi = 1;
            for (int i = 0; i < mins.length; i++) if (mins[i] == cur) mi = i;
            final int fmi = mi;
            vt.addView(Ui.item(a, 0, "Treat as a threat when", cur + (cur == 1 ? " engine flags it" : " or more engines flag it"), null, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Ui.choose(a, "Threat when flagged by", new String[]{"1 engine (more false alarms)", "3 engines (recommended)", "5 engines", "10 engines"}, fmi,
                            new Ui.Cb<Integer>() { @Override public void on(Integer w) { Prefs.sp(a).edit().putInt(org.grove.guard.scan.VirusTotal.MIN, mins[w]).apply(); redraw(); } });
                }
            }));
        }
        col.addView(vt);

        // ---------------- security
        col.addView(Ui.section(a, "Security"));
        LinearLayout sec = Ui.card(a);
        final boolean lockOn = Lock.enabled(a);
        sec.addView(Ui.item(a, R.drawable.ic_shield_check, "App lock", lockOn ? "On · fingerprint or your screen lock" : "Ask for fingerprint or your screen lock to open Groveguard",
                lockOn, new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        if (!Lock.deviceSecure(a)) { Ui.toast(a, "Set a screen lock (PIN, pattern or password) in Android settings first"); return; }
                        // confirm it's you before turning it on or off
                        Lock.authenticate(a, lockOn ? "Turn off the app lock" : "Turn on the app lock", new Lock.Result() {
                            @Override public void done(boolean ok) {
                                if (!ok) return;
                                Prefs.set(a, Lock.KEY, !lockOn);
                                if (a instanceof MainActivity) ((MainActivity) a).secureWindow();
                                redraw();
                            }
                        });
                    }
                }));
        if (lockOn) {
            final int[] secs = {0, 60, 300, 1800};
            final String[] names = {"Every time", "After 1 minute", "After 5 minutes", "After 30 minutes"};
            int cur = Prefs.sp(a).getInt(Lock.TIMEOUT, 0), idx = 0;
            for (int i = 0; i < secs.length; i++) if (secs[i] == cur) idx = i;
            final int fidx = idx;
            sec.addView(Ui.item(a, 0, "Ask again", names[idx] + " after leaving the app", null, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Ui.choose(a, "Ask again", names, fidx, new Ui.Cb<Integer>() {
                        @Override public void on(Integer w) { Prefs.sp(a).edit().putInt(Lock.TIMEOUT, secs[w]).apply(); redraw(); }
                    });
                }
            }));
        }
        final String mode = org.grove.guard.Trust.mode(a);
        String modeName = "off".equals(mode) ? "Nobody (Grove Launcher still works)" : "any".equals(mode) ? "Any app (not recommended)" : "Apps that send the key";
        sec.addView(Ui.item(a, R.drawable.ic_link, "Other apps can control Groveguard", modeName, null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                final String[] ids = {"key", "off", "any"};
                String[] n = {"Apps that send the key (Tasker, adb)", "Nobody — only Grove Launcher", "Any app, no key (not recommended)"};
                int i = "off".equals(mode) ? 1 : "any".equals(mode) ? 2 : 0;
                Ui.choose(a, "Control by other apps", n, i, new Ui.Cb<Integer>() {
                    @Override public void on(Integer w) { Prefs.set(a, org.grove.guard.Trust.CONTROL, ids[w]); redraw(); }
                });
            }
        }));
        if ("key".equals(mode)) sec.addView(Ui.item(a, 0, "Automation key", "Tap to show, copy or change. Send it as the extra \u201Ckey\u201D.", null, new View.OnClickListener() {
            @Override public void onClick(View v) { showKey(); }
        }));
        sec.addView(Ui.item(a, 0, "Grove Launcher", org.grove.guard.Trust.launcherPinned(a)
                ? "Trusted · its signing certificate is pinned. Tap to forget (e.g. after reinstalling it with a new key)."
                : "Will be trusted the first time it connects", null, new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!org.grove.guard.Trust.launcherPinned(a)) return;
                Ui.confirm(a, "Forget Grove Launcher?", "It's trusted again (and re-pinned) the next time it connects.", "Forget", new Runnable() {
                    @Override public void run() { org.grove.guard.Trust.forgetLauncher(a); redraw(); }
                });
            }
        }));
        TextView sn = Ui.text(a, "Always on: databases must be signed by the pinned key and can't be swapped for older ones; HTTPS only, with the phone's "
                + "built-in certificates; taps are ignored while another app draws over Groveguard; only Grove Launcher can read its status.", 12, p.sub);
        sn.setPadding(Ui.dp(a, 4), Ui.dp(a, 6), Ui.dp(a, 4), 0);
        sec.addView(sn);
        col.addView(sec);

        // ---------------- launcher
        col.addView(Ui.section(a, "Grove Launcher"));
        LinearLayout cl = Ui.card(a);
        cl.addView(Ui.item(a, R.drawable.ic_apps, "Status on the launcher feed", "Grove Launcher shows realtime scanning, Web protection, threats and the firewall, controls them, and checks websites in its browser "
                + "through a private connection only it is allowed to use. Nothing is shared with other apps.", null, null));
        col.addView(cl);

        // ---------------- about
        col.addView(Ui.section(a, "About"));
        LinearLayout ab = Ui.card(a);
        String ver = "";
        try { PackageInfo pi = a.getPackageManager().getPackageInfo(a.getPackageName(), 0); ver = pi.versionName; } catch (Exception ignored) { }
        ab.addView(Ui.item(a, R.drawable.ic_shield, "Groveguard " + ver, "Free software under the GNU Affero General Public License v3 or later", null, new View.OnClickListener() {
            @Override public void onClick(View v) { licences(); }
        }));
        col.addView(ab);
    }

    private View toggle(int icon, String title, String sub, final String key, final boolean def, final Runnable after) {
        return Ui.item(a, icon, title, sub, Prefs.on(a, key, def), new View.OnClickListener() {
            @Override public void onClick(View v) {
                boolean on = !Prefs.on(a, key, def);
                Prefs.set(a, key, on);
                Ui.switchOf(v).setChecked(on);
                if (after != null) after.run();
            }
        });
    }

    private static String group(String fp) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < fp.length(); i += 4) { if (i > 0) b.append(i == 20 ? "  " : " "); b.append(fp, i, Math.min(fp.length(), i + 4)); }
        return b.toString();
    }

    private void chooseSource() {
        if (Sigs.busy()) { Ui.toast(a, "Wait for the current update to finish"); return; }
        final List<String> names = new ArrayList<>();
        for (Sigs.Source s : Sigs.SOURCES) names.add(s.name);
        names.add("Custom server…");
        String cur = Prefs.str(a, Prefs.SOURCE, "mt_mirror");
        int idx = names.size() - 1;
        for (int i = 0; i < Sigs.SOURCES.length; i++) if (Sigs.SOURCES[i].id.equals(cur)) idx = i;
        Ui.choose(a, "Database server", names.toArray(new String[0]), idx, new Ui.Cb<Integer>() {
            @Override public void on(Integer w) {
                if (w < Sigs.SOURCES.length) {
                    Prefs.set(a, Prefs.SOURCE, Sigs.SOURCES[w].id);
                    afterSourceChange();
                } else {
                    Ui.input(a, "Custom server", "Address of a folder with Hypatia-format databases (must start with https://)", "https://…/",
                            Prefs.str(a, Prefs.CUSTOM_URL, ""), new Ui.Cb<String>() {
                                @Override public void on(String url) {
                                    if (!url.startsWith("https://")) { Ui.toast(a, "The address must start with https://"); return; }
                                    Prefs.set(a, Prefs.CUSTOM_URL, url.endsWith("/") ? url : url + "/");
                                    Prefs.set(a, Prefs.SOURCE, "custom");
                                    editFingerprint();
                                }
                            });
                }
            }
        });
    }

    private void afterSourceChange() {
        Sigs.md5 = null; Sigs.sha1 = null; Sigs.sha256 = null; Sigs.md5x = null; Sigs.domains = null;
        // force fresh files from the new server
        File[] fs = Sigs.dir(a).listFiles();
        if (fs != null) for (File f : fs) //noinspection ResultOfMethodCallIgnored
            f.delete();
        Events.add(Events.DB, "Database server changed", Sigs.source(a).name);
        if (Sigs.networkOk(a, true)) Sigs.update(a, true, null);
        redraw();
    }

    private void editFingerprint() {
        Sigs.Source s = Sigs.source(a);
        if (!"custom".equals(s.id)) {
            Ui.dialog(a).setTitle("Signing key").setMessage(s.name + " databases must be signed by the key with fingerprint\n\n" + group(Sigs.fingerprint(a, s).isEmpty()
                    ? "(pinned on first update)" : Sigs.fingerprint(a, s)) + "\n\nGroveguard refuses any database that isn't.")
                    .setPositiveButton(android.R.string.ok, null).show();
            return;
        }
        Ui.input(a, "Signing key fingerprint", "The full 40-character fingerprint of the key that signs this server's databases (from its operator).",
                "B26E FC8E …", Prefs.str(a, Prefs.CUSTOM_FP, ""), new Ui.Cb<String>() {
                    @Override public void on(String v) {
                        String n = PgpVerify.normFingerprint(v);
                        if (n.isEmpty()) { Ui.toast(a, "That isn't a 40-character fingerprint"); return; }
                        Prefs.set(a, Prefs.CUSTOM_FP, n);
                        afterSourceChange();
                    }
                });
    }

    private void editAllowed() {
        final List<String> l = new ArrayList<>(Prefs.set(a, Prefs.WEB_ALLOW));
        if (l.isEmpty()) { Ui.toast(a, "No allowed sites"); return; }
        java.util.Collections.sort(l);
        Ui.dialog(a).setTitle("Tap a site to remove it").setItems(l.toArray(new String[0]), new android.content.DialogInterface.OnClickListener() {
            @Override public void onClick(android.content.DialogInterface d, int w) {
                Set<String> s = Prefs.set(a, Prefs.WEB_ALLOW);
                s.remove(l.get(w));
                Prefs.set(a, Prefs.WEB_ALLOW, s);
                redraw();
            }
        }).setNegativeButton(android.R.string.cancel, null).show();
    }

    private void writeTestFiles() {
        if (!App.hasFileAccess(a)) { Ui.toast(a, "Allow file access first"); return; }
        int r = new java.util.Random().nextInt(100000);
        String[] content = {"HypatiaHypatiaHypatia-MD5", "HypatiaHypatiaHypatia-SHA1", "HypatiaHypatiaHypatia-SHA256"};
        String[] names = {"MD5", "SHA1", "SHA256"};
        File dir = new File(Environment.getExternalStorageDirectory(), "Download");
        int ok = 0;
        for (int i = 0; i < 3; i++) {
            try (FileOutputStream o = new FileOutputStream(new File(dir, "GroveGuard-" + names[i] + "-Test-" + r + ".txt"))) {
                o.write(content[i].getBytes(StandardCharsets.UTF_8));
                ok++;
            } catch (Exception ignored) { }
        }
        Ui.toast(a, ok == 3 ? "Wrote 3 test files to Download — expect 3 alerts" : "Couldn't write the test files");
    }

    private void automationHelp() {
        String pkg = a.getPackageName();
        String n = " -n " + pkg + "/.fw.AutomationReceiver --es key " + org.grove.guard.Trust.key(a);
        String s = "Firewall on / off:\nadb shell am broadcast -a shizuwall.CONTROL" + n + " --ez state true\n\n"
                + "Block apps:\nadb shell am broadcast -a shizuwall.CONTROL" + n + " --ez state true --es apps \"com.example.app,com.other.app\"\n\n"
                + "Switch profile:\nadb shell am broadcast -a shizuwall.PROFILE" + n + " --es profile \"Work\" --ez force_enable true\n\n"
                + "Report an install:\nadb shell am broadcast -a shizuwall.APP_INSTALLED" + n + " --es apps \"com.example.app\"\n\n"
                + "Realtime scanning on / off:\nadb shell am broadcast -a org.grove.guard.REALTIME" + n + " --ez state true\n\n"
                + "Scan now:\nadb shell am broadcast -a org.grove.guard.SCAN" + n + "\n\n"
                + "Update database:\nadb shell am broadcast -a org.grove.guard.UPDATE" + n + "\n\n"
                + "In Tasker or MacroDroid use “Send intent”: target Broadcast Receiver, package " + pkg + ", class " + pkg + ".fw.AutomationReceiver, "
                + "with the same action and extras. ShizuWall automations work after changing the package and class.";
        TextView tv = Ui.text(a, s, 13, p.text);
        tv.setTextIsSelectable(true);
        tv.setPadding(Ui.dp(a, 24), Ui.dp(a, 12), Ui.dp(a, 24), Ui.dp(a, 8));
        ScrollView sv = new ScrollView(a);
        sv.addView(tv);
        Ui.dialog(a).setTitle("Automation").setView(sv).setPositiveButton(android.R.string.ok, null).show();
    }

    private void showKey() {
        final String k = org.grove.guard.Trust.key(a);
        Ui.dialog(a).setTitle("Automation key").setMessage(k + "\n\nAnyone with this key can control Groveguard. Change it if it leaks.")
                .setPositiveButton("Copy", new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) {
                        android.content.ClipboardManager cm = a.getSystemService(android.content.ClipboardManager.class);
                        android.content.ClipData cd = android.content.ClipData.newPlainText("Groveguard key", k);
                        if (android.os.Build.VERSION.SDK_INT >= 33) {
                            android.os.PersistableBundle pb = new android.os.PersistableBundle();
                            pb.putBoolean("android.content.extra.IS_SENSITIVE", true); // hidden from the clipboard preview
                            cd.getDescription().setExtras(pb);
                        }
                        cm.setPrimaryClip(cd);
                    }
                })
                .setNeutralButton("Change", new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) { org.grove.guard.Trust.newKey(a); Ui.toast(a, "New key made"); }
                })
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    private void licences() {
        String s = "Groveguard is a rewrite of Hypatia, the realtime malware scanner by Divested Computing Group (2017–2018) and "
                + "MaintainTeam (2025), licensed AGPL-3.0-or-later; Groveguard is released under the same licence. The source code comes with every release.\n\n"
                + "Signature databases: MaintainTeam HypatiaDatabases (built from ClamAV, ESET, MalwareBazaar, ThreatFox, VirusShare, "
                + "Amnesty International, Echap stalkerware indicators, Nex and others). Website list: Divested hosts list.\n\n"
                + "The firewall's features are modelled on ShizuWall by Ahmet Can Arslan (GPL-3.0); no ShizuWall code is included.\n\n"
                + "Shizuku support speaks the protocol from Shizuku-API (MIT, © 2021 RikkaW); only a small compatible class is included.\n\n"
                + "Signature checks use Bouncy Castle (MIT licence, © Legion of the Bouncy Castle Inc.).\n\n"
                + "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of "
                + "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.";
        TextView tv = Ui.text(a, s, 13, p.text);
        tv.setPadding(Ui.dp(a, 24), Ui.dp(a, 12), Ui.dp(a, 24), Ui.dp(a, 8));
        ScrollView sv = new ScrollView(a);
        sv.addView(tv);
        Ui.dialog(a).setTitle("Licences & credits").setView(sv).setPositiveButton(android.R.string.ok, null).show();
    }
}
