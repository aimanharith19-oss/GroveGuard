# Grove Guard

Malware scanner, web protection and firewall for Android — part of the Grove family with
Canopy Launcher and Grove Vault.

Grove Guard is a rewrite of **Hypatia** 3.18 (Divested Computing Group / MaintainTeam), whose
development has stopped, with ShizuWall's firewall features built in. Licence: **AGPL-3.0-or-later**
(same as Hypatia). Package: `org.grove.guard` (installs alongside Hypatia; uninstall Hypatia yourself).

## What it does

**Protect tab**
- *Scan now* checks installed apps, your storage, SD cards/USB and (optionally) system folders against
  MaintainTeam's Hypatia signature databases (MD5 / SHA-1 / SHA-256, optional extended set).
- *Realtime scanning* checks every file written to your storage (Firefox downloads included) and every
  app you install or update. No notification of its own: it runs inside Web protection when that's on,
  otherwise as a background service whose notification category can be switched off. Quick Settings
  tile: **Realtime scan**.
- Threats list with *Look up* (VirusTotal, by fingerprint only), *Delete* / *Uninstall*, *Ignore*.
- Database updates automatically once a day on Wi-Fi (Hypatia only updated by hand).

**Web protection (Firefox and other browsers)**
- An accessibility service reads the browser's address bar and warns — or goes back automatically —
  when a site is on the dangerous-domain list (malware, phishing, trackers, ads).
  Firefox, Beta, Nightly, Focus/Klar, Fennec, IronFox, Iceraven, Mull, Tor Browser, Chrome, Brave,
  Vivaldi, Edge, Samsung Internet, DuckDuckGo, Opera, Kiwi, Cromite and others; a fallback finds the
  address bar on browsers/versions without view ids.
- **Share → Grove Guard** from Firefox: share a page/link to check its site, or a downloaded file to scan it.
- **Check with Grove Guard** in the text-selection menu.
- Sub-domains are matched against listed parent domains; you can allow sites.

**Firewall tab** (no VPN; needs Shizuku or root — like ShizuWall)
- On/off, *block the apps I pick* or *allow only the apps I pick*, search, system apps.
- Profiles (save, switch, update, delete), new-app blocking, re-apply after restart
  (Android clears the rules on reboot; Grove Guard re-applies them when Shizuku/root is back).
- Quick Settings tile: **Firewall**.
- ShizuWall-compatible automation (`shizuwall.CONTROL`, `shizuwall.PROFILE`, `shizuwall.APP_INSTALLED`),
  plus `org.grove.guard.REALTIME`, `.SCAN`, `.UPDATE`. Settings → Automation commands lists them.

**Canopy Launcher** reads status from `content://org.grove.guard.status/status` (one row: realtime,
web, db_loaded, signatures, db_updated, scanning, scan_progress, threats, last_threat, firewall,
firewall_wanted, firewall_mode, blocked, profile, backend, summary) and `/events` (latest 20 Activity
lines; visited-site names are withheld), and controls Grove Guard with the broadcasts above sent to
`org.grove.guard/.fw.AutomationReceiver`.

## What's new in 1.2 (security)
- **App lock**: fingerprint or the phone's screen lock (Android's own prompt) to open Grove Guard and to act on
  threat notifications; ask again every time or after 1/5/30 min; screenshots and the recents preview are hidden while on.
- **Only Grove Launcher can read status** (`content://org.grove.guard.status`), identified by Android and pinned
  to its signing certificate. It can also `call("checkUrl", url)` and `call("control", action, extras)`.
- **Automation needs a key**: broadcasts must carry `--es key <key>` (Settings → Security), or be switched to
  "nobody" / "any app".
- **No rollback**: a database signed earlier than the installed one (or dated in the future) is refused.
- HTTPS only with system CAs (no user-installed CAs), tapjacking protection, Quick Settings tiles need the phone unlocked.
- **Web protection covers Grove Launcher's built-in browser.**

## What's new in 1.1
- **Shizuku everywhere**: Settings → Shizuku shows the connection; *Set up with Shizuku* grants file access,
  alerts and battery exemption in one tap; Web protection switches on/off through Shizuku (no accessibility
  settings screen); *Scan now* can include **App data folders** (Android/data and obb, hidden from apps
  since Android 11) read through Shizuku.
- **Bigger buttons**: *Scan now* and *Update database* are full-width, with icons.
- **Firewall per network**: tap the "All networks" chip on a blocked app to block **mobile data only**
  (Android's metered firewall chain, Android 13+) or **Wi-Fi only** (switched automatically when you move
  between Wi-Fi and mobile data). Runs a small helper inside the Grove Guard APK as the Shizuku/root user
  (`app_process … org.grove.guard.fw.Helper`).
- **Background tab**: restrict apps from running in the background (`RUN_ANY_IN_BACKGROUND` /
  `RUN_IN_BACKGROUND` app-ops + restricted standby bucket), force-stop restricted apps, clear cached
  background processes.
- **Apps tab**: disable/enable, uninstall, remove system apps for your user (restorable from *Removed*),
  restore, force stop, clear data. The home screen, keyboard, system UI, Settings, Shizuku and other
  essentials are protected.
- Tabs: Protect · Firewall · Background · Apps · Activity; Settings is the gear at the top right.

## Bugs fixed from Hypatia 3.18
- Link scanner never worked in Firefox/most browsers: on-screen text was cast to `String`, which fails
  for styled text, so it was silently skipped; full addresses (`https://host/path`) never matched the
  host-name pattern; only the changed view was looked at.
- Database signatures were checked against the key file sent by the same server, matched only by the
  end of a 64-bit key ID — an empty key ID matched any key. Now the full fingerprint is pinned and the
  MaintainTeam key ships in the app.
- Failed/partial downloads replaced good databases (files were moved into place before the signature
  check). Now a file is only installed after it verifies.
- Crash at boot when realtime scanning autostarted (database sources needed the main screen open).
- Crash when a scan outlived its 10-minute wake lock, or an update its 3-minute one.
- Background scanner re-opened the app (or was blocked) whenever it logged something.
- Newly installed apps were never scanned (receiver did nothing; Android no longer delivers that
  broadcast to manifest receivers anyway).
- Folders created after realtime scanning started weren't watched.
- Shared links were rejected ("not a scannable file"); shared files were copied to cache and the
  streams never closed; the main screen opened twice; a global "cache" flag raced between scans.
- Asked for all-files access on every launch.
- Scans collected every path before starting and had no progress; directory loops weren't detected.

## Building
No Gradle needed: `./build.sh` uses aapt2, javac (Java 8), dx and uber-apk-signer from `../tools`
(see the script). `libs/bc-from-hypatia.jar` holds the Bouncy Castle (MIT) classes Hypatia 3.18
shipped, used for OpenPGP signature checks. The Guava Bloom filter format is read by an own
implementation (`scan/Bloom.java`).

## Credits
Hypatia — Divested Computing Group, MaintainTeam (AGPL-3.0). HypatiaDatabases — MaintainTeam.
ShizuWall — Ahmet Can Arslan (GPL-3.0; features modelled, no code copied). Shizuku-API — RikkaW (MIT;
protocol only). Bouncy Castle (MIT).
