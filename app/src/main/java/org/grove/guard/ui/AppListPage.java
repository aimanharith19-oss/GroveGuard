/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.LruCache;
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
import org.grove.guard.R;
import org.grove.guard.fw.Shell;
import org.grove.guard.fw.Shizuku;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** A tab with a header and a searchable list of apps (Background and Apps tabs). */
public abstract class AppListPage {
    protected final Activity a;
    protected final Ui.Pal p;
    private final ListView list;
    private final LinearLayout head;
    private final Adapter adapter = new Adapter();
    protected final List<Row> all = new ArrayList<>();
    private final List<Row> shown = new ArrayList<>();
    private final LruCache<String, Drawable> icons = new LruCache<>(120);
    private String query = "";
    protected boolean loading;
    private EditText search;

    public static class Row {
        public String pkg, label;
        public boolean system, disabled, removed;
    }

    protected AppListPage(Activity a) {
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
    }

    public View view() { return list; }

    // ---------------------------------------------------------------- for subclasses

    protected abstract String title();
    protected abstract String subtitle();
    /** Loads the rows (background thread). */
    protected abstract List<Row> load();
    /** Cards under the title. */
    protected abstract void buildTop(LinearLayout head);
    protected abstract boolean include(Row r);
    protected abstract String rowSub(Row r);
    protected int rowSubColor(Row r) { return p.sub; }
    /** Switch state for the row, or null for no switch. */
    protected abstract Boolean rowSwitch(Row r);
    protected abstract void onRowClick(Row r);
    /** Line under the search box. */
    protected abstract String listHint();

    public void reload() {
        if (loading) return;
        loading = true;
        refreshHeader();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                final List<Row> rows = load();
                a.runOnUiThread(new Runnable() {
                    @Override public void run() {
                        all.clear();
                        all.addAll(rows);
                        loading = false;
                        refreshHeader();
                    }
                });
            }
        });
    }

    public void refresh() { filter(); }

    protected void filter() {
        shown.clear();
        String q = query.toLowerCase(Locale.ROOT);
        for (Row r : all) {
            if (!include(r)) continue;
            if (!q.isEmpty() && !r.label.toLowerCase(Locale.ROOT).contains(q) && !r.pkg.toLowerCase(Locale.ROOT).contains(q)) continue;
            shown.add(r);
        }
        adapter.notifyDataSetChanged();
    }

    public void refreshHeader() {
        boolean hadFocus = search != null && search.hasFocus();
        head.removeAllViews();
        head.addView(MainActivity.pageHeader(a, title(), subtitle()));
        if (Shell.backend(a) == null) {
            LinearLayout bc = Ui.card(a);
            bc.addView(Ui.item(a, R.drawable.ic_bolt, "Needs Shizuku (or root)", Shell.status(a), null, new View.OnClickListener() {
                @Override public void onClick(View v) {
                    if (Shizuku.running() && !Shizuku.granted()) Shizuku.requestPermission(new Runnable() { @Override public void run() { } });
                    else ((MainActivity) a).openTab(1);
                }
            }));
            head.addView(bc);
        }
        buildTop(head);
        LinearLayout lc = Ui.row(a);
        lc.setPadding(Ui.dp(a, 16), Ui.dp(a, 10), Ui.dp(a, 16), Ui.dp(a, 4));
        search = Ui.field(a, "Search apps", query);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int af) { }
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) { }
            @Override public void afterTextChanged(Editable s) { query = s.toString().trim(); filter(); }
        });
        lc.addView(search, Ui.lpW(1));
        head.addView(lc);
        TextView hint = Ui.text(a, loading ? "Loading apps…" : listHint(), 12, p.sub);
        hint.setPadding(Ui.dp(a, 30), Ui.dp(a, 4), Ui.dp(a, 30), Ui.dp(a, 6));
        head.addView(hint);
        if (hadFocus) { search.requestFocus(); search.setSelection(search.getText().length()); }
        filter();
    }

    protected int shownCount() { return shown.size(); }

    protected List<Row> shownRows() { return new ArrayList<>(shown); }

    // ---------------------------------------------------------------- list

    private static final class Holder { ImageView icon; TextView label, sub; Switch sw; String pkg; }

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
                h.sub = Ui.text(a, "", 12, p.sub);
                h.sub.setSingleLine();
                h.sub.setEllipsize(android.text.TextUtils.TruncateAt.END);
                t.addView(h.label);
                t.addView(h.sub);
                r.addView(t, Ui.lpW(1));
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
            final Row row = shown.get(pos);
            h.pkg = row.pkg;
            h.label.setText(row.label);
            h.label.setAlpha(row.disabled || row.removed ? 0.6f : 1f);
            h.sub.setText(rowSub(row));
            h.sub.setTextColor(rowSubColor(row));
            Boolean sw = rowSwitch(row);
            h.sw.setVisibility(sw == null ? View.GONE : View.VISIBLE);
            if (sw != null) h.sw.setChecked(sw);
            Drawable d = icons.get(row.pkg);
            if (d != null) h.icon.setImageDrawable(d);
            else {
                h.icon.setImageDrawable(null);
                final Holder fh = h;
                App.IO.execute(new Runnable() {
                    @Override public void run() {
                        try {
                            android.content.pm.PackageManager pm = a.getPackageManager();
                            final Drawable ic = pm.getApplicationIcon(pm.getApplicationInfo(row.pkg, android.content.pm.PackageManager.MATCH_UNINSTALLED_PACKAGES
                                    | android.content.pm.PackageManager.MATCH_DISABLED_COMPONENTS));
                            icons.put(row.pkg, ic);
                            a.runOnUiThread(new Runnable() { @Override public void run() { if (row.pkg.equals(fh.pkg)) fh.icon.setImageDrawable(ic); } });
                        } catch (Exception ignored) { }
                    }
                });
            }
            v.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View view) { onRowClick(row); } });
            return v;
        }
    }
}
