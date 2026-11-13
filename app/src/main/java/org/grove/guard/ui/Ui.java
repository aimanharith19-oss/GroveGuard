/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.AlertDialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

/** Shared look for Grove apps (Canopy, Grove Vault, Grove Guard): soft green palette, rounded cards, light/dark. */
public final class Ui {
    private Ui() { }

    public static final class Pal {
        public int bg, card, cardAlt, text, sub, line, primary, onPrimary, container, onContainer, danger, dangerBg, warn, warnBg;
        public boolean dark;
    }

    public static Pal pal(Context c) {
        Pal p = new Pal();
        p.dark = (c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        if (p.dark) {
            p.bg = 0xFF0F1412; p.card = 0xFF18201C; p.cardAlt = 0xFF202A25; p.text = 0xFFE6EEE9; p.sub = 0xFF9AA8A0; p.line = 0xFF2A352F;
            p.primary = 0xFF6FCF97; p.onPrimary = 0xFF0B2A1B; p.container = 0xFF1F3A2C; p.onContainer = 0xFFBDEBCF;
            p.danger = 0xFFFF8A80; p.dangerBg = 0xFF3B1F1C; p.warn = 0xFFF2C46D; p.warnBg = 0xFF3A2F16;
        } else {
            p.bg = 0xFFF4F6F3; p.card = 0xFFFFFFFF; p.cardAlt = 0xFFEEF2EE; p.text = 0xFF17201B; p.sub = 0xFF5F6B64; p.line = 0xFFE1E7E2;
            p.primary = 0xFF2E7D5B; p.onPrimary = 0xFFFFFFFF; p.container = 0xFFDCEFE3; p.onContainer = 0xFF0F3D28;
            p.danger = 0xFFC0392B; p.dangerBg = 0xFFFBE4E1; p.warn = 0xFF9A6A12; p.warnBg = 0xFFFCF0D6;
        }
        return p;
    }

    public static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    public static GradientDrawable round(int color, float radiusPx) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusPx);
        return g;
    }

    public static Drawable ripple(Context c, int bg, float radius) {
        Pal p = pal(c);
        int rc = (p.dark ? 0x33FFFFFF : 0x22000000);
        return new RippleDrawable(ColorStateList.valueOf(rc), bg == 0 ? null : round(bg, radius), round(Color.WHITE, radius));
    }

    public static LinearLayout col(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    public static LinearLayout row(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    public static LinearLayout.LayoutParams lp(int w, int h) { return new LinearLayout.LayoutParams(w, h); }

    public static LinearLayout.LayoutParams lpW(float weight) { return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, weight); }

    public static LinearLayout.LayoutParams margins(Context c, LinearLayout.LayoutParams lp, int l, int t, int r, int b) {
        lp.setMargins(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
        return lp;
    }

    /** A rounded card that holds rows. */
    public static LinearLayout card(Context c) {
        Pal p = pal(c);
        LinearLayout l = col(c);
        l.setBackground(round(p.card, dp(c, 22)));
        l.setPadding(dp(c, 18), dp(c, 16), dp(c, 18), dp(c, 16));
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(c, 16), dp(c, 6), dp(c, 16), dp(c, 6));
        l.setLayoutParams(lp);
        return l;
    }

    public static TextView text(Context c, String s, float sp, int color) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    public static TextView title(Context c, String s, float sp) {
        TextView t = text(c, s, sp, pal(c).text);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return t;
    }

    /** Small grey heading above a card. */
    public static TextView section(Context c, String s) {
        TextView t = text(c, s, 13, pal(c).primary);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        t.setPadding(dp(c, 30), dp(c, 18), dp(c, 30), dp(c, 4));
        return t;
    }

    public static ImageView icon(Context c, int res, int tint, int sizeDp) {
        ImageView iv = new ImageView(c);
        Drawable d = c.getDrawable(res).mutate();
        d.setTint(tint);
        iv.setImageDrawable(d);
        iv.setLayoutParams(lp(dp(c, sizeDp), dp(c, sizeDp)));
        return iv;
    }

    /** Icon in a soft round badge. */
    public static FrameLayout badge(Context c, int res, int fg, int bg, int sizeDp) {
        FrameLayout f = new FrameLayout(c);
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        g.setColor(bg);
        f.setBackground(g);
        ImageView iv = icon(c, res, fg, Math.round(sizeDp * 0.55f));
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(dp(c, Math.round(sizeDp * 0.55f)), dp(c, Math.round(sizeDp * 0.55f)), Gravity.CENTER);
        f.addView(iv, lp);
        f.setLayoutParams(lp(dp(c, sizeDp), dp(c, sizeDp)));
        return f;
    }

    /** Big pill button. {@code style}: 0 = filled, 1 = tonal, 2 = outlined/text, 3 = danger. */
    public static TextView button(Context c, String label, int style, View.OnClickListener l) {
        Pal p = pal(c);
        TextView b = text(c, label, 15, style == 0 ? p.onPrimary : style == 1 ? p.onContainer : style == 3 ? p.danger : p.primary);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setGravity(Gravity.CENTER);
        b.setPadding(dp(c, 18), 0, dp(c, 18), 0);
        b.setMinHeight(dp(c, 48));
        b.setSingleLine();
        b.setEllipsize(TextUtils.TruncateAt.END);
        int bg = style == 0 ? p.primary : style == 1 ? p.container : style == 3 ? p.dangerBg : 0;
        b.setBackground(ripple(c, bg, dp(c, 24)));
        b.setOnClickListener(l);
        return b;
    }

    /** Large full-width button with an icon (56dp tall). */
    public static TextView bigButton(Context c, int iconRes, String label, int style, View.OnClickListener l) {
        Pal p = pal(c);
        TextView b = button(c, label, style, l);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        b.setMinHeight(dp(c, 56));
        int fg = style == 0 ? p.onPrimary : style == 1 ? p.onContainer : style == 3 ? p.danger : p.primary;
        Drawable d = c.getDrawable(iconRes).mutate();
        d.setTint(fg);
        d.setBounds(0, 0, dp(c, 22), dp(c, 22));
        b.setCompoundDrawablesRelative(d, null, null, null);
        b.setCompoundDrawablePadding(dp(c, 10));
        b.setBackground(ripple(c, style == 0 ? p.primary : style == 1 ? p.container : style == 3 ? p.dangerBg : 0, dp(c, 28)));
        return b;
    }

    /** Settings-style row: icon, title, subtitle, optional switch. Returns the row; the switch is its tag. */
    public static LinearLayout item(Context c, int iconRes, String title, String sub, Boolean checked, View.OnClickListener l) {
        Pal p = pal(c);
        LinearLayout r = row(c);
        r.setPadding(dp(c, 4), dp(c, 10), dp(c, 4), dp(c, 10));
        r.setMinimumHeight(dp(c, 56));
        if (iconRes != 0) {
            View ic = badge(c, iconRes, p.primary, p.container, 38);
            r.addView(ic);
            ((LinearLayout.LayoutParams) ic.getLayoutParams()).rightMargin = dp(c, 14);
        }
        LinearLayout t = col(c);
        TextView tt = title(c, title, 16);
        t.addView(tt);
        TextView st = null;
        if (sub != null) {
            st = text(c, sub, 13, p.sub);
            st.setPadding(0, dp(c, 2), 0, 0);
            t.addView(st);
        }
        r.addView(t, lpW(1));
        if (checked != null) {
            Switch s = new Switch(c);
            s.setChecked(checked);
            s.setClickable(false);
            s.setFocusable(false);
            tintSwitch(c, s);
            r.addView(s);
            r.setTag(s);
        }
        r.setTag(org.grove.guard.R.id.tag_sub, st);
        if (l != null) {
            r.setBackground(ripple(c, 0, dp(c, 14)));
            r.setOnClickListener(l);
        }
        return r;
    }

    public static Switch switchOf(View item) { return (Switch) item.getTag(); }

    public static TextView subOf(View item) { return (TextView) item.getTag(org.grove.guard.R.id.tag_sub); }

    public static void tintSwitch(Context c, Switch s) {
        Pal p = pal(c);
        int[][] st = {{android.R.attr.state_checked}, {}};
        s.setThumbTintList(new ColorStateList(st, new int[]{p.primary, p.dark ? 0xFFB8C2BC : 0xFFFFFFFF}));
        s.setTrackTintList(new ColorStateList(st, new int[]{p.dark ? 0xFF2F6B4C : 0xFF9FD3B5, p.dark ? 0xFF3A4540 : 0xFFC9D1CC}));
    }

    /** Selectable chip. */
    public static TextView chip(Context c, String label, boolean on, View.OnClickListener l) {
        Pal p = pal(c);
        TextView t = text(c, label, 14, on ? p.onContainer : p.sub);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        t.setPadding(dp(c, 14), dp(c, 8), dp(c, 14), dp(c, 8));
        GradientDrawable g = round(on ? p.container : 0, dp(c, 18));
        if (!on) g.setStroke(dp(c, 1), p.line);
        t.setBackground(new RippleDrawable(ColorStateList.valueOf(p.dark ? 0x33FFFFFF : 0x22000000), g, null));
        t.setOnClickListener(l);
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(c, 4), dp(c, 8), dp(c, 4));
        t.setLayoutParams(lp);
        return t;
    }

    public static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(pal(c).line);
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(c, 1) / 2 + 1));
        lp.setMargins(0, dp(c, 4), 0, dp(c, 4));
        v.setLayoutParams(lp);
        return v;
    }

    public static EditText field(Context c, String hint, String value) {
        Pal p = pal(c);
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setText(value);
        e.setTextColor(p.text);
        e.setHintTextColor(p.sub);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        e.setSingleLine();
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        e.setBackground(round(p.cardAlt, dp(c, 16)));
        e.setPadding(dp(c, 16), dp(c, 12), dp(c, 16), dp(c, 12));
        return e;
    }

    // ---------------------------------------------------------------- dialogs

    public interface Cb<T> { void on(T v); }

    public static AlertDialog.Builder dialog(Context c) {
        return new AlertDialog.Builder(c, pal(c).dark ? android.R.style.Theme_DeviceDefault_Dialog_Alert : android.R.style.Theme_DeviceDefault_Light_Dialog_Alert);
    }

    public static void confirm(Context c, String title, String msg, String yes, final Runnable r) {
        dialog(c).setTitle(title).setMessage(msg).setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(yes, new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) { r.run(); }
                }).show();
    }

    public static void input(Context c, String title, String msg, String hint, String value, final Cb<String> cb) {
        final EditText e = field(c, hint, value);
        LinearLayout wrap = col(c);
        wrap.setPadding(dp(c, 22), dp(c, 8), dp(c, 22), 0);
        wrap.addView(e);
        AlertDialog.Builder b = dialog(c).setTitle(title).setView(wrap).setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) { cb.on(e.getText().toString().trim()); }
                });
        if (msg != null) b.setMessage(msg);
        b.show();
    }

    public static void choose(Context c, String title, String[] items, int checked, final Cb<Integer> cb) {
        dialog(c).setTitle(title).setSingleChoiceItems(items, checked, new android.content.DialogInterface.OnClickListener() {
                    @Override public void onClick(android.content.DialogInterface d, int w) { d.dismiss(); cb.on(w); }
                })
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    public static void toast(Context c, String s) { Toast.makeText(c, s, Toast.LENGTH_SHORT).show(); }
}
