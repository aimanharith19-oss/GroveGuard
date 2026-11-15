/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.animation.TimeInterpolator;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.PathInterpolator;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.grove.guard.Prefs;

import java.util.Locale;

/**
 * Windows Phone look, shared with Grove Music: black with an accent glow at the top, light lowercase titles,
 * square accent tiles, flat lists, square buttons, the "tilt" press effect and the "feather" entrance.
 */
public final class Ui {
    private Ui() { }

    /** Windows Phone 8 accent colours (same set as Grove Music). */
    public static final int[] ACCENTS = {
            0xFFA4C400, 0xFF60A917, 0xFF008A00, 0xFF00ABA9, 0xFF1BA1E2, 0xFF0050EF, 0xFF6A00FF,
            0xFFAA00FF, 0xFFF472D0, 0xFFD80073, 0xFFA20025, 0xFFE51400, 0xFFFA6800, 0xFFF0A30A,
            0xFFE3C800, 0xFF825A2C, 0xFF6D8764, 0xFF647687, 0xFF76608A, 0xFF87794E,
    };
    public static final int DEFAULT_ACCENT = 0xFF60A917; // lime-green, the closest WP colour to Grove's green
    public static final TimeInterpolator WP_EASE = new PathInterpolator(0.1f, 0.9f, 0.2f, 1f);
    public static final int DIM = 0xFF8A8A8A;

    public static final class Pal {
        public int bg, card, cardAlt, text, sub, line, primary, onPrimary, container, onContainer, danger, dangerBg, warn, warnBg, accent;
        public boolean dark = true;
    }

    public static int accent(Context c) { return Prefs.sp(c).getInt("accent", DEFAULT_ACCENT); }

    public static Pal pal(Context c) {
        Pal p = new Pal();
        int a = accent(c);
        p.accent = a;
        p.bg = 0xFF000000; p.card = 0; p.cardAlt = 0x26FFFFFF; p.text = 0xFFFFFFFF; p.sub = DIM; p.line = 0x33FFFFFF;
        p.primary = a; p.onPrimary = 0xFFFFFFFF; p.container = mix(a, 0xFF000000, 0.55f); p.onContainer = 0xFFFFFFFF;
        p.danger = 0xFFE51400; p.dangerBg = 0xFF5A0A04; p.warn = 0xFFF0A30A; p.warnBg = 0xFF4A3304;
        return p;
    }

    public static int mix(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF, br = (b >> 16) & 0xFF, bgc = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000 | (Math.round(ar + (br - ar) * t) << 16) | (Math.round(ag + (bgc - ag) * t) << 8) | Math.round(ab + (bb - ab) * t);
    }

    public static int alpha(int color, float a) { return (Math.round(a * 255) << 24) | (color & 0xFFFFFF); }

    /** The accent glow that fades to black (Grove Music's background). */
    public static Drawable tintBackground(Context c, float strength) {
        int a = accent(c);
        return new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{alpha(a, strength), alpha(a, strength * 0.25f), 0xFF000000, 0xFF000000});
    }

    public static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    public static Typeface light() { return Typeface.create("sans-serif-light", Typeface.NORMAL); }

    public static Typeface semibold() { return Typeface.create("sans-serif-medium", Typeface.NORMAL); }

    /** Windows Phone has square corners: the radius is ignored. */
    public static GradientDrawable round(int color, float radiusPx) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        return g;
    }

    public static Drawable ripple(Context c, int bg, float radius) {
        return bg == 0 ? new ColorDrawable(0) : new ColorDrawable(bg);
    }

    static String lower(String s) { return s == null ? null : s.toLowerCase(Locale.getDefault()); }

    // ---------------------------------------------------------------- motion

    /** Windows Phone "tilt": the view tips toward the finger while pressed. Keeps normal clicks working. */
    public static void tilt(final View v) {
        v.setOnTouchListener(new View.OnTouchListener() {
            @Override public boolean onTouch(View view, MotionEvent e) {
                switch (e.getActionMasked()) {
                    case MotionEvent.ACTION_DOWN: {
                        float w = Math.max(1, view.getWidth()), h = Math.max(1, view.getHeight());
                        float nx = (e.getX() / w - 0.5f) * 2f, ny = (e.getY() / h - 0.5f) * 2f;
                        float max = w > dp(view.getContext(), 240) ? 4f : 10f;
                        view.setCameraDistance(view.getResources().getDisplayMetrics().density * 8000f);
                        view.animate().rotationY(nx * max).rotationX(-ny * max).scaleX(0.965f).scaleY(0.965f)
                                .setDuration(90).setInterpolator(WP_EASE).start();
                        break;
                    }
                    case MotionEvent.ACTION_UP:
                    case MotionEvent.ACTION_CANCEL:
                        view.animate().rotationY(0).rotationX(0).scaleX(1).scaleY(1).setDuration(260).setInterpolator(WP_EASE).start();
                        break;
                    default: break;
                }
                return false; // let the click / long-click through
            }
        });
    }

    /** Windows Phone "feather": children slide in from the right one after another. */
    public static void feather(ViewGroup g) {
        int n = Math.min(g.getChildCount(), 14);
        float dx = dp(g.getContext(), 90);
        for (int i = 0; i < n; i++) {
            View v = g.getChildAt(i);
            v.setAlpha(0f);
            v.setTranslationX(dx);
            v.animate().alpha(1f).translationX(0).setStartDelay(i * 35L).setDuration(420).setInterpolator(WP_EASE).start();
        }
    }

    // ---------------------------------------------------------------- layout

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

    /** A flat group of rows (Windows Phone has no cards). */
    public static LinearLayout card(Context c) {
        LinearLayout l = col(c);
        l.setPadding(dp(c, 20), dp(c, 2), dp(c, 20), dp(c, 6));
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
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

    /** Light, lowercase title (sizes are scaled up to Windows Phone proportions). */
    public static TextView title(Context c, String s, float sp) {
        TextView t = text(c, lower(s), sp >= 20 ? sp * 1.25f : sp * 1.3f, 0xFFFFFFFF);
        t.setTypeface(light());
        return t;
    }

    /** Small accent label above a group, in capitals (as in Grove Music). */
    public static TextView section(Context c, String s) {
        TextView t = text(c, s.toUpperCase(Locale.getDefault()), 13, accent(c));
        t.setTypeface(semibold());
        t.setLetterSpacing(0.08f);
        t.setPadding(dp(c, 20), dp(c, 22), dp(c, 20), dp(c, 6));
        return t;
    }

    /** "GROVEGUARD" + a big light lowercase page title (Grove Music / Grovebook settings style). */
    public static LinearLayout bigTitle(Context c, String title) {
        LinearLayout l = col(c);
        l.setPadding(dp(c, 20), dp(c, 14), dp(c, 20), dp(c, 6));
        TextView app = text(c, "GROVEGUARD", 15, 0xFFFFFFFF);
        app.setTypeface(semibold());
        l.addView(app);
        TextView t = text(c, lower(title), 56, 0xFFFFFFFF);
        t.setTypeface(light());
        t.setIncludeFontPadding(false);
        t.setSingleLine();
        l.addView(t);
        return l;
    }

    public static ImageView icon(Context c, int res, int tint, int sizeDp) {
        ImageView iv = new ImageView(c);
        Drawable d = c.getDrawable(res).mutate();
        d.setTint(tint);
        iv.setImageDrawable(d);
        iv.setLayoutParams(lp(dp(c, sizeDp), dp(c, sizeDp)));
        return iv;
    }

    /** Square tile with a white glyph; the tile takes the meaning colour (accent, red for threats, amber for warnings). */
    public static FrameLayout badge(Context c, int res, int fg, int bg, int sizeDp) {
        FrameLayout f = new FrameLayout(c);
        f.setBackgroundColor(fg);
        int s = Math.round(sizeDp * 0.5f);
        f.addView(icon(c, res, 0xFFFFFFFF, s), new FrameLayout.LayoutParams(dp(c, s), dp(c, s), Gravity.CENTER));
        f.setLayoutParams(lp(dp(c, sizeDp), dp(c, sizeDp)));
        return f;
    }

    /** Square button. {@code style}: 0 = accent fill, 1 = white outline, 2 = text only, 3 = red fill. */
    public static TextView button(Context c, String label, int style, View.OnClickListener l) {
        TextView b = text(c, lower(label), 17, 0xFFFFFFFF);
        b.setGravity(Gravity.CENTER);
        b.setPadding(dp(c, 18), 0, dp(c, 18), 0);
        b.setMinHeight(dp(c, 46));
        b.setSingleLine();
        b.setEllipsize(TextUtils.TruncateAt.END);
        GradientDrawable g = new GradientDrawable();
        if (style == 0) g.setColor(accent(c));
        else if (style == 3) g.setColor(0xFFE51400);
        else if (style == 1) { g.setColor(0); g.setStroke(dp(c, 2), 0xFFFFFFFF); }
        else g.setColor(0);
        b.setBackground(g);
        b.setOnClickListener(l);
        tilt(b);
        return b;
    }

    /** Large full-width button with an icon (56dp tall). */
    public static TextView bigButton(Context c, int iconRes, String label, int style, View.OnClickListener l) {
        TextView b = button(c, label, style, l);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 19);
        b.setTypeface(light());
        b.setMinHeight(dp(c, 56));
        Drawable d = c.getDrawable(iconRes).mutate();
        d.setTint(0xFFFFFFFF);
        d.setBounds(0, 0, dp(c, 22), dp(c, 22));
        b.setCompoundDrawablesRelative(d, null, null, null);
        b.setCompoundDrawablePadding(dp(c, 12));
        return b;
    }

    /** Settings-style row: square tile, light lowercase title, grey subtitle, optional switch. The switch is the row's tag. */
    public static LinearLayout item(Context c, int iconRes, String title, String sub, Boolean checked, View.OnClickListener l) {
        LinearLayout r = row(c);
        r.setPadding(0, dp(c, 9), 0, dp(c, 9));
        r.setMinimumHeight(dp(c, 60));
        if (iconRes != 0) {
            View ic = badge(c, iconRes, accent(c), 0, 46);
            r.addView(ic);
            ((LinearLayout.LayoutParams) ic.getLayoutParams()).rightMargin = dp(c, 14);
        }
        LinearLayout t = col(c);
        TextView tt = text(c, lower(title), 22, 0xFFFFFFFF);
        tt.setTypeface(light());
        t.addView(tt);
        TextView st = null;
        if (sub != null) {
            st = text(c, sub, 14, DIM);
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
            r.setOnClickListener(l);
            tilt(r);
        }
        return r;
    }

    public static Switch switchOf(View item) { return (Switch) item.getTag(); }

    public static TextView subOf(View item) { return (TextView) item.getTag(org.grove.guard.R.id.tag_sub); }

    public static void tintSwitch(Context c, Switch s) {
        int[][] st = {{android.R.attr.state_checked}, {}};
        s.setThumbTintList(new ColorStateList(st, new int[]{0xFFFFFFFF, 0xFFFFFFFF}));
        s.setTrackTintList(new ColorStateList(st, new int[]{accent(c), 0xFF5A5A5A}));
        s.setTrackTintMode(android.graphics.PorterDuff.Mode.SRC);
    }

    /** Square choice tile: accent fill when selected, white outline otherwise. */
    public static TextView chip(Context c, String label, boolean on, View.OnClickListener l) {
        TextView t = text(c, lower(label), 15, 0xFFFFFFFF);
        t.setPadding(dp(c, 14), dp(c, 8), dp(c, 14), dp(c, 8));
        GradientDrawable g = new GradientDrawable();
        if (on) { g.setColor(accent(c)); g.setStroke(dp(c, 2), accent(c)); } else { g.setColor(0); g.setStroke(dp(c, 2), 0xCCFFFFFF); }
        // inset so the outline never touches the view's edge (it was being clipped at the top)
        t.setBackground(new android.graphics.drawable.InsetDrawable(g, dp(c, 2)));
        t.setPadding(dp(c, 16), dp(c, 10), dp(c, 16), dp(c, 10));
        t.setOnClickListener(l);
        if (l != null) tilt(t);
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(c, 4), dp(c, 8), dp(c, 4));
        t.setLayoutParams(lp);
        return t;
    }

    public static View divider(Context c) {
        View v = new View(c);
        LinearLayout.LayoutParams lp = lp(ViewGroup.LayoutParams.MATCH_PARENT, dp(c, 6));
        v.setLayoutParams(lp);
        return v;
    }

    /** Windows Phone text box: light grey, white with black text when focused. */
    public static EditText field(Context c, String hint, String value) {
        final EditText e = new EditText(c);
        e.setHint(hint == null ? null : lower(hint));
        e.setText(value);
        e.setTextColor(0xFF000000);
        e.setHintTextColor(0xFF666666);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
        e.setSingleLine();
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        final GradientDrawable g = new GradientDrawable();
        g.setColor(0xFFCCCCCC);
        e.setBackground(g);
        e.setPadding(dp(c, 12), dp(c, 10), dp(c, 12), dp(c, 10));
        e.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override public void onFocusChange(View v, boolean has) { g.setColor(has ? 0xFFFFFFFF : 0xFFCCCCCC); g.setStroke(has ? dp(v.getContext(), 2) : 0, accent(v.getContext())); }
        });
        return e;
    }

    // ---------------------------------------------------------------- dialogs (Windows Phone message boxes)

    public interface Cb<T> { void on(T v); }

    /** AlertDialog restyled as a Windows Phone message box: a full-width dark band, light lowercase title, square buttons. */
    public static AlertDialog.Builder dialog(final Context c) {
        return new AlertDialog.Builder(c, android.R.style.Theme_DeviceDefault_Dialog_Alert) {
            @Override public AlertDialog create() {
                final AlertDialog d = super.create();
                // position the box before it appears (setting it on show made it jump from the centre to the top)
                android.view.Window w = d.getWindow();
                if (w != null) {
                    w.setBackgroundDrawable(new ColorDrawable(mix(accent(c), 0xFF000000, 0.78f)));
                    w.setGravity(Gravity.TOP);
                    w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    w.setWindowAnimations(android.R.style.Animation_Toast);
                    w.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING
                            | android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
                }
                d.setOnShowListener(new DialogInterface.OnShowListener() {
                    @Override public void onShow(DialogInterface di) { style(c, d); }
                });
                return d;
            }
        };
    }

    static void style(Context c, AlertDialog d) {
        try {
            android.view.Window w = d.getWindow();
            if (w == null) return;
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            // Windows Phone message box: the content drops in from the top
            View content = w.getDecorView();
            content.setTranslationY(-dp(c, 40));
            content.setAlpha(0f);
            content.animate().translationY(0).alpha(1f).setDuration(260).setInterpolator(WP_EASE).start();
            int tid = c.getResources().getIdentifier("alertTitle", "id", "android");
            TextView title = tid != 0 ? (TextView) d.findViewById(tid) : null;
            if (title != null) {
                title.setText(lower(String.valueOf(title.getText())));
                title.setTypeface(light());
                title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
                title.setTextColor(0xFFFFFFFF);
                title.setSingleLine(false);
            }
            TextView msg = (TextView) d.findViewById(android.R.id.message);
            if (msg != null) { msg.setTextColor(0xFFFFFFFF); msg.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16); }
            ListView lv = d.getListView();
            if (lv != null) { lv.setDivider(null); lv.setSelector(new ColorDrawable(alpha(accent(c), 0.4f))); }
            // Replace Android's button bar (it clips outlines) with our own Windows Phone buttons, side by side.
            LinearLayout bar = row(c);
            bar.setPadding(dp(c, 18), dp(c, 10), dp(c, 18), dp(c, 16));
            View nativeBar = null;
            for (final int which : new int[]{DialogInterface.BUTTON_POSITIVE, DialogInterface.BUTTON_NEUTRAL, DialogInterface.BUTTON_NEGATIVE}) {
                final Button nb = d.getButton(which);
                if (nb == null) continue;
                if (nativeBar == null && nb.getParent() instanceof View) nativeBar = (View) nb.getParent();
                if (nb.getVisibility() != View.VISIBLE || TextUtils.isEmpty(nb.getText())) continue;
                TextView ours = button(c, String.valueOf(nb.getText()), which == DialogInterface.BUTTON_POSITIVE ? 0 : 1, new View.OnClickListener() {
                    @Override public void onClick(View v) { nb.performClick(); }
                });
                // same size as the big "scan now" / "update database" buttons
                ours.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
                ours.setTypeface(light());
                ours.setPadding(dp(c, 8), 0, dp(c, 8), 0);
                LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0, dp(c, 56), 1);
                blp.setMargins(bar.getChildCount() == 0 ? 0 : dp(c, 10), 0, 0, 0);
                bar.addView(ours, blp);
            }
            if (bar.getChildCount() > 0 && nativeBar != null) {
                View panel = (View) nativeBar.getParent(); // the scrolling "buttonPanel" around Android's bar
                int pid = c.getResources().getIdentifier("parentPanel", "id", "android");
                ViewGroup parent = pid != 0 ? (ViewGroup) d.findViewById(pid) : null;
                if (parent != null) {
                    (panel != null && panel.getParent() == parent ? panel : nativeBar).setVisibility(View.GONE);
                    parent.addView(bar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                }
            }
        } catch (Exception ignored) { }
    }

    public static void confirm(Context c, String title, String msg, String yes, final Runnable r) {
        dialog(c).setTitle(title).setMessage(msg).setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(yes, new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { r.run(); }
                }).show();
    }

    public static void input(Context c, String title, String msg, String hint, String value, final Cb<String> cb) {
        final EditText e = field(c, hint, value);
        LinearLayout wrap = col(c);
        wrap.setPadding(dp(c, 22), dp(c, 8), dp(c, 22), 0);
        wrap.addView(e);
        AlertDialog.Builder b = dialog(c).setTitle(title).setView(wrap).setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { cb.on(e.getText().toString().trim()); }
                });
        if (msg != null) b.setMessage(msg);
        b.show();
    }

    public static void choose(Context c, String title, String[] items, int checked, final Cb<Integer> cb) {
        String[] low = new String[items.length];
        for (int i = 0; i < items.length; i++) low[i] = lower(items[i]);
        dialog(c).setTitle(title).setSingleChoiceItems(low, checked, new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int w) { d.dismiss(); cb.on(w); }
                })
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    public static void toast(Context c, String s) { Toast.makeText(c, s, Toast.LENGTH_SHORT).show(); }
}
