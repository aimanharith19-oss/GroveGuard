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
 * Windows 11 Fluent look: a Mica-style dark background with a faint accent tint, rounded layered cards with a hairline
 * border, sentence-case Segoe-like type (regular/semibold, never light), accent buttons, and Fluent motion (fast
 * decelerating curves, small slide-up entrances, a gentle press).
 */
public final class Ui {
    private Ui() { }

    /** Windows accent colours (Settings → Personalisation → Colours). */
    public static final int[] ACCENTS = {
            0xFFFFB900, 0xFFFF8C00, 0xFFF7630C, 0xFFDA3B01, 0xFFEF6950, 0xFFD13438, 0xFFE74856, 0xFFE3008C,
            0xFFBF0077, 0xFF9A0089, 0xFF0078D4, 0xFF0063B1, 0xFF8E8CD8, 0xFF6B69D6, 0xFF8764B8, 0xFF0099BC,
            0xFF00B7C3, 0xFF038387, 0xFF00B294, 0xFF018574, 0xFF00CC6A, 0xFF10893E, 0xFF7A7574, 0xFF567C73,
    };
    public static final int DEFAULT_ACCENT = 0xFF00CC6A; // Windows "green", closest to Grove's green
    /** Fluent "fast out, decelerate" curve (0, 0, 0, 1). The old name is kept so every page picks it up. */
    public static final TimeInterpolator WP_EASE = new PathInterpolator(0f, 0f, 0f, 1f);
    public static final TimeInterpolator FLUENT = WP_EASE;
    /** Theme colours, set by {@link #apply} (dark or light Fluent): text, secondary text, Mica, card layers, hairline, control fill, press. */
    public static int FG = 0xFFFFFFFF, DIM = 0xFFC5C5C5, MICA = 0xFF202020, LAYER = 0xFF2B2B2B, LAYER_ALT = 0xFF323232,
            STROKE = 0x14FFFFFF, SUBTLE = 0x0FFFFFFF, CTRL_STROKE = 0x18FFFFFF, PRESS = 0x14FFFFFF, FIELD_FOCUS = 0xFF1F1F1F;
    public static boolean LIGHT = false;

    /** 0 = follow the phone, 1 = dark, 2 = light. */
    public static int themeMode(Context c) { return Prefs.sp(c).getInt("theme", 0); }

    /** Picks dark or light for this screen (call in every activity's onCreate, before building views). */
    public static void apply(android.app.Activity a) {
        int m = themeMode(a);
        LIGHT = m == 2 || (m == 0 && (a.getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                != android.content.res.Configuration.UI_MODE_NIGHT_YES);
        if (LIGHT) {
            FG = 0xFF1B1B1B; DIM = 0xFF5F5F5F; MICA = 0xFFF3F3F3; LAYER = 0xFFFBFBFB; LAYER_ALT = 0xFFFFFFFF;
            STROKE = 0x14000000; SUBTLE = 0xB3FFFFFF; CTRL_STROKE = 0x1F000000; PRESS = 0x0F000000; FIELD_FOCUS = 0xFFFFFFFF;
        } else {
            FG = 0xFFFFFFFF; DIM = 0xFFC5C5C5; MICA = 0xFF202020; LAYER = 0xFF2B2B2B; LAYER_ALT = 0xFF323232;
            STROKE = 0x14FFFFFF; SUBTLE = 0x0FFFFFFF; CTRL_STROKE = 0x18FFFFFF; PRESS = 0x14FFFFFF; FIELD_FOCUS = 0xFF1F1F1F;
        }
        android.view.Window w = a.getWindow();
        w.setBackgroundDrawable(new ColorDrawable(MICA));
        int f = w.getDecorView().getSystemUiVisibility() & ~(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        if (LIGHT) f |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        w.getDecorView().setSystemUiVisibility(f);
    }

    public static final class Pal {
        public int bg, card, cardAlt, text, sub, line, primary, onPrimary, container, onContainer, danger, dangerBg, warn, warnBg, accent;
        public boolean dark = true;
    }

    public static int accent(Context c) { return Prefs.sp(c).getInt("accent", DEFAULT_ACCENT); }

    /** The accent as Windows draws it on dark backgrounds (a lighter shade, readable on Mica). */
    public static int accentOnDark(Context c) { return LIGHT ? mix(accent(c), 0xFF000000, 0.18f) : mix(accent(c), 0xFFFFFFFF, 0.28f); }

    /** Black or white, whichever reads better on this colour. */
    public static int onColor(int color) {
        double r = ((color >> 16) & 0xFF) / 255.0, g = ((color >> 8) & 0xFF) / 255.0, b = (color & 0xFF) / 255.0;
        return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.55 ? 0xFF000000 : 0xFFFFFFFF;
    }

    public static Pal pal(Context c) {
        Pal p = new Pal();
        int a = accent(c);
        p.accent = a;
        p.dark = !LIGHT;
        p.bg = MICA; p.card = LAYER; p.cardAlt = LAYER_ALT; p.text = FG; p.sub = DIM; p.line = STROKE;
        p.primary = accentOnDark(c); p.onPrimary = onColor(p.primary); p.container = mix(a, MICA, 0.7f); p.onContainer = FG;
        if (LIGHT) { p.danger = 0xFFC42B1C; p.dangerBg = 0xFFFDE7E9; p.warn = 0xFF9D5D00; p.warnBg = 0xFFFFF4CE; }
        else { p.danger = 0xFFFF99A4; p.dangerBg = 0xFF442726; p.warn = 0xFFFCE100; p.warnBg = 0xFF433519; }
        return p;
    }

    public static int mix(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF, br = (b >> 16) & 0xFF, bgc = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000 | (Math.round(ar + (br - ar) * t) << 16) | (Math.round(ag + (bgc - ag) * t) << 8) | Math.round(ab + (bb - ab) * t);
    }

    public static int alpha(int color, float a) { return (Math.round(a * 255) << 24) | (color & 0xFFFFFF); }

    /** Mica: the dark base with a faint wash of the accent at the top (like a wallpaper tint coming through). */
    public static Drawable tintBackground(Context c, float strength) {
        int a = accent(c);
        return new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{mix(a, MICA, 1f - strength * 0.35f), mix(a, MICA, 1f - strength * 0.12f), MICA, MICA});
    }

    public static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    /** Fluent never uses light weights: "light" is the regular face now. */
    public static Typeface light() { return Typeface.create("sans-serif", Typeface.NORMAL); }

    public static Typeface semibold() { return Typeface.create("sans-serif-medium", Typeface.NORMAL); }

    /** Rounded rectangle (Fluent: 4dp controls, 8dp cards and dialogs). */
    public static GradientDrawable round(int color, float radiusPx) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusPx);
        return g;
    }

    /** A layered card: fill, 8dp corners and the hairline border. */
    public static GradientDrawable layer(Context c, int color) {
        GradientDrawable g = round(color, dp(c, 8));
        g.setStroke(Math.max(1, dp(c, 1) / 2), STROKE);
        return g;
    }

    public static Drawable ripple(Context c, int bg, float radius) {
        GradientDrawable mask = round(0xFFFFFFFF, radius);
        return new android.graphics.drawable.RippleDrawable(ColorStateList.valueOf(PRESS), bg == 0 ? null : round(bg, radius), mask);
    }

    /** Sentence case, as Windows writes labels ("Scan now", not "scan now" or "SCAN NOW"). */
    static String lower(String s) {
        if (s == null || s.isEmpty()) return s;
        return s.substring(0, 1).toUpperCase(Locale.getDefault()) + s.substring(1);
    }

    // ---------------------------------------------------------------- motion

    /** Fluent press: the control settles in slightly and dims while held. Keeps normal clicks working. */
    public static void tilt(final View v) {
        v.setOnTouchListener(new View.OnTouchListener() {
            @Override public boolean onTouch(View view, MotionEvent e) {
                switch (e.getActionMasked()) {
                    case MotionEvent.ACTION_DOWN: {
                        float s = view.getWidth() > dp(view.getContext(), 240) ? 0.985f : 0.96f;
                        view.animate().scaleX(s).scaleY(s).alpha(0.82f).setDuration(83).setInterpolator(FLUENT).start();
                        break;
                    }
                    case MotionEvent.ACTION_UP:
                    case MotionEvent.ACTION_CANCEL:
                        view.animate().scaleX(1).scaleY(1).alpha(1f).setDuration(167).setInterpolator(FLUENT).start();
                        break;
                    default: break;
                }
                return false; // let the click / long-click through
            }
        });
    }

    /** Fluent entrance: items rise 24dp and fade in, one shortly after another. */
    public static void feather(ViewGroup g) {
        int n = Math.min(g.getChildCount(), 14);
        float dy = dp(g.getContext(), 24);
        for (int i = 0; i < n; i++) {
            View v = g.getChildAt(i);
            v.setAlpha(0f);
            v.setTranslationY(dy);
            v.animate().alpha(1f).translationY(0).setStartDelay(i * 25L).setDuration(333).setInterpolator(FLUENT).start();
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

    /** A group of settings cards (Windows 11 Settings): each row inside is its own rounded card, 4dp apart. */
    public static LinearLayout card(Context c) {
        LinearLayout l = col(c);
        l.setPadding(dp(c, 16), dp(c, 2), dp(c, 16), dp(c, 6));
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

    /** Title (Fluent type ramp: subtitle 20 / body-strong 14, semibold, sentence case). */
    public static TextView title(Context c, String s, float sp) {
        TextView t = text(c, lower(s), sp >= 20 ? 20 : Math.max(sp, 15), FG);
        t.setTypeface(semibold());
        return t;
    }

    /** Group heading above a set of cards ("Body strong", like Windows Settings). */
    public static TextView section(Context c, String s) {
        String low = s.toLowerCase(Locale.getDefault());
        TextView t = text(c, lower(low), 14, FG);
        t.setTypeface(semibold());
        t.setPadding(dp(c, 20), dp(c, 20), dp(c, 20), dp(c, 8));
        return t;
    }

    /** Page title (Fluent "Title", 28sp semibold) with the app name as a caption above it. */
    public static LinearLayout bigTitle(Context c, String title) {
        LinearLayout l = col(c);
        l.setPadding(dp(c, 20), dp(c, 14), dp(c, 20), dp(c, 6));
        TextView app = text(c, "Groveguard", 12, DIM);
        l.addView(app);
        TextView t = text(c, lower(title), 28, FG);
        t.setTypeface(semibold());
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

    /** Rounded icon tile: a soft wash of the meaning colour (accent, red for threats, amber for warnings) with the glyph in it. */
    public static FrameLayout badge(Context c, int res, int fg, int bg, int sizeDp) {
        FrameLayout f = new FrameLayout(c);
        f.setBackground(round(alpha(fg, 0.2f), dp(c, sizeDp >= 40 ? 8 : 6)));
        int s = Math.round(sizeDp * 0.5f);
        f.addView(icon(c, res, LIGHT ? fg : mix(fg, 0xFFFFFFFF, 0.3f), s), new FrameLayout.LayoutParams(dp(c, s), dp(c, s), Gravity.CENTER));
        f.setLayoutParams(lp(dp(c, sizeDp), dp(c, sizeDp)));
        return f;
    }

    /** Fluent button. {@code style}: 0 = accent, 1 = standard, 2 = subtle (text only), 3 = danger. */
    public static TextView button(Context c, String label, int style, View.OnClickListener l) {
        TextView b = text(c, lower(label), 14, FG);
        b.setGravity(Gravity.CENTER);
        b.setPadding(dp(c, 16), 0, dp(c, 16), 0);
        b.setMinHeight(dp(c, 40));
        b.setSingleLine();
        b.setEllipsize(TextUtils.TruncateAt.END);
        b.setTypeface(style == 0 || style == 3 ? semibold() : light());
        GradientDrawable g = round(0, dp(c, 4));
        if (style == 0) { int a = accentOnDark(c); g.setColor(a); b.setTextColor(onColor(a)); }
        else if (style == 3) { g.setColor(0xFFC42B1C); b.setTextColor(0xFFFFFFFF); }
        else if (style == 1) { g.setColor(SUBTLE); g.setStroke(Math.max(1, dp(c, 1) / 2), CTRL_STROKE); }
        else { g.setColor(0); b.setTextColor(accentOnDark(c)); }
        b.setBackground(g);
        b.setOnClickListener(l);
        tilt(b);
        return b;
    }

    /** Large full-width button with an icon (48dp tall). */
    public static TextView bigButton(Context c, int iconRes, String label, int style, View.OnClickListener l) {
        TextView b = button(c, label, style, l);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        b.setMinHeight(dp(c, 48));
        Drawable d = c.getDrawable(iconRes).mutate();
        d.setTint(b.getCurrentTextColor());
        d.setBounds(0, 0, dp(c, 20), dp(c, 20));
        b.setCompoundDrawablesRelative(d, null, null, null);
        b.setCompoundDrawablePadding(dp(c, 10));
        return b;
    }

    /** Settings card (Windows 11 SettingsCard): icon, title, secondary description, optional toggle on the right. The switch is the row's tag. */
    public static LinearLayout item(Context c, int iconRes, String title, String sub, Boolean checked, View.OnClickListener l) {
        LinearLayout r = row(c);
        r.setPadding(dp(c, 16), dp(c, 12), dp(c, 14), dp(c, 12));
        r.setMinimumHeight(dp(c, 64));
        r.setBackground(layer(c, LAYER));
        LinearLayout.LayoutParams rlp = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.bottomMargin = dp(c, 4);
        r.setLayoutParams(rlp);
        if (iconRes != 0) {
            View ic = icon(c, iconRes, FG, 20);
            r.addView(ic);
            ((LinearLayout.LayoutParams) ic.getLayoutParams()).rightMargin = dp(c, 16);
        }
        LinearLayout t = col(c);
        TextView tt = text(c, lower(title), 15, FG);
        t.addView(tt);
        TextView st = null;
        if (sub != null) {
            st = text(c, sub, 12.5f, DIM);
            st.setPadding(0, dp(c, 1), 0, 0);
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
        } else if (l != null) {
            TextView chev = text(c, "›", 22, DIM); // the chevron of a clickable card
            chev.setPadding(dp(c, 8), 0, dp(c, 2), dp(c, 2));
            r.addView(chev);
        }
        r.setTag(org.grove.guard.R.id.tag_sub, st);
        if (l != null) {
            r.setOnClickListener(l);
            r.setForeground(ripple(c, 0, dp(c, 8)));
            tilt(r);
        }
        return r;
    }

    public static Switch switchOf(View item) { return (Switch) item.getTag(); }

    public static TextView subOf(View item) { return (TextView) item.getTag(org.grove.guard.R.id.tag_sub); }

    /** Fluent toggle: accent track with a dark knob when on, a grey knob in an outlined track when off. */
    public static void tintSwitch(Context c, Switch s) {
        int[][] st = {{android.R.attr.state_checked}, {}};
        int a = accentOnDark(c);
        s.setThumbTintList(new ColorStateList(st, new int[]{onColor(a), LIGHT ? 0xFF5F5F5F : 0xFFCFCFCF}));
        s.setTrackTintList(new ColorStateList(st, new int[]{a, LIGHT ? 0xFFE0E0E0 : 0xFF3A3A3A}));
        s.setTrackTintMode(android.graphics.PorterDuff.Mode.SRC);
    }

    /** Toggle button (Fluent): accent fill when selected, a subtle filled outline otherwise. */
    public static TextView chip(Context c, String label, boolean on, View.OnClickListener l) {
        TextView t = text(c, lower(label), 14, FG);
        GradientDrawable g = round(0, dp(c, 4));
        if (on) { int a = accentOnDark(c); g.setColor(a); t.setTextColor(onColor(a)); t.setTypeface(semibold()); }
        else { g.setColor(SUBTLE); g.setStroke(Math.max(1, dp(c, 1) / 2), CTRL_STROKE); }
        t.setBackground(g);
        t.setPadding(dp(c, 14), dp(c, 8), dp(c, 14), dp(c, 8));
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

    /** Fluent text box: subtle fill, 4dp corners, an accent underline while typing. */
    public static EditText field(Context c, String hint, String value) {
        final EditText e = new EditText(c);
        e.setHint(hint == null ? null : lower(hint));
        e.setText(value);
        e.setTextColor(FG);
        e.setHintTextColor(alpha(FG, 0.55f));
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setSingleLine();
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        final int r = dp(c, 4);
        final GradientDrawable fill = round(SUBTLE, r);
        fill.setStroke(Math.max(1, dp(c, 1) / 2), CTRL_STROKE);
        final GradientDrawable line = round(0, 0);
        final android.graphics.drawable.LayerDrawable bg = new android.graphics.drawable.LayerDrawable(new Drawable[]{fill, line});
        bg.setLayerGravity(1, Gravity.BOTTOM | Gravity.FILL_HORIZONTAL);
        bg.setLayerHeight(1, dp(c, 1));
        bg.setLayerInset(1, r / 2, 0, r / 2, 0);
        line.setColor(alpha(FG, 0.55f));
        e.setBackground(bg);
        e.setPadding(dp(c, 12), dp(c, 10), dp(c, 12), dp(c, 10));
        e.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override public void onFocusChange(View v, boolean has) {
                fill.setColor(has ? FIELD_FOCUS : SUBTLE);
                line.setColor(has ? accentOnDark(v.getContext()) : alpha(FG, 0.55f));
                bg.setLayerHeight(1, dp(v.getContext(), has ? 2 : 1));
            }
        });
        return e;
    }

    // ---------------------------------------------------------------- dialogs (Fluent ContentDialog)

    public interface Cb<T> { void on(T v); }

    /** AlertDialog restyled as a Fluent ContentDialog: centred rounded card, semibold title, button row on a darker footer. */
    public static AlertDialog.Builder dialog(final Context c) {
        return new AlertDialog.Builder(c, LIGHT ? android.R.style.Theme_DeviceDefault_Light_Dialog_Alert : android.R.style.Theme_DeviceDefault_Dialog_Alert) {
            @Override public AlertDialog create() {
                final AlertDialog d = super.create();
                android.view.Window w = d.getWindow();
                if (w != null) {
                    w.setBackgroundDrawable(new android.graphics.drawable.InsetDrawable(layer(c, LAYER), dp(c, 20), 0, dp(c, 20), 0));
                    w.setGravity(Gravity.CENTER);
                    w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    w.setWindowAnimations(0);
                    w.setDimAmount(0.55f);
                    w.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
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
            // Fluent dialog entrance: scales down from 105% while fading in
            View content = w.getDecorView();
            content.setScaleX(1.05f); content.setScaleY(1.05f);
            content.setAlpha(0f);
            content.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(250).setInterpolator(FLUENT).start();
            int tid = c.getResources().getIdentifier("alertTitle", "id", "android");
            TextView title = tid != 0 ? (TextView) d.findViewById(tid) : null;
            if (title != null) {
                title.setText(lower(String.valueOf(title.getText())));
                title.setTypeface(semibold());
                title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
                title.setTextColor(FG);
                title.setSingleLine(false);
            }
            TextView msg = (TextView) d.findViewById(android.R.id.message);
            if (msg != null) { msg.setTextColor(FG); msg.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14); msg.setLineSpacing(0, 1.15f); }
            ListView lv = d.getListView();
            if (lv != null) { lv.setDivider(null); lv.setSelector(round(PRESS, dp(c, 4))); }
            // Replace Android's button bar with Fluent buttons on the dialog's darker footer, side by side.
            LinearLayout bar = row(c);
            bar.setPadding(dp(c, 20), dp(c, 20), dp(c, 20), dp(c, 20));
            GradientDrawable foot = new GradientDrawable();
            foot.setColor(MICA);
            float r = dp(c, 8);
            foot.setCornerRadii(new float[]{0, 0, 0, 0, r, r, r, r});
            bar.setBackground(foot);
            View nativeBar = null;
            for (final int which : new int[]{DialogInterface.BUTTON_POSITIVE, DialogInterface.BUTTON_NEUTRAL, DialogInterface.BUTTON_NEGATIVE}) {
                final Button nb = d.getButton(which);
                if (nb == null) continue;
                if (nativeBar == null && nb.getParent() instanceof View) nativeBar = (View) nb.getParent();
                if (nb.getVisibility() != View.VISIBLE || TextUtils.isEmpty(nb.getText())) continue;
                TextView ours = button(c, String.valueOf(nb.getText()), which == DialogInterface.BUTTON_POSITIVE ? 0 : 1, new View.OnClickListener() {
                    @Override public void onClick(View v) { nb.performClick(); }
                });
                ours.setPadding(dp(c, 8), 0, dp(c, 8), 0);
                LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0, dp(c, 40), 1);
                blp.setMargins(bar.getChildCount() == 0 ? 0 : dp(c, 8), 0, 0, 0);
                bar.addView(ours, blp);
            }
            if (bar.getChildCount() > 0 && nativeBar != null) {
                View panel = (View) nativeBar.getParent(); // the scrolling "buttonPanel" around Android's bar
                int pid = c.getResources().getIdentifier("parentPanel", "id", "android");
                ViewGroup parent = pid != 0 ? (ViewGroup) d.findViewById(pid) : null;
                if (parent != null) {
                    (panel != null && panel.getParent() == parent ? panel : nativeBar).setVisibility(View.GONE);
                    LinearLayout.LayoutParams bl = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    bl.topMargin = dp(c, 16);
                    parent.addView(bar, bl);
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
