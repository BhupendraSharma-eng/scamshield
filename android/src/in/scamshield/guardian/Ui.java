package in.scamshield.guardian;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Tiny view helpers so screens can be built in code (no layout XML / AndroidX). */
final class Ui {
    static final int RED = 0xFFD03B3B, AMBER = 0xFFFAB219, GREEN = 0xFF0CA30C, ACCENT = 0xFF2A78D6;
    static final int INK = 0xFF0B0B0B, INK2 = 0xFF52514E, INK3 = 0xFF898781, PAGE = 0xFFF9F9F7, CARD = 0xFFFFFFFF;

    private Ui() {}

    static int dp(Context c, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics());
    }

    static LinearLayout column(Context c, int padDp) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        int p = dp(c, padDp);
        l.setPadding(p, p, p, p);
        return l;
    }

    static TextView text(Context c, CharSequence s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setLineSpacing(0, 1.15f);
        return t;
    }

    static LinearLayout card(Context c) {
        LinearLayout l = column(c, 16);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(c, 16));
        bg.setStroke(dp(c, 1), 0x1A0B0B0B);
        l.setBackground(bg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(c, 12);
        l.setLayoutParams(lp);
        return l;
    }

    static Button button(Context c, String label, int bg, int fg) {
        Button b = new Button(c);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(fg);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        GradientDrawable d = new GradientDrawable();
        d.setColor(bg);
        d.setCornerRadius(dp(c, 14));
        b.setBackground(d);
        b.setMinHeight(dp(c, 52));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(c, 10);
        b.setLayoutParams(lp);
        return b;
    }

    static TextView pill(Context c, String s, int color) {
        TextView t = text(c, s, 13, color, true);
        GradientDrawable d = new GradientDrawable();
        d.setColor((color & 0x00FFFFFF) | 0x22000000);
        d.setCornerRadius(dp(c, 999));
        t.setBackground(d);
        t.setPadding(dp(c, 10), dp(c, 4), dp(c, 10), dp(c, 4));
        t.setGravity(Gravity.CENTER_VERTICAL);
        return t;
    }

    /** Android 15+ draws edge-to-edge: pad content clear of the status and navigation bars. */
    static void fitSystemBars(android.view.View v) {
        final int l = v.getPaddingLeft(), t = v.getPaddingTop(), r = v.getPaddingRight(), b = v.getPaddingBottom();
        v.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars()
                    | android.view.WindowInsets.Type.displayCutout());
            view.setPadding(l + bars.left, t + bars.top, r + bars.right, b + bars.bottom);
            return insets;
        });
        v.requestApplyInsets();
    }

    static int verdictColor(String v) {
        return "SCAM".equals(v) ? RED : "SUSPICIOUS".equals(v) ? AMBER : GREEN;
    }

    static String verdictLabel(String v) {
        return "SCAM".equals(v) ? "Scam" : "SUSPICIOUS".equals(v) ? "Suspicious" : "Looks safe";
    }
}
