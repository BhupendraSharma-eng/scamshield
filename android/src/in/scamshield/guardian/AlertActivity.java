package in.scamshield.guardian;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

/** Full-screen STOP warning: verdict, risk, reasons, what to do. */
public class AlertActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        JSONObject v;
        try {
            v = new JSONObject(getIntent().getStringExtra("scan"));
        } catch (Exception e) {
            finish();
            return;
        }
        String verdict = v.optString("verdict");
        String source = getIntent().getStringExtra("source");
        String sender = getIntent().getStringExtra("sender");
        int color = Ui.verdictColor(verdict);
        boolean scam = "SCAM".equals(verdict);

        Window w = getWindow();
        w.setStatusBarColor(color);
        w.setNavigationBarColor(color);
        w.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON);

        LinearLayout root = Ui.column(this, 24);
        root.setBackgroundColor(color);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView icon = Ui.text(this, scam ? "🛑" : "⚠️", 64, 0xFFFFFFFF, false);
        icon.setGravity(Gravity.CENTER);
        root.addView(icon);
        TextView head = Ui.text(this, scam ? "STOP — this is a scam" : "Be careful — this looks suspicious", 28, 0xFFFFFFFF, true);
        head.setGravity(Gravity.CENTER);
        root.addView(head);
        String from = (source == null ? "Message" : source) + (sender == null || sender.isEmpty() ? "" : " from " + sender);
        TextView sub = Ui.text(this, from + " · " + Math.round(v.optDouble("risk") * 100) + "% scam risk", 16, 0xEEFFFFFF, false);
        sub.setGravity(Gravity.CENTER);
        sub.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 8));
        root.addView(sub);

        LinearLayout action = Ui.card(this);
        action.addView(Ui.text(this, "What to do", 14, Ui.INK2, true));
        action.addView(Ui.text(this, Guard.plain(v.optString("action")), 17, Ui.INK, true));
        root.addView(action);

        LinearLayout why = Ui.card(this);
        why.addView(Ui.text(this, "Why we flagged it", 14, Ui.INK2, true));
        JSONArray reasons = v.optJSONArray("reasons");
        for (int i = 0; reasons != null && i < reasons.length(); i++) {
            TextView r = Ui.text(this, (i + 1) + ".  " + Guard.plain(reasons.optString(i)), 15, Ui.INK, false);
            r.setPadding(0, Ui.dp(this, 6), 0, 0);
            why.addView(r);
        }
        JSONObject input = v.optJSONObject("input");
        if (input != null && !input.optString("text").isEmpty()) {
            TextView msg = Ui.text(this, "“" + input.optString("text") + "”", 14, Ui.INK2, false);
            msg.setPadding(0, Ui.dp(this, 12), 0, 0);
            why.addView(msg);
        }
        root.addView(why);

        android.widget.Button details = Ui.button(this, "See full analysis", 0xFFFFFFFF, color);
        details.setOnClickListener(x -> startActivity(new Intent(this, WebActivity.class)
                .putExtra("path", "/scan/" + v.optString("scan_id"))));
        root.addView(details);
        android.widget.Button ok = Ui.button(this, "I won't respond — close", 0x33FFFFFF, 0xFFFFFFFF);
        ok.setOnClickListener(x -> finish());
        root.addView(ok);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(color);
        scroll.setFillViewport(true);
        scroll.addView(root);
        Ui.fitSystemBars(scroll);
        setContentView(scroll);
    }
}
