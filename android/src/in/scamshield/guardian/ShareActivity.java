package in.scamshield.guardian;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

/** "Share → Check with ScamShield" from any app: checks text or a link and shows the verdict. */
public class ShareActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String text = getIntent().getStringExtra(Intent.EXTRA_TEXT);
        if (text == null || text.trim().isEmpty()) {
            finish();
            return;
        }
        final String input = text.trim();
        final boolean isUrl = input.matches("(?is)^(https?://|www\\.)\\S+$") || input.matches("(?i)^[a-z0-9.-]+\\.[a-z]{2,}(/\\S*)?$");

        LinearLayout box = Ui.column(this, 24);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setMinimumWidth(Ui.dp(this, 300));
        ProgressBar spin = new ProgressBar(this);
        box.addView(spin);
        TextView status = Ui.text(this, "Checking with ScamShield…", 16, Ui.INK, true);
        status.setGravity(Gravity.CENTER);
        box.addView(status);
        setContentView(box);

        new Thread(() -> {
            JSONObject v = Guard.check(getApplicationContext(), isUrl ? "url" : "sms", "Shared " + (isUrl ? "link" : "message"), null, input);
            runOnUiThread(() -> show(box, spin, status, v));
        }, "scamshield-share").start();
    }

    private void show(LinearLayout box, ProgressBar spin, TextView status, JSONObject v) {
        box.removeView(spin);
        if (v == null) {
            status.setText("Couldn't reach the ScamShield server. Check your connection and try again.");
            return;
        }
        String verdict = v.optString("verdict");
        if (!"SAFE".equals(verdict)) {
            // Guard.check already raised the alert; open the full warning directly
            startActivity(new Intent(this, AlertActivity.class).putExtra("scan", v.toString())
                    .putExtra("source", "Shared message"));
            finish();
            return;
        }
        status.setText("✅ Looks safe · " + Math.round(v.optDouble("risk") * 100) + "% risk");
        status.setTextColor(Ui.GREEN);
        JSONArray reasons = v.optJSONArray("reasons");
        if (reasons != null && reasons.length() > 0) {
            TextView r = Ui.text(this, Guard.plain(reasons.optString(0)), 14, Ui.INK2, false);
            r.setPadding(0, Ui.dp(this, 8), 0, 0);
            box.addView(r);
        }
        box.addView(Ui.text(this, "\n" + Guard.plain(v.optString("action")), 13, Ui.INK3, false));
        android.widget.Button done = Ui.button(this, "Done", Ui.ACCENT, 0xFFFFFFFF);
        done.setOnClickListener(x -> finish());
        box.addView(done);
    }
}
