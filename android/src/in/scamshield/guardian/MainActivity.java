package in.scamshield.guardian;

import android.Manifest;
import android.app.Activity;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.provider.Settings;
import android.text.format.DateUtils;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

/** Home: protection status, stats, recent checks, dashboard, demo alert, backend setting. */
public class MainActivity extends Activity {
    private LinearLayout root;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Guard.ensureChannels(this);
        getWindow().setStatusBarColor(Ui.PAGE);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        root = Ui.column(this, 20);
        root.setBackgroundColor(Ui.PAGE);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Ui.PAGE);
        scroll.setFillViewport(true);
        scroll.addView(root);
        Ui.fitSystemBars(scroll);
        setContentView(scroll);

        if (checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.RECEIVE_SMS, Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        render();
    }

    private boolean callRole() {
        android.app.role.RoleManager rm = getSystemService(android.app.role.RoleManager.class);
        return rm != null && rm.isRoleHeld(android.app.role.RoleManager.ROLE_CALL_SCREENING);
    }

    private void requestCallRole() {
        android.app.role.RoleManager rm = getSystemService(android.app.role.RoleManager.class);
        if (rm != null && rm.isRoleAvailable(android.app.role.RoleManager.ROLE_CALL_SCREENING)) {
            startActivityForResult(rm.createRequestRoleIntent(android.app.role.RoleManager.ROLE_CALL_SCREENING), 7);
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        render();
    }

    private boolean listenerEnabled() {
        String flat = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
        return flat != null && flat.contains(new ComponentName(this, NotificationGuard.class).flattenToString());
    }

    private void render() {
        root.removeAllViews();
        root.addView(Ui.text(this, "🛡️ ScamShield", 28, Ui.INK, true));
        root.addView(Ui.text(this, "Always-on protection for SMS, calls, WhatsApp, Telegram, Gmail and links.", 15, Ui.INK2, false));

        boolean sms = checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED;
        boolean notif = getSystemService(NotificationManager.class).areNotificationsEnabled();
        boolean chats = listenerEnabled();
        boolean all = sms && notif && chats && callRole();

        LinearLayout status = Ui.card(this);
        TextView head = Ui.text(this, all ? "✅ You're protected" : "⚠️ Protection is incomplete", 20, all ? Ui.GREEN : Ui.AMBER, true);
        status.addView(head);
        status.addView(row("SMS scanning", sms, v -> requestPermissions(new String[] {Manifest.permission.RECEIVE_SMS}, 2)));
        status.addView(row("WhatsApp / Telegram / Gmail scanning", chats,
                v -> startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))));
        status.addView(row("Scam call alerts", callRole(), v -> requestCallRole()));
        status.addView(row("Scam alerts", notif, v -> requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 3)));
        TextView server = Ui.text(this, "● Checking server…", 14, Ui.INK3, false);
        server.setPadding(0, Ui.dp(this, 10), 0, 0);
        status.addView(server);
        root.addView(status);
        new Thread(() -> {
            JSONObject h = Guard.get(this, "/api/health");
            runOnUiThread(() -> {
                if (h == null) {
                    server.setText("● Server offline — " + Guard.backend(this));
                    server.setTextColor(Ui.RED);
                } else {
                    JSONObject t1 = h.optJSONObject("tier1");
                    server.setText("● AI online · " + (t1 == null ? "" : t1.optString("model")));
                    server.setTextColor(Ui.GREEN);
                }
            });
        }).start();

        LinearLayout stats = Ui.card(this);
        stats.setOrientation(LinearLayout.HORIZONTAL);
        stats.addView(stat(String.valueOf(Guard.prefs(this).getInt("checked", 0)), "messages checked"));
        stats.addView(stat(String.valueOf(Guard.prefs(this).getInt("blocked", 0)), "scams flagged"));
        root.addView(stats);

        Button test = Ui.button(this, "Run a demo scam alert", Ui.RED, 0xFFFFFFFF);
        test.setOnClickListener(v -> {
            test.setEnabled(false);
            test.setText("Checking…");
            new Thread(() -> {
                Guard.check(getApplicationContext(), "sms", "SMS", "VM-SBIINB",
                        "Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN immediately: http://sbi-kyc-update.xyz/login");
                runOnUiThread(this::render);
            }).start();
        });
        root.addView(test);
        Button dash = Ui.button(this, "Open dashboard", Ui.ACCENT, 0xFFFFFFFF);
        dash.setOnClickListener(v -> startActivity(new Intent(this, WebActivity.class).putExtra("path", "/dashboard")));
        root.addView(dash);

        LinearLayout recent = Ui.card(this);
        recent.addView(Ui.text(this, "Recent checks", 16, Ui.INK, true));
        try {
            JSONArray h = new JSONArray(Guard.prefs(this).getString("history", "[]"));
            if (h.length() == 0) recent.addView(Ui.text(this, "Nothing yet — new SMS and chat messages are checked automatically.", 14, Ui.INK3, false));
            for (int i = 0; i < Math.min(h.length(), 12); i++) {
                JSONObject e = h.getJSONObject(i);
                recent.addView(historyRow(e));
            }
        } catch (Exception ignored) {
            // corrupted history: show nothing
        }
        root.addView(recent);

        LinearLayout cfg = Ui.card(this);
        cfg.addView(Ui.text(this, "Server", 16, Ui.INK, true));
        EditText url = new EditText(this);
        url.setText(Guard.backend(this));
        url.setSingleLine(true);
        url.setTextSize(14);
        cfg.addView(url);
        Button save = Ui.button(this, "Save server URL", 0xFFF2F1ED, Ui.INK);
        save.setOnClickListener(v -> {
            Guard.prefs(this).edit().putString("backend", url.getText().toString().trim()).apply();
            render();
        });
        cfg.addView(save);
        root.addView(cfg);
    }

    private View row(String label, boolean ok, View.OnClickListener fix) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);
        r.setPadding(0, Ui.dp(this, 10), 0, 0);
        TextView t = Ui.text(this, (ok ? "✓  " : "✗  ") + label, 15, ok ? Ui.INK : Ui.INK2, false);
        r.addView(t, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        if (!ok) {
            TextView enable = Ui.pill(this, "Enable", Ui.ACCENT);
            enable.setOnClickListener(fix);
            r.addView(enable);
        }
        return r;
    }

    private View stat(String n, String label) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.addView(Ui.text(this, n, 28, Ui.INK, true));
        c.addView(Ui.text(this, label, 13, Ui.INK2, false));
        c.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        return c;
    }

    private View historyRow(JSONObject e) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.VERTICAL);
        r.setPadding(0, Ui.dp(this, 12), 0, 0);
        String verdict = e.optString("verdict");
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.addView(Ui.pill(this, Ui.verdictLabel(verdict), Ui.verdictColor(verdict)));
        CharSequence when = DateUtils.getRelativeTimeSpanString(e.optLong("t"));
        String sender = e.optString("sender");
        TextView meta = Ui.text(this, "  " + e.optString("source") + (sender.isEmpty() ? "" : " · " + sender) + " · " + when, 12, Ui.INK3, false);
        top.addView(meta);
        r.addView(top);
        TextView body = Ui.text(this, e.optString("text"), 14, Ui.INK, false);
        body.setMaxLines(2);
        body.setPadding(0, Ui.dp(this, 4), 0, 0);
        r.addView(body);
        String id = e.optString("scan_id");
        r.setOnClickListener(v -> startActivity(new Intent(this, WebActivity.class).putExtra("path", "/scan/" + id)));
        return r;
    }
}
