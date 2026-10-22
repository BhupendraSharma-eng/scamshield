package in.scamshield.guardian;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Shared core: call the ScamShield backend, raise alerts, keep a short local history. */
public final class Guard {
    static final String TAG = "ScamShield";
    static final String DEFAULT_BACKEND = "https://dandruff-sneer-almanac.ngrok-free.dev";
    static final String WEB_UI = "https://bhupendrasharma-eng.github.io/scamshield";
    static final String CH_ALERTS = "scam_alerts";
    static final String CH_INFO = "checks";
    private static final int MAX_HISTORY = 30;

    private Guard() {}

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("scamshield", Context.MODE_PRIVATE);
    }

    static String backend(Context c) {
        String b = prefs(c).getString("backend", DEFAULT_BACKEND);
        return b.replaceAll("/+$", "");
    }

    /** Blocking HTTP call — never call on the main thread. Returns null on failure. */
    static JSONObject post(Context c, String path, JSONObject body) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(backend(c) + path).openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(6000);
            conn.setReadTimeout(12000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("ngrok-skip-browser-warning", "1");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.toString().getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            if (code >= 400) {
                Log.w(TAG, "backend HTTP " + code + " for " + path);
                return null;
            }
            return new JSONObject(readAll(conn.getInputStream()));
        } catch (Exception e) {
            Log.w(TAG, "backend call failed: " + e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    static JSONObject get(Context c, String path) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(backend(c) + path).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("ngrok-skip-browser-warning", "1");
            if (conn.getResponseCode() >= 400) return null;
            return new JSONObject(readAll(conn.getInputStream()));
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toString("UTF-8");
    }

    /**
     * Checks one message and alerts if it is SCAM/SUSPICIOUS.
     * @param source human label shown in the alert, e.g. "SMS", "WhatsApp"
     */
    static JSONObject check(Context c, String channel, String source, String sender, String text) {
        try {
            JSONObject body = new JSONObject();
            String path;
            if ("url".equals(channel)) {
                path = "/api/analyze/url";
                body.put("url", text.trim());
            } else if ("email".equals(channel)) {
                path = "/api/analyze/email";
                body.put("sender", sender);
                body.put("body", text);
            } else {
                path = "/api/analyze/sms";
                body.put("content", text);
                if (sender != null) body.put("sender", sender);
            }
            JSONObject v = post(c, path, body);
            if (v == null) return null;
            remember(c, source, sender, text, v);
            String verdict = v.optString("verdict");
            if (!"SAFE".equals(verdict)) notifyScam(c, source, sender, v);
            Log.i(TAG, source + " from " + sender + " → " + verdict + " " + v.optDouble("risk"));
            return v;
        } catch (Exception e) {
            Log.w(TAG, "check failed: " + e);
            return null;
        }
    }

    /** Incoming-call check: number intelligence (+ optional transcript) → alert if risky. */
    static JSONObject checkCall(Context c, String number, String transcript) {
        try {
            JSONObject body = new JSONObject();
            body.put("number", number);
            if (transcript != null) body.put("transcript", transcript);
            JSONObject v = post(c, "/api/analyze/call", body);
            if (v == null) return null;
            String shown = v.optString("number", number);
            remember(c, "Call", shown, transcript == null ? "Incoming call" : transcript, v);
            if (!"SAFE".equals(v.optString("verdict"))) notifyScam(c, "call", shown, v);
            Log.i(TAG, "call " + shown + " → " + v.optString("verdict") + " " + v.optDouble("risk"));
            return v;
        } catch (Exception e) {
            Log.w(TAG, "call check failed: " + e);
            return null;
        }
    }

    static void ensureChannels(Context c) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        NotificationChannel alerts = new NotificationChannel(CH_ALERTS, "Scam alerts", NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription("Warnings when a message or link looks like a scam");
        alerts.enableLights(true);
        alerts.setLightColor(Color.RED);
        alerts.enableVibration(true);
        alerts.setVibrationPattern(new long[] {0, 400, 200, 400});
        nm.createNotificationChannel(alerts);
        NotificationChannel info = new NotificationChannel(CH_INFO, "Check results", NotificationManager.IMPORTANCE_DEFAULT);
        info.setDescription("Results of messages you share to ScamShield");
        nm.createNotificationChannel(info);
    }

    static void notifyScam(Context c, String source, String sender, JSONObject v) {
        ensureChannels(c);
        boolean scam = "SCAM".equals(v.optString("verdict"));
        int pct = (int) Math.round(v.optDouble("risk") * 100);
        JSONArray reasons = v.optJSONArray("reasons");
        String reason = reasons != null && reasons.length() > 0 ? plain(reasons.optString(0)) : "";
        boolean call = "call".equals(source);
        String title = call
                ? (scam ? "📞⚠️ Likely scam call " : "📞⚠️ Suspicious call ") + (sender == null ? "" : sender) + " · " + pct + "%"
                : (scam ? "⚠️ Scam " : "⚠️ Suspicious ") + source + (sender != null && !sender.isEmpty() ? " from " + sender : "") + " · " + pct + "%";
        String body = (reason.isEmpty() ? "" : reason + "\n") + plain(v.optString("action"));

        Intent open = new Intent(c, AlertActivity.class)
                .putExtra("scan", v.toString())
                .putExtra("source", source)
                .putExtra("sender", sender)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int id = v.optString("scan_id").hashCode();
        PendingIntent pi = PendingIntent.getActivity(c, id, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification n = new Notification.Builder(c, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_alert)
                .setColor(scam ? 0xFFD03B3B : 0xFFFAB219)
                .setColorized(true)
                .setContentTitle(title)
                .setContentText(reason.isEmpty() ? plain(v.optString("action")) : reason)
                .setStyle(new Notification.BigTextStyle().bigText(body))
                .setCategory(call ? Notification.CATEGORY_CALL : Notification.CATEGORY_MESSAGE)
                .setContentIntent(pi)
                .setAutoCancel(true)
                .build();
        c.getSystemService(NotificationManager.class).notify(id, n);
    }

    /** Strips the backend's light markup (`code`, **bold**). */
    static String plain(String s) {
        return s == null ? "" : s.replace("**", "").replace("`", "");
    }

    static void remember(Context c, String source, String sender, String text, JSONObject v) {
        try {
            JSONArray old = new JSONArray(prefs(c).getString("history", "[]"));
            JSONArray next = new JSONArray();
            JSONObject e = new JSONObject();
            e.put("t", System.currentTimeMillis());
            e.put("source", source);
            e.put("sender", sender == null ? "" : sender);
            e.put("text", text.length() > 140 ? text.substring(0, 140) + "…" : text);
            e.put("verdict", v.optString("verdict"));
            e.put("risk", v.optDouble("risk"));
            e.put("scan_id", v.optString("scan_id"));
            next.put(e);
            for (int i = 0; i < old.length() && next.length() < MAX_HISTORY; i++) next.put(old.get(i));
            prefs(c).edit().putString("history", next.toString())
                    .putInt("checked", prefs(c).getInt("checked", 0) + 1)
                    .putInt("blocked", prefs(c).getInt("blocked", 0) + ("SAFE".equals(v.optString("verdict")) ? 0 : 1))
                    .apply();
        } catch (Exception ignored) {
            // history is best-effort
        }
    }
}
