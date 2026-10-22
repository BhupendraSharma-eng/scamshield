package in.scamshield.guardian;

import android.app.Notification;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Reads incoming chat/email notifications (WhatsApp, Telegram, Gmail, Google Messages RCS…)
 * and checks each new message — the same proactive protection as SMS, for chat apps.
 */
public class NotificationGuard extends NotificationListenerService {
    private static final Map<String, String[]> APPS = new LinkedHashMap<>();
    static {
        // package → {label, channel}
        APPS.put("com.whatsapp", new String[] {"WhatsApp", "sms"});
        APPS.put("com.whatsapp.w4b", new String[] {"WhatsApp Business", "sms"});
        APPS.put("org.telegram.messenger", new String[] {"Telegram", "sms"});
        APPS.put("com.google.android.apps.messaging", new String[] {"Messages", "sms"});
        APPS.put("com.google.android.gm", new String[] {"Gmail", "email"});
        APPS.put("com.instagram.android", new String[] {"Instagram", "sms"});
        APPS.put("com.facebook.orca", new String[] {"Messenger", "sms"});
        APPS.put("com.android.shell", new String[] {"Test", "sms"});   // adb demo: `cmd notification post`
    }

    private final ExecutorService pool = Executors.newSingleThreadExecutor();
    /** Recently seen messages, so a re-posted/updated notification isn't checked twice. */
    private final Map<String, Long> seen = new LinkedHashMap<String, Long>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> e) {
            return size() > 200;
        }
    };

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        String[] app = APPS.get(sbn.getPackageName());
        if (app == null) return;
        Notification n = sbn.getNotification();
        if ((n.flags & Notification.FLAG_GROUP_SUMMARY) != 0) return;   // "5 new messages" summaries

        Bundle x = n.extras;
        CharSequence title = x.getCharSequence(Notification.EXTRA_TITLE);
        CharSequence big = x.getCharSequence(Notification.EXTRA_BIG_TEXT);
        CharSequence text = big != null ? big : x.getCharSequence(Notification.EXTRA_TEXT);
        if (text == null || text.length() < 8) return;

        String sender = title == null ? null : title.toString();
        String body = text.toString();
        if (body.matches("(?i)^\\d+ new messages?.*") || body.startsWith("Checking for new messages")) return;

        String key = sbn.getPackageName() + "|" + sender + "|" + body;
        synchronized (seen) {
            if (seen.containsKey(key)) return;
            seen.put(key, System.currentTimeMillis());
        }
        final String label = app[0];
        final String channel = app[1];
        pool.execute(() -> Guard.check(getApplicationContext(), channel, label, sender, body));
    }
}
