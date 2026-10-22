package in.scamshield.guardian;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

/** Checks every incoming SMS as it arrives; alerts only when it looks like a scam. */
public class SmsReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        SmsMessage[] parts = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if (parts == null || parts.length == 0) return;

        // Multi-part SMS arrive as several PDUs from the same sender
        StringBuilder text = new StringBuilder();
        String sender = parts[0].getDisplayOriginatingAddress();
        for (SmsMessage m : parts) text.append(m.getDisplayMessageBody());

        final PendingResult pending = goAsync();
        final Context app = context.getApplicationContext();
        final String body = text.toString();
        new Thread(() -> {
            try {
                Guard.check(app, "sms", "SMS", sender, body);
            } finally {
                pending.finish();
            }
        }, "scamshield-sms").start();
    }
}
