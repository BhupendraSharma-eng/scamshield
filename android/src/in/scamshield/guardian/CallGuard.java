package in.scamshield.guardian;

import android.net.Uri;
import android.telecom.Call;
import android.telecom.CallScreeningService;

/**
 * Sees each incoming call's number as it starts ringing (call-screening role). Never blocks or
 * delays the call: it lets it through immediately, then checks the number and raises a warning
 * while the phone is still ringing.
 */
public class CallGuard extends CallScreeningService {
    @Override
    public void onScreenCall(Call.Details details) {
        respondToCall(details, new CallResponse.Builder().build());   // allow, untouched
        if (details.getCallDirection() != Call.Details.DIRECTION_INCOMING) return;

        Uri handle = details.getHandle();
        String number = handle == null ? "" : handle.getSchemeSpecificPart();
        if (details.getHandlePresentation() != android.telecom.TelecomManager.PRESENTATION_ALLOWED) number = "hidden";
        final String n = number;
        new Thread(() -> Guard.checkCall(getApplicationContext(), n, null), "scamshield-call").start();
    }
}
