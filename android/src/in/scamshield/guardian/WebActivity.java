package in.scamshield.guardian;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** Hosts the ScamShield web UI (dashboard, history, scan detail) inside the app. */
public class WebActivity extends Activity {
    private WebView web;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        web = new WebView(this);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        String path = getIntent().getStringExtra("path");
        // Point the web UI at the same backend the app uses, then open the page
        String backend = Guard.backend(this).replace("'", "");
        String url = Guard.WEB_UI + (path == null ? "/" : path);
        web.setWebViewClient(new WebViewClient() {
            private boolean primed;
            @Override
            public void onPageFinished(WebView v, String u) {
                if (primed) return;
                primed = true;
                v.evaluateJavascript("(function(){var k='scamshield.apiBase',b='" + backend + "';"
                        + "if(localStorage.getItem(k)!==b){localStorage.setItem(k,b);location.reload();}})()", null);
            }
        });
        web.loadUrl(url);
        android.widget.FrameLayout frame = new android.widget.FrameLayout(this);
        frame.addView(web);
        Ui.fitSystemBars(frame);
        setContentView(frame);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }
}
