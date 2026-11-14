package org.visadahyu.lab.gapsprobe;

import android.app.Activity;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * webview: a WebView in this app loads a page of the lab's server whose image and fetch come from a
 * second origin (the server's other port). The run reads which UID Watch was given for each origin.
 */
final class WebViewOrigin {
    private WebViewOrigin() {}

    static void load(Activity activity) {
        WebView view = new WebView(activity);
        // The page's fetch to the second origin is a script.
        view.getSettings().setJavaScriptEnabled(true);
        view.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView page, String url) {
                GapsProbe.out("webview", "page", "loaded");
            }
        });
        activity.setContentView(view);
        view.loadUrl("http://" + GapsProbe.LAB_HOST + ":8792/gaps/page");
    }
}
