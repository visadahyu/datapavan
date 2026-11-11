package org.visadahyu.datapavan.testtool;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;

/**
 * A launcher entry, so that Watch can see the test tool as it sees the apps a user can open. With the
 * extra "clip64" (Base64), it puts that text on the clipboard first, as a user copying a configuration would, so
 * that a real tool can import it (W6's lab, docs/spikes/2026-11-real-tools.md): only an app on screen
 * may write the clipboard.
 */
public final class ToolActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Base64, so that a configuration's quotes and braces survive adb's shell.
        String encoded = getIntent().getStringExtra("clip64");
        String clip = encoded == null ? null
                : new String(android.util.Base64.decode(encoded, android.util.Base64.DEFAULT), java.nio.charset.StandardCharsets.UTF_8);
        if (clip != null) {
            getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("config", clip));
        }
        finish();
    }
}
