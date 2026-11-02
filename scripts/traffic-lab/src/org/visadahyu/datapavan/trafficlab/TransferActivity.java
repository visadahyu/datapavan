package org.visadahyu.datapavan.trafficlab;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** Moves the bytes in the extras "down" and "up" while on screen, then closes. */
public final class TransferActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setText("Moving data");
        setContentView(text);
        long down = getIntent().getLongExtra("down", 0);
        long up = getIntent().getLongExtra("up", 0);
        new Thread(() -> {
            Transfer.run(down, up);
            runOnUiThread(this::finish);
        }).start();
    }
}
