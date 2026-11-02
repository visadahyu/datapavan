package org.visadahyu.datapavan.trafficlab;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Moves the bytes in the extras "down" and "up" with nothing on screen: background use. */
public final class TransferReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        long down = intent.getLongExtra("down", 0);
        long up = intent.getLongExtra("up", 0);
        PendingResult result = goAsync();
        new Thread(() -> {
            Transfer.run(down, up);
            result.finish();
        }).start();
    }
}
