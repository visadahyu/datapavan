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
        String server = intent.getStringExtra("server");
        int listen = intent.getIntExtra("listen", 0);
        PendingResult result = goAsync();
        new Thread(() -> {
            if (listen > 0) Transfer.serve(listen, down, up);
            else Transfer.run(server, down, up);
            result.finish();
        }).start();
    }
}
