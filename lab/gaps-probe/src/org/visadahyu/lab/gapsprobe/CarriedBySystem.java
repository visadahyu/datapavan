package org.visadahyu.lab.gapsprobe;

import android.app.Activity;
import android.app.DownloadManager;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * carried-by-system: traffic that a component of Android carries for this app. "download" has the
 * download service fetch a fixed file from the lab's server; "tab" opens a page of the lab's server as
 * a Custom Tab, which the image's browser loads; "resolve" looks up names under .example (RFC 2606),
 * a new one each trial, so that no answer comes from a cache. The run reads which UID Watch was given
 * for each, against the capture.
 */
final class CarriedBySystem {
    private CarriedBySystem() {}

    static void run(Activity activity, String step, int trials) throws Exception {
        if (step.equals("download")) download(activity);
        else if (step.equals("tab")) tab(activity);
        else if (step.startsWith("resolve")) resolve(step, trials);
    }

    private static void download(Activity activity) throws InterruptedException {
        DownloadManager downloads = activity.getSystemService(DownloadManager.class);
        long id = downloads.enqueue(new DownloadManager.Request(Uri.parse("http://" + GapsProbe.LAB_HOST + ":8792/gaps/download"))
                .setDestinationInExternalFilesDir(activity, null, "gaps-download.bin"));
        for (int i = 0; i < 120; i++) {
            try (Cursor row = downloads.query(new DownloadManager.Query().setFilterById(id))) {
                if (row != null && row.moveToFirst()) {
                    int status = row.getInt(row.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS));
                    if (status == DownloadManager.STATUS_SUCCESSFUL || status == DownloadManager.STATUS_FAILED) {
                        GapsProbe.out("carried-by-system", "download", "answer=" + (status == DownloadManager.STATUS_SUCCESSFUL ? "done" : "failed")
                                + " bytes=" + row.getLong(row.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR))
                                + " reason=" + row.getInt(row.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON)));
                        return;
                    }
                }
            }
            Thread.sleep(500);
        }
        GapsProbe.out("carried-by-system", "download", "answer=timeout");
    }

    private static void tab(Activity activity) {
        Intent view = new Intent(Intent.ACTION_VIEW, Uri.parse("http://" + GapsProbe.LAB_HOST + ":8792/gaps/tab"));
        // The extra that makes a view intent a Custom Tab, from Custom Tabs' protocol, without its library.
        Bundle extras = new Bundle();
        extras.putBinder("android.support.customtabs.extra.SESSION", null);
        view.putExtras(extras);
        ResolveInfo handler = activity.getPackageManager().resolveActivity(view, 0);
        GapsProbe.out("carried-by-system", "tab", "handler=" + (handler == null ? "none" : handler.activityInfo.packageName));
        activity.startActivity(view);
    }

    private static void resolve(String step, int trials) throws InterruptedException {
        String run = Long.toString(System.nanoTime() & 0xffffffL, 36);
        for (int i = 0; i < trials; i++) {
            String name = "t" + i + "-" + run + ".gaps.example";
            String answer;
            try {
                InetAddress.getAllByName(name);
                answer = "address";
            } catch (UnknownHostException e) {
                answer = "none";
            }
            GapsProbe.out("carried-by-system", step, "trial=" + i + " name=" + name + " answer=" + answer);
            Thread.sleep(200);
        }
    }
}
