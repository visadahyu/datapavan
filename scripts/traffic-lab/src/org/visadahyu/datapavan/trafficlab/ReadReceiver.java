package org.visadahyu.datapavan.trafficlab;

import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.TrafficStats;
import android.os.Process;
import android.os.SystemClock;

import java.util.Map;
import java.util.TreeMap;

/**
 * Reads Android's network counts by UID with the call Datapavan makes (querySummary for mobile and
 * Wi-Fi with a null subscriber ID, ADR 0022), once for each window in the long array extras "starts"
 * and "ends" (an end of 0 or less means now), and the interface totals of TrafficStats just before.
 * The result data, which `adb shell am broadcast` prints, has one line per fact:
 *
 *   me UID | at WALL_MS ELAPSED_MS | totals RX TX MOBILE_RX MOBILE_TX | took WINDOW MS
 *   q WINDOW wifi|mobile UID STATE RX_BYTES TX_BYTES RX_PACKETS TX_PACKETS
 *
 * Needs usage access, given over adb (appops set ... GET_USAGE_STATS allow).
 */
public final class ReadReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        long[] starts = intent.getLongArrayExtra("starts");
        long[] ends = intent.getLongArrayExtra("ends");
        StringBuilder out = new StringBuilder();
        long now = System.currentTimeMillis();
        out.append("me ").append(Process.myUid()).append('\n');
        out.append("at ").append(now).append(' ').append(SystemClock.elapsedRealtime()).append('\n');
        out.append("totals ").append(TrafficStats.getTotalRxBytes()).append(' ').append(TrafficStats.getTotalTxBytes())
            .append(' ').append(TrafficStats.getMobileRxBytes()).append(' ').append(TrafficStats.getMobileTxBytes()).append('\n');
        NetworkStatsManager stats = context.getSystemService(NetworkStatsManager.class);
        for (int i = 0; starts != null && i < starts.length; i++) {
            long end = ends[i] > 0 ? ends[i] : now;
            long began = SystemClock.elapsedRealtime();
            query(stats, ConnectivityManager.TYPE_WIFI, "wifi", i, starts[i], end, out);
            query(stats, ConnectivityManager.TYPE_MOBILE, "mobile", i, starts[i], end, out);
            out.append("took ").append(i).append(' ').append(SystemClock.elapsedRealtime() - began).append('\n');
        }
        setResultData(out.toString());
    }

    @SuppressWarnings("deprecation") // The network types are the documented arguments of querySummary.
    private static void query(NetworkStatsManager stats, int type, String name, int window, long start, long end, StringBuilder out) {
        Map<String, long[]> totals = new TreeMap<>();
        try (NetworkStats buckets = stats.querySummary(type, null, start, end)) {
            NetworkStats.Bucket bucket = new NetworkStats.Bucket();
            while (buckets.getNextBucket(bucket)) {
                long[] sum = totals.computeIfAbsent(bucket.getUid() + " " + bucket.getState(), k -> new long[4]);
                sum[0] += bucket.getRxBytes();
                sum[1] += bucket.getTxBytes();
                sum[2] += bucket.getRxPackets();
                sum[3] += bucket.getTxPackets();
            }
        } catch (Exception e) {
            out.append("error ").append(window).append(' ').append(name).append(' ').append(e).append('\n');
            return;
        }
        for (Map.Entry<String, long[]> e : totals.entrySet()) {
            long[] s = e.getValue();
            out.append("q ").append(window).append(' ').append(name).append(' ').append(e.getKey())
                .append(' ').append(s[0]).append(' ').append(s[1]).append(' ').append(s[2]).append(' ').append(s[3]).append('\n');
        }
    }
}
