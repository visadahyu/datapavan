package org.visadahyu.datapavan.proxyowner;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.net.ProxyInfo;
import android.net.Uri;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.util.Log;
import java.util.List;

/**
 * The proxy record's measurements 7.1 and 7.2 (scripts/measure-proxy-settings.sh): one action per start, by the extra
 * "action", as the device owner. Each logs "ACTION ok WHAT" or "ACTION failed WHY" under the tag DatapavanProxyOwner,
 * then "done":
 *
 * <ul>
 *   <li>{@code wifi-proxy} (extras "host", "port", and "exclusions", the proxy's exclusion list comma-separated, if
 *       any), {@code wifi-pac} ("url"), {@code wifi-none}: the saved Wi-Fi
 *       network "AndroidWifi" (the emulator's) gets that proxy of its own, or none, through
 *       {@code WifiConfiguration.setHttpProxy} and {@code WifiManager.updateNetwork}, which a device owner may do to a
 *       network another app saved;</li>
 *   <li>{@code global-proxy} ("host", "port"), {@code global-pac} ("url"), {@code global-none}: the global proxy,
 *       through {@code DevicePolicyManager.setRecommendedGlobalProxy};</li>
 *   <li>{@code state}: whether this app is the device owner, and the Wi-Fi network's proxy as saved;</li>
 *   <li>{@code release}: this app stops being the device owner.</li>
 * </ul>
 */
public class OwnerActivity extends Activity {
    private static final String TAG = "DatapavanProxyOwner";
    private static final String SSID = "\"AndroidWifi\"";

    /** A refusal that says why in a word or two, with nothing an app sent. */
    private static final class Refused extends Exception {
        Refused(String why) {
            super(why);
        }
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        final String action = String.valueOf(getIntent().getStringExtra("action"));
        new Thread(() -> {
            try {
                Log.i(TAG, action + " ok " + run(action));
            } catch (Refused e) {
                Log.i(TAG, action + " failed " + e.getMessage());
            } catch (Exception e) {
                Log.i(TAG, action + " failed " + e.getClass().getSimpleName());
            }
            Log.i(TAG, "done");
            runOnUiThread(this::finish);
        }).start();
    }

    private String extra(String name) {
        String value = getIntent().getStringExtra(name);
        return value == null ? "" : value;
    }

    private ProxyInfo direct() {
        String exclusions = extra("exclusions");
        if (exclusions.isEmpty()) return ProxyInfo.buildDirectProxy(extra("host"), Integer.parseInt(extra("port")));
        return ProxyInfo.buildDirectProxy(extra("host"), Integer.parseInt(extra("port")), java.util.Arrays.asList(exclusions.split(",")));
    }

    private ProxyInfo pac() {
        return ProxyInfo.buildPacProxy(Uri.parse(extra("url")));
    }

    private String run(String action) throws Exception {
        DevicePolicyManager policy = getSystemService(DevicePolicyManager.class);
        ComponentName admin = new ComponentName(this, OwnerReceiver.class);
        boolean owner = policy.isDeviceOwnerApp(getPackageName());
        if (action.equals("state")) return (owner ? "owner" : "not-owner") + " wifi=" + describe(saved().getHttpProxy());
        if (!owner) throw new Refused("not-owner");
        switch (action) {
            case "wifi-proxy": return wifi(direct());
            case "wifi-pac": return wifi(pac());
            case "wifi-none": return wifi(null);
            case "global-proxy":
                policy.setRecommendedGlobalProxy(admin, direct());
                return "set";
            case "global-pac":
                policy.setRecommendedGlobalProxy(admin, pac());
                return "set";
            case "global-none":
                policy.setRecommendedGlobalProxy(admin, null);
                return "cleared";
            case "release":
                policy.clearDeviceOwnerApp(getPackageName());
                return "released";
            default: throw new Refused("unknown-action");
        }
    }

    /**
     * The emulator's saved Wi-Fi network, as Android lists it to the device owner: by its SSID, or, where Android
     * hides the SSID, the emulator's network 0 when it is the only one saved.
     */
    @SuppressWarnings("deprecation")
    private WifiConfiguration saved() throws Refused {
        List<WifiConfiguration> networks = getSystemService(WifiManager.class).getConfiguredNetworks();
        for (WifiConfiguration network : networks) {
            if (SSID.equals(network.SSID)) return network;
        }
        if (networks.size() == 1 && networks.get(0).networkId == 0) return networks.get(0);
        throw new Refused("no-saved-network-of " + networks.size());
    }

    /**
     * The network's own proxy changed, and nothing else. Android lists the network to the device owner with its MAC
     * randomization masked, and refuses an update that changes it, which only the Settings app may (dp-api35-ci,
     * 2026-11-24: "does not have permission to modify MAC randomization Settings"): so the update is tried with the
     * listed setting first, then with each other one, and says which Android took.
     */
    @SuppressWarnings("deprecation")
    private String wifi(ProxyInfo proxy) throws Refused {
        WifiConfiguration network = saved();
        network.setHttpProxy(proxy);
        // Below API 33 Android has no MAC randomization setting to mask (Android 10, the unit S2's run once there).
        if (android.os.Build.VERSION.SDK_INT < 33) {
            int id = getSystemService(WifiManager.class).updateNetwork(network);
            if (id >= 0) return "network " + id + " saved=" + describe(saved().getHttpProxy());
            throw new Refused("update-refused");
        }
        int listed = network.getMacRandomizationSetting();
        int[] settings = {listed, WifiConfiguration.RANDOMIZATION_AUTO, WifiConfiguration.RANDOMIZATION_PERSISTENT,
            WifiConfiguration.RANDOMIZATION_NON_PERSISTENT, WifiConfiguration.RANDOMIZATION_NONE};
        for (int setting : settings) {
            network.setMacRandomizationSetting(setting);
            int id = getSystemService(WifiManager.class).updateNetwork(network);
            if (id >= 0) return "network " + id + " mac=" + listed + "->" + setting + " saved=" + describe(saved().getHttpProxy());
        }
        throw new Refused("update-refused");
    }

    static String describe(ProxyInfo proxy) {
        if (proxy == null) return "none";
        Uri pac = proxy.getPacFileUrl();
        if (pac != null && !Uri.EMPTY.equals(pac)) return "pac:" + pac + "@" + proxy.getPort();
        String[] excluded = proxy.getExclusionList();
        return proxy.getHost() + ":" + proxy.getPort() + (excluded == null || excluded.length == 0 ? "" : " except=" + String.join(",", excluded));
    }
}
