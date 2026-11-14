package org.visadahyu.lab.gapsprobe;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * vpn-seen: what an app with ACCESS_NETWORK_STATE, a normal permission, sees of a VPN. The step names
 * the phase: "none" (no VPN), "inside" (in Watch's tunnel) or "left-out" (excluded from it). One line for
 * the app's own network, one for each network getAllNetworks lists, one for each interface.
 */
final class VpnSeen {
    private VpnSeen() {}

    static void run(Context context, String phase) throws Exception {
        ConnectivityManager connectivity = context.getSystemService(ConnectivityManager.class);
        GapsProbe.out("vpn-seen", phase, "active " + describe(connectivity, connectivity.getActiveNetwork()));
        for (Network network : connectivity.getAllNetworks()) {
            GapsProbe.out("vpn-seen", phase, "network " + describe(connectivity, network));
        }
        for (NetworkInterface face : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            List<String> addresses = new ArrayList<>();
            for (InterfaceAddress address : face.getInterfaceAddresses()) {
                addresses.add(address.getAddress().getHostAddress() + "/" + address.getNetworkPrefixLength());
            }
            GapsProbe.out("vpn-seen", phase, "interface name=" + face.getName() + " up=" + face.isUp()
                    + " addresses=" + list(addresses));
        }
    }

    private static String describe(ConnectivityManager connectivity, Network network) {
        if (network == null) return "none";
        NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
        LinkProperties link = connectivity.getLinkProperties(network);
        List<String> transports = new ArrayList<>();
        if (caps != null) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transports.add("vpn");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transports.add("wifi");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transports.add("cellular");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transports.add("ethernet");
        }
        String line = "transports=" + (caps == null ? "unreadable" : list(transports))
                + " not_vpn=" + (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
        if (link == null) return line + " link=unreadable";
        List<String> addresses = new ArrayList<>();
        for (LinkAddress address : link.getLinkAddresses()) addresses.add(address.toString());
        List<String> dns = new ArrayList<>();
        for (InetAddress server : link.getDnsServers()) dns.add(server.getHostAddress());
        return line + " iface=" + link.getInterfaceName() + " addresses=" + list(addresses)
                + " routes=" + link.getRoutes().size() + " dns=" + list(dns);
    }

    private static String list(List<String> values) {
        return values.isEmpty() ? "-" : GapsProbe.word(String.join(",", values));
    }
}
