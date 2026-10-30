package com.google.android.gms.ads.identifier;

/**
 * Inert: its name matches the class that reads Google's advertising ID through Google Play services
 * (data/sdk-needs, ADR 0021), so verify-audit.sh can check that a capability is marked when that
 * service is turned off. It reads nothing, and the fixture is never distributed.
 */
public final class AdvertisingIdClient {
    private AdvertisingIdClient() {}
}
