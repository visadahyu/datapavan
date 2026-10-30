package com.pawns.sdk;

/**
 * Inert: its package matches Datapavan's identifier for the Pawns traffic-sharing SDK (data/sdks,
 * ADR 0019), so verify-audit.sh can check that the scanner finds it. It shares nothing, and the
 * fixture is never distributed.
 */
public final class FixtureTrafficMarker {
    private FixtureTrafficMarker() {}
}
