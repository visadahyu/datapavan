package io.sentry;

/**
 * Inert: its package matches the εxodus signature of the Sentry crash reporter, so verify-audit.sh
 * can check that the scanner finds a tracker in the fixture. The fixture is never distributed.
 */
public final class FixtureTrackerMarker {
    private FixtureTrackerMarker() {}
}
