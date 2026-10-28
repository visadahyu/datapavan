# 0003. Minimum Android version 10 (API 29)

- Status: Accepted
- Date: 2026-10-28

## Context
The local VPN (v0.2) has to attribute each connection to an app. The only supported way is
`ConnectivityManager.getConnectionOwnerUid()`, which exists from Android 10. The lab device, a
Galaxy A40, runs Android 11.

## Decision
`minSdk = 29`. Compile and target SDK follow the latest stable platform (currently 37).

## Consequences
- Per-app attribution works on every supported device, with no fallback paths.
- Devices on Android 9 and older are not supported. That is a small and shrinking share, and those devices no longer receive security updates anyway.
