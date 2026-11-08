# Spike: an organisation's channels to the audit app, without INTERNET

2026-11-08. Code: [spikes/enterprise-channels/](../../spikes/enterprise-channels/README.md). For the
organisational edition beside a device-management suite ([ADR 0033](../decisions/0033-organisational-edition-beside-a-suite.md)).

## Question

The audit app holds no INTERNET permission, and its organisational edition must keep that promise.
Can it still work with an organisation's device-management suite through Android's own channels on
the phone?

1. **Policy in:** managed configurations (app restrictions), set by the suite's agent.
2. **Verdicts out:** keyed app states (`androidx.enterprise:enterprise-feedback`), sent over local IPC
   to the suite's agent, the device policy controller, which uploads them to its console.
3. **Connections seen without a VPN:** the suite delegates network logging to the app
   (`DevicePolicyManager.DELEGATION_NETWORK_LOGGING`), and Android hands it DNS and connect events.

## Method

A stand-in for the suite's agent (`controller`, device owner over adb) and a stand-in for the audit app
(`probe`, no INTERNET permission). Emulators with no accounts: Android 11 and 15 (Google APIs images,
started read-only) and a fresh Android 17 image (deleted afterwards). The packet-engine spike's workload
app made three TCP connections to example.com while network logging was on.

## Results

| Step | Android 11 | Android 15 | Android 17 |
|---|---|---|---|
| The probe holds no INTERNET permission | yes | yes | yes |
| Managed configuration in (a choice, a boolean and a string) | arrived | arrived | arrived |
| A verdict out with `setStatesImmediate` | arrived | arrived | arrived |
| A verdict out with `setStates` (batched) | arrived | arrived | not seen within 10 s |
| Limits: key 100, message 1,000, data 1,000 characters | at the limit arrived; one over is refused when the state is built | same | same |
| 50 states in one call | all 50 arrived | all 50 | all 50 |
| Network logging delegated; the delegate turns it on itself | yes | yes | yes |
| A batch read by the probe, which has no INTERNET | yes | yes | yes |
| DNS events: app, name and every resolved address | yes | app and name (addresses not printed) | yes |
| Connect events: app, address and port | yes | app only: every event read `::1`, port 0 | yes |

- **All three channels work without INTERNET.** Policy comes in, verdicts go out and an app's
  connections come in, all through Android on the phone. The audit app's promise holds for its
  organisational edition.
- **The network log names the app.** Each DNS and connect event carries the package name, so on a
  managed phone the audit app can show who talked to whom without a VPN and without taking the
  phone's one VPN slot. On the Android 11 emulator, a preinstalled app's lookup of an advertising
  domain appeared in the first batch.
- **A success status is not a receipt.** On an emulator where the controller could not become device
  owner, `setStates` still reported success: with no device policy controller the library has no one
  to deliver to. The app has to treat a verdict as sent, not as received.
- **The batched call can lag.** On Android 17, `setStates` did not arrive within ten seconds, while
  `setStatesImmediate` did. The immediate call is rate-limited by the library, so it is for changes of
  verdict, not for routine reports.
- **The Android 15 emulator's connect events had no destination** (`::1`, port 0) for every app; on
  11 and 17 they had the real address and port. To check on a real Android 15 phone before relying on
  connect events there.
- **Device owner over adb needs a phone with no accounts.** Real deployments use the suite's own
  enrolment (QR code, zero-touch, Knox Mobile Enrollment), which this spike does not test.

## Not tested here

- Whether each suite shows keyed app states to its admins, and can delegate network logging to a
  third-party app: a documentation study, summed up in ADR 0033 (most suites show the states, Intune
  does not document them; Google's API, Intune and Scalefusion document delegating the log).
- A work profile (network logging there needs Android 12), real phones of several makers, and what
  the user sees while network logging is on.
- UDP and QUIC: by Android's documentation, the network log records DNS lookups through the system
  resolver and TCP connects only, so apps' own encrypted DNS and QUIC do not appear as such.
