# Spike: an organisation's channels to the audit app, without INTERNET

Findings: [docs/spikes/2026-11-enterprise-channels.md](../../docs/spikes/2026-11-enterprise-channels.md).
Never released; built by hand.

The question: can the audit app's organisational edition take policy from an organisation's
device-management suite and report back to it, and see apps' connections, while it still holds no
INTERNET permission?

`android/` holds two debug apps:

- `controller` (`org.visadahyu.datapavan.enterprise.controller`): a stand-in for the suite's agent on
  the phone, its device policy controller. It becomes device owner over adb, sets the probe's managed
  configuration, delegates network logging to it, and logs the keyed app states it receives
  (androidx.enterprise:enterprise-feedback). `testOnly`, so that adb can remove it again.
- `probe` (`org.visadahyu.datapavan.enterprise.probe`): a stand-in for the audit app. It has **no
  INTERNET permission**. It reads its managed configuration, reports verdicts as keyed app states,
  and, once delegated, turns network logging on and reads the batches.

## Build and run

On an emulator with no accounts (device owner cannot be set over adb otherwise), started with
`-read-only` so that nothing is kept. The workload app of the packet-engine spike makes the
connections that the network log should show.

```sh
cd android && ../../../android/gradlew -p . assembleDebug
cd .. && ANDROID_SERIAL=emulator-5554 bash tools/run.sh android
```

`tools/run.sh` installs both apps, makes the controller device owner, runs six steps and removes the
controller again. It prints only the spike's own log lines.
