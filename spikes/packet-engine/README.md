# Packet-engine spike (ADR 0012)

Throwaway code that picks the packet engine for Datapavan Watch, the separate VPN app of v0.2
(ADR 0029, [docs/VPN.md](../../docs/VPN.md)). Nothing here is released or built by CI; the engine
that wins moves into Watch's own module. Findings: [docs/spikes/2026-11-packet-engine.md](../../docs/spikes/2026-11-packet-engine.md).

Three engines behind one surface (`PacketEngine` in Kotlin: start on the tunnel's descriptor, stop,
counters):

1. `userspace`: a userspace TCP/IP stack in Rust (`ipstack`), `rust/engine/src/userspace.rs`.
2. `system`: Android's own TCP stack, reached by rewriting addresses and ports, as the "system" stack
   of sing-box and mihomo; the rewriting is in safe Rust, `rust/engine/src/system.rs`.
3. `gvisor`: Go's gVisor netstack, through gomobile (`go/`, once built).

`android/` holds two debug apps: `watch` (the `VpnService`, `org.visadahyu.datapavan.watch.spike`)
and `load` (the workload whose traffic the tunnel carries, `org.visadahyu.datapavan.watch.load`).
Only the apps named in the start command go through the tunnel, the workload by default, so no
other app's traffic is touched. `tools/server.py` is the test server on the development computer,
`tools/measure.sh` one measuring round.

## Build and run

```sh
cd rust && cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 --platform 29 -o ../android/watch/build/rustJniLibs build --release
cd ../android && ../../../android/gradlew -p . assembleDebug   # the main build's wrapper: no second wrapper jar in the tree
python3 -I ../tools/server.py 8790 &
export ANDROID_SERIAL=emulator-5556
adb install -r watch/build/outputs/apk/debug/watch-debug.apk
adb install -r load/build/outputs/apk/debug/load-debug.apk
adb shell appops set org.visadahyu.datapavan.watch.spike ACTIVATE_VPN allow   # emulators only
adb shell pm grant org.visadahyu.datapavan.watch.spike android.permission.ACCESS_LOCAL_NETWORK
adb shell pm grant org.visadahyu.datapavan.watch.load android.permission.ACCESS_LOCAL_NETWORK
cd .. && tools/measure.sh none && tools/measure.sh userspace && tools/measure.sh system
```

On a phone, set `HOST` to the computer's address on the same Wi-Fi and give the VPN consent on the
phone's own screen.
