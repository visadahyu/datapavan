#!/usr/bin/env bash
# The emulator's networks, for the checks that switch the network beneath Watch (scripts/verify-watch.sh, and since
# W7's fix round scripts/verify-wireguard.sh): Android's default network and its list, whether a type is up, waits
# until mobile data and Wi-Fi are up and settled, and Wi-Fi brought back where the emulator lost it. Sourced; uses
# adb on the device ANDROID_SERIAL names.
#
#   . scripts/emulator-networks.sh

# Android's default network, and its networks as `id TYPE STATE` by semicolons. Read whole: under pipefail, a
# grep -q that stops reading early fails the pipe.
default_network() {
    adb shell dumpsys connectivity | tr -d '\r' | sed -n 's/^Active default network: //p'
}
networks() {
    adb shell dumpsys connectivity | tr -d '\r' |
        sed -n 's/^ *NetworkAgentInfo{network{\([0-9]*\)}.*ni{\([^ ]*\) \([A-Z]*\).*/\1 \2 \3/p' | paste -sd ';'
}
# Whether the network type $1 is connected, in the list $2 or in Android's list now.
up() {
    grep -qE "(^|;)[0-9]+ $1[^ ;]* CONNECTED" <<<"${2:-$(networks)}"
}
# Waits up to $1 seconds for mobile data, and for Wi-Fi too when $2 is "wifi".
wait_up() {
    for _ in $(seq 1 $(($1 / 2))); do
        up MOBILE && { [ "${2:-}" != wifi ] || up WIFI; } && return 0
        sleep 2
    done
    up MOBILE && { [ "${2:-}" != wifi ] || up WIFI; }
}
# Waits up to $1 seconds until mobile data and Wi-Fi are both up and Android's list of networks has
# stayed the same over four reads two seconds apart. After airplane mode the radios came back and then
# replaced their networks once more while Watch ran (CI, 2026-11-14); Watch starts over networks that
# have stopped changing.
wait_settled() {
    local deadline=$((SECONDS + $1)) last="" now steady=0
    while :; do
        now=$(networks)
        if up MOBILE "$now" && up WIFI "$now" && [ "$now" = "$last" ]; then
            steady=$((steady + 1))
            [ "$steady" -ge 3 ] && return 0
        else
            steady=0
        fi
        last=$now
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 2
    done
}
# What the emulator's Wi-Fi says of itself, on one line: on or off, and the network it is joined to.
wifi_state() {
    adb shell cmd wifi status 2>/dev/null | tr -d '\r' | grep -E '^Wifi is (enabled|disabled|connected|not connected)' |
        paste -sd ';' || true
}
# The emulator's Wi-Fi did not come up before Watch started once (CI, 2026-11-14), and did not come back
# after the switch turned it on again three times (CI, 2026-11-16, 2026-11-18 and 2026-11-19): Android
# listed mobile data and no Wi-Fi, and the next attempt passed. So before either check fails, Wi-Fi is
# brought back, waited for again within the same bound, and the run says so (docs/ci-flakes.md). Only when
# Wi-Fi is not up: networks that are up and still changing are waited for, not toggled. Turning Wi-Fi off
# and on alone did not bring it back on 2026-11-19; on the emulator, Wi-Fi on but joined to no network
# stays so through that, and comes back within seconds when told to join the emulator's own open access
# point, AndroidWifi, by name (`cmd wifi connect-network`, Android 11 and later). So it joins that network
# first, and only if Wi-Fi is still not up 20 s later turns it off and on and joins once more.
wifi_again() {
    up WIFI && return 0
    echo "  no Wi-Fi after $1 s ($(networks); $(wifi_state)): joining the emulator's own Wi-Fi network"
    adb shell cmd wifi set-wifi-enabled enabled >/dev/null 2>&1 || adb shell svc wifi enable
    adb shell cmd wifi connect-network AndroidWifi open >/dev/null 2>&1 || true
    for _ in $(seq 1 10); do
        up WIFI && return 0
        sleep 2
    done
    echo "  still no Wi-Fi ($(networks); $(wifi_state)): turning it off and on, and joining once more"
    adb shell svc wifi disable
    sleep 2
    adb shell svc wifi enable
    sleep 3
    adb shell cmd wifi connect-network AndroidWifi open >/dev/null 2>&1 || true
}

# The emulator came up with Wi-Fi and without its mobile data network, and turning mobile data off and on did not
# bring it, four runs out of five (CI, 2026-11-20 and 2026-11-21: runs 44796928789, 44877347782, 44899858955 and
# 44905337897, in the WireGuard check; docs/ci-flakes.md). So before a check fails for it, the radios are restarted
# with airplane mode, as verify-watch.sh has done since 2026-11-12; then the emulator's modem is told to register
# again through the emulator's console (`gsm voice home`, `gsm data home`); and only if mobile data is still not up
# is the emulator booted anew, once, and waited for. Only where mobile data is not up, and only before Watch starts:
# nothing of Watch's state is lost by it. Returns whether mobile data came up.
mobile_again() {
    up MOBILE && return 0
    echo "  no mobile data ($(networks)): restarting the radios with airplane mode"
    adb shell cmd connectivity airplane-mode enable
    sleep 5
    adb shell cmd connectivity airplane-mode disable
    wait_up 60 && return 0
    echo "  still no mobile data ($(networks)): registering the emulator's modem again"
    adb emu gsm voice home >/dev/null 2>&1 || true
    adb emu gsm data home >/dev/null 2>&1 || true
    adb shell svc data enable
    wait_up 60 && return 0
    echo "  still no mobile data ($(networks)): booting the emulator anew"
    adb reboot
    adb wait-for-device
    for _ in $(seq 1 90); do
        [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
        sleep 2
    done
    adb shell svc data enable
    wait_up 120
}
