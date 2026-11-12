# Shared helpers for the adb-driven checks and the Google Play readers. Sourced, not executed.
# They read the screen through uiautomator, so they need no test framework in the app.

DUMP=/sdcard/datapavan-ui.xml

# True on an emulator, which holds nothing of anyone's.
is_emulator() {
    [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" = 1 ] || [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ]
}

# Reads the screen into $DUMP. On a slow emulator Android can put an "isn't responding" dialog over
# anything: on CI the launcher hangs behind the app in about half the runs. For another app's process
# that says nothing about ours, so the dialog is answered and the screen read again. Wait only closes
# the dialog: a process that stays hung brings it back within seconds, and it can take a tap meant for
# the app. So on an emulator the hung process is closed and starts afresh; on a phone, someone's app is
# left running. A dialog for one of our own processes, or for one that cannot be named, stays on screen,
# so that the check waiting for the app fails and shows it. The resource id and the window title are the
# same in every language.
dump_screen() {
    local screen owner button
    for _ in 1 2 3; do
        adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
        screen=$(adb shell cat "$DUMP" 2>/dev/null) || return 1
        case $screen in
            *'resource-id="android:id/aerr_wait"'*) ;;
            *) return 0 ;;
        esac
        owner=$(adb shell dumpsys window 2>/dev/null | tr -d '\r' |
            sed -n 's/.*mCurrentFocus=.*Application Not Responding: \([^}]*\)}.*/\1/p' | head -1) || owner=""
        case $owner in
            "" | org.visadahyu.datapavan*) return 0 ;;
        esac
        button=wait
        is_emulator && button=close
        echo "Answering $button to Android's dialog for $owner" >&2
        tap_dumped_id "android:id/aerr_$button" || return 0
        sleep 1
    done
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1
}

# The attributes of the package $1's window, as Android's window manager lists them: from "mAttrs={" to
# its closing brace, over several lines on recent versions. The dump is read whole, and nothing below stops
# reading early: under pipefail, a command cut off by SIGPIPE would fail the check while the flag is there
# (CI, 2026-11-12, where the dump outgrows a pipe's buffer).
window_attrs() {
    local dump
    dump=$(adb shell dumpsys window windows 2>/dev/null | tr -d '\r') || return 1
    awk -v app="$1/" 'done { next }
        index($0, "Window{") { inside = index($0, app) > 0 }
        inside && /mAttrs=/ { attrs = 1 }
        inside && attrs { print; if (/}$/) done = 1 }' <<<"$dump"
}

# True when the package $1's window is protected from screenshots and screen recording (FLAG_SECURE,
# ADR 0040): SECURE among the window's flags (fl=).
window_secure() {
    local attrs
    attrs=$(window_attrs "$1") || return 1
    grep -o -E '(^|[^p])fl=[A-Z_ ]+' <<<"$attrs" | grep -w SECURE >/dev/null
}

# True when Android hides other apps' overlays over the package $1's window (Android 12 and later,
# ADR 0040): HIDE_NON_SYSTEM_OVERLAY_WINDOWS among its private flags (pfl=).
window_hides_overlays() {
    local attrs
    attrs=$(window_attrs "$1") || return 1
    grep -o -E 'pfl=[A-Z_ ]+' <<<"$attrs" | grep -w HIDE_NON_SYSTEM_OVERLAY_WINDOWS >/dev/null
}

# True when an element whose text starts with $1 is on screen.
screen_has() {
    dump_screen || return 1
    adb shell cat "$DUMP" 2>/dev/null | grep -q "text=\"$1"
}

# Scrolls the list down by about half a screen.
swipe_up() {
    local size width height
    size=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1)
    width=${size% *}
    height=${size#* }
    adb shell input swipe $((width / 2)) $((height * 3 / 4)) $((width / 2)) $((height / 4)) 300
    sleep 1
}

# Lists only compose what is on screen, so scroll down (up to six times) until the text shows.
scroll_to() {
    for _ in 1 2 3 4 5 6; do
        screen_has "$1" && return 0
        swipe_up
    done
    screen_has "$1"
}

# Scrolls back to the top of a list.
scroll_to_top() {
    local size width height
    size=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1)
    width=${size% *}
    height=${size#* }
    for _ in 1 2 3 4 5 6 7 8; do
        adb shell input swipe $((width / 2)) $((height / 4)) $((width / 2)) $((height * 3 / 4)) 200
    done
}

# Bounds of the first element whose text is exactly $1 in the last dump, as "left top right bottom".
text_bounds() {
    adb shell cat "$DUMP" | grep -o "text=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' '
}

# Taps the centre of the first element whose text is exactly $1, scrolling to it first. A list can
# still be moving after a swipe, and a tap would then hit another row, so it taps only once the
# element is in the same place in two dumps a second apart.
tap_text() {
    local text=$1
    scroll_to "$text" || return 1
    local bounds previous=""
    for _ in 1 2 3 4 5; do
        bounds=$(text_bounds "$text")
        [ -n "$bounds" ] && [ "$bounds" = "$previous" ] && break
        previous=$bounds
        sleep 1
        dump_screen || true
    done
    [ -n "$bounds" ] && [ "$bounds" = "$previous" ] || return 1
    set -- $bounds
    # An element at the bottom edge lies under the gesture bar, which takes the tap: move it up first.
    local height
    height=$(adb shell wm size | tr -d '\r' | sed -n 's/.*x\([0-9]*\)$/\1/p' | tail -1)
    if [ "$4" -gt $((height * 7 / 8)) ]; then
        adb shell input swipe $(( ($1 + $3) / 2 )) $((height * 3 / 5)) $(( ($1 + $3) / 2 )) $((height * 2 / 5)) 300
        sleep 1
        dump_screen || true
        bounds=$(text_bounds "$text")
        [ -n "$bounds" ] || return 1
        set -- $bounds
    fi
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# Taps the centre of the first element whose content description is exactly $1: icons have no text.
tap_desc() {
    dump_screen || return 1
    local bounds
    bounds=$(adb shell cat "$DUMP" | grep -o "content-desc=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# Taps the centre of the first element whose resource-id is $1. The app names its navigation with
# Compose test tags shown as resource ids (ADR 0027), so a script can move around in any language.
tap_id() {
    dump_screen || return 1
    tap_dumped_id "$1"
}

# Taps the centre of the first element whose resource-id is $1 in the last dump.
tap_dumped_id() {
    local bounds
    bounds=$(adb shell cat "$DUMP" | grep -o "resource-id=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# True when the element whose resource-id is $1 is on screen and selected, as a navigation tab is.
selected_id() {
    dump_screen || return 1
    adb shell cat "$DUMP" 2>/dev/null | grep -o "resource-id=\"$1\"[^>]*" | grep -q 'selected="true"'
}

# Opens a destination of the navigation bar: summary, apps, phone or network. The bar is missing
# while the audit loads, also when the activity restarts because the app's language arrived late, so
# it is waited for. A tap can be lost to a dialog that appears at that moment, so it counts only once
# the tab shows as selected.
open_tab() {
    for _ in $(seq 1 60); do
        if tap_id "nav-$1"; then
            sleep 1
            selected_id "nav-$1" && return 0
        fi
        sleep 1
    done
    return 1
}

# Opens every section of an app's page (ADR 0027), from the top each time, as opening one moves the
# others down.
open_sections() {
    local section
    for section in "Access and permissions" "Trackers and SDKs" "Network" "Signature and keys"; do
        scroll_to_top
        tap_text "$section" >/dev/null 2>&1 && sleep 1
    done
    scroll_to_top
}

# Wakes the screen, starts Datapavan in English and waits for the summary's navigation bar.
start_audit() {
    local pkg=org.visadahyu.datapavan
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
    # App-specific locales exist from Android 13; older emulators default to English anyway.
    adb shell cmd locale set-app-locales "$pkg" --locales en >/dev/null 2>&1 || true
    adb shell am force-stop "$pkg"
    adb shell am start -n "$pkg/.MainActivity" >/dev/null
    for _ in $(seq 1 60); do
        has_id nav-summary && return 0
        sleep 1
    done
    return 1
}

# True when an element whose resource-id is $1 is on screen; the navigation bar always is (ADR 0027).
has_id() {
    dump_screen || return 1
    adb shell cat "$DUMP" 2>/dev/null | grep -q "resource-id=\"$1\""
}

# Waits until the audit overview shows, in any language: the loading screen has nothing to tap.
wait_for_overview() {
    for _ in $(seq 1 60); do
        if dump_screen &&
            adb shell cat "$DUMP" | grep -q 'clickable="true"'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Waits (up to $1 seconds, default 300) until the tracker scan has finished: the summary's line for
# the apps says so. The first scan of a phone reads every app's code; later ones reuse the results of
# unchanged apps. Each try opens the summary and starts from its top.
wait_for_tracker_scan() {
    local deadline=$((SECONDS + ${1:-300}))
    while [ "$SECONDS" -lt "$deadline" ]; do
        open_tab summary >/dev/null 2>&1 || true
        scroll_to_top
        scroll_to "The tracker check is done" && return 0
        sleep 3
    done
    return 1
}

# Google Play on a test device or emulator on which someone has signed in by hand
# (data/app-signers/from-play.sh, compare-exodus.sh).

# True when package $1 is installed.
installed() {
    adb shell pm path "$1" 2>/dev/null | grep -q '^package:'
}

# Taps the element whose text is exactly $1 on the current screen, without scrolling.
tap_now() {
    dump_screen || return 1
    local bounds
    bounds=$(text_bounds "$1")
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# Opens the Play listing of $1, taps Install and waits up to seven minutes for the app. Fails when
# the listing offers no Install button: the app is not listed, not in the account's country, or not
# for this device. Offers Play shows on the way, such as payment set-up, are declined; the app is
# never opened.
install_from_play() {
    adb shell am start -a android.intent.action.VIEW -d "market://details?id=$1" com.android.vending >/dev/null
    local tapped=no
    for _ in $(seq 1 10); do
        sleep 2
        tap_now Install && { tapped=yes; break; }
    done
    if [ $tapped = no ]; then
        adb shell input keyevent KEYCODE_BACK
        return 1
    fi
    for _ in $(seq 1 200); do
        installed "$1" && return 0
        tap_now Skip || tap_now "Not now" || true
        sleep 2
    done
    return 1
}
