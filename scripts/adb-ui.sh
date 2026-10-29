# Shared helpers for the adb-driven checks (smoke.sh, verify-audit.sh). Sourced, not executed.
# They read the screen through uiautomator, so they need no test framework in the app.

DUMP=/sdcard/datapavan-ui.xml

# True when an element whose text starts with $1 is on screen.
screen_has() {
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
    adb shell cat "$DUMP" 2>/dev/null | grep -q "text=\"$1"
}

# Lists only compose what is on screen, so scroll down (up to six times) until the text shows.
scroll_to() {
    local size width height
    size=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1)
    width=${size% *}
    height=${size#* }
    for _ in 1 2 3 4 5 6; do
        screen_has "$1" && return 0
        adb shell input swipe $((width / 2)) $((height * 3 / 4)) $((width / 2)) $((height / 4)) 300
        sleep 1
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

# Taps the centre of the first element whose text is exactly $1, scrolling to it first.
tap_text() {
    scroll_to "$1" || return 1
    local bounds
    bounds=$(adb shell cat "$DUMP" | grep -o "text=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# Wakes the screen, starts Datapavan in English and waits for the audit overview.
start_audit() {
    local pkg=org.visadahyu.datapavan
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
    # App-specific locales exist from Android 13; older emulators default to English anyway.
    adb shell cmd locale set-app-locales "$pkg" --locales en >/dev/null 2>&1 || true
    adb shell am force-stop "$pkg"
    adb shell am start -n "$pkg/.MainActivity" >/dev/null
    for _ in $(seq 1 60); do
        screen_has "This phone" && return 0
        sleep 1
    done
    return 1
}
