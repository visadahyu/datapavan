# Shared helpers for the adb-driven checks and the Google Play readers. Sourced, not executed.
# They read the screen through uiautomator, so they need no test framework in the app.

DUMP=/sdcard/datapavan-ui.xml

# True when an element whose text starts with $1 is on screen.
screen_has() {
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
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
    scroll_to "$1" || return 1
    local bounds previous=""
    for _ in 1 2 3 4 5; do
        bounds=$(text_bounds "$1")
        [ -n "$bounds" ] && [ "$bounds" = "$previous" ] && break
        previous=$bounds
        sleep 1
        adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || true
    done
    [ -n "$bounds" ] && [ "$bounds" = "$previous" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}

# Taps the centre of the first element whose content description is exactly $1: icons have no text.
tap_desc() {
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
    local bounds
    bounds=$(adb shell cat "$DUMP" | grep -o "content-desc=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
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

# Waits until the audit overview shows, in any language: the loading screen has nothing to tap.
wait_for_overview() {
    for _ in $(seq 1 60); do
        if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 &&
            adb shell cat "$DUMP" | grep -q 'clickable="true"'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Waits (up to $1 seconds, default 300) until the tracker scan has finished: its result line,
# "Apps with trackers", appears under the app summary. The first scan of a phone reads every app's
# code; later ones reuse the results of unchanged apps. Each try starts from the top, because on a
# small screen the line can sit just below the app summary, out of view.
wait_for_tracker_scan() {
    local deadline=$((SECONDS + ${1:-300}))
    while [ "$SECONDS" -lt "$deadline" ]; do
        scroll_to_top
        scroll_to "Apps with trackers: " && return 0
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
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
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
