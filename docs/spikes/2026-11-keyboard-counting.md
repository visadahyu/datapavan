# Spike: how Android counts a keyboard while it is on screen (2026-11-03)

ADR 0025 shows a fact for keyboards, live wallpapers and home screens that sent at least 1 MB **in
the background**. It left open whether Android counts a keyboard's traffic as foreground or
background while the keyboard is on screen. If it were background, a keyboard with online features,
such as GIF search or cloud prediction, would reach the fact while the user types, and the fact would
say less than it seems to.

## Method

`scripts/traffic-lab/keyboard.sh` adds a keyboard to the lab app (`LabKeyboard`) and makes it the
input method. While shown, in Settings' search field, it downloads 3,000,000 bytes from `server.py` on
the computer; 20 seconds after it is hidden, it downloads 7,000,000 bytes. The two amounts tell the
two transfers apart. The lab app's counts are then read with Datapavan's query (`querySummary`, the
guided check's aligned period, a second reading 20 seconds after the first), by state: 1 is
background, 2 is foreground. The default keyboard is put back and the lab app removed afterwards.

## Results

| Android | Shown (state 2, foreground) | Hidden (state 1, background) |
|---|---|---|
| 11 (`dp-api30`) | 3,083,867 B received | 7,195,027 B received |
| 15 (`dp-api35-ci`) | 3,083,827 B received | 7,194,987 B received |
| 17 (`dp-api37-16k`) | 3,083,747 B received | 7,194,987 B received |

Every transfer landed whole in one state: what the keyboard moved while shown counted as foreground,
and what it moved after it was hidden as background. The extra 2.8 % is the headers, as in the guided
check spike. After hiding, the keyboard's process was at state 7 (important background); while it is
shown, Android binds it like a foreground service.

On Android 17 the keyboard's view did not appear at first: Android started its input but never asked
for the view, although the image has no hardware keyboard. The keyboard now always asks to be shown
(`onEvaluateInputViewShown`); the cause on Android 17 was not established.

## What this means

- The quiet-role fact counts only what a keyboard sends while it is not on screen. Sending while the
  user types, for example a GIF search, does not reach it.
- The guided check counts a keyboard's traffic during an activity under the keyboard's own UID, not
  under the app the user types into. That was already so, and the check is about one app's UID.

## Not checked

- Phones from makers that change the input method framework; the A40 and A56 were not used.
- A keyboard that keeps a connection open across shown and hidden: bytes are counted in the state of
  the moment they move, which this spike did not split within one transfer.
