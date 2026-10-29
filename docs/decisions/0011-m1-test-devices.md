# 0011. M1 tested on emulators and the Galaxy A40 only

- Status: Accepted
- Date: 2026-10-28

## Context
Two physical phones are available: a Galaxy A40 (Android 11, the lab device) and a Galaxy A56 (a
maintainer's personal phone). No other devices, a Pixel in particular, are planned at this stage.

## Decision
M1 is verified on the Android 11 emulator, on the Android 17 emulator with 16 KB memory pages, and on
the A40. Testing on the A56 is deferred to later milestones. The A40's bootloader stays locked, because
unlocking would permanently disable Knox, which the stage 2 tests need.

## Consequences
- Testing never risks a personal phone.
- Behaviour specific to One UI 7 and Android 15/16 on real hardware is verified later, on the A56.
