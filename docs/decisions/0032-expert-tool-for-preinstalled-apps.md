# 0032. An expert tool of Datapavan's own for preinstalled apps

- Status: Proposed (the direction agreed by the maintainer on 2026-11-07; details open)
- Date: 2026-11-08

## Context

Phone makers ship system apps that collect data and that Android's Settings cannot turn off or remove.
The audit app finds them (M2) and does what Settings allow: permissions, background data, special
access, and turning off the apps that Settings let the user turn off. From v0.3, Watch can also stop
an app from sending, which reaches apps that cannot be turned off.

The tools that go further work through ADB, from a computer or through Shizuku on the phone
(Universal Android Debloater, Canta and others). They are made for experts and sort apps by the risk of
breaking the phone, not by what an app sends; turning an app off that way is reversible, removing it
for the user is less so, and a factory reset restores both. A landscape study in November 2026 put
Datapavan behind these tools on reach. Sending people to a third-party tool would hand the most
powerful step of the remediation plan to software whose rules, wording and keys Datapavan does not
control.

The audit app has no INTERNET permission. An ADB connection, even to the phone's own debugging
service, is a network socket, so the audit app cannot make one.

## Decision

1. **Datapavan builds its own expert tool** (working name: the expert tool), and the audit app refers
   people to it only for the apps that Settings cannot handle, after what Settings and Watch can do.
   No other debloater is recommended in the app.
2. **A third app within Datapavan,** beside the audit app and Watch: its own package, signed with the
   same key, reproducible on its own, as Watch is under ADR 0029. It talks to no host other than the
   phone's own debugging service on loopback, which review and a test of its sockets check.
3. **On the phone, through Android's own wireless debugging** (Android 11 and later), with no Shizuku
   and no computer: the user pairs it once with the code Android shows. When the work is done, the
   tool turns wireless debugging off and forgets its pairing key, so no debugging door stays open.
   Android 10, which has no wireless debugging, would need a computer; that waits for demand.
4. **Turn off, never remove by default.** The tool uses `pm disable-user`. Removing an app for the user
   is offered only at the highest level, with its risk stated, never in bulk.
5. **The same rules as the remediation plan** (docs/REMEDIATION.md): levels, a short queue ordered by
   impact, each change confirmed, a journal with undo, and the same safety floor: the holders of the
   default roles, the keyboard, start-up and core services, calls and mobile data, system updates and
   the rest of its list are never offered.
6. **Ordered by what apps send,** from the lab's measurements and, on the user's phone, Watch's log,
   with the breakage risk beside it. Each entry records its evidence and can be disputed, as ADR 0015
   requires.
7. **Stage 2 reuses the lists and the decision engine:** a Device Owner can turn off the same system
   apps without ADB.

## Consequences

- Datapavan reaches the preinstalled apps that only ADB reaches, under its own wording, levels and undo.
- A tool with the phone's shell rights is a valuable target. It stays small, written to be reviewed,
  with no network access beyond loopback and no data leaving the phone.
- Wireless debugging needs Wi-Fi, and the steps to enable it differ by maker. Per-vendor guides are
  needed, as for battery managers.
- Lists per maker and model must be kept: which packages are safe to turn off, and what each sends.
  The lab and the expert tool's own journal (never sent anywhere) are where the evidence comes from.

## Open questions

- The tool's name and whether it ships with the audit app's first version that refers to it.
- Whether some makers block `pm disable-user` for some packages, and what the tool says then.
- How a system update that brings an app back is noticed and shown, without background work.
- Whether a computer-based variant for Android 10 is worth its cost.
