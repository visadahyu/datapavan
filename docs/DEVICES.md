# Phones Datapavan has been tried on

Results from the project's own phones and from people who tried a release and reported back. Each row
gives the phone, its Android version, the release and what happened, and nothing about the person or
where they are. CI's emulators are not listed: every change runs there (`scripts/check.sh`, and the
emulator scripts in [RELEASE.md](RELEASE.md)).

To add a phone, open an issue on GitHub with its brand, model, Android version, the release, how you
installed it and what you saw, with screenshots if you can. Leave out anything that names you or
other people's apps.

| Phone | Android | Release | Result |
|---|---|---|---|
| Samsung Galaxy A56 | not recorded | 0.1.0 | Installed from the website. Play Protect offered a scan and passed it. |
| Samsung Galaxy A40 | 11 | 0.1.0 | Installed over adb after a debug build signed with another key was removed. Opens in 8 seconds, knows itself genuine, every settings button tried opens the right page, the plan's two cards at Medium are right, and the ten largest network rows match Android's own counters. Play Protect checked it after the install without asking. The engine's tests also pass there as a 32-bit program. |
| Samsung Galaxy A40 | 11 | 0.1.1 | Installed over 0.1.0 over adb as a 32-bit app (`--abi armeabi-v7a`), keeping its data. The tracker check finishes in about 18 seconds, it knows itself genuine, and About shows the website's and GitHub's addresses. |
| Samsung Galaxy A16 | not recorded | 0.1.0 | Installed. |
| Samsung Galaxy A13 | 14 | 0.1.0 | Refused: "App not installed as app isn't compatible with your phone". This phone runs a 32-bit Android, and 0.1.0 carries its Rust library for 64-bit ARM and x86_64 only. 0.1.1 adds 32-bit ARM; not yet tried on this phone. |
| Xiaomi, model not recorded | not recorded | 0.1.0 | Installed. Before turning usage access on, the phone shows a red "Danger" screen of its own with a countdown, as it does for any app; 0.1.1 says so on the card that asks for the access. |

## Known gaps

- Apps in another profile, such as a work profile, a private space or a secure folder, are not listed
  and their traffic is not counted: Android shows an app only its own profile. 0.1.1 says so under both
  lists. On the A40, 604 MB of Android's counters belonged to another profile.
- Not tried yet: phones from Google, Motorola, OnePlus, Oppo, Vivo, Huawei, Honor, Tecno, Infinix and
  Nokia, Android 10, 12, 13, 15 and 16 with known results, Persian on a real phone, and 0.1.1 on a
  phone whose Android is 32-bit (the A40 runs it in 32-bit mode only because adb was told to).
