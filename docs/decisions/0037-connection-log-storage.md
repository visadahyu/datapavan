# 0037. The connection log: records sealed one by one, a key for each day, readable only on an unlocked phone

- Status: Accepted (by the maintainer on 2026-11-09)
- Date: 2026-11-09

## Context

W4 stores every flow Watch sees: the app's UID, the name and where it came from, IP and port, protocol,
organisation, bytes each way, start and end time ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)).
DESIGN.md §6.4 and VPN.md ask for app-private, encrypted SQLite with its key in the Android Keystore,
retention of none, 1, 7 or 30 days, and a one-tap wipe. The threat that matters most is a phone check at a
border or checkpoint (§8): there the log is evidence. Backups are already off (`allowBackup="false"` and
`data_extraction_rules`), and Android's file-based encryption protects the files of a phone that was not
unlocked since it started.

What the field does:

- **Tools of the same kind** keep their logs in plain app-private SQLite (NetGuard, RethinkDNS) or in memory
  and user exports (PCAPdroid).
- **Signal**, the usual reference for an encrypted local store, uses SQLCipher with one database key, kept
  wrapped by a Keystore key.
- **Two gaps remain even there.** First, deleted rows survive in flash memory, which no app can erase
  reliably (wear levelling); with one key for the whole database, anyone who later gets that key can read
  them. The known answer is crypto-shredding: destroy the key, not the data. Second, a key the app may use
  at any time can also be used by anyone who can act as the app, on a locked phone too.

Options:

1. **SQLCipher, one key** (net.zetetic:sqlcipher-android 4.20.0, BSD-style with attribution, OpenSSL inside):
   the whole file is encrypted, counts included. It adds about 3 MB to Watch's APK for three ABIs (the AAR
   is 4.05 MB for four), C code with its own security updates, a new Maven source, and it shares both gaps
   above.
2. **SQLCipher, one database per day**, each with its own key wrapped as in option 3: both gaps closed and
   the counts hidden, at the same size and dependency cost as option 1.
3. **Android's own SQLite, each record sealed on its own** with AES-256-GCM (`javax.crypto`, Conscrypt, in
   every Android), with a fresh key for each day. Each day key is stored only wrapped by an RSA key pair in
   the Keystore whose private key works only while the phone is unlocked
   (`setUnlockedDeviceRequired`, Android 9 and later). Writing uses the public key, so Watch logs while the
   phone is locked; reading an earlier day needs the phone unlocked. Expiry and the wipe destroy keys.

## Decision

Option 3.

1. **Records.** A flow is written when it ends; a flow still open is written as a segment every 15 minutes and
   at midnight, so a day holds only its own traffic and nothing waits for a long connection to close. Rows
   are append-only. Each row holds the day, a token of the app (HMAC-SHA-256 of the UID under a key derived
   from that day's key, so it links an app's rows within a day and not across days), and the sealed record:
   all other fields, with the day and the token as associated data. A fresh 96-bit nonce per record.
2. **Keys.** At the first record of a day Watch draws a 256-bit day key, keeps it in memory for that day, and
   stores it only wrapped with the Keystore public key (RSA-OAEP). At midnight the old day key is cleared from
   memory (best effort: the JVM may hold copies). The private key is generated in the Keystore and never
   leaves it: RSA-2048 in StrongBox where the phone has one (StrongBox's largest RSA key), otherwise RSA-3072
   in the trusted environment; it requires an unlocked device.
3. **Expiry and wipe.** Retention deletes a day's rows and its wrapped key together. "Delete everything now"
   deletes the database and the Keystore key pair, so nothing left in flash can be read. Retention "none"
   writes nothing: flows stay in memory for the screen and are gone when Watch stops.
4. **What is not a row.** Lookups that apps send to Watch's own DNS address are counted per app and day, not
   stored one by one; their names live in the flows they named. Flows chained through a tool (W6) keep their
   destination only when the user turns that on.
5. **Bytes.** The engine counts each flow's bytes as they pass, so a flow cut off, refused halfway or reset
   still has its count (W2 counted only connections that ended cleanly).
6. **Checks.** Tests show that the database and its write-ahead log hold no destination in clear, that no
   destination reaches logcat, that the wipe leaves no file and no key, and that an earlier day cannot be read
   while the phone is locked. Over a scripted emulator session, each app's bytes in the log are compared with
   Android's own count (ADR 0022's open check) against the 5 % bar of M4.

## Left open

- **Day boundaries** follow the phone's time zone at the time of writing; a change of zone can make one day
  shorter or longer. Accepted.
- **Keystore behaviour on real phones.** Unlocked-device keys and RSA-OAEP have had vendor bugs. W4 checks them
  on the emulators with Android 10, 11 and 17 and on the A40; where a phone refuses the unlocked-device flag,
  Watch makes the key without it and says so in its health check.

## Consequences

- No new dependency and no change in APK size; all cryptography is Android's own.
- Beyond the field's tools and Signal's store on two counts: expired and wiped records cannot be read even from
  flash, and a locked phone in someone else's hands does not open earlier days to anyone acting as Watch.
- **Accepted limits.**
  - The day being written is readable by anyone who can run code as Watch while it runs (a root exploit).
  - The file shows how many rows each day and each app token has, and their sizes, not what they say.
  - On a phone without a screen lock, "unlocked" is always true, and the lock protection falls away; Watch's
    onboarding (W9) says so.
  - The audit app's queries (W5) work only while the phone is unlocked, which is when someone looks.
  - RSA is not safe against a future quantum computer: a copy of the files taken today could be opened then.
    The Keystore offers no post-quantum key wrapping on the Android versions Watch supports; the day keys'
    short life and the default retention limit what such a copy holds.
- More code of our own than SQLCipher's single key: the record format and the key handling get their own unit
  tests and a review against this ADR before 0.2.0.
