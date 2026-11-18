# 0037. The connection log: records sealed one by one, a key for each day, readable only on an unlocked phone

- Status: Accepted (by the maintainer on 2026-11-09; its amendments of 2026-11-10 on 2026-11-10)
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
   (Amended 2026-11-18, W5's first part, after finding 20 of an independent review of 2026-11-09: the record's
   format is version 2. A flow's name is the server name the connection itself sent, where it sent one that is
   not the public name of an ECH configuration Watch saw, and the name a DNS answer gave its address is kept
   beside it where the two differ, while the answer that gave the flow that name when it started is still held in
   time since the phone started (a stand-in's name always is), since either can be wrong;
   bit 1 of its flags says the flow came in (ADR 0044, decision 4). Version 1, never in a release, stays
   readable, since debug builds on test phones sealed days in it; a record of a version the reader does not know
   is skipped and counted, never read as another. Both sides read one fixture the engine writes, so that the
   format cannot drift between them unseen.)
   (Amended 2026-11-18, W5's first part, after finding 4 of an independent review of 2026-11-09: the quarter
   hours were a timer's, and the timer stands still while the phone sleeps, so a flow open at 22:10 and next
   written at 06:15 became one segment of eight hours, filed under the evening's day, and a flow that ended in the
   gap the same. Now the engine reads the wall clock before it counts any byte or lookup, opens a flow or ends one,
   and first cuts every open segment, and each app's lookups, at the quarter hours passed since the last cut,
   whichever way the clock moved: the segment carries its bytes to the end of its own quarter hour, and the next
   begins at the start of the quarter hour the clock reads. So no byte is counted in a segment of another quarter
   hour, and the quarter hours of a sleep, which had none, have no record. The flush the end-to-end test asks for
   is made on the engine's thread too, between counts, and debug builds check that the log's clock is read there
   alone. In every zone of tzdata, every change of the local date since 2011 falls on a quarter hour of UTC (2026f,
   read on 2026-11-18): every offset is a whole number of quarter hours, which puts every midnight on one, and has
   been since 1979 (Africa/Monrovia and Pacific/Kiritimati left the last others in 1972 and 1979); and every
   change of offset that changes the date falls on one, as it has since 2011 (Newfoundland, Goose Bay and Moncton
   changed theirs at 00:01 local time until 2010 and 2006, so that the date changed at 02:31 or 03:01 UTC).
   Kathmandu's +5:45, the Chatham Islands' +12:45 and +13:45 and Eucla's +8:45 included, no record therefore
   spans a change of the local date; a clock set to before 2011 in Newfoundland, Goose Bay or Moncton could make
   one span it, and is accepted. (Corrected 2026-11-18 after review 1 of W5's first part, names, finding 5: the first wording
   rested the conclusion on the offsets alone.) The engine reads its clock through one
   it is handed, which tests move: a sleep of hours ended by no packet, by the app's or by the server's, a jump
   back, a jump forward, and each way a flow ends after the gap. The engine's other clocks are in ADR 0044's table
   of the same day.
   Two limits stay, named after review 1 of W5's first part (engine, findings 3 and 5). The packets the engine holds
   before a flow opens, a TCP SYN until its server accepts, datagrams and lookups until Android names their app,
   are counted when the flow opens, in its first segment: by at most the connect wait for TCP (60 seconds awake,
   longer in real time if the phone sleeps meanwhile), and the owner question and the socket for UDP and lookups
   (milliseconds). Counting them at their arrival would need a segment before the flow's own start. And each count
   reads the wall clock once: one read for each UDP datagram, but a relayed TCP connection is counted by the relay
   as it hands each read on and by the tunnel packet by packet, so about two reads for a small TCP packet and 1.1
   for bulk, against the one read for each packet the brief set; merging the two counts would place one in the
   other's quarter hour. Since W5's second fix round the reading is the coarse wall clock (ADR 0044's cost note),
   which lags the wall clock by less than two of the kernel's ticks, under 8 ms at 250 Hz, the default, and under
   20 ms at 100 Hz, the lowest Linux offers (corrected after review 3 of W5's first part, nit 2; it said one tick):
   a byte counted in that moment after a quarter hour falls in the quarter hour before, well within the bounds
   above. A flow's outcome or name that changes in a quarter hour
   after the last count changes after the cut, so the segment before keeps the outcome and name it had.)
   (Amended 2026-11-18, W5's second part, ADR 0046's decision 1: the record's format is version 3. Each record, a
   segment or an app's lookups, ends with one byte of its app's state over it: in use, with its notification, in the
   background, or none and why (no usage access, no events before the first unlock, told too late, no app, not
   told). A segment is also cut where its app's state changes, where the timeline of states changed (as of the fix
   round of the same day: walking back at most 120 seconds over quiet seconds of the new state), back in time as far
   as the engine still holds that flow's bytes second by second; so a segment cut at a quarter hour or at its flow's
   end waits until its seconds' states are told, and one quiet after its app's state changed ends with a part of no
   bytes in the state of its end (fix round 2). The state of a part with bytes is its bytes' seconds'; quiet seconds
   of another state within it, beyond the 120 walked back, are not cut out. While Watch runs and the phone is awake,
   a record waits at most one reading's period after its last second, 5 seconds with the screen on and a minute with
   it off, plus 3 seconds (the 2 a reading leaves for events not reported yet, and the second itself), and then the
   log's usual 30 seconds of gathering: each new second counted asks for a reading, and so do a segment held and a
   reading that leaves seconds waiting, which Watch's Kotlin side makes in its turn, and the screen turning off
   reads once more. In deep sleep nothing runs, so a record waits until the phone wakes. If Watch's process dies
   meanwhile, what waits is lost: the segments held and the live flows' open segments, as any record not yet handed
   to the log is. When Watch stops, it reads once more, and what is still not told is written as "not told". A clock
   set back by a second or more writes what waits at once. Watch's Kotlin side reads versions 1, 2 and 3, the first
   two as "not told"; a state byte the engine never writes, or a byte after it, makes the record malformed, skipped
   and counted. ADR 0046's "How it is built" gives the rules.)
2. **Keys.** At the first record of a day Watch draws a 256-bit day key, keeps it in memory for that day, and
   stores it only wrapped with the Keystore public key (RSA-OAEP). At midnight the old day key is cleared from
   memory (best effort: the JVM may hold copies). The private key is generated in the Keystore and never
   leaves it: RSA-2048 in StrongBox where the phone has one (StrongBox's largest RSA key), otherwise RSA-3072
   in the trusted environment; it requires an unlocked device.
   (Amended while building it, 2026-11-10: a process that sleeps through midnight clears the old key at
   its first activity after it, which is any read, write or count, or the expiry job of decision 3. A late
   record of an earlier day draws a key of its own, which does not stay in memory. A day also has a key for
   each run of Watch's process, since a key from an earlier run cannot be unwrapped on a locked phone, so
   the token links an app's rows under one key: a query for one app on one day computes a token for each
   key of that day.)
3. **Expiry and wipe.** Retention deletes a day's rows and its wrapped key together. "Delete everything now"
   deletes the database and the Keystore key pair, so nothing left in flash can be read. Retention "none"
   writes nothing: flows stay in memory for the screen and are gone when Watch stops.
   (Amended while building it, 2026-11-10: expiry does not wait for traffic. It runs when Watch's process
   makes the log, when the tunnel starts, when the screen opens, before every read, count and write, and
   from a job about every six hours (Android's JobScheduler); a day past retention is never read back nor
   written, even before expiry has run. Android decides when the job runs; some makers' phones seldom run
   one for an app the user has not opened in a long time; and the job does not survive a restart of the
   phone, which would need the permission to start at boot, which ADR 0034 does not give Watch. After a
   restart, the next start of Watch's process expires the log. Retention "none" also deletes, at each of
   those moments, whatever is left, until nothing is. A failure on the log's thread is counted and never
   reaches the tunnel.)
4. **What is not a row.** Lookups that apps send to Watch's own DNS address are counted per app and day, not
   stored one by one; their names live in the flows they named. Flows chained through a tool (W6) keep their
   destination only when the user turns that on.
5. **Bytes.** The engine counts each flow's bytes as they pass, so a flow cut off, refused halfway or reset
   still has its count (W2 counted only connections that ended cleanly).
6. **Checks.** Tests show that the database and its write-ahead log hold no destination in clear, that no
   destination reaches logcat, that the wipe leaves no file and no key, and that an earlier day cannot be read
   while the phone is locked. Over a scripted emulator session, each app's bytes in the log are compared with
   Android's own count (ADR 0022's open check) against the 5 % bar of M4.
   (Amended 2026-11-10: and that a day past retention is never read and leaves the file when Watch starts
   again, that a shorter retention deletes at once, and that "none" leaves no file and no key; and a
   model-based test, run inside Watch on the emulator with its own SQLite and Keystore, draws random
   sequences of writes, reads, the clock moving on and back, changes of time zone, restarts, locking,
   changes of retention, wipes, the expiry job, a full or failing database and a failing Keystore, and
   checks after each what must and must not be read back.)

## Left open

- **Day boundaries** follow the phone's time zone at the time of writing; a change of zone can make one day
  shorter or longer. Accepted. (Amended 2026-11-18: so does the wall clock. Set back, a flow's later records begin
  before its earlier ones end; each record lies in the quarter hour the clock read when its bytes were counted.
  A segment the clock's setting back cuts ends at the old clock's last reading, and the next begins at the new
  clock's first, so that neither claims a time no clock read (corrected the same day, after review 1 of W5's first
  part, engine, finding 6). Accepted: the log follows the clock the user sees. Whatever zone a record is filed in,
  it lies within that zone's day, since it lies within one quarter hour of UTC and every change of the local date
  falls on one (decision 1, as amended): Watch's Kotlin side reads the zone once for each batch it writes, where it
  read it for each record, so that a zone changed in between could file a record under a day whose key was not
  drawn and fail the batch. Its tests check, of every zone the runtime knows, every change of the local date from
  2012 and by the zones' rules ahead, the engine's own cuts in every zone, records filed while the zone changes
  between batches, and a batch filed while the zone changes at every reading, in the function the log files
  every batch with.)
- **Keystore behaviour on real phones.** Unlocked-device keys and RSA-OAEP have had vendor bugs. W4 checks them
  on the emulators with Android 10, 11 and 17 and on the A40; where a phone refuses the unlocked-device flag,
  Watch makes the key without it and says so in its health check.

## Consequences

- No new dependency and no change in APK size; all cryptography is Android's own.
- Beyond the field's tools and Signal's store on two counts: wiped records cannot be read even from flash, and
  a locked phone in someone else's hands does not open earlier days to anyone acting as Watch. (Amended
  2026-11-10: the first count said "expired and wiped". It holds for the wipe, which destroys the key pair.
  Expiry deletes a day's rows and wrapped keys and overwrites them in the file (`secure_delete`), but the key
  pair stays, so what flash memory may keep of an expired day could still be opened with it on an unlocked
  phone, by someone who can run code as Watch and recover those remnants. A key pair for each period,
  destroyed at its expiry, would close that; it needs a spike first.)
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
