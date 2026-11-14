# CI flakes

A flake is a check that fails in CI although nothing it tests changed: a run of a branch that did not touch
the apps, the engine or the checks, or a repeat of a run that passed. Each one goes here, before the run is
repeated, with the run, the check, what caused it as far as the logs show, and what was changed so that it
does not come back. A flake is fixed by making the check wait for the state it reads, with a bounded time and
a message that names what it waited for, or by retrying the action that prepares the state, never by loosening
what the check asserts. A flake that comes back gets a new row, and its earlier fix is looked at again.

The emulator scripts' comments name earlier flakes where they were fixed (CI, 2026-11-11 to 2026-11-13). This
log starts on 2026-11-14.

| Date | Run | Check | Cause | Fix |
| --- | --- | --- | --- | --- |
| 2026-11-14 | [43606775648](https://github.com/visadahyu/datapavan/actions/runs/43606775648), attempt 1 (gaps-probe, 5d57eda, no change to the apps, the engine or the test scripts) | `verify-chain.sh`: "the chain screen offered no user name and password for the tool" | The chain screen searches for the tool each time it comes to the front. Its first search found the tool; a later one got `ConnectException` from the tool's port while the tool was listening, and the screen then showed the tool as not answering, without the user name and password. A search after that found the tool again. The script read the user name and password once. Why a listening tool refused the connection is still open (W6's finding of 2026-11-12, noted in the script). | The script brings the screen back once, which runs the search again, before it reads the user name and password and the screen's sentences about the tool's proxy (`screen_says`), and each time it has to, the run gets a warning and a line in its summary. What the screen must show is unchanged. The missed search itself is a defect of Watch's, below. |
| 2026-11-14 | [43606775648](https://github.com/visadahyu/datapavan/actions/runs/43606775648), attempt 2 | `verify-watch.sh`: "Watch still reads Private DNS as 'strict dns.google' once it was restored" | The emulator had no mobile data for two minutes before Watch started; it came up only after airplane mode restarted the radios, and the networks were replaced again later. Wi-Fi was turned back on just before the Private DNS check, and a minute after the setting was restored Android itself still named the provider on the tunnel's network (its own dump, in the failure): Watch read what Android said. The cause on Android's side is a probable one, not proven. | Watch starts only once both networks are up and Android's list of networks has stayed the same for six seconds; after the network switch, the Private DNS check waits for Wi-Fi to be back and the networks to settle. If after 20 s Watch still reads strict mode while Android itself still names the provider, the specifier is written once more and restored, which makes Android read the setting again, and Watch must read "plain" within the next minute; if Android no longer names the provider, the check fails at once, as Watch's failure. |
| 2026-11-14 | [43611206007](https://github.com/visadahyu/datapavan/actions/runs/43611206007), attempt 1 (gaps-probe, 50f15a2, the same) | `verify-watch.sh`: "first: no TCP flow of the shell to the server" | The tunnel had just been set up again with the common addresses. The script's wait ended on the address set alone, which Watch names before its new tunnel and engine run; the TCP connection then got its answer, but Watch's engine listed no flow at all, of any app (the failure's account). | The script waits until Watch says its tunnel runs with that set and Android lists the VPN, then until the engine records a datagram of the shell from the tunnel's present address (to 192.0.2.1, which no check looks at), before the checks; the same after the switch to the spare addresses. |

## Defects found by flakes

A flake can show a defect of the product rather than of the check. Such a defect is fixed in the product;
the check may look once more so that the rest of it still runs, but it warns on the run each time it has to,
and the defect stays here until it is fixed.

| Found | Defect | Seen as | Status |
| --- | --- | --- | --- |
| 2026-11-12, again 2026-11-14 (run 43606775648, attempt 1) | Watch's search for the user's tool can get `ConnectException` from the tool's port while the tool listens there, and then reports it as not answering. | The chain screen says the tool does not answer and offers no user name and password, until the user looks again; `verify-chain.sh` warns ("Watch's tool search") when its one extra search was needed. | Open: to be fixed in Watch's search (W6), for example by trying the port again before calling the tool not answering, and checked by `verify-chain.sh` with no extra search. |
