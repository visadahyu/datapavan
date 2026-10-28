# Datapavan

**Datapavan shows you what each app on your Android phone sends, and to whom. It also lets you stop it.**
Everything runs on the device. It needs no root and no cloud service.

> Status: design phase. No code yet. See [docs/DESIGN.md](docs/DESIGN.md).

## Why

Most people cannot see what their phone does with their data. Tracking SDKs sit inside thousands of apps.
Apps keep talking to third parties in the background, and system components send data to the phone maker
and to the platform owner. Datapavan makes this traffic visible and lets the user control it.

The goal: **no data leaves the device except what the user knowingly gives to a service. The user can
see what left, where it went, and when.**

## Principles

- **Local-first.** All analysis happens on the device. Datapavan has no servers that receive user data.
- **Zero telemetry.** Datapavan collects nothing about its users and contains no analytics SDKs.
- **Open source.** You can check every claim yourself. Builds will be reproducible and releases signed.
- **Plain language.** Every finding is explained so that anyone can understand it.
- **Hands off other apps.** Datapavan never modifies or injects into other apps. It works only at the system and network level.

## Name

*Datapavan* is built from two Old Persian words found in Achaemenid inscriptions. *dāta* means "law" and
*pāvan* means "protector", as in *xšaçapāvan*, "protector of the realm". In Old Persian the compound
means "protector of the law". In English it also reads as "data protector".

Datapavan is planned to be maintained by the **Visadahyu Foundation**. *Visadahyu* means "of all nations",
from Xerxes' inscription on the *Gate of All Nations* at Persepolis.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
