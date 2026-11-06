# 0031. Datapavan Lite on Google Play: its own name, package and key

- Status: Accepted, not built yet
- Date: 2026-11-06

## Context
Datapavan's promise is that every genuine copy, on every channel, is signed with one key, kept offline. By default, Google Play signs a new app with a key
that Google generates and holds. The only ways to keep one key would be to upload it to Google or to hold it in a cloud key service, and either puts the
key online. Play also forbids an app to block or interfere with other apps' ads, which is a risk for v0.3's tracker-domain blocking.

## Decision
- Google Play carries a separate app, **Datapavan Lite**, with its own package, `org.visadahyu.datapavan.lite`, built as a Gradle flavour from the same code. Google
  generates and holds its key. The published fingerprint and the app's own check (ADR 0024) list it apart.
- Datapavan itself stays off Play, on the open channels, with its one offline key. That promise stays true as written, about Datapavan.
- Lite has no internet permission either. It never updates or replaces itself, never downloads anything and does not ask to install packages: Play forbids
  an app to update itself outside Play, and Android has no upgrade between different packages or keys.
- The app's page about itself says in a few calm lines which other editions exist and how to get them, with a link that opens in the browser. No prompts.
- In v0.1, Lite has the same checks as Datapavan, and its store text says so and says that Google signs it. From v0.2 on it stays without the VPN and without blocking, which
  live in Datapavan Watch on the open channels (ADR 0029).
- Datapavan comes first on the open channels, and Lite after it.

## Consequences
- Two apps to build, describe and keep in eight languages, and a second fingerprint to publish after Lite's first upload.
- Users of both can keep both installed. Moving from Lite to Datapavan means installing the other app. Nothing moves across by itself.
- Google could change what its key signs, so Lite is a matter of reach, not of trust. The text must not claim otherwise.
- Play's requirements still apply to Lite: a declaration for `QUERY_ALL_PACKAGES`, whose listed uses do not name privacy audits, so it may be refused; and for a personal account created
  after November 2023, a closed test with 12 testers for 14 days.
