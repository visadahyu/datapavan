# 0031. Datapavan Basic on Google Play: its own package and key

- Status: Accepted; the build is in progress (2026-11-08)
- Date: 2026-11-06
- See also: [ADR 0045](0045-three-editions-of-one-app.md): Basic, Advanced and Enterprise are editions of one app.

## Context
Datapavan's promise is that every genuine copy of Basic, on every channel, is signed with one key, kept offline. By default, Google Play signs a new app with a key
that Google generates and holds. The only ways to keep one key would be to upload it to Google or to hold it in a cloud key service, and either puts the
key online. Play also forbids an app to block or interfere with other apps' ads, which is a risk for v0.3's tracker-domain blocking.

## Decision
- Google Play carries **Datapavan Basic** as a package of its own, `org.visadahyu.datapavan.lite`, built from the same code. Google
  generates and holds its key. The published fingerprint and the app's own check (ADR 0024) list it apart.
- Basic's own package, `org.visadahyu.datapavan`, stays off Play, on the open channels, with its one offline key. That promise stays true as written, about it.
- Basic on Google Play has no internet permission either. It never updates or replaces itself, never downloads anything and does not ask to install packages: Play forbids
  an app to update itself outside Play, and Android has no upgrade between different packages or keys.
- The app's page about itself says in a few calm lines which other editions exist and how to get them, with a link that opens in the browser. No prompts.
- Basic on Google Play has the same checks as Basic on the open channels, and its store text says so and says that Google signs it. It stays without the VPN and without blocking, which
  are in Datapavan Advanced on the open channels (ADR 0045).
- Basic comes first on the open channels, and on Google Play after it.

## Consequences
- Two builds of Basic to build, describe and keep in eight languages, and a second fingerprint to publish after the first upload to Google Play.
- Users of both can keep both installed. Moving from Basic on Google Play to Basic from the open channels means installing the other package. Nothing moves across by itself.
- Google could change what its key signs, so Basic on Google Play is a matter of reach, not of trust. The text must not claim otherwise.
- Play's requirements still apply to Basic on Google Play: a declaration for `QUERY_ALL_PACKAGES`, whose listed uses do not name privacy audits, so it may be refused; and for a personal account created
  after November 2023, a closed test with 12 testers for 14 days.

## How it is built

Basic for Google Play is built with the Gradle property `-Pdatapavan.edition=play` rather than a product flavour, so that
every existing task, output path and recipe (F-Droid, `scripts/reproducible.sh`, CI) still builds
Basic for the open channels unchanged. The property sets the package, the name and `BuildConfig.PLAY`, which leaves out
the reminder of the version's age and the list of newer versions, and switches the About page's lines
on the editions.
