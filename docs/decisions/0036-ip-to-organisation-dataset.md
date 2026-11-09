# 0036. The IP-to-organisation dataset

- Status: Accepted (by the maintainer on 2026-11-09)
- Date: 2026-11-09

## Context

Watch names every flow. W3 sets the order: the DNS answers Watch served, the TLS server name, the QUIC
server name, and last an offline table that maps an IP address to its network (AS number) and the
organisation behind it, such as "AS32934 Meta" ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)).
The table ships in the APK and is updated through signed data packs ([ADR 0017](0017-data-pack-format.md)).
It must meet [ADR 0015](0015-dataset-licences.md): commercial use allowed, a converter that checks the
licence before the data, evidence for every entry that names a company.

ADR 0015's decision 4 already names two sources for v0.2: "IPtoASN, under PDDL" and "DB-IP Lite, only if
IPtoASN falls short". On 2026-11-09 the free tables were compared again, from each provider's own terms.
No dataset file was downloaded: sizes and dates come from the providers' pages and HTTP headers.

| Source | Licence and terms | Names | IPv4 and IPv6 | Last update seen | Size as published |
|---|---|---|---|---|---|
| iptoasn.com | PDDL 1.0, no conditions; no account | AS handles ("GOOGLE", "CLOUDFLARENET") | Both | 2026-11-01, though the page says "Updated hourly" | 10.96 MB gzip |
| DB-IP IP to ASN Lite | CC BY 4.0, credit "IP Geolocation by DB-IP" with a link; commercial use and redistribution allowed (DB-IP's FAQ); no account | Organisations ("Facebook, Inc.") | Both | 2026-11-01, monthly on the 1st | 7.13 MB gzip, 485,292 records |
| Tables built from RouteViews and RIPE RIS dumps | CC BY 4.0 and RIPE's terms; for commercial use a credit line, a logo and a revocable permission | None: names need another source | Both | Continuous | Large dumps |
| CAIDA prefix2as and AS2Org, PeeringDB, the registries' WHOIS bulk data | Their agreements forbid passing the data on or do not cover products | (names) | – | – | – |
| IPinfo Lite | CC BY-SA 4.0, but an account token, and terms for "internal business purposes" only | Organisations and domains | Both | 2026-11-06 | 26.23 MB gzip |
| MaxMind GeoLite2 ASN | Account, internal use, old copies deleted within 30 days | Organisations | Both | – | – |
| IP2Location LITE | "You are not permitted to redistribute or resell this product" | AS names | Both | – | – |

Three things stand out:

- **iptoasn falls short** in the sense of decision 4: it gives handles, not organisations, and its files
  were eight days old against an hourly claim, from one maintainer who does not say how they are built.
- **DB-IP Lite gives organisation names** under terms that fit ADR 0015. PCAPdroid, the tool W3 measures
  Watch against, names networks with this same file, and OpenBSD packages it. DB-IP does not publish its
  method, and calls Lite a subset with "reduced coverage and accuracy".
- **No source says "Meta".** Registry names lag behind renames, and large companies announce from several
  networks. The project already lists companies and their parents in `data/owners/entities.tsv` (CC0,
  [ADR 0020](0020-same-company-trackers.md)).

**Size.** A sorted table of ranges with deduplicated names comes to about 8 MB raw, 4 to 5 MB under the
APK's deflate and 3 to 4 MB with xz (estimated, not measured). The audit app's APK is 4.8 MB, and Watch's
W1 APK 1.5 MB; people pass APKs on by hand.

## Options

1. **iptoasn first**, as ADR 0015 says: no conditions, but handles for names and uncertain upkeep.
2. **DB-IP Lite first, iptoasn as the converter's cross-check and the fallback**, with the project's own
   CC0 map from AS numbers to the companies in `data/owners`.
3. **The project's own table** from RouteViews and RIS dumps: full control, but an MRT parser, a pipeline
   over large dumps, logos and revocable permissions in the paid editions, and still no names.

## Decision

Option 2.

1. **The table** is DB-IP IP to ASN Lite, converted by `data/dbip-asn/update.py` into a compact,
   deterministic binary file, credited on the Data sources screen as DB-IP asks, with the CC BY 4.0
   change notice. Its licence sits beside it in a `.license` file.
2. **The converter** checks DB-IP's licence sentence before it reads the data, parses strictly, drops
   private and reserved addresses and AS numbers, and compares every release with iptoasn's tables. It
   records both sources' hashes and dates and the share of addresses on which they disagree, warns when
   iptoasn's files are older than 14 days, and fails when the counts move by more than 10 % until a person
   confirms. Addresses whose network the operator documents itself (public resolvers, for example) are
   anchors that fail the run if they change.
3. **The fallback** is iptoasn for ranges and AS numbers, with names from the last DB-IP release, once
   DB-IP's licence changes, a release is missing, or the cross-check shows DB-IP far behind. The project's
   own table from RouteViews and RIS stays in reserve.
4. **Names that people know** come from a new CC0 file, `data/owners/asns.tsv`, that maps AS numbers to
   the entities of `data/owners/entities.tsv`, each row with its evidence and date (ADR 0015, decision 10),
   starting with the networks that carry most flows in W3's ten-app session. Every other network shows the
   registry name with its AS number. For a cloud or CDN network the UI says "a server on Amazon's
   network", not "Amazon": the network is the host, not necessarily the service the app used.
5. **ADR 0015** gets its decision 4 and DESIGN.md §9 their new order once this is accepted.

## Left to measurement

Accepted with the proposals below; W3's ten-app session decides between them.

- **The size budget.** (a) The full table in Watch's APK, about 4 to 5 MB more; (b) the table stored
  xz-compressed in the APK and expanded on first start, which needs a pure-Rust decoder crate, a new
  dependency; or (c) only the ranges of the companies in `data/owners/asns.tsv` in the APK, and the full
  table as an optional pack. Proposed: (c) if W3's session shows that it names nearly as many flows, else
  (a).
- **Which app carries it.** If Watch stores the AS number and name with each flow when it logs it, only
  Watch needs the table, and the audit app reads names from the log (W5).

**First build, 2026-11-09.** `data/dbip-asn/update.py` turned DB-IP's November release (485,292 lines)
into 409,312 IPv4 and 75,978 IPv6 ranges of 83,024 AS numbers: 10.7 MB raw, 4.2 MB with gzip, 2.5 MB
with xz. Watch reads it in place, stored uncompressed in the APK, so the engine's memory does not grow.
On the Android 17 emulator, 32 flows of Chrome and the system, DNS excluded, were named 88 % from DNS
answers and 12 % from the table; none stayed unnamed. A new point for the size question: committing a
10 MB table every month would grow the repository by several megabytes a month, so the table is not
committed (`.gitignore`) until the question is settled, and a clean checkout builds Watch without it;
`SOURCE` records each build. Option (c) keeps the committed part small; the full table would then
travel only in packs.

**Revised by the maintainer the same day:** option (c) is dropped. The table is the last way a flow
gets a name, so the flows it names are those that went around DNS (addresses written into an app, an
app's own encrypted DNS), the most telling ones, and they are often on small networks that (c) would
leave out. Instead the whole table ships in a compact layout: blocks of 512 ranges or 256 networks,
each compressed on its own (raw deflate, read by `miniz_oxide`), so that a lookup inflates one block of
a few kilobytes. The November table takes **2.71 MB**, stored as it is in Watch's APK.

**Decided by the maintainer the same evening:** the monthly table lives in a public data repository of
its own, which this repository pins as a git submodule at one commit, with the table's SHA-256 in
`SOURCE`. Committed here, it would add about 2.7 MB a month, some 32 MB a year against a `.git` of 40 MB
today: the compressed blocks change nearly all at once, so git cannot store one month as a change to
the last. A submodule pinned at a commit keeps the builds reproducible, F-Droid builds submodules, and a
checkout without it still builds Watch, without the table. Tor commits its geoip files into its own
repository each month; that is simpler, but this repository would double in a year. The data
repository is created before the first monthly update.
- **Data from only Watch stays out of the audit app.** `dbip-asn` is left out of the audit app's
  payload (`android/app/build.gradle.kts`); Watch's build copies the table into its own assets.

## Consequences

- Watch names the last share of flows from a source with organisation names, under a licence that allows
  the paid editions, and a second, independent source checks it every month.
- One more credit line on the Data sources screen, and one more converter to keep.
- The legal review of ADR 0015 (decision 12) covers the CC BY 4.0 notice and how signing fits its "no
  downstream restrictions" clause; ADR 0015 already reasons the same way for ODbL.
- When an app looks names up past Watch (its own encrypted DNS) and also hides its server name with
  Encrypted Client Hello, its hello carries only the provider's public name, which looks the same as
  Chrome's GREASE with a real name: Watch shows that name marked "ECH offered", and this table's
  organisation is the only name it can vouch for. Naming such a flow more closely, from the shape of its
  traffic, is open research; it is accepted as a limit and not attempted.
- The full comparison, with every source and its date, is in the private strategy repository
  (`research/2026-11-ip-datasets.md`).
