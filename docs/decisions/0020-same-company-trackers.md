# 0020. Trackers from the app's own company group

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
Many trackers that the scan finds belong to the company that publishes the app: Firebase and AdMob in
Google's apps, Meta's SDKs in Instagram and WhatsApp, a phone maker's analytics in its own preinstalled
apps. Telling the user so is useful: it says who receives the data. It can also mislead, because
"the app's own company" sounds harmless.

A review of tools, research, law and platform rules found:
- **Tools that know the owner use it to exempt trackers, not to inform.** DuckDuckGo App Tracking
  Protection does not block trackers that belong to the app's parent company, and Firefox allows
  trackers that the visited site's company owns. Both do it so that apps and sites do not break.
  TrackerControl and εxodus never compare a tracker's owner with the app's.
- **The law does not treat a company group as one party.** Under the EDPB's guidelines on controllers
  and processors, another company of the same group is a third party. The CJEU counted data from
  Instagram and WhatsApp as data from outside Facebook (C-252/21). The Digital Markets Act forbids
  gatekeepers to combine data across their own services without consent (Article 5(2)). US and
  Californian rules treat separately branded affiliates as other parties.
- **Store labels draw the line narrowly.** Apple's and Google's privacy labels count only the
  developer's own organisation as the first party, so combining data across one company's services
  never shows on a label.
- **A familiar brand reassures people.** User studies found that seeing a known company's name, or its
  own data dashboard, lowered concern.
- **No owner dataset can be reused under CC0.** DuckDuckGo's and Disconnect's entity data is CC BY-NC-SA,
  the Oxford X-Ray owner data has no licence, and OpenCorporates is ODbL. Wikidata and GLEIF are CC0
  but say almost nothing about SDK vendors. εxodus records no owners.
- **Owners change.** SDKs are bought, merged and shut down (MoPub, Adjust, ironSource, App Center), and
  some are open source and run by anyone. About 80 of εxodus's 432 trackers belong to a few large
  groups.
- **The largest same-company case is the phone maker's own software**, which no existing list covers.

The research behind this record is kept in the maintainer's private repository.

## Decision
1. **A fact, never a discount.** When a tracker and the app belong to the same company group, the
   tracker's entry says so and adds what follows from it, for example: "Made by the same company group
   as this app (Alphabet). The group can combine this data with what its other apps and services
   collect." The finding keeps its severity and its place. Ownership never hides, greys out, sorts
   down or excuses a tracker, and the words "first-party", "trusted", "expected" or "safe" are not used.
2. **Same group only on evidence.** Both sides must resolve to the same ultimate parent that holds a
   majority of each, as of the data pack's date. An owner that is not recorded on either side gives no
   line at all, never a guess. Joint ventures and minority stakes are shown as "linked", or not at all.
3. **Who runs the service, not who wrote the code.** A tracker's owner is the company that runs the
   service receiving its data. Open-source and self-hosted analytics (for example Matomo or Countly)
   have no owner in this sense. A service that has shut down shows "service shut down on DATE",
   kept apart from ownership.
4. **Apps are matched by signing certificate, never by package name.** A publisher's own list of its
   packages and keys (its Digital Asset Links file) is the strongest evidence; certificates recorded
   under ADR 0018 count as well. Package prefixes, installer names and developer names are only leads.
   Preinstalled apps signed with the phone's own platform key are the phone maker's software, except
   for the public AOSP test keys and platform keys known to have leaked.
5. **Datapavan keeps its own data, under CC0**, in `data/owners/`, each row dated, graded as in ADR 0018
   and with a primary source, and open to dispute through `data/CORRECTIONS.md`:
   - which company runs each SDK's service, and since when;
   - which company controls which, with the level of control and its dates, keyed by LEI or Wikidata
     identifier;
   - which company publishes each package and certificate.

   Other datasets serve only as leads. Before the table refers to εxodus tracker ids, it is checked
   whether that makes it a derivative of εxodus's ODbL database; until then it refers to the SDKs'
   own identifiers.

## Consequences
- The first list is small: the trackers of the largest groups and the SDKs of Datapavan's own list.
  Most trackers show no owner line at first, by design.
- No surveyed tool states ownership without exempting the tracker; this design informs without
  excusing. Its wording is tested with a few users, in each language, before the first release.
- Dated ownership statements found along the way can be given back to Wikidata, where they are missing.
- Owners and shut-downs are re-checked at least every six months, the same staleness limit as the
  other datasets.
