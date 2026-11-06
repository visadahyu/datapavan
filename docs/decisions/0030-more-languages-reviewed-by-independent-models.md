# 0030. Spanish, Russian, Chinese and Arabic at launch, reviewed by independent models

- Status: Accepted
- Date: 2026-11-06
- Changes [ADR 0004](0004-ui-languages-and-rtl.md), which held Arabic back until native reviewers were found.

## Context
The project is for everyone, and the strings are close to stable before the first release, so adding
languages costs little now. Native reviewers are still not at hand. Some strings carry real weight: a care
warning about someone who may have installed an app to watch the user can do harm if it is translated badly.

## Decision
- The app, the store texts and the website ship in English, French, German, Spanish, Russian, Simplified
  Chinese, Arabic and Persian. Chinese is `zh-rCN`, so a phone set to Traditional Chinese falls back to
  English until Traditional is added. Arabic is Modern Standard Arabic, and Spanish is neutral.
- English is the source. Each translation is made by one AI model and then reviewed separately by two others,
  which report without seeing each other's work; the maintainer's session compares the reports and settles the
  differences. The care warnings get the closest reading. A native speaker reviews Persian. No native speaker has
  reviewed the others, and corrections from native speakers are welcome.
- `scripts/check-translations.py` runs in `scripts/check.sh`. It checks that every string exists with the same
  placeholders, tags, directional marks and line breaks; that plurals have their language's CLDR forms; that
  store texts fit their limits; and that the website's texts have the shape of English's. It says nothing
  about whether a translation is good.

## Consequences
- Each new English string needs seven translations before a release.
- Models reviewing each other catch far more than one model alone, but they can share a blind spot, above all on
  what a phone's own settings are called in a language. A wrong translation can still reach users, and the app and
  the website do not mark a language as machine-reviewed. Native review, starting with the care warnings, is
  still wanted before 1.0.
- Security reports stay in the languages the maintainer reads (`security.txt`).
