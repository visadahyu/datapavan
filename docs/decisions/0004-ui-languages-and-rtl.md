# 0004. UI languages at launch, RTL from the first commit

- Status: Accepted
- Date: 2026-10-28

## Context
The first market is Europe, and the project is meant for all nations. Retrofitting right-to-left
support later touches every screen. Datapavan constantly shows left-to-right tokens (domains, IPs,
package names) inside translated sentences, and these scramble RTL text unless they are isolated.

## Decision
- Launch languages: English (source), French, German and Persian. Persian is the RTL reference language, reviewed natively by the founder.
- Arabic follows after launch, once native reviewers are found. Further languages are added mechanically (translations only, no code).
- RTL support, string-resource discipline, ICU plurals, LTR token isolation (`isolateLtr()`, LRI…PDI) and the pseudo-locales `en-XA` and `ar-XB` are in place from the first commit.
- Only the shipped locales are packaged (`localeFilters`), so the UI never mixes languages.

## Consequences
- Every screen is RTL-safe from day one, and adding a language needs no code changes.
- Each new string must be translated into four languages before release.
