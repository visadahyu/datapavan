---
title: "Accessibility"
---

Datapavan is for everyone who carries a phone, and that includes people who are blind or have low vision, people who
need large text or strong contrast, and people who use a keyboard, a switch or their voice instead of touch. This page
says what Datapavan aims for, how it is checked, what is known to fall short, and how to tell us when something does
not work for you.

## What we aim for

- **The website** ([datapavan.org](https://datapavan.org/)): WCAG 2.2, level AA.
- **The apps** (Datapavan Basic and Datapavan Advanced): WCAG 2.2, level AA, read for native apps as W3C's Group Draft
  Note on applying WCAG to mobile applications (WCAG2Mobile) reads it. The European standard EN 301 549 (chapter 11)
  takes WCAG 2.1 AA into software through WCAG2ICT; it reads four criteria differently for software that is
  not a web page (2.4.1 Bypass Blocks, 2.4.5 Multiple Ways, 3.2.3 Consistent Navigation, 3.2.4 Consistent
  Identification). We aim at WCAG 2.2, which asks more.
- **Every language** the apps and the site speak, right-to-left ones included: a screen reader must read Persian and
  Arabic in their own voice and in their own order.

## How it is checked

| What | Where | How |
|---|---|---|
| Datapavan Basic's four destinations, its settings, an app's page and the plan: labels for screen readers, touch targets of 48 dp, the contrast of every text (4.5:1) and of every button that is only an icon (3:1) | CI, every change | `scripts/screenshots.sh` and `scripts/a11y-check.py`, in all eight languages, both pseudo-locales and dark mode; contrast measured on the captured frame as Google's Accessibility Test Framework measures it (its `ContrastSwatch`, ported and tested in `scripts/a11y-check-test.py`) |
| Datapavan Advanced's "Now" and an app's history: the same checks | locally (`scripts/screenshots.sh --now`, which starts a VPN on an emulator) | the same |
| Large text on the same screens of Basic: every text grows at Android's largest font size and display size with bold text | CI (English, Persian), locally (more languages) | the same script's large pass: each text's height compared with its height at the default size; the pictures read by eye, since a text cut off inside a box that grew does not show in the numbers |
| A keyboard's Tab (or a switch, which moves the same focus) reaches every button that Basic's summary and settings first show, in reading order | CI (English, Persian) | the same script's keyboard walk: Tab after Tab, the focused element read from each dump |
| The colours of both themes | CI | `ThemeTest`: every text colour on every ground |
| What TalkBack says, item by item, and in which language, on nine of Datapavan Advanced's screens so far ([the latest walk](#the-latest-talkback-walk)); every screen of both editions before Datapavan Advanced's first release (ADR 0039, gate 9) | locally, before each release with new screens | `scripts/talkback-walk.sh` on an emulator with TalkBack, with a speech engine of our own that writes down what TalkBack says |
| Every page of the website: axe-core's WCAG 2.0 to 2.2 A and AA rules, reflow at 320 px, text spacing, text at 200%, a keyboard walk with the contrast of each focus ring, forced colours | locally, before each deployment | `scripts/a11y-site.sh` |
| What the website can be held to without a browser: languages and directions, headings, names, the language list, landmarks, zoom, the colours of both schemes | CI, every change | `scripts/check-site.py` |
| People who use a screen reader every day, and people who use large text or magnification | before Datapavan Advanced's first release | the test with real users that gates it ([ADR 0045](https://github.com/visadahyu/datapavan/blob/main/docs/decisions/0045-three-editions-of-one-app.md), decision 8) |

Automated checks find only part of what fails: the people who make axe-core count about half of the issues by volume,
and fewer by criterion. That is why the walks and the test with real users are part of the check, not extras.

## What no tool checks, read by hand

Read again when a screen or a page is added or changed:

- **Reaching a page more than one way (2.4.5).** On the site, the main page and the news are linked from both the
  header's navigation and every page's footer; the pages for bots and privacy and the guides' index only from the
  footer, and each guide only from the guides' index, which every footer links (the guides are in English only, and
  the footer says so in each language). So these reach 2.4.5 only partly: see the known gaps. In the apps, every
  screen is reached from the bottom bar or from the screen before it, and the plan also from its launcher shortcut.
- **The same thing named the same way (3.2.3, 3.2.4).** The bottom bar's four destinations keep their order and
  names on every screen; "Network" names only Datapavan Advanced's screen and "Data use" only the audit's tab.
- **Help in the same place (3.2.6).** The one way to reach the project that the site offers, the security report, is
  in the same place in every page's footer. The site does not yet link this page's "Tell us": see the known gaps.
- **Orientation (1.3.4).** No screen of either edition is locked to portrait or landscape.
- **Dragging (2.5.7).** Nothing in either edition or on the site needs a drag.
- **Signing in (3.3.8).** Neither edition has an account, a sign-in or anything to remember.
- **Errors in a form (3.3.1 to 3.3.3, 4.1.3).** The text fields are the app search, a WireGuard configuration's name
  and, in Datapavan Advanced, your own resolver. When Datapavan's test of your resolver fails, both its fields are in
  Material's error state, which screen readers announce, and the reason is said in words. A configuration's name
  that holds nothing usable leaves the Save button off without saying why: a known gap. A configuration file that
  cannot be read is refused with its line and setting in plain words.
- **Titles (2.4.2).** Every screen's title is a heading, so that a screen reader can jump to it.
- **Moving and changing content (2.2.2).** "Now" updates its counts every second; its button stops them and starts
  them again, and a screen reader hears that they stopped. On the network screen, each WireGuard configuration's
  line "last handshake … ago" changes every second with no way to stop it: a known gap. The site's drawing opens
  only as it is scrolled into view, and not at all for readers who ask for less motion.
- **Forced colours and Android's contrast setting.** The site keeps its text, borders and drawing visible with forced
  colours (Windows' high contrast). Android 14 and later lets users ask apps for medium or high contrast; Datapavan's
  own colours already pass WCAG AA in both themes, and do not change with that setting yet: a known gap, below.

## The latest TalkBack walk

On 2026-11-23, with TalkBack 17.0 at its default settings on Android 17 (an emulator), on nine of Datapavan Advanced's
screens (the summary, the apps, phone and data use tabs, the settings, an app's page, the plan, the network screen and
"Now"), with Datapavan set to English, Persian and Arabic on a phone set to English (about 4,500 utterances in all).
Not walked yet: Datapavan Basic, an app's history, the guides, About, the data sources, the journal, the strict review,
own copy, "Now" while paused, and any screen with the phone itself set to Persian or Arabic.

- **Every item has a name.** TalkBack called nothing "unlabelled" on any screen in any language.
- **Roles and states are said.** Buttons as buttons, tabs as tabs with their number ("Tab, 2 of 4"), choices as radio
  buttons, selected or not, the app's page's sections as headings that are expanded or collapsed, the search field as
  an edit box.
- **Found by the walk, and fixed:** the destinations' titles were not headings, so a screen reader could not jump to
  them (the other screens' titles were fixed from the code); each preset resolver's "Its privacy policy" button did not
  say whose policy it was.
- **Fixed before the walk, and confirmed by it:** the app's page's sections are said as expanded or collapsed in
  TalkBack's own words, rather than "open" and "closed" in Datapavan's; tappable cards are said as buttons.
- **The order** goes down each screen, and along the bottom bar in its tabs' order. In long lists TalkBack leaves the
  list for the bottom bar before it scrolls on, then comes back: Android's own behaviour with lazy lists.

## Known gaps

- **The voice for the app's language.** When Datapavan's own language differs from the phone's (Persian in Datapavan on
  a phone set to English, for example), TalkBack reads Datapavan's text with the phone's voice: in the walk, every
  Persian and Arabic text was handed to the speech engine as English. Marking the text's language on the text, the
  way Android expects, did not change this in a test with Compose's text. Until it is solved, set the phone's
  language, or TalkBack's own speech language, to the language you read Datapavan in.
- **Android's contrast setting.** Android 14 and later lets users ask apps for medium or high contrast. Datapavan's
  colours pass WCAG AA in both themes, but do not yet change with that setting.
- **Reaching the site's pages more than one way (2.4.5).** The pages for bots and privacy, the guides' index and each
  guide can be reached only one way within the site; an HTML map of the site would give them a second.
- **The site does not link this page.** Its footer should carry "Accessibility", leading to the way to tell us.
- **A WireGuard configuration's handshake age** changes every second on the network screen, with no pause (2.2.2).
- **A configuration's name that holds nothing usable** leaves Save off without saying why (3.3.1).
- **The keyboard in the apps:** the walk checks that Tab reaches every button in order, not how visible the focus is
  (Material's own focus tint, which no check measures yet, 2.4.7), and not the arrow keys.
- **The walk does not reach every screen yet,** as above; gate 9 of ADR 0039 needs it to before Datapavan Advanced's
  first release.
- **No independent audit yet.** The checks above are the project's own and automated tools' own. A review by
  people who use assistive technology every day comes with Datapavan Advanced's test with real users; a professional
  accessibility audit is not planned yet.
- **The website's guides are in English only.** Every page says so where it links them.

## Tell us

If something in Datapavan or on its website does not work with your screen reader, your keyboard, your text size or
your colours, please tell us: open an issue on [GitHub](https://github.com/visadahyu/datapavan/issues), or write to the
address in [SECURITY.md](https://github.com/visadahyu/datapavan/blob/main/SECURITY.md) if you would rather not post in public. Please say which phone, which Android
version, which screen reader and which voice (speech engine) you use: Persian and Arabic voices often come from other
engines than Google's, and they behave differently.
