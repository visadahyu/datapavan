# Accessibility

Datapavan is for everyone who carries a phone, and that includes people who are blind or have low vision, people who
need large text or strong contrast, and people who use a keyboard, a switch or their voice instead of touch. This page
says what Datapavan aims for, how it is checked, what is known to fall short, and how to tell us when something does
not work for you.

## What we aim for

- **The website** ([datapavan.org](https://datapavan.org/)): WCAG 2.2, level AA.
- **The apps** (Datapavan Basic and Datapavan Advanced): WCAG 2.2, level AA, read for native apps as W3C's Group Draft
  Note on applying WCAG to mobile applications (WCAG2Mobile) reads it. The European standard EN 301 549 (v3.2.1,
  chapter 11) takes WCAG 2.1 AA into software through WCAG2ICT; it reads four criteria differently for software that is
  not a web page (2.4.1 Bypass Blocks, 2.4.5 Multiple Ways, 3.2.3 Consistent Navigation, 3.2.4 Consistent
  Identification). We aim at WCAG 2.2, which asks more.
- **Every language** the apps and the site speak, right-to-left ones included: a screen reader must read Persian and
  Arabic in their own voice and in their own order.

## How it is checked

| What | Where | How |
|---|---|---|
| Every screen of both apps: labels for screen readers, touch targets of 48 dp, the contrast of every text (4.5:1) and icon (3:1) | CI, every change | `scripts/screenshots.sh` and `scripts/a11y-check.py`, in all eight languages, both pseudo-locales and dark mode; contrast measured on the captured frame as Google's Accessibility Test Framework measures it (its `ContrastSwatch`, ported and tested in `scripts/a11y-check-test.py`) |
| Large text: every text grows at Android's largest font size and display size with bold text, and nothing is cut off | CI (English, Persian), locally (more languages) | the same script's large pass: each text's height compared with its height at the default size; the pictures read by eye |
| A keyboard (or a switch, which moves the same focus) reaches every button, in reading order | CI (English, Persian) | the same script's keyboard walk: Tab after Tab, the focused element read from each dump |
| The colours of both themes | CI | `ThemeTest`: every text colour on every ground |
| What TalkBack says on every screen, item by item, and in which language | locally, before each release with new screens | `scripts/talkback-walk.sh` on an emulator with TalkBack, with a speech engine of our own that writes down what TalkBack says ([the latest walk](#the-latest-talkback-walk)) |
| Every page of the website: axe-core's WCAG 2.0 to 2.2 A and AA rules, reflow at 320 px, text spacing, text at 200%, a keyboard walk with the contrast of each focus ring, forced colours | locally, before each deployment | `scripts/a11y-site.sh` |
| What the website can be held to without a browser: languages and directions, headings, names, the language list, landmarks, zoom, the colours of both schemes | CI, every change | `scripts/check-site.py` |
| People who use a screen reader every day, and people who use large text or magnification | before Datapavan Advanced's first release | the test with real users that gates it ([ADR 0045](decisions/0045-three-editions-of-one-app.md), decision 8) |

Automated checks find only part of what fails: the people who make axe-core count about half of the issues by volume,
and fewer by criterion. That is why the walks and the test with real users are part of the check, not extras.

## What no tool checks, read by hand

Read again when a screen or a page is added or changed:

- **Reaching a page more than one way (2.4.5).** The site's pages are linked from the header's navigation and from
  every page's footer, and the guides' index lists every guide; the guides are in English only, and the footer says
  so in each language. In the apps, every screen is reached from the bottom bar or from the screen before it, and
  the plan also from its launcher shortcut.
- **The same thing named the same way (3.2.3, 3.2.4).** The bottom bar's four destinations keep their order and
  names on every screen; "Network" names only Datapavan Advanced's screen and "Data use" only the audit's tab.
- **Help in the same place (3.2.6).** The site's footer, on every page, holds the security report, the privacy policy
  and the source.
- **Orientation (1.3.4).** No screen of either edition is locked to portrait or landscape.
- **Dragging (2.5.7).** Nothing in either edition or on the site needs a drag.
- **Signing in (3.3.8).** Neither edition has an account, a sign-in or anything to remember.
- **Errors in a form (3.3.1 to 3.3.3, 4.1.3).** The text fields are the app search, a WireGuard configuration's name
  and, in Datapavan Advanced, your own resolver. Only the resolver's are ever refused: when Datapavan's test of it
  fails, both fields are in Material's error state, which screen readers announce, and the reason is said in words.
  A configuration file that cannot be read is refused with its line and setting in plain words.
- **Titles (2.4.2).** Every screen's title is a heading, and TalkBack reads it when the screen opens.
- **Moving and changing content (2.2.2).** "Now" updates its counts every second; its button stops them and starts
  them again. Nothing else moves by itself, and the site's drawing opens only as it is scrolled into view, and not at
  all for readers who ask for less motion.
- **Forced colours and Android's contrast setting.** The site keeps its text, borders and drawing visible with forced
  colours (Windows' high contrast). Android 14 and later lets users ask apps for medium or high contrast; Datapavan's
  own colours already pass WCAG AA in both themes, and do not change with that setting yet: a known gap, below.

## The latest TalkBack walk

On 2026-11-23, with TalkBack 17.0 at its default settings on Android 17 (an emulator), on Datapavan Advanced's
summary, apps, phone and data use tabs, the settings, an app's page, the plan, the network screen and "Now", in English,
Persian and Arabic (about 4,500 utterances in all):

- **Every item has a name.** TalkBack called nothing "unlabelled" on any screen in any language.
- **Roles and states are said.** Buttons as buttons, tabs as tabs with their number ("Tab, 2 of 4"), choices as radio
  buttons, selected or not, the app's page's sections as headings that are expanded or collapsed, the search field as
  an edit box.
- **Fixed on the way:**
  - the screens' titles were not headings, so a screen reader could not jump to them;
  - the app's page's sections said "open" and "closed" in Datapavan's words rather than TalkBack's own;
  - tappable cards had no role;
  - each preset resolver's "Its privacy policy" button did not say whose policy it was.
- **The order** follows the screen: down the page, right to left in Persian and Arabic. In long lists TalkBack leaves
  the list for the bottom bar before it scrolls on, then comes back: Android's own behaviour with lazy lists.

## Known gaps

- **The voice for the app's language.** When Datapavan's own language differs from the phone's (Persian in Datapavan on
  a phone set to English, for example), TalkBack reads Datapavan's text with the phone's voice: in the walk, every
  Persian and Arabic text was handed to the speech engine as English. Marking the text's language on the text, the
  way Android expects, did not change this in a test with Compose's text. Until it is solved, set the phone's
  language, or TalkBack's own speech language, to the language you read Datapavan in.
- **Android's contrast setting.** Android 14 and later lets users ask apps for medium or high contrast. Datapavan's
  colours pass WCAG AA in both themes, but do not yet change with that setting.
- **No independent audit yet.** The checks above are the project's own and automated tools' own. A review by
  people who use assistive technology every day comes with Datapavan Advanced's test with real users; a professional
  accessibility audit is not planned yet.
- **The website's guides are in English only.** Every page says so where it links them.

## Tell us

If something in Datapavan or on its website does not work with your screen reader, your keyboard, your text size or
your colours, please tell us: open an issue on [GitHub](https://github.com/visadahyu/datapavan/issues), or write to the
address in [SECURITY.md](../SECURITY.md) if you would rather not post in public. Please say which phone, which Android
version, which screen reader and which voice (speech engine) you use: Persian and Arabic voices often come from other
engines than Google's, and they behave differently.
