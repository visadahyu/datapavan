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

<!-- Filled from the unit's walk. -->

## The latest TalkBack walk

<!-- Filled from the unit's walk. -->

## Known gaps

<!-- Filled from the unit's results. -->

## Tell us

If something in Datapavan or on its website does not work with your screen reader, your keyboard, your text size or
your colours, please tell us: open an issue on [GitHub](https://github.com/visadahyu/datapavan/issues), or write to the
address in [SECURITY.md](../SECURITY.md) if you would rather not post in public. Please say which phone, which Android
version, which screen reader and which voice (speech engine) you use: Persian and Arabic voices often come from other
engines than Google's, and they behave differently.
