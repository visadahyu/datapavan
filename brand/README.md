# Brand

Logos and colours of **Datapavan** (the product) and the **Visadahyu Foundation**. The history behind
both names is in [docs/NAMES.md](../docs/NAMES.md).

## Marks

| File | Use | Sign |
|---|---|---|
| `datapavan-mark.svg` | Product mark and app icon | Old Persian **DA** (U+103AD) |
| `datapavan-shield.svg` | Product mark in a shield (security contexts, documents) | Old Persian **DA** |
| `visadahyu-mark.svg` | Foundation mark | Old Persian logogram **DAHYĀUŠ** (U+103CC) |
| `avatars/visadahyu-avatar.png` | Avatar of the `visadahyu` organisation on GitHub (1024×1024, safe for circular crops) | DAHYĀUŠ |
| `avatars/datapavan-avatar.png` | Spare square avatar of the product, e.g. for social accounts or a future forge (1024×1024) | DA |
| `avatars/datapavan-social.png` | GitHub social preview of the repository (1280×640) | DA + name |

- **DA** is the first sign of *dāta* "law" and of *dahyu* "land", so it links both names. Its three wedges (a horizontal one over two vertical ones) read as a gateway, echoing the Gate of All Nations. That reading is ours: Old Persian signs are phonetic, not pictures.
- **DAHYĀUŠ** is one of the very few Old Persian logograms, signs that stand for a whole word. It means "land, country, people", the root of *Visadahyu* ("of all nations").
- The outlines are taken unchanged from **Noto Sans Old Persian** (SIL Open Font License 1.1). The OFL allows using the font's glyphs in artwork such as logos. Before registering the marks as figurative trademarks, have a designer redraw them so the outlines are our own.

The Android launcher icon (`android/app/src/main/res/drawable/ic_launcher_foreground.xml`) uses the
same DA outline, 54 dp tall inside the 108 dp adaptive-icon canvas, so it stays within the safe zone
under every launcher mask.

**Editions (ADR 0045, 2026-11-13).** One family of icons, told apart by shape as well as colour, and by the name
under the icon:
- Datapavan Basic keeps the DA mark.
- Datapavan Advanced takes the shield drawn as one outline around DA (study B of 2026-11-13).
- Datapavan Enterprise takes, as a first idea, the shield with a double outline, its second line in gold.

No sword and no crown.

Datapavan Advanced's icon is the shield as one clay outline, 2.5 dp wide with round joins, around DA in clay, on
lapis (`android/app/src/main/res/drawable/ic_launcher_advanced_foreground.xml`), so that it differs from Basic's
on a home screen by shape as well as by name. The shield is 60 dp tall, centred in the 108 dp canvas, and its
farthest point, at the top corners, stays within the 33 dp safe zone. Its themed icon is the same drawing in one
colour (`ic_launcher_advanced_monochrome.xml`).

## Colours

| Name | Hex | Use |
|---|---|---|
| Lapis | `#1F4E8C` | Primary colour, app icon, emphasis text. After lapis lazuli, which Darius's foundation charter at Susa (DSf) lists as brought from Sogdiana |
| Clay | `#F3EBDC` | Background, mark colour on lapis. After the clay tablets of the Persepolis archives |
| Gold | `#B07D2B` | Decoration and graphics only, never body text. After Achaemenid goldwork |
| Dark gold | `#8A5F17` | Gold-coloured text on light backgrounds |
| Light lapis | `#8DB0E6` | Primary colour in dark mode |
| Light gold | `#D9A54A` | Accent in dark mode |
| Night | `#14161C` | Dark-mode background |

Measured WCAG contrast ratios:

| Pair | Ratio | Allowed for |
|---|---|---|
| Lapis on clay, clay on lapis | 7.02 | Any text (AAA) |
| Lapis on white | 8.31 | Any text (AAA) |
| Dark gold on clay | 4.75 | Normal text (AA) |
| Gold on clay | 3.05 | Large text and graphics only |
| Light lapis on night | 8.17 | Any text (AAA) |
| Light gold on night | 8.12 | Any text (AAA) |
| Gold on lapis | 2.30 | **Never** |
| Lapis on night | 2.18 | **Never**: use light lapis in dark mode |

Blue and gold stay distinct for the most common colour-vision deficiencies (red-green).

### In the app

The app's Material 3 colour scheme (`android/app/src/main/java/org/visadahyu/datapavan/ui/Theme.kt`) is
built from this palette: lapis as the primary colour on a lighter clay (`#FBF7F0`) in light mode, light
lapis and light gold on night in dark mode, with cards in clay tones. Gold text in light mode uses
`#7A5212`, darker than dark gold, because dark gold falls below 4.5:1 on the darker clay of cards. The
app does not take its colours from the wallpaper: `ThemeTest` checks that every text colour reaches
4.5:1 on every surface (WCAG AA) and outlines 3:1, in both modes, and a finding's colour means the same
on every phone. The lowest text ratios are 4.94 (light) and 5.26 (dark).

## Rules

- The foundation leans on clay (calm, institutional); the product leans on lapis.
- Do not stretch, rotate, outline or recolour the marks outside this palette.
- Keep clear space around a mark of at least the height of DA's horizontal wedge.
- Do not combine the marks with national, political or religious symbols (flags, maps, the faravahar,
  the lion and sun). The foundation is meant for all nations.
