# The website

datapavan.org is built from here into `../docs/site`, which is what gets deployed. `scripts/build-site.sh` fetches a
pinned [Hugo](https://gohugo.io) by its hash and builds; with `--check`, which `scripts/check.sh` runs, it fails if the
two differ. Nothing runs on the server: the output is plain files. A release's signed files are not built with the site or
kept in Git: they go to `download/` on the server beside it, and `hugo.toml` names the current APK, its hash and size.

- `data/text/<lang>.json`: every word of the main page, one file per language, all with the shape of `en.json`.
- `content/news/`: one file per item and language. Each item says what happened, why it matters and where it was reported.
- `content/privacy/`: written by the build from `PRIVACY.md`, which stays the one source.
- `layouts/`, `assets/style.css`: the pages. The drawing is `layouts/_partials/drawing-*.html`.
- `static/`: fonts under the SIL Open Font License 1.1 (`static/fonts/LICENSES.txt`), images, `security.txt`. Chinese uses
  the phone's own fonts. `static/images` comes from `scripts/store-images.sh`.

The rules, which `scripts/check-site.py` enforces: no script, nothing from another server, about 200 KB or less on a first
load before images, and no broken link inside the site, nor one that names `index.html`: a link by the site's full
address (`https://datapavan.org/...`) or from its root counts as inside it. Anything meant to be read is text, so that a browser without web
fonts or SVG loses only the look.

News items state facts their sources state, in our own words, and link out. They load nothing from the source's server, and
they never say Datapavan would have prevented or detected anything. The sample app on the main page is marked as sample data.

## Accessibility

The site aims at WCAG 2.2, level AA, in every language, as [docs/ACCESSIBILITY.md](../docs/ACCESSIBILITY.md) says. Two
checks hold it there:

- `scripts/check-site.py`, in CI, for what needs no browser:
  - each page's `lang` and `dir`;
  - one `h1` and no skipped heading level (a house rule);
  - a name for every link, control, picture and drawing, holding its visible text where it has one;
  - the language list's `lang` and `hreflang`;
  - one `<main id="main">` with a link to it first in the body;
  - zoom never blocked;
  - a role and a name for every box that takes the focus;
  - the stylesheet's colours: every text colour on every ground, and the pairs listed in the script, at least 4.5:1
    in both schemes; a focus ring that stands out at least 3:1 where a component has its own colour; a rule for
    readers who ask for less motion. A colour used for text or ground that the script does not list fails, so add a
    new colour to its lists.
- `scripts/a11y-site.sh`, locally before a deployment: axe-core in Chrome over every page in both schemes at 1280 and
  320 px, reflow, text spacing, text at 200%, a keyboard walk that measures each focus ring, and pictures with forced
  colours. Its packages are pinned in `scripts/a11y-site/package-lock.json`. It writes to `build/a11y-site/`. Read
  its "to review" lines too: they are what axe could not decide.

Tables in a page's text scroll inside a box of their own on narrow screens (`layouts/_markup/render-table.html`). A
picture that carries meaning has `alt`; a drawing has `role="img"` and an `aria-label`, or `aria-hidden="true"` if it
only decorates.

## Search engines

The goal (maintainer, 2026-11-23): a search for Datapavan in any of the eight languages finds this site and the
repository first, not a copy of the app from somewhere else; the AI assistants that answer from search indexes can
find and cite it; and the guides are found by the questions they answer. Nothing on the site tracks visitors for
this: the engines' own consoles report searches and clicks.

- **`robots.txt`** (`layouts/robots.txt`): every crawler is welcome, AI crawlers included, since the project is open
  source and wants models to describe it correctly. Only `/download/`, the signed APKs, is left out.
- **`sitemap.xml`** (`layouts/sitemapindex.xml`): one file at the root with every page of every language, each with its
  translations and English as `x-default`. Hugo's per-language sitemaps are removed by `scripts/build-site.sh`,
  since English's would sit under `/en/`, where a sitemap may not list the root's pages.
- **Each page's head** (`layouts/baseof.html`): its own title (the main page adds its heading), a description (a
  guide's opening, else the tagline), one canonical address, matching `og:url`, its translations, and a link
  preview with the store icon (`static/images/icon-512.png`, from `scripts/store-images.sh icon`).
- **`llms.txt`** (`layouts/home.llms.txt`, [llmstxt.org](https://llmstxt.org)): what Datapavan is and every page, in
  plain text for AI assistants, written from the same data as the pages. No large engine has said it reads the file;
  it costs nothing to keep. Only the root one is kept, and it links the other languages.
- **schema.org data** (`layouts/home.html`): the site's name, with the names in other scripts, and the app as a
  SoftwareApplication, as microdata rather than JSON-LD, so that the site keeps no script tag at all.
- **`404.html`** (`layouts/404.html`): the page a missing address gets, with the 404 status, from the server's
  `handle_errors` (`server/site.sh` in the strategy repository). It is kept out of the indexes and links every
  language's main page; only the root one is kept, and since it is served at any depth, its links start at the root.
- **IndexNow:** the key file `static/<key>.txt`. After a deploy, `scripts/indexnow.py --send` tells Bing, Yandex,
  Naver and Seznam which pages exist; Google reads the sitemap.
- **The consoles:** Google Search Console holds datapavan.org as a domain property, and Yandex Webmaster holds it too,
  each verified by its own TXT record in the domain's DNS, which must stay; Bing Webmaster Tools imported it from
  Google's (all on 2026-11-23). Each gets the sitemap once it is live. Bing's AI Performance report shows where
  Copilot's answers cite the site.

`scripts/check-site.py` checks all of it: robots.txt, the sitemap against the pages, llms.txt's links, the key file,
and on every page
one canonical address and a title no other page of its language has.
