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
load before images, and no broken link inside the site. Anything meant to be read is text, so that a browser without web
fonts or SVG loses only the look.

News items state facts their sources state, in our own words, and link out. They load nothing from the source's server, and
they never say Datapavan would have prevented or detected anything. The sample app on the main page is marked as sample data.

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
- **IndexNow:** the key file `static/<key>.txt`. After a deploy, `scripts/indexnow.py --send` tells Bing, Yandex,
  Naver and Seznam which pages exist; Google reads the sitemap.
- **The consoles:** Google Search Console holds datapavan.org as a domain property, verified by a TXT record in its
  DNS; Bing Webmaster Tools imports it from there. Both have the sitemap.

`scripts/check-site.py` checks all of it: robots.txt, the sitemap against the pages, llms.txt's links, the key file,
and on every page
one canonical address and a title no other page of its language has.
