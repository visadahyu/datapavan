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
