// SPDX-License-Identifier: Apache-2.0
// The site's local accessibility audit (scripts/a11y-site.sh, site/README.md "Accessibility"). Over every built page,
// opened as file:// in the system's Chrome with every other request refused:
//   - axe-core with WCAG 2.0, 2.1 and 2.2 A and AA rules (failures), best practices (notes) and the results axe cannot
//     decide (to review), in the light and the dark scheme, at 1280 and 320 CSS px wide;
//   - Reflow (1.4.10): no page-wide horizontal scroll at 320 px, the same links and controls reachable at 320 px as at
//     1280, and no scroll either with WCAG's text spacing (1.4.12) or with text at 200% (1.4.4);
//   - Text spacing and text size: no text clipped by a box that hides its overflow;
//   - a keyboard walk in both schemes: Tab through every focusable element, the language list open and closed; each
//     shows a focus indicator (2.4.7) whose changed pixels stand at least 3:1 against what they replaced (the house
//     rule, after 1.4.11), and is not hidden under another box (2.4.11); Enter and Space open and close the list;
//   - pictures of a few pages with forced colours (Windows' high contrast), for a reading by eye.
// Writes report.json and summary.txt to the output folder; exits 1 if any failure was found.
//
//   node run.mjs SITE_DIR OUT_DIR
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from "node:fs";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { inflateSync } from "node:zlib";
import puppeteer from "puppeteer-core";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const AXE_VERSION = JSON.parse(readFileSync(require.resolve("axe-core/package.json"), "utf8")).version;
const [SITE, OUT] = process.argv.slice(2);
const CHROME = process.env.CHROME || "/usr/bin/google-chrome";
const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const SPACING = `*{line-height:1.5!important;letter-spacing:.12em!important;word-spacing:.16em!important}
p{margin-bottom:2em!important}`;
const BIG_TEXT = "html{font-size:200%!important}";
const INSTANT = "html{scroll-behavior:auto!important}";
const FORCED = ["index.html", "fa/index.html", "privacy/index.html", "guides/index.html"];

function pages(dir) {
  const found = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (relative(SITE, path) !== "download") found.push(...pages(path));
    } else if (name.endsWith(".html")) found.push(path);
  }
  return found.sort();
}

// A PNG from Chrome: 8-bit RGB or RGBA, not interlaced. Returns {w, h, px(x, y) -> [r, g, b]}.
function png(buf) {
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20), type = buf[25];
  const bpp = type === 6 ? 4 : 3;
  const chunks = [];
  for (let i = 8; i < buf.length; ) {
    const n = buf.readUInt32BE(i), kind = buf.toString("latin1", i + 4, i + 8);
    if (kind === "IDAT") chunks.push(buf.subarray(i + 8, i + 8 + n));
    i += 12 + n;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  const stride = w * bpp, out = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = y * (stride + 1) + 1, dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? out[dst + x - bpp] : 0, b = y ? out[dst - stride + x] : 0, c = x >= bpp && y ? out[dst - stride + x - bpp] : 0;
      let v = raw[src + x];
      if (f === 1) v += a;
      else if (f === 2) v += b;
      else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) {
        const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      out[dst + x] = v & 255;
    }
  }
  return { w, h, px: (x, y) => [out[y * stride + x * bpp], out[y * stride + x * bpp + 1], out[y * stride + x * bpp + 2]] };
}

const luminance = ([r, g, b]) => {
  const l = (c) => ((c /= 255) <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * l(r) + 0.7152 * l(g) + 0.0722 * l(b);
};
const ratio = (p, q) => {
  const [a, b] = [luminance(p), luminance(q)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
};

// The focus indicator's contrast: the pixels that changed when the element took the focus, each against what it
// replaced; the indicator passes when its most common changed colour stands at least 3:1 against what it replaced.
function ringContrast(focused, unfocused) {
  const counts = new Map();
  for (let y = 0; y < focused.h; y++) {
    for (let x = 0; x < focused.w; x++) {
      const f = focused.px(x, y), u = unfocused.px(x, y);
      if (Math.abs(f[0] - u[0]) + Math.abs(f[1] - u[1]) + Math.abs(f[2] - u[2]) < 24) continue;
      const key = `${f.join(",")}|${u.join(",")}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
  }
  if (!counts.size) return 0;
  const [key] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  const [f, u] = key.split("|").map((s) => s.split(",").map(Number));
  return ratio(f, u);
}

// The page's own widest scroll against the window: a page-wide horizontal scroll fails Reflow.
const sideScroll = () => document.documentElement.scrollWidth - window.innerWidth;

// Boxes that hide their overflow while their text overflows them.
function clipped() {
  const out = [];
  for (const el of document.querySelectorAll("body *")) {
    const s = getComputedStyle(el);
    const hides = (v) => v === "hidden" || v === "clip";
    if (!el.textContent.trim() || (!hides(s.overflowX) && !hides(s.overflowY))) continue;
    if (el.getClientRects().length === 0 || el.clientWidth <= 1) continue;
    if ((hides(s.overflowX) && el.scrollWidth > el.clientWidth + 1) || (hides(s.overflowY) && el.scrollHeight > el.clientHeight + 1)) {
      out.push(`${el.tagName.toLowerCase()}${el.className ? "." + String(el.className).split(" ")[0] : ""}: ${el.textContent.trim().slice(0, 40)}`);
    }
  }
  return out;
}

// Every link and control a reader can reach, by where it leads and what it says.
const reachable = () =>
  [...document.querySelectorAll("a[href], summary, [tabindex]")]
    .filter((el) => el.getClientRects().length && getComputedStyle(el).visibility !== "hidden" && !el.closest("details:not([open]) > :not(summary)"))
    .map((el) => `${el.tagName.toLowerCase()} ${el.getAttribute("href") || ""} ${(el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 30)}`);

// One step of the keyboard walk: what has the focus, whether it shows an indicator, and whether another box covers
// it. A link broken over lines, or into pieces by bidi, is covered only if every piece is.
function focusState() {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const s = getComputedStyle(el);
  const indicator = (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== "none");
  const pieces = [...el.getClientRects()].filter((r) => r.width > 0 && r.height > 0);
  const seen = pieces.some((r) => {
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) return false;
    const top = document.elementFromPoint(x, y);
    return top && (el === top || el.contains(top));
  });
  const r = el.getBoundingClientRect();
  const name = (el.getAttribute("aria-label") || el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40);
  const kind = `${el.tagName.toLowerCase()}.${el.className || ""}<${el.parentElement ? el.parentElement.tagName.toLowerCase() + "." + (el.parentElement.className || "") : ""}`;
  return { tag: el.tagName.toLowerCase(), href: el.getAttribute("href"), name, kind, indicator, covered: !seen,
    box: { x: Math.max(0, r.left - 8 + window.scrollX), y: Math.max(0, r.top - 8 + window.scrollY), width: r.width + 16, height: r.height + 16 } };
}

const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ["--no-first-run", "--disable-extensions"] });
const report = { chrome: await browser.version(), axe: AXE_VERSION, failures: [], notes: [], review: [], walks: {}, rings: {} };
const fail = (page, what, detail) => report.failures.push({ page, what, detail });
try {
  const tab = await browser.newPage();
  await tab.setRequestInterception(true);
  tab.on("request", (req) => (req.url().startsWith("file:") ? req.continue() : req.abort()));
  const load = async (url, scheme, width, css) => {
    await tab.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }, { name: "forced-colors", value: "none" }]);
    await tab.setViewport({ width, height: 800, deviceScaleFactor: 1 });
    await tab.goto(url, { waitUntil: "load" });
    for (const c of css) await tab.addStyleTag({ content: c });
  };

  async function walk(name, url, scheme, width, openList) {
    await load(url, scheme, width, [INSTANT]);
    if (openList) await tab.evaluate(() => { const d = document.querySelector("details.lng"); if (d) d.open = true; });
    const steps = [];
    for (let i = 0; i < 250; i++) {
      await tab.keyboard.press("Tab");
      const state = await tab.evaluate(focusState);
      if (!state) break;
      if (steps.length && state.tag === steps[0].tag && state.href === steps[0].href && state.name === steps[0].name) break;
      steps.push(state);
      const where = `${scheme} ${width}${openList ? " list open" : ""}`;
      if (!state.indicator) fail(name, "focus-visible", `${where}: no focus indicator on ${state.tag} "${state.name}"`);
      if (state.covered) fail(name, "focus-obscured", `${where}: ${state.tag} "${state.name}" is hidden by another box`);
      // Each kind of element's ring is measured once per scheme, where it first appears.
      const ringKey = `${scheme} ${state.kind}`;
      if (state.indicator && !state.covered && !(ringKey in report.rings) && state.box.width > 0) {
        const clip = { ...state.box, width: Math.min(state.box.width, width - state.box.x) };
        if (clip.width > 2 && clip.height > 2) {
          const on = png(await tab.screenshot({ clip }));
          await tab.evaluate(() => document.activeElement.blur());
          const off = png(await tab.screenshot({ clip }));
          await tab.evaluate((n) => {
            // Back to where the walk was: the n-th element the Tab key reaches.
            const all = [...document.querySelectorAll("a[href], summary, [tabindex]:not([tabindex='-1'])")].filter((e) => e.getClientRects().length);
            if (all[n]) all[n].focus({ focusVisible: true });
          }, steps.length - 1);
          const r = ringContrast(on, off);
          report.rings[ringKey] = { page: name, element: state.name, ratio: Math.round(r * 100) / 100 };
          if (r < 3) fail(name, "focus-contrast", `${scheme} ${width}: the focus indicator of ${state.tag} "${state.name}" is ${r.toFixed(2)}:1`);
        }
      }
    }
    if (!steps.length) fail(name, "keyboard", `${scheme} ${width}: nothing takes the focus`);
    report.walks[`${name} ${scheme} ${width}${openList ? " list open" : ""}`] = steps.map((s) => `${s.tag} ${s.name}`);
  }

  for (const path of pages(SITE)) {
    const name = relative(SITE, path);
    const url = pathToFileURL(path).href;
    const sets = {};
    for (const scheme of ["light", "dark"]) {
      for (const width of [1280, 320]) {
        await load(url, scheme, width, []);
        await tab.addScriptTag({ content: AXE });
        const result = await tab.evaluate(async (tags) => {
          const r = await window.axe.run(document, { runOnly: { type: "tag", values: [...tags, "best-practice"] }, resultTypes: ["violations", "incomplete"] });
          // For what axe could not decide, its reason (for example a background it cannot see, or text partly scrolled away).
          const why = (n) => { const d = (n.any[0] || {}).data; return d && d.messageKey ? ` (${d.messageKey})` : ""; };
          const brief = (v) => ({ id: v.id, tags: v.tags, help: v.help, nodes: v.nodes.map((n) => n.target.join(" ") + why(n)).slice(0, 5) });
          return { violations: r.violations.map(brief), incomplete: r.incomplete.map(brief) };
        }, WCAG);
        for (const v of result.violations) {
          const entry = { page: name, what: v.id, detail: `${scheme} ${width}: ${v.help} [${v.nodes.join(", ")}]` };
          (v.tags.some((t) => WCAG.includes(t)) ? report.failures : report.notes).push(entry);
        }
        for (const v of result.incomplete) report.review.push({ page: name, what: v.id, detail: `${scheme} ${width}: ${v.help} [${v.nodes.join(", ")}]` });
        if (scheme !== "light") continue;
        sets[width] = await tab.evaluate(reachable);
        const over = await tab.evaluate(sideScroll);
        if (width === 320 && over > 0) fail(name, "reflow", `scrolls ${over} px sideways at 320 px`);
        // Text spacing at both widths; text at 200% at the full width only (at 320 px it would stand for 800% zoom).
        for (const [what, css] of width === 320 ? [["text-spacing", SPACING]] : [["text-spacing", SPACING], ["text-200", BIG_TEXT]]) {
          await load(url, scheme, width, [css]);
          for (const c of await tab.evaluate(clipped)) fail(name, what, `${width}: ${c}`);
          const o = await tab.evaluate(sideScroll);
          if (o > 0) fail(name, `reflow-${what}`, `scrolls ${o} px sideways at 320 px`);
        }
      }
    }
    const missing = sets[1280].filter((x) => !sets[320].includes(x));
    if (missing.length) fail(name, "reflow-lost", `at 320 px, ${missing.length} links or controls of 1280 px are gone, e.g. ${missing[0]}`);
    for (const scheme of ["light", "dark"]) await walk(name, url, scheme, 1280, false);
    await walk(name, url, "light", 320, false);
    await walk(name, url, "light", 1280, true);
    // The language list opens and closes with Enter and with Space.
    for (const key of ["Enter", "Space"]) {
      await load(url, "light", 1280, [INSTANT]);
      const has = await tab.evaluate(() => { const s = document.querySelector("details.lng > summary"); if (s) s.focus(); return !!s; });
      if (!has) break;
      await tab.keyboard.press(key);
      const open = await tab.evaluate(() => document.querySelector("details.lng").open);
      await tab.keyboard.press(key);
      const closed = await tab.evaluate(() => !document.querySelector("details.lng").open);
      if (!open || !closed) fail(name, "language-list", `${key} does not ${open ? "close" : "open"} the language list`);
    }
  }
  // Forced colours, for a reading by eye.
  mkdirSync(join(OUT, "forced-colors"), { recursive: true });
  for (const name of FORCED) {
    for (const scheme of ["light", "dark"]) {
      await tab.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }, { name: "forced-colors", value: "active" }]);
      await tab.setViewport({ width: 1280, height: 800, deviceScaleFactor: 1 });
      await tab.goto(pathToFileURL(join(SITE, name)).href, { waitUntil: "load" });
      await tab.screenshot({ path: join(OUT, "forced-colors", `${name.replaceAll("/", "-")}-${scheme}.png`), fullPage: true });
    }
  }
} finally {
  await browser.close();
}

mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 1));
const group = (list) => {
  const by = {};
  for (const f of list) (by[f.what] ||= []).push(f);
  return Object.entries(by).map(([what, all]) => `  ${what}: ${all.length} on ${new Set(all.map((f) => f.page)).size} pages, e.g. ${all[0].page}: ${all[0].detail}`);
};
const rings = Object.values(report.rings).map((r) => r.ratio);
const summary = [
  `Chrome ${report.chrome}, axe-core ${report.axe}`,
  `failures: ${report.failures.length}`, ...group(report.failures),
  `notes (best practice): ${report.notes.length}`, ...group(report.notes),
  `to review (axe could not decide): ${report.review.length}`, ...group(report.review),
  `focus indicators measured: ${rings.length}, lowest ${rings.length ? Math.min(...rings).toFixed(2) : "-"}:1`,
].join("\n");
writeFileSync(join(OUT, "summary.txt"), summary + "\n");
console.log(summary);
process.exit(report.failures.length ? 1 : 0);
