#!/usr/bin/env node
// The website's fallback faces (site/README.md, "Fonts"): for each web font, faces on the phone's or computer's own
// fonts, set to the web font's width and height (size-adjust, ascent-override, descent-override), so that the text
// takes the same room before the web font arrives as after, and its arrival moves nothing (Cumulative Layout Shift,
// web.dev/articles/vitals). Archivo is drawn at several widths (font-stretch), so its fallbacks come in one face per
// width the stylesheet uses.
//
// It measures in Chrome: each web font from site/static/fonts, beside each fallback as the browser finds it by name,
// on the site's own words in that script (site/data/text), and writes the faces between the markers in
// site/assets/script-{latin,ru,rtl}.css. It checks the result in Chrome too. A fallback not installed here can be
// measured from a file of it: --file Roboto=regular.ttf,bold.ttf (Roboto is Android's, and few computers have it).
//
//   node scripts/font-fallbacks.mjs [--file NAME=REGULAR,BOLD ...]
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const FONTS = join(ROOT, 'site/static/fonts');
const BEGIN = '/* Fallbacks with the web fonts\' metrics, written by scripts/font-fallbacks.mjs */';
const END = '/* End of the fallbacks */';

// Each fallback: the names the browser finds it by (full name, then PostScript name), for its regular and bold.
const ARIAL = { regular: ['Arial', 'ArialMT', 'Liberation Sans', 'LiberationSans', 'Arimo'],
  bold: ['Arial Bold', 'Arial-BoldMT', 'Liberation Sans Bold', 'LiberationSans-Bold', 'Arimo Bold', 'Arimo-Bold'] };
const NARROW = { regular: ['Arial Narrow', 'ArialNarrow', 'Liberation Sans Narrow', 'LiberationSansNarrow'],
  bold: ['Arial Narrow Bold', 'ArialNarrow-Bold', 'Liberation Sans Narrow Bold', 'LiberationSansNarrow-Bold'] };
const ROBOTO = { regular: ['Roboto', 'Roboto Regular', 'Roboto-Regular'], bold: ['Roboto Bold', 'Roboto-Bold'] };
const NASKH = { regular: ['Noto Naskh Arabic', 'NotoNaskhArabic-Regular'], bold: ['Noto Naskh Arabic Bold', 'NotoNaskhArabic-Bold'] };

// Per web font: its files, its fallbacks (the family each becomes: "<font> <name>"), and its faces: the weight and
// width it is measured at, the weights and widths the face answers for, and which of the site's words it sets. A
// fallback for only part of the web font's characters names that part (unicode-range) and the language whose words
// it is measured on: the Persian and Arabic pages' Latin letters (the name, versions) are Vazirmatn's Latin, whose
// fallback is Arial, not the Arabic script's.
const REGULAR = '100 549', BOLD = '550 1000';
const SCRIPTS = {
  latin: { css: 'script-latin.css', lang: 'en', fonts: [
    { family: 'Archivo', files: ['archivo-latin-wdth-normal.woff2'], fallbacks: { Roboto: ROBOTO, Arial: ARIAL }, faces: [
      { weight: 400, stretch: 100, weights: REGULAR, stretches: '50% 200%', words: 'body' },
      { weight: 700, stretch: 100, weights: BOLD, stretches: '95% 200%', words: 'body' },
      { weight: 800, stretch: 88, weights: BOLD, stretches: '83.5% 95%', words: 'heads' },
      { weight: 800, stretch: 80, weights: BOLD, stretches: '76% 83.5%', words: 'heads' },
      { weight: 800, stretch: 74, weights: BOLD, stretches: '68% 76%', words: 'heads' },
      { weight: 900, stretch: 62, weights: BOLD, stretches: '50% 68%', words: 'heads' },
    ] },
  ] },
  ru: { css: 'script-ru.css', lang: 'ru', fonts: [
    { family: 'Sofia Sans Extra Condensed', files: ['sofia-sans-extra-condensed-cyrillic-wght-normal.woff2', 'sofia-sans-extra-condensed-latin-wght-normal.woff2'],
      fallbacks: { Roboto: ROBOTO, Narrow: NARROW }, faces: [
        { weight: 800, weights: '1 1000', words: 'heads' },
      ] },
    { family: 'Sofia Sans', files: ['sofia-sans-cyrillic-wght-normal.woff2', 'sofia-sans-latin-wght-normal.woff2'],
      fallbacks: { Roboto: ROBOTO, Arial: ARIAL }, faces: [
        { weight: 400, weights: REGULAR, words: 'body' },
        { weight: 800, weights: BOLD, words: 'heads' },
      ] },
  ] },
  rtl: { css: 'script-rtl.css', lang: 'fa', fonts: [
    { family: 'Vazirmatn', files: ['vazirmatn-arabic-wght-normal.woff2', 'vazirmatn-latin-wght-normal.woff2'],
      fallbacks: {
        Naskh: { font: NASKH, range: 'U+0600-06FF,U+0750-077F,U+0870-088E,U+0890-0891,U+0897-08E1,U+08E3-08FF,U+200C-200E,U+2010-2011,U+204F,U+2E41,U+FB50-FDFF,U+FE70-FE74,U+FE76-FEFC' },
        Arial: { font: ARIAL, lang: 'en', range: 'U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-200B,U+2012-204E,U+2050-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD' },
      }, faces: [
        { weight: 400, weights: REGULAR, words: 'body' },
        { weight: 900, weights: BOLD, words: 'heads' },
      ] },
  ] },
};

const files = {};
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] !== '--file') { console.error(readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 14).join('\n')); process.exit(2); }
  const [name, paths] = process.argv[++i].split('=');
  const [regular, bold] = paths.split(',').map((p) => resolve(p));
  files[name] = { regular, bold };
}

// The site's own words: headings, and running text.
function words(lang) {
  const t = JSON.parse(readFileSync(join(ROOT, `site/data/text/${lang}.json`), 'utf8'));
  return {
    heads: [t.h1, t.checks_title, t.limits_title, t.plan_title, t.faq_title, ...t.checks.map((c) => c[0])].join(' '),
    body: [t.tagline, t.lead, t.checks_lead, t.plan_body, ...t.checks.map((c) => c[1])].join(' '),
  };
}

const quote = (s) => JSON.stringify(s);
const norm = (fallback) => (fallback.font ? fallback : { font: fallback });
const local = (names) => names.map((n) => `local(${quote(n)})`).join(',');
const pct = (x) => `${(Math.round(x * 10000) / 100).toFixed(2)}%`;

// Chrome, headless, over the DevTools protocol (no packages needed).
async function chrome() {
  const dir = mkdtempSync(join(tmpdir(), 'font-fallbacks-'));
  const port = 9400 + Math.floor(Math.random() * 400);
  const proc = spawn('google-chrome', ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`,
    '--no-first-run', '--disable-extensions', '--allow-file-access-from-files', 'about:blank'], { stdio: 'ignore' });
  let ws;
  for (let i = 0; i < 100 && !ws; i++) {
    try {
      const page = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === 'page');
      if (page) ws = new WebSocket(page.webSocketDebuggerUrl);
    } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  await new Promise((r) => { ws.onopen = r; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  return {
    async run(html, expression) {
      const page = join(dir, `page-${id}.html`);
      writeFileSync(page, html);
      await send('Page.enable');
      await send('Page.navigate', { url: `file://${page}` });
      await new Promise((r) => setTimeout(r, 1500));
      const answer = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (answer.result.exceptionDetails) throw new Error(JSON.stringify(answer.result.exceptionDetails));
      return answer.result.result.value;
    },
    close() { ws.close(); proc.kill(); rmSync(dir, { recursive: true, force: true }); },
  };
}

// In the page: each face's width on a line of words at 100 px, and its ascent and descent: an inline box's content
// area runs from the ascent to the descent, and a box of no height inside it sits on the baseline.
const MEASURE = `(async () => {
  await document.fonts.ready;
  for (const f of document.fonts) await f.load().catch(() => {});
  const missing = [...document.fonts].filter((f) => f.status !== 'loaded').map((f) => f.family);
  const out = { missing, faces: {} };
  for (const el of document.querySelectorAll('[data-k]')) {
    const box = el.getBoundingClientRect(), base = el.querySelector('i').getBoundingClientRect().top;
    out.faces[el.dataset.k] = { width: box.width, ascent: (base - box.top) / 100, descent: (box.bottom - base) / 100 };
  }
  return out;
})()`;

function page(css, spans) {
  return `<!doctype html><meta charset="utf-8"><style>${css}
div{position:absolute;left:0;top:0;font-size:100px;white-space:nowrap}span{line-height:normal}i{display:inline-block;width:0;height:0}</style>${spans.join('')}`;
}

const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const span = (key, style, words) => `<div><span data-k="${key}" style='${style}'>${escape(words)}<i></i></span></div>`;

function src(name, fallback, weight) {
  const file = files[name]?.[weight];
  return file ? `url(${quote('file://' + file)})` : local(fallback[weight]);
}

const browser = await chrome();
let failed = false;
try {
  for (const [script, spec] of Object.entries(SCRIPTS)) {
    const textOf = (fallback) => words(norm(fallback).lang || spec.lang);
    let css = '', spans = [];
    // The web fonts, and each fallback as it is, untouched.
    for (const font of spec.fonts) {
      for (const file of font.files) css += `@font-face{font-family:${quote(font.family)};src:url(${quote('file://' + join(FONTS, file))});font-weight:1 1000;font-stretch:50% 200%}`;
      for (const [name, fallback] of Object.entries(font.fallbacks)) {
        for (const weight of ['regular', 'bold']) css += `@font-face{font-family:${quote(`raw ${name} ${weight}`)};src:${src(name, norm(fallback).font, weight)};font-weight:${weight === 'bold' ? 700 : 400}}`;
      }
      for (const [i, face] of font.faces.entries()) {
        const stretch = face.stretch ? `font-stretch:${face.stretch}%;` : '';
        for (const [name, fallback] of Object.entries(font.fallbacks)) {
          const weight = face.weight >= 550 ? 'bold' : 'regular', text = textOf(fallback)[face.words];
          spans.push(span(`${font.family}|${i}|${name}|web`, `font-family:${quote(font.family)};font-weight:${face.weight};${stretch}`, text));
          spans.push(span(`${font.family}|${i}|${name}`, `font-family:${quote(`raw ${name} ${weight}`)};font-weight:${weight === 'bold' ? 700 : 400}`, text));
        }
      }
    }
    const raw = await browser.run(page(css, spans), MEASURE);
    if (raw.missing.length) throw new Error(`${script}: not found: ${[...new Set(raw.missing)].join(', ')}; install it or give --file`);
    // The faces: the fallback scaled to the web font's width, its ascent and descent the web font's. Chrome applies
    // size-adjust to the overrides too, so they are divided by it. A fallback with a range of its own sets only part
    // of a line (its spaces come from the next one), so its first scale is refined from the check, up to three times.
    const adjusts = {};
    for (const font of spec.fonts) {
      for (const name of Object.keys(font.fallbacks)) {
        for (const i of font.faces.keys()) {
          const key = `${font.family}|${i}|${name}`;
          adjusts[key] = raw.faces[`${key}|web`].width / raw.faces[key].width;
        }
      }
    }
    let rules, checked;
    for (let round = 0; round < 4; round++) {
      rules = [];
      let checkCss = '', checkSpans = [];
      for (const font of spec.fonts) {
        for (const file of font.files) checkCss += `@font-face{font-family:${quote(font.family)};src:url(${quote('file://' + join(FONTS, file))});font-weight:1 1000;font-stretch:50% 200%}`;
        for (const [name, fallback] of Object.entries(font.fallbacks)) {
          for (const [i, face] of font.faces.entries()) {
            const key = `${font.family}|${i}|${name}`, web = raw.faces[`${key}|web`], adjust = adjusts[key];
            const { font: names, range } = norm(fallback), text = textOf(fallback)[face.words];
            const only = range ? `;unicode-range:${range}` : '';
            const weight = face.weight >= 550 ? 'bold' : 'regular';
            const stretch = face.stretches ? `;font-stretch:${face.stretches}` : '';
            const metrics = `size-adjust:${pct(adjust)};ascent-override:${pct(web.ascent / adjust)};descent-override:${pct(web.descent / adjust)};line-gap-override:0%`;
            rules.push(`@font-face{font-family:${quote(`${font.family} ${name}`)};src:${local(names[weight])};font-weight:${face.weights}${stretch};${metrics}${only}}`);
            checkCss += `@font-face{font-family:${quote(`check ${font.family} ${name}`)};src:${src(name, names, weight)};font-weight:${face.weights}${stretch};${metrics}${only}}`;
            const style = `font-weight:${face.weight};${face.stretch ? `font-stretch:${face.stretch}%;` : ''}`;
            checkSpans.push(span(`${key}|web`, `font-family:${quote(font.family)};${style}`, text));
            // As on the page: the other fallbacks after it, for the characters outside its range (a space included).
            const chain = [name, ...Object.keys(font.fallbacks).filter((n) => n !== name)].map((n) => quote(`check ${font.family} ${n}`));
            checkSpans.push(span(key, `font-family:${chain.join(',')};${style}`, text));
          }
        }
      }
      // The check: each fallback face, as the stylesheet will set it, against its web font.
      checked = await browser.run(page(checkCss, checkSpans), MEASURE);
      if (checked.missing.length) throw new Error(`${script}: the check found no ${[...new Set(checked.missing)].join(', ')}`);
      let refined = false;
      for (const key of Object.keys(adjusts)) {
        const ratio = checked.faces[`${key}|web`].width / checked.faces[key].width;
        if (Math.abs(ratio - 1) > 0.002 && round < 3) { adjusts[key] *= ratio; refined = true; }
      }
      if (!refined) break;
    }
    for (const [key, value] of Object.entries(checked.faces)) {
      if (key.endsWith('|web')) continue;
      const web = checked.faces[`${key}|web`];
      const off = [value.width / web.width, value.ascent / web.ascent, value.descent / web.descent].map((x) => Math.abs(x - 1));
      const line = `${script} ${key}: width ${(value.width / web.width).toFixed(4)}, ascent ${(value.ascent / web.ascent).toFixed(4)}, descent ${(value.descent / web.descent).toFixed(4)}`;
      if (Math.max(...off) > 0.01) { console.error(`${line}: more than 1% off`); failed = true; } else console.log(line);
    }
    const path = join(ROOT, 'site/assets', spec.css);
    const old = readFileSync(path, 'utf8');
    const block = `${BEGIN}\n${rules.join('\n')}\n${END}\n`;
    const start = old.indexOf(BEGIN);
    const next = start >= 0 ? old.slice(0, start) + block + old.slice(old.indexOf(END) + END.length + 1)
      : old.replace(/^:root\{/m, block + ':root{');
    writeFileSync(path, next);
  }
} finally {
  browser.close();
}
process.exit(failed ? 1 : 0);
