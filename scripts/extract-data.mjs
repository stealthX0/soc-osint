#!/usr/bin/env node
/**
 * One-off converter: legacy single-file dashboard (HTML with an inline `const DATA = {...}`)
 * -> typed JSON consumed by the React app.
 *
 *   node scripts/extract-data.mjs path/to/osint_soc_dashboard.html
 *
 * Output:
 *   src/data/resources.json   normalized categories + tools (deduplicated)
 *   src/data/playbooks.json   investigation playbooks (tool ids remapped after dedupe)
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const input = process.argv[2];
if (!input) {
  console.error('usage: node scripts/extract-data.mjs <dashboard.html>');
  process.exit(1);
}

const html = readFileSync(input, 'utf8');
const m = html.match(/^const DATA = (\{.*\});?\s*$/m);
if (!m) throw new Error('Could not find `const DATA = {...}` in input file');
const legacy = JSON.parse(m[1]);

const normUrl = (u) =>
  String(u || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\/(www\.)?/, '')
    .replace(/[#?].*$/, '')
    .replace(/\/+$/, '');

const richness = (t) => ['d', 'bf', 'in', 'o', 'op', 'on', 'pr', 'st'].filter((k) => t[k]).length + (t.fl?.length ? 1 : 0);

// --- 1. dedupe: same category + same URL + same name (keep the richest entry) --
// Cross-category listings (e.g. Shodan under Domain and under IP) are intentional
// and are kept; only exact repeats inside one category are merged.
const normName = (n) => String(n).toLowerCase().replace(/\s*\(t\)\s*$/, '').trim();
const dedupeKey = (t) => `${t.c}|${normUrl(t.u)}|${normName(t.n)}`;
const keep = new Map(); // dedupeKey -> legacy index
legacy.tools.forEach((t, i) => {
  const key = dedupeKey(t);
  const prev = keep.get(key);
  if (prev === undefined || richness(t) > richness(legacy.tools[prev])) keep.set(key, i);
});
const keptIdx = new Set(keep.values());
const remap = new Map(); // legacy index -> new id (for removed dupes points at survivor)
const survivors = [...keptIdx].sort((a, b) => a - b);
const newIdOf = new Map(survivors.map((old, n) => [old, n]));
legacy.tools.forEach((t, i) => {
  remap.set(i, newIdOf.get(keep.get(dedupeKey(t))));
});

// --- 2. normalize tool records ----------------------------------------------
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const categories = legacy.cats.map((c, ci) => ({
  id: slug(c.name),
  name: c.name,
  subs: c.subs.map((s) => ({ name: s.name, toolIds: [] })),
}));

const tools = survivors.map((old, id) => {
  const t = legacy.tools[old];
  const flags = new Set(t.fl || []);
  const rec = {
    id,
    name: t.n,
    url: t.u,
    category: t.c,
    sub: t.s,
    ...(t.g ? { group: t.g } : {}),
    ...(t.d ? { description: t.d } : {}),
    ...(t.bf ? { bestFor: t.bf } : {}),
    ...(t.in ? { input: t.in } : {}),
    ...(t.o ? { output: t.o } : {}),
    ...(t.op && t.op !== 'unknown' ? { opsec: t.op } : {}),
    ...(t.on ? { opsecNote: t.on } : {}),
    ...(t.pr ? { pricing: t.pr } : {}),
    ...(t.st ? { status: t.st } : {}),
    flags: [...flags],
  };
  categories[t.c].subs[t.s].toolIds.push(id);
  return rec;
});

// --- 3. playbooks -------------------------------------------------------------
const playbooks = (legacy.books || []).map((b) => ({
  id: b.id,
  title: b.title,
  summary: b.summary,
  steps: b.steps.map((s) => ({
    title: s.t,
    detail: s.d,
    toolIds: [...new Set((s.tools || []).map((i) => remap.get(i)).filter((x) => x !== undefined))],
    // steps that touch the target are flagged so the UI can warn about authorisation
    ...(/only if|authoris|touch(es)? the target/i.test(`${s.t} ${s.d}`) ? { active: true } : {}),
  })),
}));

const outDir = resolve(here, '../src/data');
mkdirSync(outDir, { recursive: true });
writeFileSync(`${outDir}/resources.json`, JSON.stringify({ categories, tools }));
writeFileSync(`${outDir}/playbooks.json`, JSON.stringify(playbooks, null, 1));

const count = (f) => tools.filter(f).length;
const stats = {
  tools: tools.length,
  categories: categories.length,
  playbooks: playbooks.length,
  passive: count((t) => t.opsec === 'passive'),
  active: count((t) => t.opsec === 'active'),
  free: count((t) => t.pricing === 'free'),
  withApi: count((t) => t.flags.includes('api')),
  perCategory: categories.map((c, i) => ({ id: c.id, name: c.name, count: count((t) => t.category === i) })),
};
writeFileSync(`${outDir}/stats.json`, JSON.stringify(stats, null, 1));

const removed = legacy.tools.length - tools.length;
console.log(`categories: ${categories.length}`);
console.log(`tools:      ${legacy.tools.length} -> ${tools.length} (${removed} duplicates merged)`);
console.log(`playbooks:  ${playbooks.length}`);
const missing = tools.filter((t) => !t.description).length;
console.log(`tools without description/metadata: ${missing}`);
