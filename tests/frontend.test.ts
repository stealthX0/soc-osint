import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { routeFor } from '../src/lib/omnibox';
import { matchPath } from '../src/lib/match';
import { buildIndex, filterTools, NO_FILTERS, searchIndex } from '../src/lib/search';
import type { Playbook, ResourceData } from '../src/types/resources';

const data = JSON.parse(readFileSync(new URL('../src/data/resources.json', import.meta.url), 'utf8')) as ResourceData;
const books = JSON.parse(readFileSync(new URL('../src/data/playbooks.json', import.meta.url), 'utf8')) as Playbook[];
const index = buildIndex(data);

describe('dataset integrity (output of scripts/extract-data.mjs)', () => {
  it('has the expected shape', () => {
    assert.equal(data.categories.length, 12);
    assert.ok(data.tools.length > 440);
    data.tools.forEach((t, i) => assert.equal(t.id, i, 'ids are dense and ordered'));
  });
  it('every tool references a real category and sub-category, and is listed there', () => {
    for (const t of data.tools) {
      const c = data.categories[t.category];
      assert.ok(c?.subs[t.sub], `tool ${t.id} has a valid placement`);
      assert.ok(c.subs[t.sub].toolIds.includes(t.id), `tool ${t.id} is listed in its sub-category`);
    }
  });
  it('category listings contain no dangling ids', () => {
    const ids = new Set(data.tools.map((t) => t.id));
    for (const c of data.categories) for (const s of c.subs) for (const id of s.toolIds) assert.ok(ids.has(id));
  });
  it('playbooks reference only existing tools', () => {
    const ids = new Set(data.tools.map((t) => t.id));
    assert.equal(books.length, 8);
    for (const b of books) for (const s of b.steps) for (const id of s.toolIds) assert.ok(ids.has(id), `${b.id}: ${id}`);
  });
  it('urls are absolute http(s)', () => {
    for (const t of data.tools) assert.match(t.url, /^https?:\/\//, t.name);
  });
});

describe('search', () => {
  const names = (q: string) => searchIndex(index, q).map((i) => i.tool.name.toLowerCase());
  it('returns everything for an empty query', () => assert.equal(searchIndex(index, '').length, data.tools.length));
  it('is AND across words', () => assert.ok(searchIndex(index, 'phishing zzzznotaword').length === 0));
  it('exact name matches rank first', () => {
    const r = searchIndex(index, 'shodan');
    assert.ok(r[0].tool.name.toLowerCase().startsWith('shodan'));
  });
  it('expands synonyms at lower weight (whois -> rdap/registrant)', () => assert.ok(searchIndex(index, 'whois').length > 5));
  it('short tokens only match at word starts ("ip" must not match "zip")', () => {
    const hits = searchIndex(index, 'ip');
    assert.ok(hits.length > 0);
    assert.ok(hits.every((h) => /(^|[^a-z0-9])ip|ipv4|asn/.test(Object.values(h.h).join(' '))));
  });
  it('stems plurals', () => assert.deepEqual(names('sandboxes').slice(0, 3), names('sandboxe').slice(0, 3)));
  it('filters combine with search', () => {
    const passive = filterTools(index, { ...NO_FILTERS, opsec: 'passive' });
    const active = filterTools(index, { ...NO_FILTERS, opsec: 'active' });
    assert.ok(passive.length && active.length);
    assert.ok(passive.every((i) => i.tool.opsec === 'passive'));
    assert.equal(searchIndex(filterTools(index, { ...NO_FILTERS, category: 99 }), 'x').length, 0);
    const api = filterTools(index, { ...NO_FILTERS, flags: ['api'] });
    assert.ok(api.every((i) => i.tool.flags.includes('api')));
  });
});

describe('omnibox routing', () => {
  const to = (s: string) => routeFor(s)?.to;
  it('routes indicators to the right tool', () => {
    assert.equal(to('8.8.8.8'), '/ip?q=8.8.8.8');
    assert.equal(to('2606:4700:4700::1111'), '/ip?q=2606%3A4700%3A4700%3A%3A1111');
    assert.equal(to('Example.com'), '/domain?q=example.com');
    assert.equal(to('hxxps://evil[.]example[.]com/login?x=1'), '/domain?tab=http&q=evil.example.com');
    assert.equal(to('bob@Example.com'), '/email?q=example.com');
    assert.equal(to('d41d8cd98f00b204e9800998ecf8427e'), '/resources?q=hash');
    assert.equal(to('CVE-2021-44228'), '/resources?q=cve');
  });
  it('falls back to directory search for free text and ignores blanks', () => {
    assert.equal(to('analyse phishing email'), '/resources?q=analyse%20phishing%20email');
    assert.equal(routeFor('   '), null);
  });
  it('does not smuggle javascript:/internal hosts into tool URLs', () => {
    assert.ok(to('javascript:alert(1)')!.startsWith('/resources?q='));
  });
});

describe('router matchPath', () => {
  it('matches static and param segments', () => {
    assert.deepEqual(matchPath('/', '/'), {});
    assert.deepEqual(matchPath('/playbooks/:id', '/playbooks/ip'), { id: 'ip' });
    assert.deepEqual(matchPath('/playbooks/:id', '/playbooks/a%20b/'), { id: 'a b' });
    assert.equal(matchPath('/ip', '/dns'), null);
    assert.equal(matchPath('/playbooks/:id', '/playbooks'), null);
  });
});
