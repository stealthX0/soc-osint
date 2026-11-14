import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { doh, jsonRes, mockFetch, type Handler } from './helpers';
import { costFor, resetRateLimitMemory } from '../worker/_lib/ratelimit';
import { buildIndex, feedKey, loadFeed, matchFeed, resetOpenPhishMemory } from '../worker/_lib/openphish';
import { resolve } from '../worker/routes';
import {
  analyzeDisplayText, assembleUrlStage, brandMismatchOf, canonicalKey, deepCandidatesOf, detectClaimedBrands, selectDeep, signalFinding, triageLinks, validateUrlRequest,
  type LinkInput, type TriageContext, type UrlStageResult,
} from '../shared/phishing/urlTriage';
import { parseTargetUrl } from '../shared/url';

const ctx = (o: Partial<TriageContext> = {}): TriageContext => ({ senderDomains: [], claimedBrands: [], claimedDomains: [], ...o });
const link = (url: string, o: Partial<LinkInput> = {}): LinkInput => ({ url, ...o });
const parsed = (u: string) => { const r = parseTargetUrl(u); assert.ok(r.ok); return r.value; };

/* ------------------------------------------------------------------ validation */

describe('validateUrlRequest', () => {
  it('requires links, caps the full-lookup count and drops unknown sources', () => {
    assert.equal(validateUrlRequest({}).ok, false);
    assert.equal(validateUrlRequest({ links: [] }).ok, false);
    assert.equal(validateUrlRequest({ links: [{ nope: 1 }] }).ok, false);
    assert.equal(validateUrlRequest({ links: Array.from({ length: 201 }, (_, i) => ({ url: `https://a${i}.example/` })) }).ok, false);
    const r = validateUrlRequest({ links: [{ url: 'https://a.example/', sources: ['form', 'bogus'], count: 9999 }], maxDeep: 99, deep: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] });
    assert.ok(r.ok);
    if (r.ok) {
      assert.deepEqual(r.value.links[0].sources, ['form']);
      assert.equal(r.value.links[0].count, 1000);
      assert.equal(r.value.maxDeep, 4);
      assert.equal(r.value.deep.length, 4);
    }
    assert.equal(validateUrlRequest({ links: [{ url: 'https://a.example/' }], maxDeep: -1 }).ok, false);
  });
  it('defaults to two full lookups', () => {
    const r = validateUrlRequest({ links: [{ url: 'https://a.example/' }] });
    assert.ok(r.ok && r.value.maxDeep === 2);
  });
});

/* ------------------------------------------------------------------ normalise / dedupe */

describe('normalising and de-duplicating links', () => {
  it('tracking parameters, fragments, trailing slashes and host case do not make a new link', () => {
    const a = canonicalKey(parsed('https://Shop.Example.com/offer/?utm_source=x&id=7#top'));
    const b = canonicalKey(parsed('https://shop.example.com/offer?id=7&utm_campaign=y&fbclid=zz'));
    assert.equal(a, b);
    assert.notEqual(a, canonicalKey(parsed('https://shop.example.com/offer?id=8')));
    assert.notEqual(canonicalKey(parsed('http://shop.example.com/offer?id=7')), canonicalKey(parsed('https://shop.example.com/offer?id=7')));
  });
  it('merges duplicates, adds their counts and sources, and reports invalid links as skipped', () => {
    const t = triageLinks([
      link('https://shop.example.com/offer?utm_source=a', { sources: ['anchor'], count: 2, text: 'Offer' }),
      link('https://shop.example.com/offer/?utm_source=b', { sources: ['text'] }),
      link('javascript:alert(1)'),
    ], ctx());
    assert.equal(t.items.length, 1);
    assert.equal(t.merged, 1);
    assert.equal(t.items[0].count, 3);
    assert.deepEqual([...t.items[0].sources].sort(), ['anchor', 'text']);
    assert.equal(t.items[0].text, 'Offer');
    assert.equal(t.skipped.length, 1);
  });
});

/* ------------------------------------------------------------------ deceptive text */

describe('deceptive link text', () => {
  it('flags text naming one organisation while the link goes to another, but not the same organisation', () => {
    assert.deepEqual(analyzeDisplayText('www.paypal.com', 'evil.example'), { displayedHost: 'www.paypal.com', mismatch: true });
    assert.equal(analyzeDisplayText('https://www.paypal.com/signin', 'paypal.com').mismatch, false);
    assert.equal(analyzeDisplayText('Verify your account', 'evil.example').displayedHost, null);
    assert.equal(analyzeDisplayText(null, 'evil.example').mismatch, false);
  });
});

/* ------------------------------------------------------------------ claimed brands */

describe('claimed brand detection', () => {
  it('uses the sender name, subject and sender domain', () => {
    assert.ok(detectClaimedBrands(ctx({ displayName: 'PayPal Support' })).some((c) => c.brand === 'paypal' && c.confidence === 'high'));
    assert.ok(detectClaimedBrands(ctx({ subject: 'Your Netflix payment failed' })).some((c) => c.brand === 'netflix'));
    assert.ok(detectClaimedBrands(ctx({ senderDomains: ['mail.paypal.com'] })).some((c) => c.brand === 'paypal'));
    assert.ok(detectClaimedBrands(ctx({ claimedDomains: ['microsoft.com'] })).some((c) => c.brand === 'microsoft'));
    assert.ok(detectClaimedBrands(ctx({ claimedBrands: ['Bank of America'] })).some((c) => c.brand === 'bankofamerica'));
  });
  it('needs more evidence for everyday words and for body-only mentions', () => {
    assert.equal(detectClaimedBrands(ctx({ text: 'I picked an apple on my way home.' })).length, 0);
    assert.equal(detectClaimedBrands(ctx({ text: 'Thanks for using Dropbox.' })).length, 0, 'one body mention is not a claim');
    assert.ok(detectClaimedBrands(ctx({ text: 'Dropbox shared a file. Open Dropbox to view it.' })).some((c) => c.brand === 'dropbox' && c.confidence === 'medium'));
    assert.equal(detectClaimedBrands(ctx({ text: 'apple apple' })).length, 0);
  });
  it('a brand is mismatched only when the host belongs to none of the claimed organisations', () => {
    const paypal = detectClaimedBrands(ctx({ displayName: 'PayPal' }));
    assert.equal(brandMismatchOf(parsed('https://www.paypal.com/signin'), paypal), null);
    assert.equal(brandMismatchOf(parsed('https://paypal-secure-login.xyz/a'), paypal), 'paypal');
    assert.equal(brandMismatchOf(parsed('https://evil.example/a'), []), null);
    const ms = detectClaimedBrands(ctx({ claimedDomains: ['microsoft.com'] }));
    assert.equal(brandMismatchOf(parsed('https://login.microsoftonline.com/'), ms), null, 'sibling Microsoft domains are official');
  });
});

/* ------------------------------------------------------------------ ranking and selection */

describe('ranking', () => {
  const phish = triageLinks([
    link('https://example-news.org/article', { sources: ['anchor'], text: 'Read more' }),
    link('https://secure-paypa1-login.xyz/verify', { sources: ['anchor'], text: 'www.paypal.com' }),
    link('https://bit.ly/3abc', { sources: ['anchor'], text: 'Verify your account' }),
    link('https://www.paypal.com/help', { sources: ['text'] }),
    link('https://evil.example/collect', { sources: ['form'] }),
  ], ctx({ displayName: 'PayPal Support', senderDomains: ['paypal.com'] }));

  it('puts the look-alike with deceptive text first and the sender’s own help page last', () => {
    assert.equal(phish.items[0].host, 'secure-paypa1-login.xyz');
    assert.equal(phish.items[0].displayMismatch, true);
    assert.equal(phish.items[phish.items.length - 1].host, 'www.paypal.com');
    assert.deepEqual(phish.items.map((i) => i.rank), [1, 2, 3, 4, 5]);
  });
  it('raises form actions, shorteners with a call to action, and brand mismatches', () => {
    const by = (h: string) => phish.items.find((i) => i.host === h)!;
    assert.ok(by('evil.example').score >= 25 + 35, 'form + not a PayPal domain');
    assert.ok(by('bit.ly').score >= 12 + 10);
    assert.equal(by('bit.ly').brandMismatch, 'paypal');
    assert.ok(by('www.paypal.com').score < 10);
    assert.ok(phish.items.every((i) => i.score >= 0 && i.score <= 100));
  });
  it('picks the few that get a full lookup', () => {
    const items = phish.items;
    assert.deepEqual(selectDeep(items, [], 2), [items[0].url, items[1].url]);
    assert.deepEqual(selectDeep(items, [], 0), []);
    assert.equal(selectDeep(items, [], 3).length, 3);
    assert.deepEqual(selectDeep(items, [items[3].url, 'https://not-in-list.example/'], 2), [items[3].url], 'explicit picks must be ranked links');
    assert.ok(!deepCandidatesOf(items).includes(items[items.length - 1].url), 'a harmless link is not a candidate');
    // a clean-looking message still gets its top link checked
    const calm = triageLinks([link('https://example-news.org/a')], ctx());
    assert.deepEqual(deepCandidatesOf(calm.items), [calm.items[0].url]);
  });
});

/* ------------------------------------------------------------------ findings */

describe('findings and checks', () => {
  it('maps provider signals to stable finding ids and skips context-only signals', () => {
    const f = signalFinding({ id: 'urlhaus-online', severity: 'critical', source: 'urlhaus', title: 'Listed', detail: 'Threat: malware_download', link: 'https://urlhaus.abuse.ch/url/1/' }, 'https://x.example/a');
    assert.equal(f?.id, 'url_listed_malware');
    assert.equal(f?.exactness, 'exact');
    assert.equal(f?.reliability, 'high');
    assert.equal(f?.trust, 'independently_verified');
    assert.equal(f?.source, 'URLhaus');
    assert.equal(signalFinding({ id: 'shared-hosting', severity: 'info', source: 'heuristic', title: 'x' }, 'u'), null);
    assert.equal(signalFinding({ id: 'redirects', severity: 'info', source: 'trace', title: 'x' }, 'u'), null);
    const fin = signalFinding({ id: 'final-gsb-social_engineering', severity: 'critical', source: 'safebrowsing', title: 'Final destination: Safe Browsing lists this URL for phishing' }, 'u');
    assert.equal(fin?.id, 'url_final_listed_phishing');
    assert.equal(signalFinding({ id: 'vt-malicious-1', severity: 'medium', source: 'virustotal', title: '1 engine' }, 'u')?.reliability, 'low');
    assert.equal(signalFinding({ id: 'homograph-mixed', severity: 'high', source: 'heuristic', title: 'h' }, 'u')?.id, 'url_homograph_domain');
  });

  const t = triageLinks([
    link('https://paypa1.com/verify', { sources: ['anchor'], text: 'www.paypal.com' }),
    link('https://www.paypal.com/help', { sources: ['text'] }),
  ], ctx({ displayName: 'PayPal Support' }));
  const base = (over: Partial<UrlStageResult> = {}) => assembleUrlStage({
    ranked: t.items.map(({ parsed: _p, ...r }) => r), lookups: {}, lookupErrors: {}, openphish: { status: 'ok', feedSize: 100, fetchedAt: '2026-11-06T00:00:00Z' },
    claimedBrands: t.claimed, deepCandidates: deepCandidatesOf(t.items), deepChecked: [], skipped: [], merged: 0, truncated: false, maxDeep: 2, ...over,
  });

  it('turns offline evidence into findings: text mismatch, brand mismatch and look-alike', () => {
    const r = base();
    const ids = r.findings.map((f) => f.id);
    assert.ok(ids.includes('link_text_mismatch'));
    assert.ok(ids.includes('url_brand_mismatch'));
    assert.ok(ids.includes('url_lookalike_domain'));
    const tm = r.findings.find((f) => f.id === 'link_text_mismatch')!;
    assert.equal(tm.severity, 'high', 'the text names a known brand');
    assert.equal(tm.indicator?.value, 'https://paypa1.com/verify');
    assert.ok(!r.findings.some((f) => f.indicator?.value === 'https://www.paypal.com/help' && f.severity !== 'info'), 'the brand’s own page is not a finding');
  });

  it('never shows a failed, paused or unconfigured provider as clean', () => {
    const url = t.items[0].url;
    const lookups = {
      [url]: {
        url, verdict: 'no_detections', score: 5, confidence: 'low', summary: 's', checked: 1, attempted: 3, finalUrl: null, redirects: 0, domainAgeDays: null,
        providers: [
          { name: 'VirusTotal (URL verdicts)', ok: false, skipped: true, error: 'Request budget reached (4/min); retry in 30s' },
          { name: 'urlscan.io (prior scans)', ok: false, error: 'Upstream provider timed out.' },
          { name: 'Cloudflare Security DNS', ok: true },
        ],
        signals: [], cached: false, ms: 10, finalOpenphish: null, finalBrandMismatch: null,
      },
    };
    const r = base({ lookups });
    const row = (id: string) => r.checks.find((c) => c.id === id)!;
    assert.equal(row('urls.provider.virustotal_url_verdicts').status, 'skipped');
    assert.match(row('urls.provider.virustotal_url_verdicts').detail ?? '', /budget/i);
    assert.equal(row('urls.provider.urlscan_io_prior_scans').status, 'failed');
    assert.equal(row('urls.provider.cloudflare_security_dns').status, 'complete');
    assert.equal(row('urls.deep').result, '1 of 2 links fully checked');
    assert.equal(row('urls.heuristic_only').status, 'skipped');
  });

  it('reports an unreachable OpenPhish feed as failed, and a lookup that errored as failed', () => {
    const r = base({ openphish: { status: 'failed', feedSize: null, fetchedAt: null, error: 'OpenPhish feed unreachable.' }, lookupErrors: { [t.items[0].url]: 'Upstream provider unreachable.' } });
    assert.equal(r.checks.find((c) => c.id === 'urls.openphish')?.status, 'failed');
    assert.equal(r.checks.find((c) => c.id === 'urls.deep')?.status, 'failed');
  });

  it('turns an OpenPhish exact match into a critical, exact finding and a host match into a related one', () => {
    const ranked = t.items.map(({ parsed: _p, ...r }) => r);
    ranked[0] = { ...ranked[0], openphish: { exact: true, hostMatches: 0 } };
    ranked[1] = { ...ranked[1], openphish: { exact: false, hostMatches: 2 } };
    const r = assembleUrlStage({ ranked, lookups: {}, lookupErrors: {}, openphish: { status: 'ok', feedSize: 5, fetchedAt: null }, claimedBrands: t.claimed, deepCandidates: [], deepChecked: [], skipped: [], merged: 0, truncated: false, maxDeep: 2 });
    const listed = r.findings.find((f) => f.id === 'url_listed_phishing')!;
    assert.deepEqual([listed.severity, listed.exactness, listed.source], ['critical', 'exact', 'OpenPhish']);
    const host = r.findings.find((f) => f.id === 'url_host_listed')!;
    // Host-level matches are capped at medium (8 Nov fix: other tenants' listings on docs.google.com made a genuine email Malicious).
    assert.deepEqual([host.severity, host.exactness], ['medium', 'related']);
    assert.match(r.checks.find((c) => c.id === 'urls.openphish')!.result ?? '', /1 exact match/);
  });
});

/* ------------------------------------------------------------------ OpenPhish provider */

describe('OpenPhish feed', () => {
  let mf: ReturnType<typeof mockFetch> | undefined;
  beforeEach(() => { resetOpenPhishMemory(); resetRateLimitMemory(); });
  afterEach(() => mf?.restore());
  const wctx = { env: {} as never, waitUntil: () => {} };
  const FEED = 'https://evil-site.net/login.php\nhttps://evil-site.net/other\nhttp://45.33.32.50/x/y.html\n\nnot a url\n';

  it('indexes URLs, ignores junk, and matches exactly or by host', () => {
    const idx = buildIndex(FEED.split('\n'));
    assert.equal(idx.size, 3);
    assert.deepEqual(matchFeed(idx, 'https://EVIL-SITE.net/login.php#frag'), { exact: true, hostMatches: 1 });
    assert.deepEqual(matchFeed(idx, 'https://evil-site.net/new'), { exact: false, hostMatches: 2 });
    assert.equal(matchFeed(idx, 'https://evil-site.net/login.php/').exact, true, 'a trailing slash does not matter');
    assert.deepEqual(matchFeed(idx, 'https://evil-site.net/login.php?x=1'), { exact: false, hostMatches: 2 }, 'a different query is not an exact match');
    assert.deepEqual(matchFeed(idx, 'https://example.org/'), { exact: false, hostMatches: 0 });
    assert.equal(feedKey('ftp://x.example/a'), null);
  });

  it('downloads once and reuses the parsed feed', async () => {
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response(FEED) : undefined)]);
    const a = await loadFeed(wctx);
    const b = await loadFeed(wctx, Date.now() + 60_000);
    assert.equal(a.index.size, 3);
    assert.equal(b.stale, false);
    assert.equal(mf.calls.length, 1);
  });

  it('serves the previous copy, flagged stale, when a refresh fails; fails outright with no copy', async () => {
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response(FEED) : undefined)]);
    await loadFeed(wctx);
    mf.restore();
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response('', { status: 503 }) : undefined)]);
    const stale = await loadFeed(wctx, Date.now() + 3 * 3600_000);
    assert.equal(stale.stale, true);
    assert.equal(stale.index.size, 3);

    resetOpenPhishMemory();
    await assert.rejects(() => loadFeed(wctx), /HTTP 503/);
  });

  it('rejects an empty or oversized feed instead of treating it as "no listings"', async () => {
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response('\n\n') : undefined)]);
    await assert.rejects(() => loadFeed(wctx), /empty/);
    mf.restore();
    resetOpenPhishMemory();
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response('x'.repeat(6_100_000)) : undefined)]);
    await assert.rejects(() => loadFeed(wctx), /larger than expected/);
  });

  it('only accepts an https override, and never a non-http scheme', async () => {
    mf = mockFetch([(u) => (u.hostname === 'feed.example.net' ? new Response(FEED) : undefined)]);
    await loadFeed({ env: { OPENPHISH_FEED_URL: 'https://feed.example.net/f.txt' } as never, waitUntil: () => {} });
    assert.equal(new URL(mf.calls[0]).hostname, 'feed.example.net');
    mf.restore();
    resetOpenPhishMemory();
    mf = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response(FEED) : undefined)]);
    await loadFeed({ env: { OPENPHISH_FEED_URL: 'http://insecure.example/f.txt' } as never, waitUntil: () => {} });
    assert.equal(new URL(mf.calls[0]).hostname, 'openphish.com');
  });
});

/* ------------------------------------------------------------------ endpoint */

describe('POST /api/phishing/urls', () => {
  let mf: ReturnType<typeof mockFetch> | undefined;
  beforeEach(() => { resetOpenPhishMemory(); resetRateLimitMemory(); });
  afterEach(() => mf?.restore());

  const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
  const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
  const post = async (body: unknown, e: Record<string, unknown> = {}) => {
    const res = await worker.fetch(new Request('https://app.test/api/phishing/urls', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.9' }, body: typeof body === 'string' ? body : JSON.stringify(body) }), { ...(env as object), ...e } as never, exec);
    return { res, json: (await res.json()) as { ok: boolean; data?: UrlStageResult; error?: { code: string; message: string } } };
  };
  const on = (host: string, fn: (u: URL, init?: RequestInit) => Response | undefined): Handler => (u, init) => (u.hostname === host ? fn(u, init) : undefined);
  const FEED = 'https://evil-site.net/login.php\n';
  const world = (extra: Handler[] = []): Handler[] => [
    ...extra,
    on('openphish.com', () => new Response(FEED)),
    on('urlscan.io', () => jsonRes({ results: [] })),
    on('rdap.org', () => jsonRes({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 3 * 86_400_000).toISOString() }] })),
    on('evil-site.net', () => new Response('', { status: 200, headers: { 'content-type': 'text/html' } })),
    on('example-news.org', () => new Response('', { status: 200, headers: { 'content-type': 'text/html' } })),
    doh({ 'evil-site.net': { A: ['45.33.32.50'] }, 'example-news.org': { A: ['93.184.216.34'] } }),
  ];

  it('is routed and cost-weighted, and rejects bad requests clearly', async () => {
    assert.ok(resolve('POST', '/api/phishing/urls').handler);
    assert.equal(costFor('/api/phishing/urls'), 8);
    mf = mockFetch(world());
    assert.equal((await post({})).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post('{nope')).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post({ links: [{ url: 'javascript:alert(1)' }] })).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post({ links: [{ url: 'https://example.org/' }] , maxDeep: 'x' })).res.status, 400);
    const big = await post('x'.repeat(700_000));
    assert.equal(big.res.status, 413);
    assert.equal(mf.calls.length, 0, 'invalid input never reaches a provider');
    const get = await worker.fetch(new Request('https://app.test/api/phishing/urls'), env, exec);
    assert.equal(get.status, 405);
  });

  it('ranks every link, lists the OpenPhish match and fully checks only the top ones', async () => {
    mf = mockFetch(world());
    const { res, json } = await post({
      links: [
        { url: 'https://example-news.org/article', text: 'Read more', sources: ['anchor'] },
        { url: 'https://evil-site.net/login.php', text: 'www.paypal.com', sources: ['anchor'] },
        { url: 'https://example-news.org/other' },
      ],
      context: { displayName: 'PayPal Support' },
      maxDeep: 1,
    });
    assert.equal(res.status, 200);
    const d = json.data!;
    assert.equal(d.ranked[0].url, 'https://evil-site.net/login.php');
    assert.equal(d.ranked[0].tier, 'deep');
    assert.equal(d.ranked[0].openphish?.exact, true);
    assert.equal(d.ranked[1].tier, 'heuristic');
    assert.deepEqual(d.deepChecked, ['https://evil-site.net/login.php']);
    assert.ok(Object.keys(d.lookups).length === 1);
    assert.ok(d.lookups['https://evil-site.net/login.php'].providers.length > 0);

    const ids = d.findings.map((f) => f.id);
    assert.ok(ids.includes('url_listed_phishing'));
    assert.ok(ids.includes('link_text_mismatch'));
    assert.ok(ids.includes('url_brand_mismatch'));
    assert.ok(ids.includes('url_domain_young'), 'RDAP domain age came from the existing URL lookup');
    assert.equal(d.findings[0].severity, 'critical');
    assert.equal(d.openphish.status, 'ok');
    assert.equal(mf.calls.filter((c) => new URL(c).hostname === 'openphish.com').length, 1, 'one feed download for all links');
    // without API keys the keyed sources are listed as skipped, never absent or clean
    const vt = d.checks.find((c) => c.id.startsWith('urls.provider.virustotal'));
    assert.equal(vt?.status, 'skipped');
    assert.ok(d.checks.some((c) => c.id === 'urls.heuristic_only'));
    assert.ok(d.limits.some((l) => /full lookup/.test(l)));
    assert.deepEqual(d.deepCandidates.slice(0, 1), ['https://evil-site.net/login.php']);
  });

  it('lets the caller name the links for a later batch, and ignores links that are not in the list', async () => {
    mf = mockFetch(world());
    const body = { links: [{ url: 'https://example-news.org/article' }, { url: 'https://evil-site.net/login.php' }], deep: ['https://example-news.org/article', 'https://attacker.example/not-listed'], maxDeep: 0 };
    const d = (await post(body)).json.data!;
    assert.deepEqual(d.deepChecked, ['https://example-news.org/article']);
    assert.ok(!mf.calls.some((c) => c.includes('attacker.example')), 'nothing outside the submitted links is ever contacted');
  });

  it('maxDeep 0 runs no full lookups and says so', async () => {
    mf = mockFetch(world());
    const d = (await post({ links: [{ url: 'https://evil-site.net/login.php' }], maxDeep: 0 })).json.data!;
    assert.deepEqual(d.deepChecked, []);
    assert.equal(d.checks.find((c) => c.id === 'urls.deep')?.status, 'skipped');
    assert.equal(d.ranked[0].openphish?.exact, true, 'the feed check still covers every link');
  });

  it('keeps working when OpenPhish is down, and reports it as failed', async () => {
    mf = mockFetch(world([on('openphish.com', () => new Response('', { status: 500 }))]));
    const d = (await post({ links: [{ url: 'https://evil-site.net/login.php' }], maxDeep: 0 })).json.data!;
    assert.equal(d.openphish.status, 'failed');
    assert.equal(d.checks.find((c) => c.id === 'urls.openphish')?.status, 'failed');
    assert.ok(!d.findings.some((f) => f.id === 'url_listed_phishing'));
  });

  it('analyses private and internal hosts locally without sending them anywhere', async () => {
    mf = mockFetch(world());
    const d = (await post({ links: [{ url: 'http://192.168.1.10/admin' }, { url: 'https://intranet.local/login' }], maxDeep: 2 })).json.data!;
    assert.equal(d.ranked.length, 2);
    assert.ok(!mf.calls.some((c) => /192\.168|intranet\.local/.test(c) && !/openphish/.test(c)), mf.calls.join('\n'));
  });
});
