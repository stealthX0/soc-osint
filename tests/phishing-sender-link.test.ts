import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { doh, jsonRes, mockFetch, type Handler } from './helpers';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';
import { resetOpenPhishMemory } from '../worker/_lib/openphish';
import {
  DEEP_HARD_CAP, assembleUrlStage, deepCandidatesOf, selectDeep, triageLinks, validateUrlRequest,
  type LinkInput, type TriageContext, type UrlStageResult,
} from '../shared/phishing/urlTriage';
import { senderDomainLink, withSenderLink } from '../shared/phishing/links';
import { parseSubmission } from '../shared/phishing/parse';
import { computeVerdict } from '../shared/phishing/verdict';
import { buildReport, parseStoredReport, renderJson, renderMarkdown, renderTicketText, senderDomainOf } from '../shared/phishing/report';

const ctx = (o: Partial<TriageContext> = {}): TriageContext => ({ senderDomains: [], claimedBrands: [], claimedDomains: [], ...o });
const link = (url: string, o: Partial<LinkInput> = {}): LinkInput => ({ url, ...o });
const SENDER = 'https://abcd-corp.net/';
const senderIn = (o: Partial<LinkInput> = {}) => link(SENDER, { sources: ['sender'], ...o });

describe('sender domain as a link: building it', () => {
  it('turns the From domain into a root URL with source "sender"', () => {
    const l = senderDomainLink('abcd-corp.net')!;
    assert.equal(l.normalized, SENDER);
    assert.deepEqual(l.sources, ['sender']);
    assert.equal(l.host, 'abcd-corp.net');
  });
  it('includes consumer mailbox providers; unusable values give nothing', () => {
    assert.equal(senderDomainLink('gmail.com')!.normalized, 'https://gmail.com/');
    assert.equal(senderDomainLink('outlook.com')!.sources[0], 'sender');
    assert.equal(senderDomainLink(null), null);
    assert.equal(senderDomainLink(''), null);
  });
  it('merges into an identical body link instead of listing the URL twice, and goes first', () => {
    const body = [{ ...senderDomainLink('other.example')!, sources: ['anchor' as const] }, { ...senderDomainLink('abcd-corp.net')!, sources: ['anchor' as const], count: 3 }];
    const out = withSenderLink(body, senderDomainLink('abcd-corp.net'));
    assert.equal(out.length, 2);
    assert.equal(out[0].host, 'abcd-corp.net');
    assert.deepEqual(out[0].sources, ['anchor', 'sender']);
    assert.equal(out[0].count, 3);
  });
});

describe('sender domain as a link: parse stage', () => {
  const headers = 'From: "Billing" <xyz@abcd-corp.net>\nSubject: Invoice\nContent-Type: text/plain';
  it('lists the sender domain first, ahead of links found in the body, without making it an IOC URL', async () => {
    const r = await parseSubmission({ headers, body: 'Pay at https://pay.other.example/now' });
    assert.deepEqual(r.links.map((l) => l.host), ['abcd-corp.net', 'pay.other.example']);
    assert.deepEqual(r.links[0].sources, ['sender']);
    assert.deepEqual(r.indicators.urls, ['https://pay.other.example/now'], 'only URLs that appeared in the message are IOC URLs');
    assert.ok(r.indicators.domains.some((d) => d.domain === 'abcd-corp.net'));
  });
  it('still produces a link to investigate when the body has none', async () => {
    const r = await parseSubmission({ headers, body: 'Please call me.' });
    assert.equal(r.links.length, 1);
    assert.equal(r.links[0].host, 'abcd-corp.net');
    assert.deepEqual(r.indicators.urls, []);
  });
  it('also looks up a consumer mailbox provider such as gmail.com', async () => {
    const r = await parseSubmission({ headers: 'From: x@gmail.com\nSubject: hi\nContent-Type: text/plain', body: 'hello' });
    assert.deepEqual(r.links.map((l) => [l.host, l.sources]), [['gmail.com', ['sender']]]);
  });
  it('the verdict treats an unchecked sender link as an unchecked link', async () => {
    const { computeVerdict } = await import('../shared/phishing/verdict');
    const r = await parseSubmission({ headers, body: 'Please call me.' });
    const v = computeVerdict({ parse: r, findings: r.findings, checks: r.checks, now: Date.parse('2026-11-07') });
    assert.ok(v.gaps.some((g) => /1 link not checked for reputation/.test(g.text)), JSON.stringify(v.gaps));
    assert.notEqual(v.label, 'likely_legitimate');
  });
});

describe('sender domain as a link: ranking and selection', () => {
  const phishyBody = [
    link('https://evil-site.net/login.php', { text: 'www.paypal.com', sources: ['anchor', 'form'] }),
    link('https://bit.ly/x', { text: 'Verify your account', sources: ['anchor'] }),
  ];
  const t = triageLinks([...phishyBody, senderIn()], ctx({ displayName: 'PayPal Support', senderDomains: ['abcd-corp.net'] }));

  it('ranks the sender domain first even when another link scores far higher', () => {
    assert.equal(t.items[0].url, SENDER);
    assert.ok(t.items.slice(1).some((i) => i.score > t.items[0].score), 'a body link outscores it, yet it is still first');
    assert.deepEqual(t.items.map((i) => i.rank), [1, 2, 3]);
    assert.ok(t.items[0].reasons[0].startsWith('Sender domain'));
  });
  it('is not discounted as "a link back to the sender" and is not given a brand-mismatch', () => {
    assert.equal(t.items[0].brandMismatch, null);
    assert.ok(!t.items[0].reasons.some((r) => /not a .* domain/.test(r)));
  });
  it('is always a full-lookup candidate, and first when only one lookup is allowed', () => {
    assert.equal(deepCandidatesOf(t.items)[0], SENDER);
    assert.deepEqual(selectDeep(t.items, [], 1), [SENDER]);
    assert.deepEqual(selectDeep(t.items, [], 2), [SENDER, t.items[1].url]);
    const calm = triageLinks([link('https://example-news.org/a', { sources: ['anchor'] }), senderIn()], ctx());
    assert.ok(deepCandidatesOf(calm.items).includes(SENDER));
  });
  it('allows up to four full lookups and no more', () => {
    assert.equal(DEEP_HARD_CAP, 4);
    const many = triageLinks([senderIn(), ...Array.from({ length: 8 }, (_, i) => link(`https://evil${i}.example/login.php`, { text: 'Verify your account', sources: ['anchor', 'form'] }))], ctx());
    const picked = selectDeep(many.items, [], 99);
    assert.equal(picked.length, 4);
    assert.equal(picked[0], SENDER);
    const v = validateUrlRequest({ links: [link(SENDER)], maxDeep: 99, deep: Array.from({ length: 9 }, (_, i) => `https://e${i}.example/`) });
    assert.ok(v.ok && v.value.maxDeep === 4 && v.value.deep.length === 4);
  });
  it('accepts "sender" as a link source over the wire', () => {
    const v = validateUrlRequest({ links: [{ url: SENDER, sources: ['sender', 'bogus'] }] });
    assert.ok(v.ok && v.value.links[0].sources.join() === 'sender');
  });
  it('its offline findings reach the verdict like any other link (look-alike sender domain)', () => {
    const lookalike = triageLinks([senderIn({ url: 'https://paypa1.example/' })], ctx({ displayName: 'PayPal', senderDomains: ['paypa1.example'] }));
    const ranked = lookalike.items.map(({ parsed: _p, ...rest }) => rest);
    const stage = assembleUrlStage({ ranked, lookups: {}, lookupErrors: {}, openphish: { status: 'skipped', feedSize: null, fetchedAt: null }, claimedBrands: lookalike.claimed, deepCandidates: [], deepChecked: [], skipped: [], merged: 0, truncated: false, maxDeep: 0 });
    const f = stage.findings.find((x) => x.id === 'url_lookalike_domain');
    assert.ok(f, 'look-alike signal raised for the sender domain');
    assert.deepEqual(f!.indicator, { type: 'url', value: 'https://paypa1.example/' });
  });
});

describe('sender domain as a link: POST /api/phishing/urls', () => {
  let mf: ReturnType<typeof mockFetch> | undefined;
  beforeEach(() => { resetOpenPhishMemory(); resetRateLimitMemory(); });
  afterEach(() => mf?.restore());
  const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
  const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
  const post = async (body: unknown) => {
    const res = await worker.fetch(new Request('https://app.test/api/phishing/urls', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.7' }, body: JSON.stringify(body) }), env, exec);
    return { res, json: (await res.json()) as { ok: boolean; data?: UrlStageResult } };
  };
  const on = (host: string, fn: () => Response): Handler => (u) => (u.hostname === host ? fn() : undefined);

  it('runs the full provider lookup on the sender domain first and reports its risk with the other link findings', async () => {
    mf = mockFetch([
      on('openphish.com', () => new Response('https://evil-site.net/login.php\n')),
      on('urlscan.io', () => jsonRes({ results: [] })),
      on('rdap.org', () => jsonRes({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 3 * 86_400_000).toISOString() }] })),
      on('abcd-corp.net', () => new Response('', { status: 200, headers: { 'content-type': 'text/html' } })),
      on('evil-site.net', () => new Response('', { status: 200, headers: { 'content-type': 'text/html' } })),
      doh({ 'abcd-corp.net': { A: ['93.184.216.34'] }, 'evil-site.net': { A: ['45.33.32.50'] } }),
    ]);
    const { res, json } = await post({
      links: [link('https://evil-site.net/login.php', { text: 'Sign in', sources: ['anchor', 'form'] }), senderIn()],
      context: { senderDomains: ['abcd-corp.net'] },
      maxDeep: 1,
    });
    assert.equal(res.status, 200);
    const d = json.data!;
    assert.equal(d.ranked[0].url, SENDER);
    assert.equal(d.ranked[0].tier, 'deep');
    assert.deepEqual(d.deepChecked, [SENDER], 'with one lookup allowed it goes to the sender domain, not the higher-scoring body link');
    assert.ok(d.lookups[SENDER].providers.length > 0, 'the same provider fan-out as any URL');
    assert.ok(mf.calls.some((c) => new URL(c).hostname === 'rdap.org'), 'domain age was looked up for the sender domain');
    const young = d.findings.find((f) => f.id === 'url_domain_young');
    assert.deepEqual(young?.indicator, { type: 'url', value: SENDER });
    assert.ok(d.findings.some((f) => f.id === 'url_listed_phishing'), 'the body link is still checked against OpenPhish alongside it');
  });
});

describe('sender domain as a link: exported report', () => {
  const headers = 'From: "Billing" <xyz@abcd-corp.net>\nSubject: Invoice\nContent-Type: text/plain';
  const lookup = (o: Record<string, unknown> = {}) => ({
    url: SENDER, verdict: 'no_detections', score: 4, confidence: 'medium', summary: 'No source flagged this URL.', checked: 5, attempted: 6,
    finalUrl: null, redirects: 0, domainAgeDays: 4200, providers: [{ name: 'VirusTotal', ok: true }, { name: 'URLhaus', ok: true }, { name: 'Pulsedive', ok: false, skipped: true }],
    signals: [], cached: false, ms: 10, finalOpenphish: null, finalBrandMismatch: null, ...o,
  }) as never;
  const stageFor = async (parse: Awaited<ReturnType<typeof parseSubmission>>, lk?: unknown, err?: string): Promise<UrlStageResult> => {
    const t = triageLinks(parse.links.map((l) => ({ url: l.normalized, sources: l.sources, count: l.count })), ctx());
    const ranked = t.items.map(({ parsed: _p, ...rest }) => rest);
    return assembleUrlStage({ ranked, lookups: lk ? { [SENDER]: lk as never } : {}, lookupErrors: err ? { [SENDER]: err } : {}, openphish: { status: 'ok', feedSize: 10, fetchedAt: null }, claimedBrands: [], deepCandidates: [SENDER], deepChecked: lk ? [SENDER] : [], skipped: [], merged: 0, truncated: false, maxDeep: 4 });
  };
  const reportFor = async (lk?: unknown, err?: string) => {
    const parse = await parseSubmission({ headers, body: 'Please call me.' });
    const urlStage = await stageFor(parse, lk, err);
    const findings = [...parse.findings, ...urlStage.findings];
    const checks = [...parse.checks, ...urlStage.checks].map((c) => ({ id: c.id, label: c.label, stage: c.stage, status: c.status, result: c.result ?? null, detail: c.detail }));
    const verdict = computeVerdict({ parse, findings, checks: checks.map((c) => ({ ...c })) });
    return buildReport({ verdict, findings, checks, parse, urlStage, generatedAt: '2026-11-14T10:00:00Z' });
  };

  it('shows a clean (no detections) sender domain result in every export format, defanged', async () => {
    const r = await reportFor(lookup());
    assert.equal(r.senderDomain?.result, 'no_detections');
    assert.equal(r.senderDomain?.url, 'hxxps://abcd-corp[.]net/');
    assert.equal(r.senderDomain?.sourcesChecked, 5);
    assert.equal(r.senderDomain?.domainAgeDays, 4200);
    assert.deepEqual(r.senderDomain?.providers.map((p) => p.status), ['ok', 'ok', 'skipped']);
    const txt = renderTicketText(r), md = renderMarkdown(r), json = renderJson(r);
    assert.match(txt, /SENDER DOMAIN[\s\S]*hxxps:\/\/abcd-corp\[\.\]net\/: no detections · 5\/6 sources/);
    assert.match(md, /## Sender domain[\s\S]*\*\*no detections\*\* · 5\/6 sources/);
    assert.match(json, /"senderDomain"/);
    for (const out of [txt, md, json]) assert.ok(!/https?:\/\/abcd-corp\.net/.test(out), 'never an un-defanged URL');
  });
  it('shows malicious and suspicious results with the risks that were detected', async () => {
    const bad = await reportFor(lookup({ verdict: 'malicious', score: 91, summary: 'Flagged by 3 sources.', finalUrl: 'https://landing.evil-site.net/x', redirects: 2, domainAgeDays: 3,
      signals: [{ id: 'a', severity: 'high', source: 'urlhaus', title: 'Listed in URLhaus' }, { id: 'b', severity: 'info', source: 'dns', title: 'Resolves' }] }));
    assert.equal(bad.senderDomain?.result, 'malicious');
    assert.deepEqual(bad.senderDomain?.signals.map((x) => x.title), ['Listed in URLhaus'], 'info-level context is left out');
    assert.match(renderMarkdown(bad), /\*\*malicious\*\*[\s\S]*Risks detected:[\s\S]*\[high\]\*\* Listed in URLhaus/);
    assert.match(renderTicketText(bad), /Redirects to: hxxps:\/\/landing\[\.\]evil-site\[\.\]net\/x/);
    const sus = await reportFor(lookup({ verdict: 'suspicious', score: 40 }));
    assert.equal(sus.senderDomain?.resultText, 'suspicious');
  });
  it('says so when the lookup failed or never ran, instead of leaving the sender out', async () => {
    assert.equal((await reportFor(undefined, 'upstream timeout')).senderDomain?.result, 'lookup_failed');
    const parse = await parseSubmission({ headers, body: 'x' });
    const none = senderDomainOf(parse, null)!;
    assert.deepEqual([none.result, none.resultText, none.openphish, none.sourcesChecked], ['heuristics_only', 'heuristics only (no full lookup)', 'not_checked', null]);
  });
  it('is null when the message has no sender domain, and survives a save/load round trip', async () => {
    const parse = await parseSubmission({ headers: 'Subject: no sender\nContent-Type: text/plain', body: 'hi' });
    assert.equal(senderDomainOf(parse, null), null);
    const r = await reportFor(lookup({ verdict: 'suspicious' }));
    assert.deepEqual(parseStoredReport(JSON.parse(renderJson(r))), r);
    const { senderDomain: _drop, ...older } = JSON.parse(renderJson(r));
    assert.equal(parseStoredReport(older)?.senderDomain, null, 'reports saved before this field existed still load');
    const tampered = JSON.parse(renderJson(r)); tampered.senderDomain.result = 'safe'; tampered.senderDomain.extra = '<script>';
    assert.equal(parseStoredReport(tampered)?.senderDomain, null);
  });
});
