/**
 * Step 8: hardening tests for the phishing investigation.
 *  - hostile input must be processed in bounded time (every case here took 10 seconds to over a minute before the fixes)
 *  - nothing the parser or verdict engine does may throw on arbitrary input
 *  - the message text never leaves the app, and no secret appears in a response
 *  - the endpoints reject malformed, oversized and wrong-method requests cleanly
 */
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { parseSubmission, validateInput } from '../shared/phishing/parse';
import { extractLinks } from '../shared/phishing/links';
import { htmlToText, stripTags } from '../shared/phishing/html';
import { analyzeContent } from '../shared/phishing/content';
import { analyzeEmailHeaders } from '../shared/phishing/forensics';
import { computeVerdict } from '../shared/phishing/verdict';
import { POINTS } from '../shared/phishing/verdictRules';
import { makeFinding } from '../shared/phishing/findings';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';
import { resetOpenPhishMemory } from '../worker/_lib/openphish';
import { doh, jsonRes, mockFetch } from './helpers';

const H = 'From: a@x.example\nSubject: hi\nContent-Type: text/html\n';
/** Generous on purpose (slow CI machines); the unfixed code needed 10 s to more than a minute for each of these. */
const BUDGET_MS = 4000;
async function within<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
  const t0 = performance.now();
  const r = await fn();
  const ms = performance.now() - t0;
  assert.ok(ms < BUDGET_MS, `${name} took ${Math.round(ms)} ms (budget ${BUDGET_MS})`);
  return r;
}

describe('hostile input is processed in bounded time', () => {
  const cases: [string, () => { headers?: string; body?: string }][] = [
    ['unclosed <a href> tags', () => ({ headers: H, body: '<a href=x>'.repeat(200_000) })],
    ['unclosed <script', () => ({ headers: H, body: '<script '.repeat(250_000) })],
    ['unclosed hidden div', () => ({ headers: H, body: '<div style="display:none">'.repeat(80_000) })],
    ['anchors with images, never closed', () => ({ headers: H, body: '<a href="https://a.example/x"><img src=y>'.repeat(50_000) })],
    ['a 200k-character URL of closing brackets', () => ({ headers: H, body: `http://a.example/${')'.repeat(200_000)}` })],
    ['100k repeated URLs', () => ({ headers: H, body: 'https://a.example/p '.repeat(100_000) })],
    ['"<" with no ">" anywhere', () => ({ headers: H, body: '<'.repeat(1_500_000) })],
    ['comment openers that never close', () => ({ headers: H, body: '<!--'.repeat(400_000) })],
    ['repeated lure phrase', () => ({ headers: 'From: a@x.example\nContent-Type: text/plain', body: 'account will be '.repeat(120_000) })],
    ['encoded words', () => ({ headers: `From: a@x.example\nSubject: ${'=?utf-8?B?QQ==?= '.repeat(5000)}`, body: 'x' })],
    ['quoted-printable soft breaks', () => ({ headers: 'From: a@x.example\nContent-Type: text/plain\nContent-Transfer-Encoding: quoted-printable', body: '=3D=\n'.repeat(300_000) })],
    ['2000 MIME parts', () => ({ headers: 'From: a@x.example\nContent-Type: multipart/mixed; boundary=B', body: `${Array.from({ length: 2000 }, () => '--B\nContent-Type: text/plain\n\nhi').join('\n')}\n--B--` })],
    ['mixed-script words', () => ({ headers: 'From: a@x.example\nContent-Type: text/plain', body: 'pаypal '.repeat(200_000) })],
    ['repeated "from" in a Received header', () => ({ headers: `Received: ${'from '.repeat(18000)}\nFrom: a@x.example` })],
    ['an HTML attachment of "<input <input"', () => ({ headers: 'From: a@x.example\nContent-Type: multipart/mixed; boundary=B', body: `--B\nContent-Type: text/html; name="a.html"\nContent-Disposition: attachment; filename="a.html"\nContent-Transfer-Encoding: base64\n\n${Buffer.from('<input '.repeat(150_000)).toString('base64').replace(/(.{76})/g, '$1\n')}\n--B--` })],
  ];
  for (const [name, make] of cases) {
    it(name, async () => {
      const input = make();
      const r = await within(name, () => parseSubmission(input));
      assert.ok(Array.isArray(r.findings) && Array.isArray(r.checks));
    });
  }
  it('keeps real links in a message that also contains hostile markup', async () => {
    const body = `${'<a href=x>'.repeat(5000)}<a href="https://real.example/login">Sign in</a>`;
    const r = await parseSubmission({ headers: H, body });
    assert.ok(r.links.some((l) => l.host === 'real.example'));
  });
  it('caps what it reports and says so', () => {
    const many = Array.from({ length: 5000 }, (_, i) => `<a href="https://h${i}.example/">l</a>`).join('');
    const out = extractLinks({ html: many });
    assert.ok(out.links.length <= 200);
    assert.equal(out.truncated, true);
  });
  it('text helpers stay linear', () => {
    const t0 = performance.now();
    htmlToText('<'.repeat(1_000_000) + '<p>hello</p>');
    stripTags('<a '.repeat(500_000));
    analyzeContent({ subject: null, text: 'verify your password '.repeat(10_000), html: '<span style="display:none">x</span>'.repeat(20_000), linkCount: 0, attachments: [], displayName: null, fromDomain: 'a.example', fromIsFreeMail: false });
    assert.ok(performance.now() - t0 < BUDGET_MS);
  });
});

describe('padding a message cannot clear it', () => {
  const clean = [{ id: 'sender.ip.x', label: 'IP', status: 'complete' as const, result: 'ok' }, { id: 'sender.domain.x', label: 'Domain', status: 'complete' as const, result: 'ok' }, { id: 'urls.openphish', label: 'OpenPhish', status: 'complete' as const, result: 'ok' }, { id: 'urls.provider.virustotal', label: 'VT', status: 'complete' as const, result: 'ok' }];
  it('a message with far more links than the analysis keeps is flagged as incompletely examined, never "likely legitimate"', async () => {
    const links = Array.from({ length: 260 }, (_, i) => `<a href="https://benign${i}.example/p">link ${i}</a>`).join(' ');
    const r = await parseSubmission({ headers: 'From: a@partner.example\nSubject: hi\nContent-Type: text/html\nAuthentication-Results: spf=pass smtp.mailfrom=partner.example; dkim=pass header.d=partner.example; dmarc=pass header.from=partner.example\nReceived: from m.partner.example (m.partner.example [198.51.100.9]) by BN9PR12MB2222.namprd12.prod.outlook.com with Microsoft SMTP Server; Wed, 4 Nov 2026 09:00:04 +0000', body: `${links} <a href="https://really-bad.example/login">Sign in</a>` });
    assert.equal(r.truncation.links, true);
    const v = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...clean] });
    assert.notEqual(v.label, 'likely_legitimate');
    assert.ok(v.gaps.some((g) => g.critical && /more links than the analysis keeps/.test(g.text)));
  });
  it('a message whose structure exceeds the MIME limits is treated the same way', async () => {
    const body = `${Array.from({ length: 400 }, (_, i) => `--B\nContent-Type: application/octet-stream; name="f${i}.bin"\nContent-Disposition: attachment; filename="f${i}.bin"\nContent-Transfer-Encoding: base64\n\nQUJD`).join('\n')}\n--B--`;
    const r = await parseSubmission({ headers: 'From: a@x.example\nContent-Type: multipart/mixed; boundary=B', body });
    assert.equal(r.truncation.mime, true);
    const v = computeVerdict({ parse: r, findings: r.findings, checks: r.checks });
    assert.ok(v.gaps.some((g) => g.critical && /structure exceeded/.test(g.text)));
  });
});

/* ------------------------------------------------------------------ fuzzing */

function rng(seed: number) { let s = seed >>> 0; return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32); }
const PIECES = ['From: ', 'Subject: ', 'Received: from ', ' by ', 'Authentication-Results: ', 'spf=pass ', 'dkim=fail ', 'dmarc=', '<a href="', '</a>', '<', '>', '"', '\'', '=?utf-8?Q?', '=?x?B?', '?=', '\n', '\r\n', '\n\n', '\t', ' ', ';', ',', '=', '--B', 'Content-Type: multipart/mixed; boundary=B', 'Content-Transfer-Encoding: base64', 'http://', 'https://a.example/', 'hxxp://', '[.]', '@', '.', '\u200b', '\u202e', 'р', '漢字', '\u0000', '\ud800', 'javascript:', 'data:', '%', '&amp;', '&#x', '1.2.3.4', '[2001:db8::1]', 'verify your password', 'account will be suspended', 'bitcoin', 'QUJD', '/*', '*/', '(', ')', '\\'];
function junk(rand: () => number, parts: number): string {
  let s = '';
  for (let i = 0; i < parts; i++) s += PIECES[Math.floor(rand() * PIECES.length)];
  return s;
}

describe('fuzzing: nothing throws on arbitrary input', () => {
  it('parseSubmission and the verdict engine survive 600 random messages', async () => {
    const rand = rng(1234);
    for (let i = 0; i < 600; i++) {
      const input = { headers: rand() < 0.8 ? junk(rand, 1 + Math.floor(rand() * 60)) : undefined, body: rand() < 0.8 ? junk(rand, Math.floor(rand() * 120)) : undefined, urls: rand() < 0.3 ? [junk(rand, 4)] : undefined, sender: rand() < 0.4 ? { email: junk(rand, 3), domain: junk(rand, 2), ip: junk(rand, 2) } : undefined, attachments: rand() < 0.2 ? [{ name: junk(rand, 2), hash: junk(rand, 1) }] : undefined };
      const v = validateInput(input);
      if (!v.ok) continue;
      let r;
      try { r = await parseSubmission(v.value); } catch (e) { assert.fail(`parseSubmission threw on iteration ${i}: ${(e as Error).message}\n${JSON.stringify(input).slice(0, 300)}`); }
      JSON.stringify(r); // must be serialisable
      const verdict = computeVerdict({ parse: r, findings: r.findings, checks: r.checks });
      assert.ok(verdict.risk >= 0 && verdict.risk <= 100 && Number.isFinite(verdict.risk));
      assert.ok(['malicious', 'suspicious', 'likely_legitimate', 'inconclusive', 'analysis_unavailable'].includes(verdict.label));
    }
  });
  it('header forensics survives random headers', () => {
    const rand = rng(99);
    for (let i = 0; i < 500; i++) analyzeEmailHeaders(junk(rand, 80), { email: junk(rand, 2), ip: junk(rand, 2), domain: junk(rand, 2) });
  });
  it('the verdict engine is bounded and deterministic over random finding sets', async () => {
    const rand = rng(7);
    const ids = [...Object.keys(POINTS), 'unknown_rule'];
    const sev = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const dims = ['authentication', 'infrastructure', 'url', 'attachment', 'content'] as const;
    const r = await parseSubmission({ headers: 'From: a@partner.example\nSubject: x', body: 'hello https://partner.example/a' });
    for (let i = 0; i < 400; i++) {
      const findings = Array.from({ length: Math.floor(rand() * 25) }, () => makeFinding({ id: ids[Math.floor(rand() * ids.length)], dimension: dims[Math.floor(rand() * 5)], severity: sev[Math.floor(rand() * 5)], title: 't', detail: 'd', source: rand() < 0.5 ? 'a' : 'b', exactness: rand() < 0.5 ? 'exact' : 'related', reliability: rand() < 0.5 ? 'high' : 'low', trust: rand() < 0.5 ? 'unverified' : 'independently_verified', indicator: rand() < 0.5 ? { type: 'url', value: `https://u${Math.floor(rand() * 3)}.example/` } : undefined }));
      const a = computeVerdict({ parse: r, findings, checks: r.checks, now: 1 });
      const b = computeVerdict({ parse: r, findings, checks: r.checks, now: 1 });
      assert.deepEqual(a, b);
      assert.ok(a.risk >= 0 && a.risk <= 100 && a.confidence.score >= 5 && a.confidence.score <= 98 && a.coverage >= 0 && a.coverage <= 1);
      assert.ok(a.contributions.every((c) => Number.isFinite(c.counted) && c.counted >= 0));
    }
  });
});

/* --------------------------------------------------------------- endpoints */

const env = { ASSETS: { fetch: async () => new Response('asset') }, USERCHECK_API_KEY: 'sk-canary-usercheck-key', IPQS_API_KEY: 'sk-canary-ipqs-key', VIRUSTOTAL_API_KEY: 'sk-canary-vt-key', ABUSEIPDB_API_KEY: 'sk-canary-abuse-key' } as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
let n = 0;
const call = async (path: string, init: RequestInit = {}) => {
  const res = await worker.fetch(new Request(`https://app.test${path}`, { ...init, headers: { 'content-type': 'application/json', 'cf-connecting-ip': `198.51.100.${(n++ % 200) + 1}`, ...(init.headers as Record<string, string> | undefined) } }), env, exec);
  const text = await res.text();
  let json: { ok?: boolean; data?: any; error?: { code: string; message: string } } | null = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { res, text, json };
};
const post = (path: string, body: unknown) => call(path, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body) });
const ENDPOINTS = ['/api/phishing/parse', '/api/phishing/sender', '/api/phishing/urls', '/api/phishing/attachments'];

describe('phishing endpoints reject bad requests cleanly', () => {
  afterEach(() => resetRateLimitMemory());
  for (const path of ENDPOINTS) {
    it(`${path}: GET is refused, invalid JSON and wrong types give 400, never 500`, async () => {
      assert.equal((await call(path)).res.status, 405);
      for (const body of ['{nope', '[]', '"string"', 'null', '{"check":5}', '{"links":"x"}']) {
        const r = await post(path, body);
        assert.ok(r.res.status === 400 || r.res.status === 413, `${path} ${body} -> ${r.res.status}`);
        assert.equal(r.json?.ok, false);
      }
    });
    it(`${path}: an oversized body is cut off with 413`, async () => {
      const r = await post(path, `{"x":"${'a'.repeat(3_200_000)}"}`);
      assert.equal(r.res.status, 413);
    });
  }
  it('validateInput caps counts and sizes', () => {
    assert.equal(validateInput({ urls: Array.from({ length: 51 }, () => 'https://a.example') }).ok, false);
    assert.equal(validateInput({ attachments: Array.from({ length: 21 }, () => ({ name: 'a' })) }).ok, false);
    assert.equal(validateInput({ headers: 'x'.repeat(250_000) }).ok, false);
    assert.equal(validateInput({ body: 'x'.repeat(2_000_001) }).ok, false);
  });
  it('the parse endpoint answers a 3 MB hostile body quickly', async () => {
    const body = JSON.stringify({ headers: H, body: '<a href=x>'.repeat(200_000) });
    const t0 = performance.now();
    const r = await post('/api/phishing/parse', body);
    assert.equal(r.res.status, 200);
    assert.ok(performance.now() - t0 < BUDGET_MS);
  });
});

describe('data leaving the app', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); resetOpenPhishMemory(); });
  const CANARY = 'ZX9-CANARY-7731';
  const SECRET = /sk-canary-[a-z]+-key/;

  /** Records every outbound request (URL, headers and body) and answers 404 so providers fail harmlessly. */
  function capture() {
    const seen: { url: string; headers: string; body: string }[] = [];
    const m = mockFetch([
      (u, init) => { seen.push({ url: u.toString(), headers: JSON.stringify([...new Headers(init?.headers).entries()]), body: typeof init?.body === 'string' ? init.body : '' }); return undefined; },
      (u) => (u.hostname === 'openphish.com' ? new Response('https://listed.example/x\n') : undefined),
      doh({}),
      () => jsonRes({}, 404),
    ]);
    restore = m.restore;
    return seen;
  }

  it('parsing a message makes no outbound request at all', async () => {
    const seen = capture();
    const r = await post('/api/phishing/parse', { headers: `${H}X-Canary: ${CANARY}`, subject: CANARY, body: `${CANARY} https://a.example/p`, sender: { email: 'a@b.example' } });
    assert.equal(r.res.status, 200);
    assert.equal(seen.length, 0);
  });

  it('the link stage never forwards the message text, subject or display name to a provider', async () => {
    const seen = capture();
    const body = { links: [{ url: 'https://listed.example/x', text: 'Open', sources: ['anchor'] }], context: { senderDomains: ['a.example'], displayName: CANARY, subject: CANARY, text: `${CANARY} secret body text` }, maxDeep: 1 };
    const r = await post('/api/phishing/urls', body);
    assert.equal(r.res.status, 200);
    assert.ok(seen.length > 0, 'the feed and at least one provider were contacted');
    for (const s of seen) assert.ok(!`${s.url}${s.headers}${s.body}`.includes(CANARY), `canary leaked to ${s.url}`);
  });

  it('only the address, IP, domain or hash is sent by the sender and attachment stages, and no key ever appears in a response', async () => {
    const seen = capture();
    const outputs: string[] = [];
    for (const [path, body] of [
      ['/api/phishing/sender', { check: 'ip', ip: '45.33.32.156', role: 'connecting', trust: 'receiver_reported' }],
      ['/api/phishing/sender', { check: 'domain', domain: 'evil.example', roles: ['from'] }],
      ['/api/phishing/sender', { check: 'usercheck', email: 'a@evil.example', roles: ['from'] }],
      ['/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }],
      ['/api/phishing/sender', { check: 'spf', domain: 'evil.example', ip: '45.33.32.156', reported: 'pass', trust: 'unverified' }],
      ['/api/phishing/attachments', { hash: 'a'.repeat(64), hashType: 'sha256', filename: `${CANARY}.exe`, index: 0 }],
    ] as const) outputs.push((await post(path, body)).text);
    for (const o of outputs) assert.ok(!SECRET.test(o), 'a secret key appeared in a response');
    for (const s of seen) assert.ok(!s.url.includes(CANARY) && !s.body.includes(CANARY), 'the attachment file name was sent to a provider');
    // keys go only to their own provider
    for (const s of seen) if (SECRET.test(s.headers)) assert.match(new URL(s.url).hostname, /usercheck\.com|virustotal\.com|abuseipdb\.com|ipqualityscore\.com/);
    // IPQS takes its key in the URL path: only its own host may see it there
    assert.ok(seen.some((s) => s.url.includes('sk-canary-ipqs-key')), 'the IPQS lookup was attempted');
    for (const s of seen) if (SECRET.test(s.url)) assert.equal(new URL(s.url).hostname, 'www.ipqualityscore.com');
  });

  it('private and reserved addresses are never sent to a third party', async () => {
    const seen = capture();
    for (const ip of ['10.0.0.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1']) await post('/api/phishing/sender', { check: 'ip', ip, role: 'supplied' });
    assert.equal(seen.length, 0);
  });

  it('every phishing lookup endpoint is rate-limited at more than the default cost', async () => {
    const { costFor } = await import('../worker/_lib/ratelimit');
    for (const p of ENDPOINTS) assert.ok(costFor(p) > 1, p);
  });
});
