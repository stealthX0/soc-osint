import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ctxFor, doh, jsonRes, mockFetch, type Handler } from './helpers';
import { onRequestGet as urlLookup } from '../worker/api/url/lookup';
import { resetRateLimitMemory, costFor } from '../worker/_lib/ratelimit';
import { resolve } from '../worker/routes';
import type { UrlLookup } from '../shared/types';

type Fn = (c: never) => Response | Promise<Response>;
const call = async (path: string, env: Record<string, unknown> = {}) => {
  const res = await (urlLookup as unknown as Fn)(ctxFor(path, { env }));
  return { status: res.status, body: (await res.json()) as { ok: boolean; data: UrlLookup; error?: { code: string; message: string } } };
};
const q = (u: string, extra = '') => `/api/url/lookup?q=${encodeURIComponent(u)}${extra}`;
const ALL = { ABUSECH_AUTH_KEY: 'abuse', GOOGLE_SAFE_BROWSING_API_KEY: 'gkey', VIRUSTOTAL_API_KEY: 'vt', PULSEDIVE_API_KEY: 'pd' };

let mf: ReturnType<typeof mockFetch> | undefined;
beforeEach(() => resetRateLimitMemory());
afterEach(() => mf?.restore());

const form = (init?: RequestInit) => new URLSearchParams(String(init?.body ?? ''));
const on = (host: string, fn: (u: URL, init?: RequestInit) => Response | undefined): Handler => (u, init) => (u.hostname === host ? fn(u, init) : undefined);

/** Provider mocks. Each can be overridden per test; defaults describe a URL nobody has ever heard of. */
function world(o: {
  urlhaus?: (u: URL, init?: RequestInit) => Response; gsb?: (u: URL, init?: RequestInit) => Response; vt?: (u: URL) => Response;
  pd?: (u: URL) => Response; urlscan?: (u: URL) => Response; rdapDays?: number | null; extra?: Handler[]; dnsTable?: Record<string, Record<string, string[]>>;
} = {}): Handler[] {
  const created = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  return [
    ...(o.extra ?? []),
    on('urlhaus-api.abuse.ch', (u, init) => {
      if (init?.headers && (init.headers as Record<string, string>)['Auth-Key'] !== 'abuse') return new Response('', { status: 401 });
      return o.urlhaus ? o.urlhaus(u, init) : jsonRes({ query_status: 'no_results' });
    }),
    on('safebrowsing.googleapis.com', (u, init) => (o.gsb ? o.gsb(u, init) : jsonRes({}))),
    on('www.virustotal.com', (u) => (o.vt ? o.vt(u) : new Response('', { status: 404 }))),
    on('pulsedive.com', (u) => (o.pd ? o.pd(u) : new Response('', { status: 404 }))),
    on('urlscan.io', (u) => (o.urlscan ? o.urlscan(u) : jsonRes({ results: [] }))),
    on('rdap.org', () => (o.rdapDays === null ? new Response('', { status: 404 }) : jsonRes({ events: [{ eventAction: 'registration', eventDate: created(o.rdapDays ?? 2000) }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]] }] }))),
    doh(o.dnsTable ?? { 'example.org': { A: ['93.184.216.34'], AAAA: [] }, 'evil-site.net': { A: ['45.33.32.50'] }, 'short-link.net': { A: ['45.33.32.60'] } }),
  ];
}
const vtBody = (m: number, s = 0, engines: Record<string, unknown> = {}) => jsonRes({ data: { id: 'a'.repeat(64), attributes: { last_analysis_stats: { malicious: m, suspicious: s, harmless: 60, undetected: 10 }, last_analysis_results: engines, last_analysis_date: Math.floor(Date.now() / 1000) - 3600 } } });

describe('/api/url/lookup: input handling and plumbing', () => {
  it('is routed, cost-weighted, and rejects bad input with 400', async () => {
    assert.ok(resolve('GET', '/api/url/lookup').handler);
    assert.equal(costFor('/api/url/lookup'), 3);
    mf = mockFetch(world());
    for (const bad of ['', 'javascript:alert(1)', 'mailto:a@b.co', 'ftp://example.org/x', 'http://exa mple.org']) {
      const r = await call(q(bad));
      assert.equal(r.status, 400, bad);
      assert.equal(r.body.error?.code, 'INVALID_INPUT');
    }
    assert.equal((await call('/api/url/lookup')).status, 400);
    assert.equal((await call(q('http://example.org/' + 'a'.repeat(2100)))).status, 400);
    assert.equal(mf.calls.length, 0, 'invalid input never reaches a provider');
  });
});

describe('/api/url/lookup: clean and unknown results', () => {
  it('an unlisted URL is "no detections" (never "safe"), and "never scanned" answers do not inflate coverage', async () => {
    mf = mockFetch(world());
    const r = await call(q('https://example.org/docs'), { ...ALL });
    assert.equal(r.status, 200);
    const d = r.body.data;
    assert.equal(d.verdict, 'no_detections');
    // URLhaus, Safe Browsing and Cloudflare DNS gave verdicts; VirusTotal/Pulsedive/urlscan had no data on this URL
    assert.deepEqual([d.checked, d.attempted], [3, 6]);
    assert.equal(d.confidence, 'high');
    assert.equal(d.intel.virustotal?.found, false);
    assert.equal(d.intel.pulsedive?.observed, false);
    assert.equal(d.intel.urlscan?.scans, 0);
    assert.equal(d.intel.cloudflareDns?.blocked, false);
    assert.ok(d.signals.every((s) => ['info', 'low'].includes(s.severity)), JSON.stringify(d.signals));
    assert.match(d.summary, /not a guarantee/i);
    assert.equal(d.domain?.resolves, true);
    assert.equal(d.providers.every((p) => p.ok), true, JSON.stringify(d.providers));
  });

  it('without any API keys only the keyless sources run, and a clean result is low confidence', async () => {
    mf = mockFetch(world({ rdapDays: 4000 }));
    const d = (await call(q('https://example.org/'))).body.data;
    const skipped = d.providers.filter((p) => p.skipped).map((p) => p.name);
    assert.equal(skipped.length, 4);
    assert.ok(skipped.every((n) => /URLhaus|Safe Browsing|VirusTotal|Pulsedive/.test(n)));
    assert.deepEqual([d.checked, d.attempted], [1, 2]); // Cloudflare DNS checked; urlscan answered but had no scans
    assert.equal(d.verdict, 'no_detections');
    assert.equal(d.confidence, 'low');
    assert.equal(mf.calls.filter((c) => /urlhaus|virustotal|pulsedive|safebrowsing/.test(c)).length, 0);
  });

  it('private and internal targets are analysed locally and never sent to third parties', async () => {
    mf = mockFetch(world());
    for (const u of ['http://192.168.1.10/admin', 'http://10.0.0.5:8080/login', 'http://127.0.0.1/', 'http://intranet.local/x', 'http://localhost:3000/']) {
      const d = (await call(q(u, '&trace=1'), { ...ALL })).body.data;
      assert.equal(d.verdict, d.verdict === 'suspicious' ? 'suspicious' : 'unknown', u);
      assert.ok(d.signals.some((s) => s.id === 'internal'), u);
      assert.equal(d.checked, 0);
      assert.equal(d.trace?.performed, false, u);
    }
    assert.equal(mf.calls.length, 0, `no outbound requests expected, got: ${mf.calls.join(', ')}`);
  });
});

describe('/api/url/lookup: detections', () => {
  it('URLhaus: an online listing is critical and confirmed; an offline listing is high and confirmed', async () => {
    const listed = (status: string) => (u: URL, init?: RequestInit) =>
      u.pathname === '/v1/url/'
        ? jsonRes({ query_status: 'ok', url_status: status, threat: 'malware_download', tags: ['elf', 'Mozi'], date_added: '2026-10-01 10:00:00 UTC', urlhaus_reference: 'https://urlhaus.abuse.ch/url/12345/' })
        : jsonRes({ query_status: 'ok', url_count: '3', urls: [{ url_status: 'online' }, { url_status: 'offline' }, { url_status: 'offline' }], blacklists: { spamhaus_dbl: 'not listed', surbl: 'listed' } });
    mf = mockFetch(world({ urlhaus: listed('online') }));
    let d = (await call(q('http://45.33.32.9/bins/mozi.m'), { ...ALL })).body.data;
    assert.equal(d.verdict, 'malicious');
    assert.equal(d.confidence, 'high');
    const s = d.signals.find((x) => x.id === 'urlhaus-online')!;
    assert.deepEqual([s.severity, s.confirmed, s.link], ['critical', true, 'https://urlhaus.abuse.ch/url/12345/']);
    assert.match(s.detail!, /malware_download/);
    assert.ok(d.signals.some((x) => x.id === 'urlhaus-bl-surbl'), 'host blocklist entries are reported');
    assert.ok(!d.signals.some((x) => x.id === 'urlhaus-bl-spamhaus_dbl'), '"not listed" is not a finding');
    assert.equal(d.intel.urlhaus?.host.online, 1);

    mf.restore();
    mf = mockFetch(world({ urlhaus: listed('offline') }));
    d = (await call(q('http://45.33.32.9/bins/mozi.m'), { ...ALL })).body.data;
    assert.equal(d.verdict, 'malicious');
    assert.equal(d.signals.find((x) => x.id === 'urlhaus-listed')?.severity, 'high');
  });

  it('URLhaus: a link pointing outside urlhaus.abuse.ch is dropped, and a host-only listing is suspicious, not malicious', async () => {
    mf = mockFetch(world({ urlhaus: (u) => (u.pathname === '/v1/url/' ? jsonRes({ query_status: 'ok', url_status: 'online', urlhaus_reference: 'https://evil-site.net/phish' }) : jsonRes({ query_status: 'no_results' })) }));
    const d = (await call(q('http://45.33.32.9/x'), { ...ALL })).body.data;
    assert.equal(d.signals.find((x) => x.id === 'urlhaus-online')?.link, undefined);

    mf.restore();
    mf = mockFetch(world({ urlhaus: (u) => (u.pathname === '/v1/url/' ? jsonRes({ query_status: 'no_results' }) : jsonRes({ query_status: 'ok', url_count: '2', urls: [{ url_status: 'online' }, { url_status: 'offline' }] })) }));
    const h = (await call(q('http://example.org/benign-page'), { ...ALL })).body.data;
    const s = h.signals.find((x) => x.id === 'urlhaus-host-online')!;
    assert.equal(s.severity, 'high');
    assert.ok(!s.confirmed);
    assert.equal(h.verdict, 'suspicious');
  });

  it('Google Safe Browsing: a match is critical, confirmed and malicious; the request carries the stripped URL', async () => {
    let sent: { threatInfo: { threatEntries: { url: string }[] } } | undefined;
    mf = mockFetch(world({ gsb: (_u, init) => { sent = JSON.parse(String(init?.body)); return jsonRes({ matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'x' } }, { threatType: 'BOGUS_TYPE' }] }); } }));
    const d = (await call(q('https://paypal.com@evil-site.net/signin?x=1#frag'), { ...ALL })).body.data;
    assert.equal(d.verdict, 'malicious');
    assert.deepEqual(d.intel.safeBrowsing?.matches.map((m) => m.threatType), ['SOCIAL_ENGINEERING'], 'unknown threat types are ignored');
    assert.match(d.signals.find((s) => s.id === 'gsb-social_engineering')!.title, /phishing/);
    assert.equal(sent?.threatInfo.threatEntries[0].url, 'https://evil-site.net/signin?x=1', 'no userinfo, no fragment');
    assert.ok(d.signals.some((s) => s.id === 'userinfo-deception'), 'the @ trick is still reported locally');
  });

  it('VirusTotal thresholds: 5+ critical, 2-4 high, 1 medium (a lone detection is not a verdict); the id is base64url of the stripped URL', async () => {
    let vtPath = '';
    const run = async (m: number, s = 0) => {
      mf?.restore();
      mf = mockFetch(world({ vt: (u) => { vtPath = u.pathname; return vtBody(m, s, { Alpha: { category: 'malicious', result: 'phishing' }, Beta: { category: 'harmless', result: 'clean' } }); } }));
      return (await call(q('http://example.org/a?b=c'), { ...ALL })).body.data;
    };
    let d = await run(7);
    assert.equal(d.signals.find((x) => x.id === 'vt-malicious')?.severity, 'critical');
    assert.equal(d.verdict, 'malicious');
    assert.deepEqual(d.intel.virustotal?.engines, ['Alpha: phishing']);
    assert.equal(d.intel.virustotal?.link, `https://www.virustotal.com/gui/url/${'a'.repeat(64)}`);
    assert.equal(Buffer.from(vtPath.split('/').pop()!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(), 'http://example.org/a?b=c');
    assert.ok(!vtPath.endsWith('='), 'no padding');

    d = await run(3);
    assert.equal(d.signals.find((x) => x.id === 'vt-malicious')?.severity, 'high');
    assert.equal(d.verdict, 'suspicious');

    d = await run(1);
    assert.equal(d.signals.find((x) => x.id === 'vt-malicious-1')?.severity, 'medium');
    assert.notEqual(d.verdict, 'malicious');
    assert.notEqual(d.verdict, 'suspicious', 'one engine alone does not make a URL suspicious');

    d = await run(0, 4);
    assert.equal(d.signals.find((x) => x.id === 'vt-suspicious')?.severity, 'medium');
  });

  it('two different sources at "high" corroborate each other into a malicious verdict; one alone does not', async () => {
    mf = mockFetch(world({ pd: () => jsonRes({ risk: 'high', threats: [{ name: 'Phishing' }], feeds: [{ name: 'OpenPhish' }] }) }));
    let d = (await call(q('https://example.org/x'), { ...ALL })).body.data;
    assert.equal(d.signals.find((s) => s.id === 'pd-risk')?.severity, 'high');
    assert.equal(d.verdict, 'suspicious');
    assert.deepEqual(d.intel.pulsedive?.threats, ['Phishing']);

    mf.restore();
    const blocked: Handler = on('security.cloudflare-dns.com', (u) => jsonRes({ Status: 0, Answer: [{ name: 'example.org.', type: u.searchParams.get('type') === 'AAAA' ? 28 : 1, TTL: 60, data: u.searchParams.get('type') === 'AAAA' ? '::' : '0.0.0.0' }] }));
    mf = mockFetch(world({ extra: [blocked], pd: () => jsonRes({ risk: 'critical' }) }));
    d = (await call(q('https://example.org/x'), { ...ALL })).body.data;
    assert.equal(d.intel.cloudflareDns?.blocked, true);
    assert.equal(d.verdict, 'malicious');
    assert.equal(d.confidence, 'medium');
  });

  it('Cloudflare Security DNS: only a 0.0.0.0 answer that differs from the unfiltered resolver counts as a block', async () => {
    const zero = (host: string): Handler => on('security.cloudflare-dns.com', (u) => jsonRes({ Status: 0, Answer: u.searchParams.get('type') === 'A' ? [{ name: `${host}.`, type: 1, TTL: 60, data: '0.0.0.0' }] : [] }));
    // both resolvers sinkhole it -> not a Cloudflare block
    mf = mockFetch(world({ extra: [zero('example.org')], dnsTable: { 'example.org': { A: ['0.0.0.0'] } } }));
    let d = (await call(q('https://example.org/x'))).body.data;
    assert.equal(d.intel.cloudflareDns?.blocked, false);
    assert.ok(!d.signals.some((s) => s.id === 'cfdns-blocked'));

    // filtered says 0.0.0.0 but the unfiltered resolver has nothing to compare with -> undetermined, not a verdict
    mf.restore();
    mf = mockFetch(world({ extra: [zero('gone-site.net')], dnsTable: {} }));
    d = (await call(q('https://gone-site.net/x'))).body.data;
    assert.equal(d.intel.cloudflareDns?.blocked, null);
    assert.ok(!d.signals.some((s) => s.id === 'cfdns-blocked'));
    assert.equal(d.domain?.resolves, false);
    assert.ok(d.signals.some((s) => s.id === 'nxdomain' && s.severity === 'low'));
  });

  it('urlscan.io: a malicious verdict on this exact URL is high, on another page of the host only medium', async () => {
    const scan = (url: string) => ({ results: [{ _id: 'x', task: { url, time: '2026-10-20T10:00:00Z', uuid: '0e37e828-a9d9-45c0-ac50-1ca579b86c72' }, page: { url, domain: 'example.org', country: 'US' }, verdicts: { overall: { malicious: true, score: 100, categories: ['phishing'], brands: ['paypal'] } } }] });
    mf = mockFetch(world({ urlscan: () => jsonRes(scan('https://example.org/login')) }));
    let d = (await call(q('https://example.org/login'))).body.data;
    assert.equal(d.signals.find((s) => s.id === 'urlscan-malicious')?.severity, 'high');
    assert.equal(d.intel.urlscan?.exactMatches, 1);
    assert.equal(d.intel.urlscan?.latest?.resultUrl, 'https://urlscan.io/result/0e37e828-a9d9-45c0-ac50-1ca579b86c72/');

    mf.restore();
    mf = mockFetch(world({ urlscan: () => jsonRes(scan('https://example.org/other')) }));
    d = (await call(q('https://example.org/login'))).body.data;
    const s = d.signals.find((x) => x.id === 'urlscan-host-malicious')!;
    assert.equal(s.severity, 'medium');
    assert.match(s.detail!, /not this exact URL/);
  });

  it('domain age from RDAP: new domains are flagged, shared-hosting platforms are never judged by their parent domain', async () => {
    mf = mockFetch(world({ rdapDays: 3 }));
    let d = (await call(q('https://example.org/x'))).body.data;
    assert.equal(d.signals.find((s) => s.id === 'age-new')?.severity, 'high');
    assert.equal(d.domain?.ageDays, 3);
    assert.equal(d.domain?.registrar, 'Example Registrar');
    assert.equal(d.verdict, 'suspicious');

    mf.restore();
    mf = mockFetch(world({ rdapDays: 3, dnsTable: { 'victim.pages.dev': { A: ['45.33.32.70'] } } }));
    d = (await call(q('https://victim.pages.dev/login'))).body.data;
    assert.ok(!d.signals.some((s) => s.id.startsWith('age-')));
    assert.ok(!mf.calls.some((c) => c.includes('rdap.org')), 'RDAP is not queried for shared-hosting hosts');
    assert.ok(d.signals.some((s) => s.id === 'shared-hosting'));
  });
});

describe('/api/url/lookup: resilience and budgets', () => {
  it('a failing provider is reported, never treated as clean, and never fails the lookup', async () => {
    mf = mockFetch(world({ urlhaus: () => new Response('', { status: 500 }), gsb: () => new Response('', { status: 403 }) }));
    const d = (await call(q('https://example.org/x'), { ...ALL })).body.data;
    const uh = d.providers.find((p) => p.name.startsWith('URLhaus'))!;
    const g = d.providers.find((p) => p.name.startsWith('Google'))!;
    assert.deepEqual([uh.ok, g.ok], [false, false]);
    assert.match(g.error!, /rejected the API key/);
    assert.equal(d.intel.urlhaus, null);
    assert.equal(d.checked, 1, 'only Cloudflare DNS produced a verdict');
    assert.equal(d.attempted, 6);
    assert.equal(d.confidence, 'low');
  });

  it('a spent provider budget skips that source, counts it as attempted-but-unchecked, and never calls it', async () => {
    mf = mockFetch(world({ vt: () => vtBody(0) }));
    const env = { ...ALL, VIRUSTOTAL_RPM: '1' };
    await call(q('https://example.org/one'), env);
    const before = mf.calls.filter((c) => c.includes('virustotal')).length;
    const d = (await call(q('https://example.org/two'), env)).body.data;
    const vt = d.providers.find((p) => p.name.startsWith('VirusTotal'))!;
    assert.equal(vt.skipped, true);
    assert.match(vt.error!, /budget/i);
    assert.equal(mf.calls.filter((c) => c.includes('virustotal')).length, before);
    assert.equal(d.attempted, 6);
  });

  it('never sends credentials from the URL to any provider', async () => {
    const bodies: string[] = [];
    mf = mockFetch(world({ urlhaus: (_u, init) => { bodies.push(String(init?.body)); return jsonRes({ query_status: 'no_results' }); } }));
    await call(q('https://user:hunter2@example.org/path'), { ...ALL });
    assert.ok(bodies.length >= 1);
    assert.ok(bodies.every((b) => !b.includes('hunter2') && !b.includes('user%3A')), bodies.join('|'));
    assert.ok(mf.calls.every((c) => !c.includes('hunter2')), 'credentials never appear in any outbound URL');
  });
});

describe('/api/url/lookup: redirect trace (opt-in, SSRF-safe)', () => {
  const hop = (host: string, status: number, location?: string, extra: Record<string, string> = {}): Handler =>
    on(host, () => new Response(null, { status, headers: { ...(location ? { location } : {}), ...extra } }));

  it('is off by default: the target is never contacted', async () => {
    mf = mockFetch(world({ extra: [hop('short-link.net', 302, 'https://evil-site.net/payload.exe')] }));
    const d = (await call(q('http://short-link.net/abc'), { ...ALL })).body.data;
    assert.equal(d.trace, null);
    assert.ok(!mf.calls.some((c) => c.startsWith('http://short-link.net/')), 'no request to the suspect host');
  });

  it('follows the chain, then checks the final destination with the same sources', async () => {
    mf = mockFetch(world({
      extra: [hop('short-link.net', 302, 'https://evil-site.net/payload.exe'), hop('evil-site.net', 200, undefined, { 'content-type': 'application/x-msdownload' })],
      urlhaus: (u, init) => (form(init).get('url') === 'https://evil-site.net/payload.exe' || form(init).get('host') === 'evil-site.net'
        ? (u.pathname === '/v1/url/' ? jsonRes({ query_status: 'ok', url_status: 'online', threat: 'malware_download' }) : jsonRes({ query_status: 'no_results' }))
        : jsonRes({ query_status: 'no_results' })),
    }));
    const d = (await call(q('http://short-link.net/abc', '&trace=1'), { ...ALL })).body.data;
    assert.equal(d.trace?.performed, true);
    assert.deepEqual(d.trace?.hops.map((h) => h.status), [302, 200]);
    assert.equal(d.trace?.finalUrl, 'https://evil-site.net/payload.exe');
    assert.equal(d.trace?.hops[1].download, true);
    assert.ok(d.signals.some((s) => s.id === 'cross-domain'));
    assert.ok(d.signals.some((s) => s.id === 'download'));
    const fin = d.signals.find((s) => s.id === 'final-urlhaus-online')!;
    assert.match(fin.title, /^Final destination:/);
    assert.equal(d.verdict, 'malicious', 'the destination, not the shortener, decides');
    assert.ok(d.providers.some((p) => p.name.includes('[final URL]')));
    assert.equal(d.checked <= d.attempted, true);
  });

  it('refuses to follow a redirect into private address space and reports it', async () => {
    mf = mockFetch(world({ extra: [hop('short-link.net', 301, 'http://127.0.0.1:8080/admin')] }));
    const d = (await call(q('http://short-link.net/x', '&trace=1'))).body.data;
    assert.ok(!mf.calls.some((c) => c.includes('127.0.0.1')), 'the private target is never requested');
    const last = d.trace!.hops[d.trace!.hops.length - 1];
    assert.match(last.error!, /private, reserved|private or reserved/);
    assert.equal(last.status, null);
    assert.equal(d.trace?.finalUrl, null);
  });

  it('stops on loops and on non-web redirect schemes', async () => {
    mf = mockFetch(world({ extra: [hop('short-link.net', 302, 'http://short-link.net/x')] }));
    let d = (await call(q('http://short-link.net/x', '&trace=1'))).body.data;
    assert.match(d.trace!.error!, /loop/i);
    mf.restore();
    mf = mockFetch(world({ extra: [hop('short-link.net', 302, 'javascript:alert(1)')] }));
    d = (await call(q('http://short-link.net/x', '&trace=1'))).body.data;
    assert.match(d.trace!.error!, /non-web scheme/);
  });
});
