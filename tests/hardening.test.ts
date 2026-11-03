import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ctxFor, doh, jsonRes, mockFetch } from './helpers';
import { onRequestGet as ipLookup } from '../worker/api/ip/lookup';
import { onRequestPost as emailHeaders } from '../worker/api/email/headers';
import { rateLimit, resetRateLimitMemory, takeProviderBudget } from '../worker/_lib/ratelimit';
import { readTextLimited } from '../worker/_lib/input';

type Fn = (c: never) => Response | Promise<Response>;
const call = async (fn: unknown, path: string, init?: RequestInit & { env?: Record<string, unknown> }) => {
  const res = await (fn as Fn)(ctxFor(path, init));
  return { status: res.status, body: (await res.json()) as any };
};

let mf: ReturnType<typeof mockFetch> | undefined;
beforeEach(() => resetRateLimitMemory());
afterEach(() => mf?.restore());

const baseMocks = (extra: ((u: URL) => Response | undefined)[] = []) => [
  doh({}),
  (u: URL) => (u.hostname === 'api.ipapi.is' ? jsonRes({ ip: '45.33.32.1', asn: { asn: 64500, org: 'EXAMPLE', route: '45.33.32.0/24' }, location: { country_code: 'US' } }) : undefined),
  (u: URL) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { resource: '45.33.32.0/24', asns: [{ asn: 64500, holder: 'EXAMPLE' }] } }) : undefined),
  (u: URL) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [], vulns: [] }) : undefined),
  ...extra,
];

const vtOk = (u: URL) =>
  u.hostname === 'www.virustotal.com'
    ? jsonRes({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20 } } } })
    : undefined;

describe('provider quota budgets', () => {
  it('VirusTotal is capped at 4/min globally; later lookups skip it with a budget message and the lookup still works', async () => {
    mf = mockFetch(baseMocks([vtOk]));
    const env = { VIRUSTOTAL_API_KEY: 'k' };
    for (let i = 1; i <= 4; i++) {
      const d = (await call(ipLookup, `/api/ip/lookup?q=45.33.32.${i}`, { env })).body.data;
      assert.equal(d.providers.find((p: any) => p.name.startsWith('VirusTotal')).ok, true, `lookup ${i} reaches VT`);
    }
    const vtCallsBefore = mf.calls.filter((c) => c.includes('virustotal')).length;
    assert.equal(vtCallsBefore, 4);

    const r = await call(ipLookup, '/api/ip/lookup?q=45.33.32.5', { env });
    assert.equal(r.status, 200);
    assert.equal(r.body.data.network.asn, 'AS64500', 'rest of the lookup is unaffected');
    const vt = r.body.data.providers.find((p: any) => p.name.startsWith('VirusTotal'));
    assert.equal(vt.skipped, true);
    assert.match(vt.error, /budget/i);
    assert.equal(mf.calls.filter((c) => c.includes('virustotal')).length, vtCallsBefore, 'VirusTotal is not contacted once the budget is spent');
  });

  it('budget windows roll over and env overrides raise the limits', async () => {
    const t0 = Date.UTC(2026, 0, 1, 12, 0, 10);
    for (let i = 0; i < 4; i++) assert.equal((await takeProviderBudget({} as never, 'virustotal', t0)).ok, true);
    const blocked = await takeProviderBudget({} as never, 'virustotal', t0);
    assert.equal(blocked.ok, false);
    assert.match(blocked.why!, /4\/min/);
    assert.equal((await takeProviderBudget({} as never, 'virustotal', t0 + 61_000)).ok, true, 'next minute is allowed');

    resetRateLimitMemory();
    const env = { VIRUSTOTAL_RPM: '100', VIRUSTOTAL_DAILY: '3' } as never;
    for (let i = 0; i < 3; i++) assert.equal((await takeProviderBudget(env, 'virustotal', t0)).ok, true);
    const daily = await takeProviderBudget(env, 'virustotal', t0);
    assert.equal(daily.ok, false);
    assert.match(daily.why!, /3\/day/);
  });

  it('unknown or unconfigured providers are never blocked, and the client limiter is unchanged', async () => {
    for (let i = 0; i < 50; i++) assert.equal((await takeProviderBudget({} as never, 'pulsedive')).ok, true);
    const now = Date.now();
    const a = await rateLimit({ RATE_LIMIT_PER_MIN: '3' } as never, 'client-x', 2, now);
    const b = await rateLimit({ RATE_LIMIT_PER_MIN: '3' } as never, 'client-x', 2, now);
    assert.equal(a.allowed, true);
    assert.equal(b.allowed, false);
  });

  it('a budget-skipped lookup is cached only briefly', async () => {
    mf = mockFetch(baseMocks([vtOk]));
    const env = { VIRUSTOTAL_API_KEY: 'k', VIRUSTOTAL_DAILY: '1' };
    await call(ipLookup, '/api/ip/lookup?q=45.33.32.20', { env });
    const store = new Map<string, Response>();
    const cache = { match: async (r: Request) => store.get(r.url)?.clone(), put: async (r: Request, res: Response) => void store.set(r.url, res) };
    const g = globalThis as unknown as { caches?: unknown };
    const prev = g.caches;
    g.caches = { default: cache };
    try {
      await call(ipLookup, '/api/ip/lookup?q=45.33.32.21', { env });
      const cc = [...store.values()].map((r) => r.headers.get('cache-control') ?? '');
      assert.ok(cc.length > 0 && cc.every((h) => /max-age=120\b/.test(h)), `expected short TTL, got ${cc.join(',')}`);
    } finally {
      g.caches = prev;
    }
  });
});

describe('CVE filtering', () => {
  it('drops anything from InternetDB that is not a CVE identifier', async () => {
    mf = mockFetch([
      doh({}),
      (u) => (u.hostname === 'api.ipapi.is' ? jsonRes({ ip: '45.33.32.30', asn: { asn: 64500, org: 'EXAMPLE', route: '45.33.32.0/24' }, location: { country_code: 'US' } }) : undefined),
      (u) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { asns: [{ asn: 64500, holder: 'EXAMPLE' }] } }) : undefined),
      (u) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [443], vulns: ['CVE-2021-44228', 'cve-2023-1234', '../../evil', 'javascript:alert(1)', 'CVE-1-2'] }) : undefined),
    ]);
    const d = (await call(ipLookup, '/api/ip/lookup?q=45.33.32.30')).body.data;
    assert.deepEqual(d.exposure.vulns, ['CVE-2021-44228', 'cve-2023-1234']);
    assert.ok(d.flags.includes('2 known CVE(s) on exposed services'));
  });
});

describe('bounded request bodies', () => {
  const chunked = (chunks: string[], headers: Record<string, string> = {}) =>
    new Request('https://app.test/x', {
      method: 'POST',
      headers,
      body: new ReadableStream({
        start(c) {
          for (const s of chunks) c.enqueue(new TextEncoder().encode(s));
          c.close();
        },
      }),
      // @ts-expect-error duplex is required by Node's fetch for stream bodies
      duplex: 'half',
    });

  it('readTextLimited reads small bodies and rejects chunked bodies that exceed the cap (no Content-Length)', async () => {
    assert.equal(await readTextLimited(chunked(['hel', 'lo ', 'wörld']), 100), 'hello wörld');
    await assert.rejects(readTextLimited(chunked(['a'.repeat(60), 'b'.repeat(60)]), 100), (e: any) => e.status === 413 && e.code === 'PAYLOAD_TOO_LARGE');
    await assert.rejects(readTextLimited(new Request('https://app.test/x', { method: 'POST', body: 'x', headers: { 'content-length': '999999' } }), 100), (e: any) => e.status === 413);
    assert.equal(await readTextLimited(new Request('https://app.test/x'), 100), '');
  });

  it('/api/email/headers rejects an oversized chunked upload with 413 and still accepts normal input', async () => {
    const big = chunked(['X: ' + 'a'.repeat(150_000), 'b'.repeat(150_000)]);
    const res = await (emailHeaders as unknown as Fn)({ request: big, env: {}, params: {}, data: {}, waitUntil() {}, next: async () => new Response('') } as never);
    assert.equal(res.status, 413);

    const okRes = await call(emailHeaders, '/api/email/headers', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ headers: 'From: a@example.com\nTo: b@example.com\nSubject: hi\n' }),
    });
    assert.equal(okRes.status, 200);
    const bad = await call(emailHeaders, '/api/email/headers', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json' });
    assert.equal(bad.status, 400);
  });
});
