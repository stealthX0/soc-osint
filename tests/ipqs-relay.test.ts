/** The Vercel relay (relay/ipqs-vercel/api/ipqs.js) and the Worker's relay mode. */
import { describe, it, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
// @ts-expect-error plain-JS module without types
import relayHandler, { sameSecret } from '../relay/ipqs-vercel/api/ipqs.js';
import { relayConfig } from '../worker/api/email/ipqs';
import { jsonRes, mockFetch } from './helpers';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';

const SECRET = 'f'.repeat(16) + '0123456789abcdef0123456789abcdef';
const KEY = 'TESTkeyTESTkeyTESTkeyTESTkey0000';
const RAW_OK = { success: true, valid: true, fraud_score: 12, recent_abuse: false, dns_valid: true, smtp_score: 3, overall_score: 4, request_id: 'ok1' };

/** Minimal stand-ins for Vercel's Node request/response objects. */
function call(opts: { method?: string; secret?: string; body?: unknown }) {
  const req = { method: opts.method ?? 'POST', headers: opts.secret === undefined ? {} : { 'x-relay-secret': opts.secret }, body: opts.body } as never;
  const out = { status: 0, headers: {} as Record<string, string>, body: '' };
  const res = {
    set statusCode(v: number) { out.status = v; },
    setHeader(k: string, v: string) { out.headers[k.toLowerCase()] = v; },
    end(b: string) { out.body = b; },
  };
  return relayHandler(req, res).then(() => ({ ...out, json: JSON.parse(out.body) }));
}

describe('relay function', () => {
  let restore = () => {};
  beforeEach(() => { process.env.RELAY_SECRET = SECRET; process.env.IPQS_API_KEY = KEY; });
  afterEach(() => { restore(); delete process.env.RELAY_SECRET; delete process.env.IPQS_API_KEY; });

  it('compares secrets in constant time and exactly', () => {
    assert.equal(sameSecret(SECRET, SECRET), true);
    assert.equal(sameSecret(SECRET + 'x', SECRET), false);
    assert.equal(sameSecret(undefined, SECRET), false);
  });

  it('refuses anything but POST, a wrong or missing secret, and a bad address, without calling IPQS', async () => {
    const m = mockFetch([]); restore = m.restore;
    assert.equal((await call({ method: 'GET', secret: SECRET })).status, 405);
    assert.equal((await call({ secret: 'wrong', body: { email: 'a@b.example' } })).status, 401);
    assert.equal((await call({ body: { email: 'a@b.example' } })).status, 401);
    assert.equal((await call({ secret: SECRET, body: { email: 'not an email' } })).status, 400);
    assert.equal((await call({ secret: SECRET, body: { email: 'a@b.example/../x' } })).status, 400);
    assert.equal(m.calls.length, 0);
  });

  it('is unusable until configured with a 32+ character secret and a key', async () => {
    process.env.RELAY_SECRET = 'short';
    assert.equal((await call({ secret: 'short', body: { email: 'a@b.example' } })).status, 503);
  });

  it('makes one IPQS call with the key in the path and returns IPQS JSON unchanged', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes(RAW_OK) : undefined)]); restore = m.restore;
    const r = await call({ secret: SECRET, body: { email: ' Test@Gmail.com ' } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, RAW_OK);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(m.calls.length, 1);
    assert.equal(m.calls[0], `https://www.ipqualityscore.com/api/json/email/${KEY}/test@gmail.com?timeout=7&abuse_strictness=0`);
  });

  it('passes IPQS errors through but never the key', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes({ success: false, message: `Invalid or unauthorized key ${KEY}.`, request_id: 'x1' }) : undefined)]); restore = m.restore;
    const r = await call({ secret: SECRET, body: JSON.stringify({ email: 'a@b.example' }) });
    assert.equal(r.status, 200);
    assert.equal(r.json.success, false);
    assert.ok(!r.body.includes(KEY));
  });

  it('reports IPQS being unreachable as 504 without details', async () => {
    const m = mockFetch([() => { throw Object.assign(new Error('t'), { name: 'TimeoutError' }); }]); restore = m.restore;
    const r = await call({ secret: SECRET, body: { email: 'a@b.example' } });
    assert.equal(r.status, 504);
  });
});

const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
const post = async (body: unknown, e: Record<string, unknown>) => {
  const res = await worker.fetch(new Request('https://app.test/api/phishing/sender', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.9' }, body: JSON.stringify(body) }), { ...(env as object), ...e } as never, exec);
  return (await res.json()) as { data: any };
};
const RELAY_URL = 'https://spectrix-ipqs-relay.vercel.app/api/ipqs';

describe('Worker relay mode', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); });

  it('validates its settings', () => {
    assert.equal(relayConfig({} as never), null);
    assert.deepEqual(relayConfig({ IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: ` ${SECRET}\n` } as never), { url: RELAY_URL, secret: SECRET });
    assert.throws(() => relayConfig({ IPQS_RELAY_URL: 'http://x.example/api/ipqs', IPQS_RELAY_SECRET: SECRET } as never), /must be an https URL/);
    assert.throws(() => relayConfig({ IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: 'short' } as never), /at least 32 characters/);
  });

  it('sends only the address and the secret to the relay (never IPQS directly, never the key) and uses its answer', async () => {
    const seen: { url: string; method?: string; secret: string | null; body: string }[] = [];
    const m = mockFetch([(u, init) => {
      if (u.hostname !== 'spectrix-ipqs-relay.vercel.app') return undefined;
      seen.push({ url: u.toString(), method: init?.method, secret: new Headers(init?.headers).get('x-relay-secret'), body: String(init?.body) });
      return jsonRes({ ...RAW_OK, fraud_score: 93, recent_abuse: true });
    }]);
    restore = m.restore;
    const { data } = await post({ check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: SECRET, IPQS_API_KEY: KEY });
    assert.equal(data.data.check, 'ipqs');
    assert.equal(data.data.value.fraudScore, 93);
    assert.deepEqual(data.findings.map((f: { id: string }) => f.id).sort(), ['sender_address_fraud_score', 'sender_address_recent_abuse']);
    assert.deepEqual(seen, [{ url: RELAY_URL, method: 'POST', secret: SECRET, body: '{"email":"a@evil.example"}' }]);
    assert.ok(!m.calls.some((c) => c.includes('ipqualityscore')), 'IPQS is not called directly');
    assert.ok(!m.calls.some((c) => c.includes(KEY)) && !seen.some((s) => s.body.includes(KEY)), 'the key is not sent');
    assert.ok(!JSON.stringify(data).includes(SECRET));
  });

  it('works with no IPQS key on the Worker', async () => {
    const m = mockFetch([(u) => (u.hostname === 'spectrix-ipqs-relay.vercel.app' ? jsonRes(RAW_OK) : undefined)]);
    restore = m.restore;
    const { data } = await post({ check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: SECRET });
    assert.equal(data.data.check, 'ipqs');
  });

  it('explains a wrong shared secret, then falls back to UserCheck', async () => {
    const m = mockFetch([
      (u) => (u.hostname === 'spectrix-ipqs-relay.vercel.app' ? new Response('{"success":false,"message":"Unauthorized."}', { status: 401 }) : undefined),
      (u) => (u.hostname === 'api.usercheck.com' ? jsonRes({ email: 'a@evil.example', domain: 'evil.example', mx: true }) : undefined),
    ]);
    restore = m.restore;
    const { data } = await post({ check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: SECRET, USERCHECK_API_KEY: 'uc' });
    assert.equal(data.data.check, 'usercheck');
    assert.match(data.checks[0].detail, /IPQS relay: the relay rejected the shared secret/);
  });

  it('a key rejection through the relay points at the relay key, with the request id', async () => {
    const m = mockFetch([
      (u) => (u.hostname === 'spectrix-ipqs-relay.vercel.app' ? jsonRes({ success: false, message: 'Invalid or unauthorized key. (EID: 61771)', request_id: 'Rr1' }) : undefined),
      (u) => (u.hostname === 'api.usercheck.com' ? jsonRes({ email: 'a@evil.example', domain: 'evil.example', mx: true }) : undefined),
    ]);
    restore = m.restore;
    const { data } = await post({ check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: SECRET, USERCHECK_API_KEY: 'uc' });
    assert.match(data.checks[0].detail, /sent via the IPQS relay, which holds the key: check IPQS_API_KEY on the relay; request_id: Rr1/);
    assert.equal(m.calls.filter((c) => c.includes('vercel.app')).length, 1, 'no retries through the relay');
  });

  it('a misconfigured relay falls back to UserCheck and says what to fix', async () => {
    const m = mockFetch([(u) => (u.hostname === 'api.usercheck.com' ? jsonRes({ email: 'a@evil.example', domain: 'evil.example', mx: true }) : undefined)]);
    restore = m.restore;
    const { data } = await post({ check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_RELAY_URL: RELAY_URL, IPQS_RELAY_SECRET: 'short', USERCHECK_API_KEY: 'uc' });
    assert.equal(data.data.check, 'usercheck');
    assert.match(data.checks[0].detail, /relay is misconfigured/);
  });
});
