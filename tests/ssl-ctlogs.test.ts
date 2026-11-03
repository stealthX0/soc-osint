import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ctxFor, jsonRes, mockFetch } from './helpers';
import { onRequestGet as ssl } from '../worker/api/domain/ssl';

type Fn = (c: never) => Response | Promise<Response>;
const call = async (path: string, env: Record<string, unknown> = {}) => {
  const res = await (ssl as unknown as Fn)(ctxFor(path, { env }));
  return { status: res.status, body: (await res.json()) as any };
};

let mf: ReturnType<typeof mockFetch> | undefined;
afterEach(() => mf?.restore());

const now = Date.now();
const iso = (d: number) => new Date(now + d * 86_400_000).toISOString();
const row = (id: string, o: Record<string, unknown> = {}) => ({ id, match: 'example.com', not_before: iso(-30), not_after: iso(60), serial_hex: `ab${id}`, issuer: 'R11', key_algo: 'ECDSA', san_count: 2, ...o });
const isCtlogs = (u: URL) => u.hostname === 'api.ctlogs.dev';
const crtRows = [{ id: 9, issuer_name: "C=US, O=Let's Encrypt, CN=R10", common_name: 'example.com', name_value: 'example.com', not_before: iso(-30).replace('Z', ''), not_after: iso(60).replace('Z', ''), serial_number: 'CC' }];

describe('/api/domain/ssl: ctlogs.dev primary, crt.sh fallback', () => {
  it('uses ctlogs.dev first, sends the key as a bearer token, and never calls crt.sh', async () => {
    let auth: string | null = null;
    mf = mockFetch([(u, init) => {
      if (!isCtlogs(u)) return undefined;
      auth = new Headers(init?.headers).get('authorization');
      if (u.pathname.startsWith('/v1/domain/*.')) return jsonRes({ rows: [], has_next: false, next_cursor: '' });
      return jsonRes({ rows: [row('1'), row('2', { issuer: 'R10', not_before: iso(-200), not_after: iso(-110) }), row('1')], has_next: false, next_cursor: '', history_window_days: 90, history_truncated: true });
    }]);
    const r = await call('/api/domain/ssl?domain=example.com', { CTLOGS_API_KEY: 'secret-key' });
    assert.equal(r.status, 200);
    assert.equal(auth, 'Bearer secret-key');
    assert.ok(!mf.calls.some((c) => c.includes('crt.sh')));
    const d = r.body.data;
    assert.equal(d.source, 'ctlogs.dev');
    assert.equal(d.total, 2); // duplicate id dropped
    assert.equal(d.active, 1);
    assert.equal(d.certificates[0].issuer, 'R11');
    assert.equal(d.wildcard, false);
    assert.match(d.note, /ctlogs\.dev/);
    assert.ok(d.issues.some((i: any) => /crt\.sh has the full history/.test(i.message)));
    assert.ok(!JSON.stringify(r.body).includes('secret-key'));
  });

  it('works without a key and follows the page cursor', async () => {
    let headerSeen = true;
    mf = mockFetch([(u, init) => {
      if (!isCtlogs(u)) return undefined;
      if (new Headers(init?.headers).get('authorization')) headerSeen = false;
      if (u.pathname.startsWith('/v1/domain/*.')) return jsonRes({ rows: [row('w', { match: '*.example.com' })], has_next: false, next_cursor: '' });
      return u.searchParams.get('after') === 'c1'
        ? jsonRes({ rows: [row('2')], has_next: false, next_cursor: '' })
        : jsonRes({ rows: [row('1')], has_next: true, next_cursor: 'c1' });
    }]);
    const d = (await call('/api/domain/ssl?domain=example.org')).body.data;
    assert.ok(headerSeen);
    assert.equal(d.total, 2);
    assert.equal(d.wildcard, true);
  });

  it('lists subdomains from the ctlogs.dev host finder', async () => {
    mf = mockFetch([(u) => {
      if (!isCtlogs(u)) return undefined;
      if (u.pathname.startsWith('/v1/hosts/')) return jsonRes({ hosts: [{ host: 'www.example.net' }, { host: '*.example.net' }, { host: 'api.example.net' }], has_next: false, next_cursor: '' });
      return jsonRes({ rows: [row('1', { match: 'example.net' })], has_next: false, next_cursor: '' });
    }]);
    const d = (await call('/api/domain/ssl?domain=example.net&subdomains=1')).body.data;
    assert.deepEqual(d.subdomains, ['*.example.net', 'api.example.net', 'www.example.net']);
    assert.equal(d.wildcard, true);
    assert.equal(d.source, 'ctlogs.dev');
  });

  for (const [label, res] of [
    ['an HTTP 503', () => new Response('busy', { status: 503 })],
    ['a rate limit (429)', () => new Response('{"error":"limit"}', { status: 429 })],
    ['a rejected key (401)', () => new Response('{"error":"bad key"}', { status: 401 })],
    ['a garbage body', () => new Response('<html>oops</html>', { status: 200 })],
    ['a network error', () => { throw new Error('connection reset'); }],
  ] as const) {
    it(`falls back to crt.sh on ${label}`, async () => {
      mf = mockFetch([(u) => (isCtlogs(u) ? res() : undefined), (u) => (u.hostname === 'crt.sh' ? jsonRes(crtRows) : undefined)]);
      const r = await call(`/api/domain/ssl?domain=fallback-${label.replace(/\W/g, '')}.com`, { CTLOGS_API_KEY: 'k' });
      assert.equal(r.status, 200);
      assert.equal(r.body.data.source, 'crt.sh');
      assert.equal(r.body.data.total, 1);
      assert.ok(r.body.data.issues.some((i: any) => /ctlogs\.dev was unavailable/.test(i.message)));
    });
  }

  it('reports both providers when both fail', async () => {
    mf = mockFetch([(u) => (isCtlogs(u) ? new Response('', { status: 503 }) : undefined), (u) => (u.hostname === 'crt.sh' ? new Response('', { status: 502 }) : undefined)]);
    const r = await call('/api/domain/ssl?domain=both-down.com');
    assert.equal(r.status, 502);
    assert.match(r.body.error.message, /ctlogs\.dev/);
    assert.match(r.body.error.message, /crt\.sh/);
  });
});
