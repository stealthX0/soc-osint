import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { resolve } from '../worker/routes';

const env = (extra: Record<string, unknown> = {}) =>
  ({ ASSETS: { fetch: async (r: Request) => new Response(`asset:${new URL(r.url).pathname}`) }, ...extra }) as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
const call = async (path: string, init: RequestInit = {}) => {
  const res = await worker.fetch(new Request(`https://app.test${path}`, { headers: { 'cf-connecting-ip': '198.51.100.7' }, ...init }), env(), exec);
  return { res, text: await res.text() };
};

describe('worker entry', () => {
  it('serves non-API paths from the assets binding', async () => {
    assert.equal((await call('/')).text, 'asset:/');
    assert.equal((await call('/ip')).text, 'asset:/ip');
  });
  it('routes /api/health through the middleware', async () => {
    const { res, text } = await call('/api/health');
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(text).data.status, 'ok');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });
  it('returns a JSON 404 for unknown API paths and 405 for wrong methods', async () => {
    const nf = await call('/api/nope');
    assert.equal(nf.res.status, 404);
    assert.equal(JSON.parse(nf.text).error.code, 'NOT_FOUND');
    const mm = await call('/api/network/subnet?cidr=10.0.0.0/8', { method: 'POST' });
    assert.equal(mm.res.status, 405);
    assert.equal((await call('/api/health', { method: 'DELETE' })).res.status, 405);
  });
  it('handles subnet requests end to end, HEAD and trailing slashes', async () => {
    const r = await call('/api/network/subnet?cidr=192.168.1.0/24');
    assert.equal(r.res.status, 200);
    assert.equal((await call('/api/health/')).res.status, 200);
    assert.equal(resolve('HEAD', '/api/health').handler !== null, true);
  });
  it('handles CORS preflight', async () => {
    const r = await call('/api/health', { method: 'OPTIONS', headers: { origin: 'https://app.test' } });
    assert.equal(r.res.status, 204);
  });
});
