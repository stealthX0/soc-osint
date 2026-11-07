import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { callInternal } from '../worker/_lib/internal';
import { costFor } from '../worker/_lib/ratelimit';

const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
const post = async (path: string, body: unknown, raw = false) => {
  const res = await worker.fetch(new Request(`https://app.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.7' }, body: raw ? (body as string) : JSON.stringify(body) }), env, exec);
  return { res, json: (await res.json()) as { ok: boolean; data?: any; error?: { code: string; message: string } } };
};

describe('POST /api/phishing/parse', () => {
  it('returns structured forensics, links and indicators', async () => {
    const { res, json } = await post('/api/phishing/parse', {
      headers: 'Received: from mail.evil.example (mail.evil.example [45.33.32.156]) by mx.google.com with ESMTPS; Tue, 3 Nov 2026 10:04:50 -0800\nAuthentication-Results: mx.google.com; spf=fail smtp.mailfrom=a@evil.example; dkim=none; dmarc=fail header.from=bank.example\nFrom: "Bank" <alerts@bank.example>\nSubject: Verify now',
      body: 'Go to https://evil.example/login',
    });
    assert.equal(res.status, 200);
    assert.equal(json.ok, true);
    assert.equal(json.data.forensics.trust.connectingIp, '45.33.32.156');
    assert.equal(json.data.links[0].host, 'evil.example');
    assert.deepEqual(json.data.indicators.urls, ['https://evil.example/login']);
    assert.ok(json.data.findings.some((f: { id: string }) => f.id === 'auth_all_failed'));
  });
  it('rejects empty input, bad JSON and oversized bodies with clear errors', async () => {
    assert.equal((await post('/api/phishing/parse', {})).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post('/api/phishing/parse', '{nope', true)).json.error?.code, 'INVALID_INPUT');
    const big = await post('/api/phishing/parse', { body: 'x'.repeat(3_100_000) });
    assert.equal(big.res.status, 413);
  });
  it('only accepts POST', async () => {
    const res = await worker.fetch(new Request('https://app.test/api/phishing/parse'), env, exec);
    assert.equal(res.status, 405);
  });
  it('is rate limited at a fixed cost', () => assert.equal(costFor('/api/phishing/parse'), 2));
});

describe('callInternal', () => {
  const ctx = { request: new Request('https://app.test/api/phishing/parse', { method: 'POST' }), env, waitUntil: () => {} };
  it('invokes an existing lookup in-process and unwraps the response', async () => {
    const r = await callInternal<{ cidr?: string }>(ctx, '/api/network/subnet', { params: { cidr: '192.168.1.0/24' } });
    assert.equal(r.ok, true);
  });
  it('passes through endpoint validation errors', async () => {
    const r = await callInternal(ctx, '/api/network/subnet', { params: { cidr: 'nonsense' } });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'INVALID_INPUT');
  });
  it('refuses recursion into workflow endpoints and path tricks', async () => {
    assert.equal((await callInternal(ctx, '/api/phishing/parse')).ok, false);
    assert.equal((await callInternal(ctx, '/api/../etc')).ok, false);
    assert.equal((await callInternal(ctx, '/other')).ok, false);
  });
  it('reports unknown endpoints', async () => {
    const r = await callInternal(ctx, '/api/nope');
    assert.equal(r.ok, false);
  });
});
