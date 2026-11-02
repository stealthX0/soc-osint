import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assertPublicTarget, safeFetch } from '../worker/_lib/safeFetch';
import { ApiError } from '../worker/_lib/errors';
import { doh, mockFetch } from './helpers';

let mf: ReturnType<typeof mockFetch>;
afterEach(() => mf?.restore());

const rejects = async (p: Promise<unknown>, code: string) => {
  await assert.rejects(p, (e: unknown) => e instanceof ApiError && e.code === code, `expected ${code}`);
};

describe('assertPublicTarget: blocks without touching the network', () => {
  const blocked = [
    'http://127.0.0.1/',
    'http://127.1/',
    'http://2130706433/', // decimal form of 127.0.0.1
    'http://0x7f.0.0.1/',
    'http://169.254.169.254/latest/meta-data/', // cloud metadata
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://[fd00::1]/',
    'http://10.0.0.1:8080/',
    'http://192.168.1.1/',
    'http://localhost/',
    'http://printer.local/',
    'http://db.internal/',
    'http://intranet/',
  ];
  for (const u of blocked) {
    it(`blocks ${u}`, async () => {
      mf = mockFetch([]); // any fetch would throw "unexpected fetch"
      await rejects(assertPublicTarget(u), 'TARGET_NOT_ALLOWED');
      assert.equal(mf.calls.length, 0);
    });
  }
  it('blocks odd schemes, credentials and ports', async () => {
    mf = mockFetch([]);
    await rejects(assertPublicTarget('ftp://example.com/'), 'INVALID_URL');
    await rejects(assertPublicTarget('file:///etc/passwd'), 'INVALID_URL');
    await rejects(assertPublicTarget('http://user:pw@example.com/'), 'INVALID_URL');
    await rejects(assertPublicTarget('http://example.com:22/'), 'TARGET_NOT_ALLOWED');
    await rejects(assertPublicTarget('http://example.com:6379/'), 'TARGET_NOT_ALLOWED');
    await rejects(assertPublicTarget('not a url'), 'INVALID_URL');
  });
  it('allows public IP literals', async () => {
    mf = mockFetch([]);
    const r = await assertPublicTarget('https://8.8.8.8/');
    assert.deepEqual(r.addresses, ['8.8.8.8']);
  });
});

describe('assertPublicTarget: DNS-based checks', () => {
  it('blocks a public-looking name that resolves to a private address', async () => {
    mf = mockFetch([doh({ 'evil.example.com': { A: ['10.0.0.5'] } })]);
    await rejects(assertPublicTarget('https://evil.example.com/'), 'TARGET_NOT_ALLOWED');
  });
  it('blocks when ANY address is private (mixed answers)', async () => {
    mf = mockFetch([doh({ 'mixed.example.com': { A: ['93.184.216.34'], AAAA: ['::1'] } })]);
    await rejects(assertPublicTarget('https://mixed.example.com/'), 'TARGET_NOT_ALLOWED');
  });
  it('reports names that do not resolve', async () => {
    mf = mockFetch([doh({})]);
    await rejects(assertPublicTarget('https://nope.example.com/'), 'DOES_NOT_RESOLVE');
  });
  it('accepts public resolution', async () => {
    mf = mockFetch([doh({ 'example.com': { A: ['93.184.216.34'] } })]);
    const r = await assertPublicTarget('https://example.com/');
    assert.deepEqual(r.addresses, ['93.184.216.34']);
  });
});

describe('safeFetch', () => {
  it('re-validates every redirect hop (public -> metadata IP is blocked)', async () => {
    mf = mockFetch([
      doh({ 'example.com': { A: ['93.184.216.34'] } }),
      (u) => (u.hostname === 'example.com' ? new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } }) : undefined),
    ]);
    await rejects(safeFetch('https://example.com/'), 'TARGET_NOT_ALLOWED');
    assert.ok(!mf.calls.some((c) => c.includes('169.254.169.254')), 'must never request the internal address');
  });
  it('follows legitimate redirects and records hops', async () => {
    mf = mockFetch([
      doh({ 'example.com': { A: ['93.184.216.34'] }, 'www.example.com': { A: ['93.184.216.35'] } }),
      (u) => (u.hostname === 'example.com' ? new Response(null, { status: 301, headers: { location: 'https://www.example.com/home' } }) : undefined),
      (u) => (u.hostname === 'www.example.com' ? new Response('hello world', { status: 200 }) : undefined),
    ]);
    const r = await safeFetch('http://example.com/');
    assert.equal(r.hops.length, 2);
    assert.equal(r.finalUrl, 'https://www.example.com/home');
    assert.equal(r.response.status, 200);
    assert.equal(r.bytesRead, 11);
  });
  it('caps redirect chains', async () => {
    mf = mockFetch([
      doh({ 'loop.example.com': { A: ['93.184.216.34'] } }),
      (u) => (u.hostname === 'loop.example.com' ? new Response(null, { status: 302, headers: { location: 'https://loop.example.com/' } }) : undefined),
    ]);
    await rejects(safeFetch('https://loop.example.com/', { maxRedirects: 3 }), 'UPSTREAM_ERROR');
  });
  it('stops pulling the body once maxBytes is reached', async () => {
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (pulled >= 500) return c.close();
        pulled++;
        c.enqueue(new Uint8Array(1000));
      },
    });
    mf = mockFetch([
      doh({ 'big.example.com': { A: ['93.184.216.34'] } }),
      (u) => (u.hostname === 'big.example.com' ? new Response(stream, { status: 200 }) : undefined),
    ]);
    const r = await safeFetch('https://big.example.com/', { maxBytes: 5000 });
    assert.ok(r.bytesRead >= 5000 && r.bytesRead <= 7000, `bytesRead=${r.bytesRead}`);
    assert.ok(pulled < 50, `pulled ${pulled} chunks`);
  });
  it('maxRedirects: 0 returns the redirect instead of following or throwing', async () => {
    mf = mockFetch([
      doh({ 'example.com': { A: ['93.184.216.34'] } }),
      (u) => (u.hostname === 'example.com' ? new Response(null, { status: 301, headers: { location: 'https://example.com/' } }) : undefined),
    ]);
    const r = await safeFetch('http://example.com/', { maxRedirects: 0 });
    assert.equal(r.response.status, 301);
    assert.equal(r.hops.length, 1);
    assert.equal(mf.calls.filter((c) => c.startsWith('https://example.com')).length, 0);
  });
});
