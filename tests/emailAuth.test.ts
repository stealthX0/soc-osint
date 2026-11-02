import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseDkim, parseDmarc, parseSpf, summarizeAuth } from '../shared/emailAuth';

describe('SPF', () => {
  it('counts lookups and flags weak policies', () => {
    const s = parseSpf('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com mx a:mail.example.com ~all');
    assert.equal(s.directLookups, 3);
    assert.equal(s.all, '~');
    assert.deepEqual(s.includes, ['_spf.google.com']);
  });
  it('flags +all as an error and ptr as deprecated', () => {
    const s = parseSpf('v=spf1 ptr +all');
    assert.ok(s.issues.some((i) => i.level === 'error' && /\+all/.test(i.message)));
    assert.ok(s.issues.some((i) => /ptr/.test(i.message)));
  });
  it('handles redirect', () => {
    const s = parseSpf('v=spf1 redirect=_spf.example.net');
    assert.equal(s.redirect, '_spf.example.net');
    assert.equal(s.directLookups, 1);
    assert.equal(s.issues.length, 0);
  });
});

describe('DMARC', () => {
  it('parses tags', () => {
    const d = parseDmarc('v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s');
    assert.equal(d.policy, 'reject');
    assert.equal(d.pct, 50);
    assert.equal(d.rua.length, 2);
    assert.equal(d.adkim, 's');
    assert.ok(d.issues.some((i) => /50%/.test(i.message)));
  });
  it('warns on p=none and missing rua', () => {
    const d = parseDmarc('v=DMARC1; p=none');
    assert.ok(d.issues.some((i) => /monitor-only/.test(i.message)));
    assert.ok(d.issues.some((i) => /rua/.test(i.message)));
  });
  it('errors on a missing policy', () => assert.ok(parseDmarc('v=DMARC1;').issues.some((i) => i.level === 'error')));
});

describe('DKIM', () => {
  it('detects revoked keys', () => assert.equal(parseDkim('v=DKIM1; k=rsa; p=').revoked, true));
  it('estimates RSA size', () => {
    // 1024-bit RSA SPKI is 162 bytes; 2048-bit is 294 bytes
    const mk = (n: number) => Buffer.alloc(n, 1).toString('base64');
    assert.equal(parseDkim(`v=DKIM1; p=${mk(162)}`).approxKeyBits, 1024);
    assert.equal(parseDkim(`v=DKIM1; p=${mk(294)}`).approxKeyBits, 2048);
    assert.ok(parseDkim(`v=DKIM1; p=${mk(162)}`).issues.some((i) => i.level === 'warn'));
  });
});

describe('grading', () => {
  it('strong config scores A and is not spoofable', () => {
    const s = summarizeAuth({ spf: parseSpf('v=spf1 -all'), dmarc: parseDmarc('v=DMARC1; p=reject; rua=mailto:r@x.com'), dkimFound: 1, hasMx: true });
    assert.equal(s.grade, 'A');
    assert.equal(s.spoofable, false);
  });
  it('nothing configured is F and spoofable', () => {
    const s = summarizeAuth({ spf: null, dmarc: null, dkimFound: 0, hasMx: true });
    assert.equal(s.grade, 'F');
    assert.equal(s.spoofable, true);
  });
  it('p=none is still spoofable', () => {
    const s = summarizeAuth({ spf: parseSpf('v=spf1 -all'), dmarc: parseDmarc('v=DMARC1; p=none'), dkimFound: 1, hasMx: true });
    assert.equal(s.spoofable, true);
  });
});
