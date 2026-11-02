import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { defang, detectInput, normalizeDomain, normalizeHostname, parseEmail, refang } from '../shared/domain';

describe('normalizeDomain', () => {
  it('normalises URLs, case, ports, trailing dots', () => {
    assert.equal(normalizeDomain('https://User:pw@Example.COM:8443/a/b?c=d#e'), 'example.com');
    assert.equal(normalizeDomain('EXAMPLE.com.'), 'example.com');
    assert.equal(normalizeDomain('someone@mail.example.org'), 'mail.example.org');
  });
  it('converts IDNs to punycode', () => {
    assert.equal(normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
  });
  it('rejects junk', () => {
    for (const bad of ['', 'localhost', 'no_tld', '1.2.3.4', '-bad-.com', 'a..b.com', 'exa mple.com', 'a.b.123', 'x'.repeat(64) + '.com']) {
      assert.equal(normalizeDomain(bad), null, bad);
    }
  });
  it('hostnames may be single-label but never IPs', () => {
    assert.equal(normalizeHostname('localhost'), 'localhost');
    assert.equal(normalizeHostname('127.0.0.1'), null);
    assert.equal(normalizeHostname('[::1]'), null);
  });
});

describe('email / defang', () => {
  it('parses addresses', () => {
    assert.deepEqual(parseEmail('Bob@Example.COM'), { local: 'Bob', domain: 'example.com' });
    assert.equal(parseEmail('bob@'), null);
    assert.equal(parseEmail('a b@example.com'), null);
  });
  it('defang / refang round-trip', () => {
    const u = 'https://evil.example.com/path';
    assert.equal(defang(u), 'hxxps://evil[.]example[.]com/path');
    assert.equal(refang(defang(u)), u);
    assert.equal(refang('user[@]example(dot)com'), 'user@example.com');
  });
});

describe('detectInput', () => {
  const k = (s: string) => detectInput(s).kind;
  it('classifies', () => {
    assert.equal(k('8.8.8.8'), 'ipv4');
    assert.equal(k('2001:db8::1'), 'ipv6');
    assert.equal(k('example.com'), 'domain');
    assert.equal(k('hxxps://evil[.]com/x'), 'url');
    assert.equal(k('bob@example.com'), 'email');
    assert.equal(k('d41d8cd98f00b204e9800998ecf8427e'), 'hash');
    assert.equal(k('cve-2021-44228'), 'cve');
    assert.equal(k('as13335'), 'asn');
    assert.equal(k('how to analyse phishing email'), 'text');
  });
  it('refangs before classifying', () => assert.deepEqual(detectInput('1[.]1[.]1[.]1'), { kind: 'ipv4', value: '1.1.1.1' }));
});
