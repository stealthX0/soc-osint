import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyIP, cidrContains, cidrInfo, convertIP, formatIPv6, normalizeIP, parseIPv4, parseIPv6, ptrName, rangeToCidrs, isPublicIP,
} from '../shared/ip';

describe('parsing', () => {
  it('parses IPv4 strictly', () => {
    assert.equal(parseIPv4('192.168.1.1'), 3232235777n);
    for (const bad of ['256.1.1.1', '1.2.3', '01.2.3.4', '1.2.3.4.5', '', 'a.b.c.d', '1.2.3.-4']) assert.equal(parseIPv4(bad), null, bad);
  });
  it('parses and compresses IPv6 (RFC 5952)', () => {
    assert.equal(normalizeIP('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
    assert.equal(normalizeIP('::'), '::');
    assert.equal(normalizeIP('0:0:0:0:0:0:0:1'), '::1');
    assert.equal(normalizeIP('::ffff:1.2.3.4'), '::ffff:102:304');
    assert.equal(formatIPv6(parseIPv6('2001:db8:0:1:0:0:0:1')!), '2001:db8:0:1::1');
    // a single zero group must NOT be compressed
    assert.equal(normalizeIP('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1');
  });
  it('rejects malformed IPv6', () => {
    for (const bad of ['1::2::3', '12345::1', 'g::1', '1:2:3:4:5:6:7', 'fe80::1%eth0', ':::', '1:2:3:4:5:6:7:8:9']) assert.equal(parseIPv6(bad), null, bad);
  });
});

describe('classification', () => {
  const cases: [string, string, boolean][] = [
    ['8.8.8.8', 'public', true],
    ['1.1.1.1', 'public', true],
    ['10.1.2.3', 'private', false],
    ['172.16.0.1', 'private', false],
    ['172.32.0.1', 'public', true],
    ['192.168.0.1', 'private', false],
    ['127.0.0.1', 'loopback', false],
    ['169.254.169.254', 'link-local', false], // cloud metadata endpoint
    ['100.64.0.1', 'cgnat', false],
    ['224.0.0.1', 'multicast', false],
    ['255.255.255.255', 'reserved', false],
    ['0.0.0.0', 'unspecified', false],
    ['192.0.2.1', 'documentation', false],
    ['::1', 'loopback', false],
    ['fe80::1', 'link-local', false],
    ['fd00::1', 'private', false],
    ['2001:db8::1', 'documentation', false],
    ['2606:4700:4700::1111', 'public', true],
    ['::ffff:127.0.0.1', 'loopback', false], // mapped loopback must not slip through
    ['::ffff:10.0.0.1', 'private', false],
    ['::ffff:8.8.8.8', 'public', true],
    ['64:ff9b::7f00:1', 'reserved', false],
  ];
  for (const [ip, scope, pub] of cases) {
    it(`${ip} -> ${scope}`, () => {
      const c = classifyIP(ip)!;
      assert.equal(c.scope, scope);
      assert.equal(c.public, pub);
      assert.equal(isPublicIP(ip), pub);
    });
  }
  it('returns null for non-IPs', () => assert.equal(classifyIP('example.com'), null));
});

describe('CIDR', () => {
  it('computes a /24', () => {
    const i = cidrInfo('192.168.1.77/24')!;
    assert.equal(i.cidr, '192.168.1.0/24');
    assert.equal(i.netmask, '255.255.255.0');
    assert.equal(i.wildcard, '0.0.0.255');
    assert.equal(i.broadcast, '192.168.1.255');
    assert.equal(i.firstHost, '192.168.1.1');
    assert.equal(i.lastHost, '192.168.1.254');
    assert.equal(i.totalAddresses, '256');
    assert.equal(i.usableHosts, '254');
    assert.equal(i.hostBitsSet, true);
  });
  it('handles /31, /32, /0', () => {
    assert.equal(cidrInfo('10.0.0.0/31')!.usableHosts, '2');
    assert.equal(cidrInfo('10.0.0.1/32')!.usableHosts, '1');
    assert.equal(cidrInfo('0.0.0.0/0')!.totalAddresses, '4294967296');
  });
  it('handles IPv6', () => {
    const i = cidrInfo('2001:db8::/32')!;
    assert.equal(i.lastAddress, '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff');
    assert.equal(i.totalAddresses, (2n ** 96n).toString());
  });
  it('rejects bad input', () => {
    for (const b of ['1.2.3.4/33', '1.2.3.4', '::1/129', 'x/8', '1.2.3.4/-1']) assert.equal(cidrInfo(b), null, b);
  });
  it('containment', () => {
    assert.equal(cidrContains('10.0.0.0/8', '10.255.255.255'), true);
    assert.equal(cidrContains('10.0.0.0/8', '11.0.0.0'), false);
    assert.equal(cidrContains('10.0.0.0/8', '::1'), false);
  });
  it('range -> minimal CIDR cover', () => {
    assert.deepEqual(rangeToCidrs('10.0.0.0', '10.0.0.255'), ['10.0.0.0/24']);
    assert.deepEqual(rangeToCidrs('10.0.0.5', '10.0.0.10'), ['10.0.0.5/32', '10.0.0.6/31', '10.0.0.8/31', '10.0.0.10/32']);
    assert.deepEqual(rangeToCidrs('0.0.0.0', '255.255.255.255'), ['0.0.0.0/0']);
    assert.equal(rangeToCidrs('10.0.0.9', '10.0.0.1'), null);
    assert.equal(rangeToCidrs('10.0.0.1', '::1'), null);
  });
});

describe('conversion', () => {
  it('converts IPv4 in all forms', () => {
    const c = convertIP('192.168.1.1')!;
    assert.equal(c.decimal, '3232235777');
    assert.equal(c.hex, '0xc0a80101');
    assert.equal(c.binary, '11000000.10101000.00000001.00000001');
    assert.equal(c.reverseDns, '1.1.168.192.in-addr.arpa');
    assert.equal(c.ipv4MappedIPv6, '::ffff:192.168.1.1');
    assert.equal(c.scope, 'private');
  });
  it('accepts decimal and hex integers', () => {
    assert.equal(convertIP('3232235777')!.canonical, '192.168.1.1');
    assert.equal(convertIP('0xC0A80101')!.canonical, '192.168.1.1');
    assert.equal(convertIP('99999999999'), null);
  });
  it('converts IPv6', () => {
    const c = convertIP('2001:db8::1')!;
    assert.equal(c.expanded, '2001:0db8:0000:0000:0000:0000:0000:0001');
    assert.equal(c.compressed, '2001:db8::1');
    assert.equal(c.reverseDns, '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
    assert.equal(ptrName('8.8.4.4'), '4.4.8.8.in-addr.arpa');
  });
});
