/** IP risk rating shared by the dashboard's IP Reputation panel and the Domain & IP Intelligence tab. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assessIpRisk } from '../shared/phishing/ipRisk';
import { ipLookup } from './fixtures/ip-lookup';

describe('IP risk assessment', () => {
  it('clean answers from every provider are low risk, with only notes', () => {
    const r = assessIpRisk(ipLookup());
    assert.equal(r.level, 'low');
    assert.ok(r.factors.every((f) => f.level === 'info'));
  });
  it('rates on the strongest provider signal, whichever provider it comes from', () => {
    assert.equal(assessIpRisk(ipLookup({ reputation: { ...ipLookup().reputation!, abuseConfidence: 90, totalReports: 40, distinctReporters: 12 } })).level, 'high');
    assert.equal(assessIpRisk(ipLookup({ reputation: { ...ipLookup().reputation!, abuseConfidence: 30, totalReports: 3 } })).level, 'medium');
    assert.equal(assessIpRisk(ipLookup({ virustotal: { ...ipLookup().virustotal!, malicious: 5 } })).level, 'high', 'VirusTotal alone can make it high');
    assert.equal(assessIpRisk(ipLookup({ pulsedive: { ...ipLookup().pulsedive!, observed: true, risk: 'high', threats: [{ name: 'Phishing', category: null, risk: null }] } })).level, 'high');
    assert.equal(assessIpRisk(ipLookup({ netType: { ...ipLookup().netType!, isTor: true } })).level, 'high');
    assert.equal(assessIpRisk(ipLookup({ netType: { ...ipLookup().netType!, isVpn: true } })).level, 'medium');
    assert.equal(assessIpRisk(ipLookup({ exposure: { ports: [22, 25], hostnames: [], vulns: ['CVE-2024-0001'], tags: [], cpes: [] } })).level, 'medium');
  });
  it('the strongest factor is listed first', () => {
    const r = assessIpRisk(ipLookup({ virustotal: { ...ipLookup().virustotal!, malicious: 1 }, reputation: { ...ipLookup().reputation!, abuseConfidence: 95, totalReports: 80, distinctReporters: 30 } }));
    assert.equal(r.factors[0].source, 'AbuseIPDB');
    assert.equal(r.factors[0].level, 'high');
  });
  it('no provider answering is unknown, never low', () => {
    assert.equal(assessIpRisk(ipLookup({ reputation: null, virustotal: null, pulsedive: null, netType: null })).level, 'unknown');
  });
  it('names shared mail infrastructure so its reputation is not over-read', () => {
    assert.equal(assessIpRisk(ipLookup({ network: { asn: 'AS15169', org: 'Google LLC', isp: 'Google LLC', domain: 'google.com', prefix: null } })).sharedProvider, 'Google');
  });
});
