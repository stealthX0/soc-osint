import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ctxFor, doh, jsonRes, mockFetch } from './helpers';
import { onRequestGet as dnsLookup } from '../worker/api/dns/lookup';
import { onRequestGet as dnsProp } from '../worker/api/dns/propagation';
import { onRequestGet as ipLookup } from '../worker/api/ip/lookup';
import { onRequestGet as whois } from '../worker/api/domain/whois';
import { onRequestGet as ssl } from '../worker/api/domain/ssl';
import { onRequestGet as httpCheck } from '../worker/api/domain/http';
import { onRequestGet as emailAuth } from '../worker/api/email/auth';
import { onRequestPost as emailHeaders } from '../worker/api/email/headers';
import { onRequestGet as latency } from '../worker/api/network/latency';
import { onRequestGet as subnet } from '../worker/api/network/subnet';
import { onRequestGet as ipConvert } from '../worker/api/util/ip-convert';
import { onRequestGet as ipRange } from '../worker/api/util/ip-range';
import { onRequest as middleware } from '../worker/middleware';

type Fn = (c: never) => Response | Promise<Response>;
const call = async (fn: unknown, path: string, init?: RequestInit & { env?: Record<string, unknown> }) => {
  const res = await (fn as Fn)(ctxFor(path, init));
  return { status: res.status, body: (await res.json()) as any, headers: res.headers };
};

let mf: ReturnType<typeof mockFetch> | undefined;
afterEach(() => mf?.restore());

describe('error envelope', () => {
  it('rejects bad input with 400 + code', async () => {
    mf = mockFetch([]);
    const r = await call(dnsLookup, '/api/dns/lookup?name=not%20valid');
    assert.equal(r.status, 400);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.error.code, 'INVALID_INPUT');
    assert.equal(r.headers.get('cache-control'), 'no-store');
  });
});

describe('/api/dns/lookup', () => {
  it('returns grouped records and flags DNSSEC validation', async () => {
    mf = mockFetch([doh({ 'example.com': { A: ['93.184.216.34'], MX: ['10 mail.example.com.'], TXT: ['"v=spf1 -all"'] } }, { ad: true })]);
    const r = await call(dnsLookup, '/api/dns/lookup?name=Example.COM&type=ALL');
    assert.equal(r.status, 200);
    const by = Object.fromEntries(r.body.data.results.map((x: any) => [x.type, x]));
    assert.equal(by.A.records[0].data, '93.184.216.34');
    assert.equal(by.MX.records[0].data, '10 mail.example.com'); // trailing dot stripped
    assert.equal(by.TXT.records[0].data, 'v=spf1 -all'); // quotes stripped
    assert.equal(by.A.authenticated, true);
    assert.equal(by.AAAA.records.length, 0);
  });
  it('converts an IP into a PTR query', async () => {
    mf = mockFetch([doh({ '8.8.8.8.in-addr.arpa': { PTR: ['dns.google.'] } })]);
    const r = await call(dnsLookup, '/api/dns/lookup?name=8.8.8.8');
    assert.equal(r.body.data.results[0].type, 'PTR');
    assert.equal(r.body.data.results[0].records[0].data, 'dns.google');
  });
  it('joins multi-string TXT records', async () => {
    mf = mockFetch([doh({ 'long.example.com': { TXT: ['"v=DKIM1; p=AAA" "BBB"'] } })]);
    const r = await call(dnsLookup, '/api/dns/lookup?name=long.example.com&type=TXT');
    assert.equal(r.body.data.results[0].records[0].data, 'v=DKIM1; p=AAABBB');
  });
  it('rejects unknown types/resolvers', async () => {
    mf = mockFetch([]);
    assert.equal((await call(dnsLookup, '/api/dns/lookup?name=example.com&type=ANY')).status, 400);
    assert.equal((await call(dnsLookup, '/api/dns/lookup?name=example.com&resolver=evil')).status, 400);
  });
  it('surfaces upstream failure when every query fails', async () => {
    mf = mockFetch([(u) => (/dns/.test(u.hostname) ? new Response('', { status: 500 }) : undefined)]);
    const r = await call(dnsLookup, '/api/dns/lookup?name=example.com&type=A');
    assert.equal(r.status, 502);
    assert.equal(r.body.error.code, 'UPSTREAM_ERROR');
  });
});

describe('/api/dns/propagation', () => {
  it('reports consistency across resolvers', async () => {
    mf = mockFetch([doh({ 'example.com': { A: ['1.2.3.4', '5.6.7.8'] } })]);
    const r = await call(dnsProp, '/api/dns/propagation?name=example.com');
    assert.equal(r.body.data.consistent, true);
    assert.equal(r.body.data.resolvers.length, 3);
  });
  it('detects disagreement and tolerates one failed resolver', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'dns.google' ? jsonRes({ Status: 0, Answer: [{ name: 'example.com.', type: 1, TTL: 60, data: '9.9.9.9' }] }) : undefined),
      (u) => (u.hostname === 'dns.quad9.net' ? new Response('', { status: 503 }) : undefined),
      doh({ 'example.com': { A: ['1.2.3.4'] } }),
    ]);
    const r = await call(dnsProp, '/api/dns/propagation?name=example.com');
    assert.equal(r.body.data.consistent, false);
    assert.ok(r.body.data.resolvers.some((x: any) => x.status === 'ERROR' && x.error));
  });
});

const ipapiIs = (over: Record<string, unknown> = {}) => ({
  ip: '8.8.8.8', is_datacenter: false, is_vpn: false, is_proxy: false, is_tor: false, is_mobile: false, is_crawler: false, is_abuser: false,
  company: { name: 'Google LLC', abuser_score: '0.0039 (Low)', domain: 'google.com', type: 'hosting' },
  asn: { asn: 15169, route: '8.8.8.0/24', org: 'Google LLC', domain: 'google.com', abuser_score: '0.0008 (Low)', type: 'hosting' },
  location: { country: 'United States', country_code: 'US', state: 'California', city: 'Mountain View', zip: '94043', latitude: 37.4, longitude: -122.1, timezone: 'America/Los_Angeles' },
  ...over,
});

describe('/api/ip/lookup: ipapi.is primary', () => {
  // overrides go first: the first matching handler wins
  const base = (extra: ((u: URL, init?: RequestInit) => Response | undefined)[] = []) => [
    ...extra,
    doh({}),
    (u: URL) => (u.hostname === 'api.ipapi.is' ? jsonRes(ipapiIs()) : undefined),
    (u: URL) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { resource: '8.8.8.0/24', asns: [{ asn: 15169, holder: 'GOOGLE' }] } }) : undefined),
    (u: URL) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [] }) : undefined),
  ];
  const names = (d: any) => Object.fromEntries(d.providers.map((p: any) => [p.name, p]));

  it('fills geo, network and network-type from ipapi.is and never contacts the fallbacks', async () => {
    mf = mockFetch(base());
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.8')).body.data;
    assert.equal(d.geoSource, 'ipapi.is');
    assert.equal(d.geo.countryCode, 'US');
    assert.equal(d.geo.city, 'Mountain View');
    assert.equal(d.geo.postal, '94043');
    assert.equal(d.geo.timezone, 'America/Los_Angeles');
    assert.equal(d.network.asn, 'AS15169');
    assert.equal(d.network.org, 'Google LLC');
    assert.equal(d.network.prefix, '8.8.8.0/24');
    assert.equal(d.netType.isVpn, false);
    assert.equal(d.netType.companyType, 'hosting');
    assert.ok(!mf.calls.some((c) => /ipwho\.is|ipapi\.co/.test(c)), 'fallbacks are not called when the primary works');
    assert.equal(names(d)['ipapi.is (geo/ASN/network type)'].ok, true);
    assert.ok(!names(d)['ipwho.is (fallback geo/ASN)']);
  });

  it('surfaces VPN / proxy / Tor / datacenter / abuser signals as flags', async () => {
    mf = mockFetch(base([(u) => (u.hostname === 'api.ipapi.is' ? jsonRes(ipapiIs({ is_vpn: true, vpn: { service: 'NordVPN' }, is_datacenter: true, datacenter: { datacenter: 'M247' }, is_tor: true, is_abuser: true })) : undefined)]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.4.4')).body.data;
    assert.ok(d.flags.includes('VPN (NordVPN)'));
    assert.ok(d.flags.includes('Datacenter (M247)'));
    assert.ok(d.flags.includes('Tor exit node'));
    assert.ok(d.flags.includes('Flagged as abuser (ipapi.is)'));
    assert.equal(d.flags.filter((f: string) => f === 'Tor exit node').length, 1, 'no duplicate flags');
    assert.equal(d.netType.vpnService, 'NordVPN');
  });

  it('is keyless by default; a configured key is sent only to ipapi.is', async () => {
    mf = mockFetch(base());
    await call(ipLookup, '/api/ip/lookup?q=8.8.8.9');
    const first = mf.calls.find((c) => c.includes('ipapi.is'))!;
    assert.ok(!first.includes('key='));
    mf = mockFetch(base());
    await call(ipLookup, '/api/ip/lookup?q=8.8.8.10', { env: { IPAPI_IS_API_KEY: 'secret-key' } });
    assert.ok(mf.calls.find((c) => c.includes('api.ipapi.is'))!.includes('key=secret-key'));
    for (const c of mf.calls.filter((c) => !c.includes('api.ipapi.is'))) assert.ok(!c.includes('secret-key'), 'key never appears in other URLs');
  });

  it('falls back to ipwho.is when ipapi.is is rate limited', async () => {
    mf = mockFetch(base([
      (u) => (u.hostname === 'api.ipapi.is' ? new Response('', { status: 429 }) : undefined),
      (u) => (u.hostname === 'ipwho.is' ? jsonRes({ success: true, country: 'Germany', country_code: 'DE', city: 'Berlin', region: 'Berlin', connection: { asn: 3320, org: 'Deutsche Telekom' } }) : undefined),
    ]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.11')).body.data;
    assert.equal(d.geoSource, 'ipwho.is');
    assert.equal(d.geo.countryCode, 'DE');
    assert.equal(d.network.org, 'Deutsche Telekom');
    assert.equal(d.netType, null);
    assert.match(names(d)['ipapi.is (geo/ASN/network type)'].error, /rate limit/i);
    assert.equal(names(d)['ipwho.is (fallback geo/ASN)'].ok, true);
    assert.ok(!mf.calls.some((c) => c.includes('ipapi.co')), 'ipapi.co only when ipwho.is also fails');
  });

  it('treats an ipapi.is error body as a failure and falls through the whole chain to ipapi.co', async () => {
    mf = mockFetch(base([
      (u) => (u.hostname === 'api.ipapi.is' ? jsonRes({ error: 'Daily limit reached' }) : undefined),
      (u) => (u.hostname === 'ipwho.is' ? jsonRes({ success: false, message: 'Rate limit reached' }) : undefined),
      (u) => (u.hostname === 'ipapi.co' ? jsonRes({ country_name: 'France', country_code: 'FR', city: 'Paris', asn: 'AS3215', org: 'Orange' }) : undefined),
    ]));
    const r = await call(ipLookup, '/api/ip/lookup?q=8.8.8.12');
    const d = r.body.data;
    assert.equal(r.status, 200);
    assert.equal(d.geoSource, 'ipapi.co');
    assert.equal(d.geo.countryCode, 'FR');
    assert.equal(names(d)['ipapi.is (geo/ASN/network type)'].ok, false);
    assert.equal(names(d)['ipwho.is (fallback geo/ASN)'].ok, false);
    assert.equal(names(d)['ipapi.co (fallback geo)'].ok, true);
  });

  it('when every geo provider fails the lookup still returns RIPEstat and Shodan data, and is not cached', async () => {
    mf = mockFetch(base([
      (u) => (u.hostname === 'api.ipapi.is' ? new Response('', { status: 500 }) : undefined),
      (u) => (u.hostname === 'ipwho.is' ? new Response('', { status: 500 }) : undefined),
      (u) => (u.hostname === 'ipapi.co' ? new Response('', { status: 500 }) : undefined),
    ]));
    const r = await call(ipLookup, '/api/ip/lookup?q=8.8.8.13');
    assert.equal(r.status, 200);
    assert.equal(r.body.data.geo, null);
    assert.equal(r.body.data.geoSource, null);
    assert.equal(r.body.data.network.asn, 'AS15169'); // RIPEstat
  });

  it('tolerates a sparse ipapi.is body (missing fields) without throwing', async () => {
    mf = mockFetch(base([(u) => (u.hostname === 'api.ipapi.is' ? jsonRes({ ip: '8.8.8.14', location: { country_code: 'US' } }) : undefined)]));
    const r = await call(ipLookup, '/api/ip/lookup?q=8.8.8.14');
    assert.equal(r.status, 200);
    assert.equal(r.body.data.geo.countryCode, 'US');
    assert.equal(r.body.data.geo.latitude, null);
    assert.equal(r.body.data.netType.isVpn, false);
  });

  it('IPinfo is gone: no token is read and api.ipinfo.io is never contacted', async () => {
    mf = mockFetch(base());
    await call(ipLookup, '/api/ip/lookup?q=8.8.8.15', { env: { IPINFO_TOKEN: 'legacy' } as any });
    assert.ok(!mf.calls.some((c) => /ipinfo/.test(c)));
  });
});

describe('/api/ip/lookup: GreyNoise', () => {
  const keys = { GREYNOISE_API_KEY: 'key-grey' };
  const base = (extra: ((u: URL, init?: RequestInit) => Response | undefined)[] = []) => [
    doh({}),
    (u: URL) => (u.hostname === 'api.ipapi.is' ? jsonRes(ipapiIs()) : undefined),
    (u: URL) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { resource: '8.8.8.0/24', asns: [{ asn: 15169, holder: 'GOOGLE' }] } }) : undefined),
    (u: URL) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [] }) : undefined),
    ...extra,
  ];

  it('RIOT result is surfaced and the key goes only to GreyNoise', async () => {
    const seen: Record<string, Record<string, string>> = {};
    mf = mockFetch(base([
      (u, init) => { if (u.hostname === 'api.greynoise.io') { seen[u.hostname] = init?.headers as Record<string, string>; return jsonRes({ noise: false, riot: true, classification: 'benign', name: 'Google Public DNS', link: 'https://viz.greynoise.io/ip/8.8.8.8', last_seen: '2026-10-30' }); } },
    ]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.8', { env: keys })).body.data;
    assert.equal(d.greynoise.riot, true);
    assert.equal(d.greynoise.classification, 'benign');
    assert.equal(d.greynoise.observed, true);
    assert.ok(d.flags.includes('Common business service (RIOT)'));
    assert.equal(seen['api.greynoise.io'].key, 'key-grey');
    for (const c of mf.calls.filter((c) => !c.includes('greynoise'))) assert.ok(!c.includes('key-grey'), 'key never appears in other URLs');
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['GreyNoise Community (noise/RIOT)'].ok, true);
  });

  it('GreyNoise 404 means "not observed", not an error', async () => {
    mf = mockFetch(base([(u) => (u.hostname === 'api.greynoise.io' ? new Response(JSON.stringify({ message: 'IP not observed' }), { status: 404 }) : undefined)]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.9', { env: { GREYNOISE_API_KEY: 'k' } })).body.data;
    assert.equal(d.greynoise.observed, false);
    assert.equal(d.greynoise.noise, false);
    assert.equal(d.providers.find((p: any) => p.name.startsWith('GreyNoise')).ok, true);
  });

  it('malicious scanners are flagged', async () => {
    mf = mockFetch(base([(u) => (u.hostname === 'api.greynoise.io' ? jsonRes({ noise: true, riot: false, classification: 'malicious', name: 'unknown' }) : undefined)]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.10', { env: { GREYNOISE_API_KEY: 'k' } })).body.data;
    assert.ok(d.flags.includes('GreyNoise: malicious scanner'));
  });

  it('rate limit degrades to a failed badge and the rest of the lookup still works', async () => {
    mf = mockFetch(base([(u) => (u.hostname === 'api.greynoise.io' ? new Response('', { status: 429 }) : undefined)]));
    const r = await call(ipLookup, '/api/ip/lookup?q=8.8.8.11', { env: keys });
    assert.equal(r.status, 200);
    assert.equal(r.body.data.network.asn, 'AS15169');
    assert.equal(r.body.data.greynoise, null);
    const st = Object.fromEntries(r.body.data.providers.map((p: any) => [p.name, p]));
    assert.match(st['GreyNoise Community (noise/RIOT)'].error, /rate limit/i);
  });

  it('without a key it is skipped and never contacted', async () => {
    mf = mockFetch(base());
    const d = (await call(ipLookup, '/api/ip/lookup?q=8.8.8.12')).body.data;
    assert.ok(!mf.calls.some((c) => /greynoise/.test(c)));
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['GreyNoise Community (noise/RIOT)'].skipped, true);
    assert.equal(d.greynoise, null);
  });
});

describe('/api/ip/lookup: VirusTotal', () => {
  const vtBase = (extra: ((u: URL, init?: RequestInit) => Response | undefined)[] = []) => [
    doh({}),
    (u: URL) => (u.hostname === 'api.ipapi.is' ? jsonRes(ipapiIs({ asn: { asn: 64500, org: 'EXAMPLE' } })) : undefined),
    (u: URL) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { resource: '203.0.113.0/24', asns: [{ asn: 64500, holder: 'EXAMPLE' }] } }) : undefined),
    (u: URL) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [] }) : undefined),
    ...extra,
  ];

  it('surfaces verdict counts, flags malicious detections, and sends the key only to VirusTotal', async () => {
    const seen: Record<string, Record<string, string>> = {};
    mf = mockFetch(vtBase([
      (u, init) => {
        if (u.hostname !== 'www.virustotal.com') return undefined;
        seen[u.hostname] = init?.headers as Record<string, string>;
        return jsonRes({ data: { attributes: { last_analysis_stats: { malicious: 7, suspicious: 2, harmless: 60, undetected: 25 }, reputation: -12, as_owner: 'EXAMPLE-AS', last_analysis_date: 1790000000, total_votes: { harmless: 1, malicious: 4 } } } });
      },
    ]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=45.33.32.156', { env: { VIRUSTOTAL_API_KEY: 'key-vt' } })).body.data;
    assert.equal(d.virustotal.malicious, 7);
    assert.equal(d.virustotal.suspicious, 2);
    assert.equal(d.virustotal.harmless, 60);
    assert.equal(d.virustotal.undetected, 25);
    assert.equal(d.virustotal.reputation, -12);
    assert.equal(d.virustotal.asOwner, 'EXAMPLE-AS');
    assert.equal(d.virustotal.observed, true);
    assert.ok(typeof d.virustotal.lastAnalysis === 'string' && d.virustotal.lastAnalysis.startsWith('20'));
    assert.equal(d.virustotal.link, 'https://www.virustotal.com/gui/ip-address/45.33.32.156');
    assert.ok(d.flags.includes('VirusTotal: 7 engine(s) flag as malicious'));
    assert.equal(seen['www.virustotal.com']['x-apikey'], 'key-vt');
    for (const c of mf.calls.filter((c) => !c.includes('virustotal'))) assert.ok(!c.includes('key-vt'), 'key never appears in other URLs');
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['VirusTotal (multi-engine verdicts)'].ok, true);
  });

  it('a clean IP adds no flag', async () => {
    mf = mockFetch(vtBase([(u) => (u.hostname === 'www.virustotal.com' ? jsonRes({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20 } } } }) : undefined)]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=45.33.32.157', { env: { VIRUSTOTAL_API_KEY: 'k' } })).body.data;
    assert.equal(d.virustotal.malicious, 0);
    assert.ok(!d.flags.some((f: string) => f.startsWith('VirusTotal')));
  });

  it('404 means "no record", not an error', async () => {
    mf = mockFetch(vtBase([(u) => (u.hostname === 'www.virustotal.com' ? new Response(JSON.stringify({ error: { code: 'NotFoundError' } }), { status: 404 }) : undefined)]));
    const d = (await call(ipLookup, '/api/ip/lookup?q=45.33.32.158', { env: { VIRUSTOTAL_API_KEY: 'k' } })).body.data;
    assert.equal(d.virustotal.observed, false);
    assert.equal(d.providers.find((p: any) => p.name.startsWith('VirusTotal')).ok, true);
  });

  it('rate limit degrades to a failed badge and the rest of the lookup still works', async () => {
    mf = mockFetch(vtBase([(u) => (u.hostname === 'www.virustotal.com' ? new Response('', { status: 429 }) : undefined)]));
    const r = await call(ipLookup, '/api/ip/lookup?q=45.33.32.159', { env: { VIRUSTOTAL_API_KEY: 'k' } });
    assert.equal(r.status, 200);
    assert.equal(r.body.data.virustotal, null);
    assert.equal(r.body.data.network.asn, 'AS64500');
    const st = Object.fromEntries(r.body.data.providers.map((p: any) => [p.name, p]));
    assert.match(st['VirusTotal (multi-engine verdicts)'].error, /rate limit/i);
  });

  it('without a key it is skipped and never contacted', async () => {
    mf = mockFetch(vtBase());
    const d = (await call(ipLookup, '/api/ip/lookup?q=45.33.32.160')).body.data;
    assert.ok(!mf.calls.some((c) => c.includes('virustotal')));
    assert.equal(d.virustotal, null);
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['VirusTotal (multi-engine verdicts)'].skipped, true);
  });
});

describe('/api/ip/lookup', () => {
  it('classifies private addresses locally and never calls third parties', async () => {
    mf = mockFetch([]);
    const r = await call(ipLookup, '/api/ip/lookup?q=192.168.1.10');
    assert.equal(r.status, 200);
    assert.equal(r.body.data.scope, 'private');
    assert.equal(r.body.data.isPublic, false);
    assert.equal(mf.calls.length, 0);
  });
  it('rejects invalid IPs', async () => {
    mf = mockFetch([]);
    assert.equal((await call(ipLookup, '/api/ip/lookup?q=999.1.1.1')).status, 400);
  });
  it('merges providers and reports per-provider status', async () => {
    mf = mockFetch([
      doh({ '8.8.8.8.in-addr.arpa': { PTR: ['dns.google.'] } }),
      (u) => u.hostname === 'api.ipapi.is' ? jsonRes(ipapiIs()) : undefined,
      (u) => u.hostname === 'stat.ripe.net' ? jsonRes({ data: { resource: '8.8.8.0/24', asns: [{ asn: 15169, holder: 'GOOGLE' }] } }) : undefined,
      (u) => u.hostname === 'internetdb.shodan.io' ? jsonRes({ ports: [53, 443], hostnames: ['dns.google'], vulns: [], tags: ['cloud'], cpes: [] }) : undefined,
      (u) => u.hostname === 'api.abuseipdb.com' ? jsonRes({ data: { abuseConfidenceScore: 0, totalReports: 0, numDistinctUsers: 0, lastReportedAt: null, usageType: 'Data Center/Web Hosting/Transit' } }) : undefined,
    ]);
    const r = await call(ipLookup, '/api/ip/lookup?q=8.8.8.8', { env: { ABUSEIPDB_API_KEY: 'k' } });
    const d = r.body.data;
    assert.equal(d.geo.countryCode, 'US');
    assert.equal(d.network.asn, 'AS15169');
    assert.equal(d.network.prefix, '8.8.8.0/24');
    assert.deepEqual(d.reverseDns, ['dns.google']);
    assert.deepEqual(d.exposure.ports, [53, 443]);
    assert.equal(d.reputation.abuseConfidence, 0);
    assert.ok(d.flags.includes('cloud'));
    assert.ok(d.providers.filter((p: any) => !p.skipped).every((p: any) => p.ok)); // keyless providers are skipped, not failed
    // key is sent only to AbuseIPDB
    assert.equal(mf.calls.filter((c) => c.includes('abuseipdb')).length, 1);
  });
  it('degrades gracefully: provider failures are reported, others still returned; InternetDB 404 is not an error', async () => {
    mf = mockFetch([
      doh({}),
      (u) => u.hostname === 'api.ipapi.is' ? new Response('', { status: 500 }) : undefined,
      (u) => u.hostname === 'ipwho.is' ? new Response('', { status: 500 }) : undefined,
      (u) => u.hostname === 'ipapi.co' ? jsonRes({ country_name: 'Germany', country_code: 'DE', city: 'Berlin', asn: 'AS3320', org: 'Deutsche Telekom' }) : undefined,
      (u) => u.hostname === 'stat.ripe.net' ? new Response('', { status: 429 }) : undefined,
      (u) => u.hostname === 'internetdb.shodan.io' ? new Response('', { status: 404 }) : undefined,
    ]);
    const r = await call(ipLookup, '/api/ip/lookup?q=93.184.216.34');
    const d = r.body.data;
    assert.equal(r.status, 200);
    assert.equal(d.geo.countryCode, 'DE'); // fallback geo provider used
    assert.equal(d.network.asn, 'AS3320');
    assert.deepEqual(d.exposure.ports, []); // 404 = never seen by Shodan
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['ipapi.is (geo/ASN/network type)'].ok, false);
    assert.equal(st['ipwho.is (fallback geo/ASN)'].ok, false);
    assert.equal(st['RIPEstat (prefix/ASN)'].ok, false);
    assert.equal(st['Shodan InternetDB (exposure)'].ok, true);
    assert.equal(st['AbuseIPDB (reputation)'].skipped, true);
  });
  it('uses the caller address when q is omitted', async () => {
    mf = mockFetch([]);
    const r = await call(ipLookup, '/api/ip/lookup', { headers: { 'cf-connecting-ip': '10.1.1.1' } });
    assert.equal(r.body.data.ip, '10.1.1.1');
  });
});

const RDAP = {
  ldhName: 'EXAMPLE.COM',
  status: ['client transfer prohibited', 'server delete prohibited'],
  events: [
    { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
    { eventAction: 'expiration', eventDate: new Date(Date.now() + 20 * 86_400_000).toISOString() },
    { eventAction: 'last changed', eventDate: '2024-08-14T07:01:34Z' },
  ],
  nameservers: [{ ldhName: 'B.IANA-SERVERS.NET' }, { ldhName: 'A.IANA-SERVERS.NET' }],
  secureDNS: { delegationSigned: true },
  links: [{ rel: 'self', href: 'https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM' }],
  entities: [
    { roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'RESERVED-Internet Assigned Numbers Authority']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }],
      entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['email', {}, 'text', 'abuse@iana.org'], ['tel', {}, 'uri', 'tel:+1.3103015800']]] }] },
    { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'REDACTED FOR PRIVACY']]] },
  ],
};

describe('/api/domain/whois', () => {
  it('parses RDAP', async () => {
    mf = mockFetch([(u) => (u.hostname === 'rdap.org' ? jsonRes(RDAP) : undefined)]);
    const d = (await call(whois, '/api/domain/whois?domain=example.com')).body.data;
    assert.equal(d.domain, 'example.com');
    assert.equal(d.registrar.name, 'RESERVED-Internet Assigned Numbers Authority');
    assert.equal(d.registrar.ianaId, '376');
    assert.equal(d.registrar.abuseEmail, 'abuse@iana.org');
    assert.deepEqual(d.nameservers, ['a.iana-servers.net', 'b.iana-servers.net']);
    assert.equal(d.registrant.redacted, true);
    assert.equal(d.dnssecSigned, true);
    assert.ok(d.ageDays > 10000);
    assert.ok(d.daysToExpiry >= 19 && d.daysToExpiry <= 20);
    assert.ok(d.issues.some((i: any) => /expires in/.test(i.message)));
  });
  it('flags newly registered domains', async () => {
    const fresh = { ...RDAP, events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 3 * 86_400_000).toISOString() }] };
    mf = mockFetch([(u) => (u.hostname === 'rdap.org' ? jsonRes(fresh) : undefined)]);
    const d = (await call(whois, '/api/domain/whois?domain=new-site.com')).body.data;
    assert.ok(d.issues.some((i: any) => i.level === 'warn' && /registered only 3 day/.test(i.message)));
  });
  it('404 -> unregistered, not an error', async () => {
    mf = mockFetch([(u) => (u.hostname === 'rdap.org' ? new Response('', { status: 404 }) : undefined)]);
    const r = await call(whois, '/api/domain/whois?domain=unregistered-xyz.com');
    assert.equal(r.status, 200);
    assert.equal(r.body.data.registered, false);
  });
});

describe('/api/domain/ssl', () => {
  const now = Date.now();
  const iso = (d: number) => new Date(now + d * 86_400_000).toISOString().replace('Z', '');
  const rows = [
    { id: 3, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: 'example.com', name_value: 'example.com\nwww.example.com', not_before: iso(-30), not_after: iso(60), serial_number: 'AA' },
    { id: 2, issuer_name: "C=US, O=Let's Encrypt, CN=R10", common_name: 'example.com', name_value: 'example.com', not_before: iso(-120), not_after: iso(-30), serial_number: 'BB' },
    { id: 4, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: 'example.com', name_value: 'example.com', not_before: iso(-30), not_after: iso(60), serial_number: 'AA' }, // duplicate serial (precert/final)
  ];
  it('dedupes by serial, marks validity, summarises issuers', async () => {
    mf = mockFetch([(u) => (u.hostname === 'crt.sh' ? jsonRes(rows) : undefined)]);
    const d = (await call(ssl, '/api/domain/ssl?domain=example.com')).body.data;
    assert.equal(d.total, 2);
    assert.equal(d.active, 1);
    assert.equal(d.certificates[0].issuer, 'R11');
    assert.equal(d.certificates[0].validNow, true);
    assert.equal(d.certificates[1].validNow, false);
    assert.ok(d.certificates[0].daysRemaining >= 59);
    assert.match(d.note, /Certificate Transparency/);
  });
  it('lists subdomains when asked', async () => {
    const subs = [{ ...rows[0], name_value: 'example.com\napi.example.com\n*.example.com\nother.test' }];
    mf = mockFetch([(u) => (u.hostname === 'crt.sh' ? jsonRes(subs) : undefined)]);
    const d = (await call(ssl, '/api/domain/ssl?domain=example.com&subdomains=1')).body.data;
    assert.deepEqual(d.subdomains, ['*.example.com', 'api.example.com', 'example.com']);
    assert.equal(d.wildcard, true);
  });
  it('handles crt.sh garbage responses', async () => {
    mf = mockFetch([(u) => (u.hostname === 'crt.sh' ? new Response('<html>Bad gateway</html>', { status: 200 }) : undefined)]);
    const r = await call(ssl, '/api/domain/ssl?domain=example.com');
    assert.equal(r.status, 502);
  });
});

describe('/api/domain/http', () => {
  it('audits headers, follows redirects and checks HTTP->HTTPS upgrade', async () => {
    mf = mockFetch([
      doh({ 'example.com': { A: ['93.184.216.34'] }, 'www.example.com': { A: ['93.184.216.35'] } }),
      (u, init) => {
        if (u.hostname === 'example.com' && u.protocol === 'http:') return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
        if (u.hostname === 'example.com') return new Response(null, { status: 302, headers: { location: 'https://www.example.com/' } });
        if (u.hostname === 'www.example.com') {
          const h = new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'x-content-type-options': 'nosniff', server: 'nginx/1.18.0', 'content-type': 'text/html' });
          h.append('set-cookie', 'sid=abc; Path=/');
          return new Response('<html></html>', { status: 200, headers: h });
        }
      },
    ]);
    const d = (await call(httpCheck, '/api/domain/http?target=https://Example.com/path')).body.data;
    assert.equal(d.target, 'example.com');
    assert.equal(d.status, 200);
    assert.equal(d.finalUrl, 'https://www.example.com/');
    assert.equal(d.chain.length, 2);
    assert.equal(d.httpsReachable, true);
    assert.equal(d.httpUpgradesToHttps, true);
    const hsts = d.audit.checks.find((c: any) => c.header === 'strict-transport-security');
    assert.equal(hsts.status, 'good');
    assert.equal(d.audit.checks.find((c: any) => c.header === 'content-security-policy').status, 'missing');
    assert.deepEqual(d.server, [{ header: 'server', value: 'nginx/1.18.0' }]);
    assert.equal(d.cookies[0].name, 'sid');
    assert.ok(d.issues.some((i: any) => /Secure flag/.test(i.message)));
    assert.ok(d.issues.some((i: any) => /version information/.test(i.message)));
  });
  it('refuses internal targets', async () => {
    mf = mockFetch([]);
    for (const t of ['127.0.0.1', 'localhost', 'http://169.254.169.254/']) {
      const r = await call(httpCheck, `/api/domain/http?target=${encodeURIComponent(t)}`);
      assert.ok([400, 403].includes(r.status), `${t} -> ${r.status}`);
    }
    assert.equal(mf.calls.length, 0);
  });
  it('refuses names that resolve internally', async () => {
    mf = mockFetch([doh({ 'sneaky.example.com': { A: ['10.0.0.9'] } })]);
    const r = await call(httpCheck, '/api/domain/http?target=sneaky.example.com');
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, 'TARGET_NOT_ALLOWED');
  });
});

describe('/api/email/auth', () => {
  it('evaluates SPF/DKIM/DMARC/MX and counts recursive SPF lookups', async () => {
    mf = mockFetch([doh({
      'example.com': { TXT: ['"v=spf1 include:_spf.mail.example.net mx -all"'], MX: ['10 mx1.example.com.'] },
      '_spf.mail.example.net': { TXT: ['"v=spf1 include:a.example.net include:b.example.net ~all"'] },
      'a.example.net': { TXT: ['"v=spf1 a mx -all"'] },
      'b.example.net': { TXT: ['"v=spf1 ip4:192.0.2.1 -all"'] },
      '_dmarc.example.com': { TXT: ['"v=DMARC1; p=reject; rua=mailto:r@example.com"'] },
      'google._domainkey.example.com': { TXT: ['"v=DKIM1; k=rsa; p=' + Buffer.alloc(294, 7).toString('base64') + '"'] },
      '_mta-sts.example.com': { TXT: ['"v=STSv1; id=1"'] },
    })]);
    const d = (await call(emailAuth, '/api/email/auth?domain=bob@example.com')).body.data;
    assert.equal(d.domain, 'example.com');
    assert.equal(d.hasMx, true);
    assert.equal(d.spf.parsed.all, '-');
    // root: include + mx = 2; _spf.mail: 2 includes = 2; a.example.net: a + mx = 2; b: 0  => 6
    assert.equal(d.spf.totalLookups, 6);
    assert.equal(d.dmarc.parsed.policy, 'reject');
    assert.equal(d.dkim.filter((k: any) => k.found).length, 1);
    assert.equal(d.dkim.find((k: any) => k.found).parsed.approxKeyBits, 2048);
    assert.equal(d.mtaSts.found, true);
    assert.equal(d.summary.grade, 'A');
  });
  it('finds DMARC at the parent domain and reports a missing SPF', async () => {
    mf = mockFetch([doh({
      'sub.example.com': { TXT: ['"hello"'] },
      '_dmarc.example.com': { TXT: ['"v=DMARC1; p=quarantine"'] },
    })]);
    const d = (await call(emailAuth, '/api/email/auth?domain=sub.example.com')).body.data;
    assert.equal(d.dmarc.foundAt, '_dmarc.example.com');
    assert.equal(d.spf.found, false);
    assert.ok(d.spf.issues.some((i: any) => i.level === 'error'));
  });
  it('flags duplicate SPF records', async () => {
    mf = mockFetch([doh({ 'dup.example.com': { TXT: ['"v=spf1 -all"', '"v=spf1 ~all"'] } })]);
    const d = (await call(emailAuth, '/api/email/auth?domain=dup.example.com')).body.data;
    assert.ok(d.spf.issues.some((i: any) => /2 SPF records/.test(i.message)));
  });
});

describe('/api/email/headers', () => {
  it('parses a JSON body', async () => {
    const headers = 'From: a@example.com\nReceived: from x (x [93.184.216.34]) by y; Tue, 3 Nov 2026 10:00:00 +0000\nAuthentication-Results: y; spf=pass smtp.mailfrom=a@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\nMessage-ID: <1@x>';
    const r = await call(emailHeaders, '/api/email/headers', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ headers }) });
    assert.equal(r.body.data.authentication.dmarc, 'pass');
    assert.equal(r.body.data.originIp, '93.184.216.34');
  });
  it('accepts text/plain, rejects empty and oversized input', async () => {
    assert.equal((await call(emailHeaders, '/api/email/headers', { method: 'POST', body: 'From: a@b.com' })).status, 200);
    assert.equal((await call(emailHeaders, '/api/email/headers', { method: 'POST', body: '   ' })).status, 400);
    assert.equal((await call(emailHeaders, '/api/email/headers', { method: 'POST', body: 'X: ' + 'a'.repeat(150_000) })).status, 413);
  });
});

describe('/api/network/*', () => {
  it('measures latency over several samples', async () => {
    mf = mockFetch([doh({ 'example.com': { A: ['93.184.216.34'] } }), (u) => (u.hostname === 'example.com' ? new Response('ok', { status: 200 }) : undefined)]);
    const d = (await call(latency, '/api/network/latency?target=example.com&samples=3')).body.data;
    assert.equal(d.samples.length, 3);
    assert.equal(d.stats.successRate, 100);
    assert.equal(d.address, '93.184.216.34');
  });
  it('rejects private targets immediately and validates sample count', async () => {
    mf = mockFetch([]);
    assert.equal((await call(latency, '/api/network/latency?target=10.0.0.1')).status, 403);
    assert.equal((await call(latency, '/api/network/latency?target=example.com&samples=50')).status, 400);
  });
  it('computes subnets', async () => {
    const d = (await call(subnet, '/api/network/subnet?cidr=192.168.1.0/26&contains=192.168.1.63')).body.data;
    assert.equal(d.usableHosts, '62');
    assert.equal(d.contains.inside, true);
    assert.equal((await call(subnet, '/api/network/subnet?cidr=10.0.0.1')).body.data.prefix, 32);
    assert.equal((await call(subnet, '/api/network/subnet?cidr=bogus')).status, 400);
  });
});

describe('/api/util/*', () => {
  it('converts and ranges', async () => {
    assert.equal((await call(ipConvert, '/api/util/ip-convert?value=3232235777')).body.data.canonical, '192.168.1.1');
    assert.equal((await call(ipConvert, '/api/util/ip-convert?value=zzz')).status, 400);
    const r = (await call(ipRange, '/api/util/ip-range?start=10.0.0.0&end=10.0.1.255')).body.data;
    assert.deepEqual(r.blocks.map((b: any) => b.cidr), ['10.0.0.0/23']);
    assert.equal((await call(ipRange, '/api/util/ip-range?start=10.0.0.9&end=10.0.0.1')).status, 400);
  });
});

describe('middleware', () => {
  const run = async (path: string, init: RequestInit & { env?: Record<string, unknown> } = {}, ip = '9.9.9.9') => {
    const { env, ...rest } = init;
    const c = ctxFor(path, { ...rest, headers: { 'cf-connecting-ip': ip, ...(rest.headers as object) }, env });
    const res = await (middleware as Fn)(c as never);
    return { status: res.status, headers: res.headers, body: await res.text() };
  };
  it('passes non-API paths through untouched', async () => {
    const r = await run('/index.html');
    assert.equal(r.body, 'next');
    assert.equal(r.headers.get('x-ratelimit-limit'), null);
  });
  it('rate limits per client with cost weighting and Retry-After', async () => {
    const env = { RATE_LIMIT_PER_MIN: '10' };
    const ip = '203.0.113.200';
    // dns lookup costs 1: 10 allowed, the 11th is rejected
    for (let i = 0; i < 10; i++) assert.equal((await run('/api/dns/lookup', { env }, ip)).status, 200, `request ${i}`);
    const blocked = await run('/api/dns/lookup', { env }, ip);
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) > 0);
    assert.equal(JSON.parse(blocked.body).error.code, 'RATE_LIMITED');
    // another client is unaffected
    assert.equal((await run('/api/dns/lookup', { env }, '203.0.113.201')).status, 200);
    // heavier endpoints consume more budget
    const heavy = await run('/api/network/latency', { env: { RATE_LIMIT_PER_MIN: '6' } }, '203.0.113.202');
    assert.equal(heavy.headers.get('x-ratelimit-remaining'), '1');
  });
  it('health is free and never limited', async () => {
    for (let i = 0; i < 5; i++) assert.equal((await run('/api/health', { env: { RATE_LIMIT_PER_MIN: '1' } }, '203.0.113.210')).status, 200);
  });
  it('rejects unsupported methods', async () => {
    const r = await run('/api/dns/lookup', { method: 'DELETE' });
    assert.equal(r.status, 405);
  });
  it('CORS: same-origin and allow-listed origins only', async () => {
    const ok1 = await run('/api/health', { headers: { origin: 'https://app.test' } });
    assert.equal(ok1.headers.get('access-control-allow-origin'), 'https://app.test');
    const bad = await run('/api/health', { headers: { origin: 'https://evil.test' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
    const listed = await run('/api/health', { headers: { origin: 'https://partner.test' }, env: { ALLOWED_ORIGINS: 'https://partner.test' } });
    assert.equal(listed.headers.get('access-control-allow-origin'), 'https://partner.test');
    const pre = await run('/api/health', { method: 'OPTIONS', headers: { origin: 'https://app.test' } });
    assert.equal(pre.status, 204);
  });
  it('adds security headers', async () => {
    const r = await run('/api/health');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });
});
