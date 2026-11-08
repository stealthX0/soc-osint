import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { evaluateSpf, type DnsReader } from '../worker/_lib/spfEval';
import { analyzeIdentity } from '../shared/phishing/brand';
import { parseSubmission } from '../shared/phishing/parse';
import { convertAuth, convertDomain, convertUserCheck, convertIp, convertSpf, isPlatformDomain, planSenderChecks, sharedProviderOf, type SenderCheckResponse } from '../shared/phishing/sender';
import type { EmailAuth, EmailCheck, IpLookup, WhoisResult } from '../shared/types';
import { doh, jsonRes, mockFetch } from './helpers';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';

const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
const post = async (path: string, body: unknown, e: Record<string, unknown> = {}) => {
  const res = await worker.fetch(new Request(`https://app.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.7' }, body: JSON.stringify(body) }), { ...(env as object), ...e } as never, exec);
  return { res, json: (await res.json()) as { ok: boolean; data?: any; error?: { code: string; message: string } } };
};

const fakeDns = (table: Record<string, Partial<Record<'txt' | 'a' | 'aaaa' | 'mx', string[]>>>): DnsReader => ({
  txt: async (n) => table[n]?.txt ?? [],
  a: async (n) => table[n]?.a ?? [],
  aaaa: async (n) => table[n]?.aaaa ?? [],
  mx: async (n) => table[n]?.mx ?? [],
});

describe('independent SPF evaluation', () => {
  const dns = fakeDns({
    'corp.example': { txt: ['v=spf1 ip4:203.0.113.0/24 include:_spf.mail.example mx -all'], mx: ['mx1.corp.example'] },
    '_spf.mail.example': { txt: ['v=spf1 ip4:198.51.100.0/25 ip6:2001:db8::/32 ~all'] },
    'mx1.corp.example': { a: ['192.0.2.55'] },
    'loop.example': { txt: ['v=spf1 include:loop.example -all'] },
    'soft.example': { txt: ['v=spf1 ~all'] },
    'redir.example': { txt: ['v=spf1 redirect=corp.example'] },
    'none.example': { txt: ['hello'] },
  });
  it('passes on a direct ip4 match', async () => {
    const r = await evaluateSpf('corp.example', '203.0.113.9', dns);
    assert.equal(r.result, 'pass');
    assert.equal(r.matched, 'ip4:203.0.113.0/24');
  });
  it('follows include and reports the path', async () => {
    const r = await evaluateSpf('corp.example', '198.51.100.20', dns);
    assert.equal(r.result, 'pass');
    assert.match(r.matched!, /include:_spf\.mail\.example/);
  });
  it('matches the mx mechanism and IPv6', async () => {
    assert.equal((await evaluateSpf('corp.example', '192.0.2.55', dns)).result, 'pass');
    assert.equal((await evaluateSpf('corp.example', '2001:db8::1', dns)).result, 'pass');
  });
  it('fails on -all, softfails on ~all and follows redirect', async () => {
    assert.equal((await evaluateSpf('corp.example', '45.33.32.156', dns)).result, 'fail');
    assert.equal((await evaluateSpf('soft.example', '45.33.32.156', dns)).result, 'softfail');
    assert.equal((await evaluateSpf('redir.example', '45.33.32.156', dns)).result, 'fail');
  });
  it('returns none for a domain without SPF and permerror on loops', async () => {
    assert.equal((await evaluateSpf('none.example', '1.2.3.4', dns)).result, 'none');
    assert.equal((await evaluateSpf('loop.example', '1.2.3.4', dns)).result, 'permerror');
  });
  it('enforces the 10 lookup limit', async () => {
    const inc = Array.from({ length: 11 }, (_, i) => `include:i${i}.example`).join(' ');
    const table: Record<string, { txt: string[] }> = { 'big.example': { txt: [`v=spf1 ${inc} -all`] } };
    for (let i = 0; i < 11; i++) table[`i${i}.example`] = { txt: ['v=spf1 -all'] };
    assert.equal((await evaluateSpf('big.example', '1.2.3.4', fakeDns(table))).result, 'permerror');
  });
  it('reports DNS failures as temperror', async () => {
    const r = await evaluateSpf('x.example', '1.2.3.4', { ...fakeDns({}), txt: async () => { throw new Error('timeout'); } });
    assert.equal(r.result, 'temperror');
  });
});

describe('sender identity analysis', () => {
  const ids = (a: Parameters<typeof analyzeIdentity>[0]) => analyzeIdentity(a).map((f) => f.id);
  it('flags a look-alike of a known brand', () => {
    assert.ok(ids({ fromDomain: 'paypa1.com', display: null, claimedDomain: null }).includes('sender_domain_lookalike'));
    assert.ok(ids({ fromDomain: 'paypal-secure-login.example', display: null, claimedDomain: null }).includes('sender_domain_brand_misuse'));
  });
  it('flags a display name that uses a brand the domain does not own, higher for free mail', () => {
    const f = analyzeIdentity({ fromDomain: 'gmail.com', display: 'PayPal Support', claimedDomain: null }).find((x) => x.id === 'display_name_brand_spoof')!;
    assert.equal(f.severity, 'high');
    assert.equal(analyzeIdentity({ fromDomain: 'paypal.com', display: 'PayPal Support', claimedDomain: null }).length, 0);
  });
  it('flags executive / IT titles sent from a consumer mailbox', () => {
    assert.ok(ids({ fromDomain: 'outlook.com', display: 'IT Helpdesk', claimedDomain: null }).includes('role_impersonation_freemail'));
    assert.ok(!ids({ fromDomain: 'corp.example', display: 'IT Helpdesk', claimedDomain: null }).includes('role_impersonation_freemail'));
  });
  it('flags a sender domain that imitates the claimed organisation', () => {
    assert.ok(ids({ fromDomain: 'contoso-billing.example', display: null, claimedDomain: 'contoso.com' }).includes('sender_domain_lookalikes_claimed_org'));
    assert.ok(!ids({ fromDomain: 'unrelated.example', display: null, claimedDomain: 'contoso.com' }).includes('sender_domain_lookalikes_claimed_org'));
  });
  it('flags a homograph sender domain', () => {
    assert.ok(ids({ fromDomain: 'xn--pypal-4ve.com', display: null, claimedDomain: null }).includes('sender_domain_homograph'));
  });
  it('is quiet for an ordinary legitimate sender', () => {
    assert.deepEqual(ids({ fromDomain: 'partner.example', display: 'Alice Partner', claimedDomain: null }), []);
  });
});

const ipBase = (over: Partial<IpLookup>): IpLookup => ({
  ip: '45.33.32.156', version: 4, scope: 'global' as never, scopeLabel: 'Public', isPublic: true, ptrName: '', geo: null, network: { asn: 'AS63949', org: 'Akamai Connected Cloud', isp: null, domain: null, prefix: null },
  netType: null, geoSource: null, reverseDns: ['scan.example.net'], exposure: null, reputation: null, pulsedive: null, virustotal: null, flags: [],
  providers: [{ name: 'ipapi.is', ok: true, ms: 5 }], ...over,
});

describe('result converters', () => {
  const req = { check: 'ip' as const, ip: '45.33.32.156', role: 'connecting' as const, trust: 'receiver_reported' as const };
  it('scores abuse reports and VirusTotal detections, and marks them exact for the connecting IP', () => {
    const { findings } = convertIp(req, ipBase({ reputation: { abuseConfidence: 92, totalReports: 120, distinctReporters: 40, lastReportedAt: '2026-11-01T00:00:00Z', usageType: null, isTor: false, isWhitelisted: false }, virustotal: { malicious: 12, suspicious: 1, harmless: 50, undetected: 10, reputation: -5, votesMalicious: 0, votesHarmless: 0, asOwner: null, lastAnalysis: null, link: '', observed: true } }));
    assert.equal(findings.find((f) => f.id === 'sender_ip_abuse_reports')!.severity, 'high');
    assert.equal(findings.find((f) => f.id === 'sender_ip_vt_detections')!.severity, 'high');
    assert.ok(findings.every((f) => f.exactness === 'exact' && f.trust === 'independently_verified'));
  });
  it('does not treat shared mail infrastructure as evidence, and says so', () => {
    const d = ipBase({ network: { asn: 'AS15169', org: 'Google LLC', isp: null, domain: null, prefix: null }, reverseDns: ['mail-sor-f41.google.com'] });
    assert.equal(sharedProviderOf(d), 'Google');
    const { findings } = convertIp(req, d);
    assert.deepEqual(findings.map((f) => f.id), ['sender_infra_shared_provider']);
    assert.equal(findings[0].severity, 'info');
  });
  it('flags a missing PTR and Tor, but only treats the connecting IP as exact', () => {
    const { findings } = convertIp(req, ipBase({ reverseDns: [], netType: { isVpn: false, isProxy: false, isTor: true, isDatacenter: false, isMobile: false, isCrawler: false, isAbuser: false, companyName: null, companyType: null, companyAbuserScore: null, asnAbuserScore: null, datacenter: null, vpnService: null } }));
    assert.ok(findings.some((f) => f.id === 'sender_ip_tor') && findings.some((f) => f.id === 'sender_ip_no_ptr'));
    const claimed = convertIp({ ...req, role: 'claimed_origin' }, ipBase({ reverseDns: [] }));
    assert.equal(claimed.findings.length, 0);
  });
  it('reports a lookup where every provider failed as failed, never clean', () => {
    const r = convertIp(req, ipBase({ providers: [{ name: 'ipapi.is', ok: false, ms: 1, error: 'down' }] }));
    assert.equal(r.check.status, 'failed');
    assert.equal(r.check.result, null);
  });
  it('grades new domains by age', () => {
    const w = (age: number): WhoisResult => ({ domain: 'x.example', registered: true, source: 'rdap', registrar: { name: 'Reg', ianaId: null, url: null, abuseEmail: null, abusePhone: null }, dates: { registered: null, updated: null, expires: null }, ageDays: age, daysToExpiry: 300, status: [], nameservers: [], dnssecSigned: null, rdapUrl: null, issues: [] });
    const r = { check: 'domain' as const, domain: 'x.example', roles: ['from' as const] };
    assert.equal(convertDomain(r, w(3)).findings[0].severity, 'high');
    assert.equal(convertDomain(r, w(20)).findings[0].severity, 'medium');
    assert.equal(convertDomain(r, w(60)).findings[0].severity, 'low');
    assert.equal(convertDomain(r, w(400)).findings.length, 0);
  });
  it('flags DMARC failure against an enforcing policy and an unprotected domain', () => {
    const auth = (policy: string | null, spoofable: boolean, found = true) => ({ domain: 'bank.example', hasMx: true, mx: [], spf: { found: true, records: 1, parsed: null, totalLookups: 1, issues: [] }, dmarc: { found, foundAt: null, parsed: policy ? { policy } : null, issues: [] }, dkim: [], mtaSts: { found: false, record: null }, summary: { spoofable }, providers: [{ name: 'DNS', ok: true, ms: 1 }] }) as unknown as EmailAuth;
    const req2 = { check: 'auth' as const, domain: 'bank.example', role: 'from' as const, reportedDmarc: 'fail' };
    assert.ok(convertAuth(req2, auth('reject', false)).findings.some((f) => f.id === 'dmarc_policy_not_applied'));
    assert.ok(convertAuth({ ...req2, reportedDmarc: 'pass' }, auth('none', true)).findings.some((f) => f.id === 'sender_domain_spoofable'));
  });
  it('compares the independent SPF result with the headers', () => {
    const ev = (result: SenderCheckResponse extends never ? never : 'pass' | 'fail') => ({ domain: 'corp.example', ip: '1.2.3.4', result, matched: result === 'pass' ? 'ip4:1.2.3.0/24' : '-all', lookups: 1, record: 'v=spf1', notes: [] });
    const r = { check: 'spf' as const, domain: 'corp.example', ip: '1.2.3.4', reported: 'pass', trust: 'receiver_reported' as const };
    assert.ok(convertSpf(r, ev('fail')).findings.some((f) => f.id === 'spf_independent_disagrees'));
    assert.ok(convertSpf({ ...r, reported: 'pass' }, ev('pass')).findings.every((f) => f.severity === 'info'));
  });
  it('turns UserCheck data into address-level findings', () => {
    const uc = (over: Partial<EmailCheck>): EmailCheck => ({ email: 'a@evil.example', domain: 'evil.example', domainAgeDays: 400, mx: true, disposable: false, spam: false, publicDomain: false, relayDomain: false, freeSubdomain: false, roleAccount: false, didYouMean: null, spf: null, dmarc: null, providers: [], ...over });
    const req3 = { check: 'usercheck' as const, email: 'a@evil.example', roles: ['from' as const] };
    assert.equal(convertUserCheck(req3, uc({})).findings.length, 0);
    assert.equal(convertUserCheck(req3, uc({ spam: true })).findings[0].id, 'sender_address_spam_domain');
    assert.deepEqual(convertUserCheck(req3, uc({ disposable: true, mx: false, didYouMean: 'a@gmail.com' })).findings.map((f) => f.id).sort(), ['sender_address_disposable', 'sender_address_misspelt_domain', 'sender_address_no_mx']);
    assert.equal(convertUserCheck(req3, uc({ mx: null })).findings.length, 0, 'an unknown MX result is not a finding');
    assert.equal(convertUserCheck({ ...req3, roles: ['reply_to' as const] }, uc({ spam: true })).findings[0].exactness, 'related');
  });
  it('treats platforms and free mail as uninteresting for registration lookups', () => {
    assert.ok(isPlatformDomain('mail.google.com') && isPlatformDomain('gmail.com') && !isPlatformDomain('evil.example'));
  });
});

describe('sender check planning', () => {
  const headers = `Received: from mail.evil.example (mail.evil.example [45.33.32.156]) by mx.google.com with ESMTPS; Tue, 3 Nov 2026 10:04:50 -0800
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@evil.example; dkim=none; dmarc=fail header.from=bank.example
Return-Path: <bounce@evil.example>
From: "Bank" <alerts@bank.example>
Reply-To: help@gmail.com
Subject: x`;
  it('plans IP, domain, DNS, SPF and address checks, bounded and de-duplicated', async () => {
    const r = await parseSubmission({ headers, body: 'hello', sender: { domain: 'bank.example' } });
    const plan = planSenderChecks(r);
    const kinds = plan.requests.map((q) => q.check);
    assert.equal(kinds.filter((k) => k === 'ip').length, 1);
    assert.deepEqual(plan.requests.filter((q) => q.check === 'domain').map((q) => (q as { domain: string }).domain).sort(), ['bank.example', 'evil.example']);
    assert.ok(kinds.includes('spf') && kinds.includes('auth') && kinds.includes('usercheck'));
    assert.ok(!plan.requests.some((q) => q.check === 'domain' && (q as { domain: string }).domain === 'gmail.com'));
  });
  it('always plans the address check when there is a sender address, and notes when there is none', async () => {
    const r = await parseSubmission({ body: 'hello' });
    const plan = planSenderChecks(r);
    assert.ok(!plan.requests.some((q) => q.check === 'usercheck'));
    assert.ok(plan.skipped.some((c) => c.id === 'sender.usercheck' && c.status === 'not_applicable'));
  });
  it('plans nothing risky for a message with no headers and a free-mail sender', async () => {
    const r = await parseSubmission({ body: 'hi', sender: { email: 'x@gmail.com' } });
    const plan = planSenderChecks(r);
    assert.deepEqual(plan.requests, []);
  });
});

describe('POST /api/phishing/sender', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); });

  it('runs an IP check through the existing lookup and returns findings', async () => {
    const m = mockFetch([
      (u) => (u.hostname === 'api.ipapi.is' ? jsonRes({ ip: '45.33.32.156', location: { country: 'United States', country_code: 'US' }, asn: { asn: 63949, org: 'Akamai' }, is_tor: true }) : undefined),
      (u) => (u.hostname === 'stat.ripe.net' ? jsonRes({ data: { asns: [] } }) : undefined),
      (u) => (u.hostname === 'internetdb.shodan.io' ? jsonRes({ detail: 'No information available' }, 404) : undefined),
      doh({}),
    ]);
    restore = m.restore;
    const { json } = await post('/api/phishing/sender', { check: 'ip', ip: '45.33.32.156', role: 'connecting', trust: 'receiver_reported' });
    assert.equal(json.ok, true);
    assert.equal(json.data.checks[0].status, 'complete');
    assert.ok(json.data.findings.some((f: { id: string }) => f.id === 'sender_ip_tor'));
  });

  it('does not send private addresses to third parties', async () => {
    const m = mockFetch([]);
    restore = m.restore;
    const { json } = await post('/api/phishing/sender', { check: 'ip', ip: '10.1.2.3', role: 'supplied' });
    assert.equal(json.data.checks[0].status, 'skipped');
    assert.equal(m.calls.length, 0);
  });

  it('runs the independent SPF re-check over DoH', async () => {
    const m = mockFetch([doh({ 'corp.example': { TXT: ['"v=spf1 ip4:203.0.113.0/24 -all"'] } })]);
    restore = m.restore;
    const { json } = await post('/api/phishing/sender', { check: 'spf', domain: 'corp.example', ip: '203.0.113.9', reported: 'fail', trust: 'receiver_reported' });
    assert.equal(json.data.data.value.result, 'pass');
    assert.ok(json.data.findings.some((f: { id: string }) => f.id === 'spf_independent_pass'));
  });

  it('reports an upstream failure as a failed check with HTTP 200', async () => {
    const m = mockFetch([(u) => (u.hostname === 'api.usercheck.com' ? new Response('nope', { status: 500 }) : undefined)]);
    restore = m.restore;
    const { res, json } = await post('/api/phishing/sender', { check: 'usercheck', email: 'a@evil.example', roles: ['from'] }, { USERCHECK_API_KEY: 'k' });
    assert.equal(res.status, 200);
    assert.equal(json.data.checks[0].status, 'failed');
    assert.deepEqual(json.data.findings, []);
  });

  it('skips the address check, saying why, when UserCheck has no key (nothing is sent anywhere)', async () => {
    const m = mockFetch([]);
    restore = m.restore;
    const { res, json } = await post('/api/phishing/sender', { check: 'usercheck', email: 'a@evil.example', roles: ['from'] });
    assert.equal(res.status, 200);
    assert.equal(json.data.checks[0].status, 'skipped');
    assert.match(json.data.checks[0].detail, /not configured/);
  });

  it('rejects malformed requests', async () => {
    assert.equal((await post('/api/phishing/sender', { check: 'nope' })).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post('/api/phishing/sender', { check: 'ip', ip: 'not-an-ip' })).json.error?.code, 'INVALID_INPUT');
    assert.equal((await post('/api/phishing/sender', { check: 'usercheck', email: 'nope' })).json.error?.code, 'INVALID_INPUT');
  });
});

describe('GET /api/email/usercheck', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); });
  it('normalises the UserCheck response and sends the key only to api.usercheck.com as a bearer token', async () => {
    let seenAuth: string | null = null;
    let seenUrl = '';
    const m = mockFetch([(u, init) => { if (u.hostname !== 'api.usercheck.com') return undefined; seenAuth = new Headers(init?.headers).get('authorization'); seenUrl = u.pathname; return jsonRes({ status: 200, email: 'a@evil.example', domain: 'evil.example', domain_age_in_days: 4, mx: false, disposable: true, spam: true, public_domain: false, relay_domain: false, free_subdomain: false, role_account: false, did_you_mean: null, spf: 'missing', dmarc: 'none' }); }]);
    restore = m.restore;
    const res = await worker.fetch(new Request('https://app.test/api/email/usercheck?email=A@Evil.Example', { headers: { 'cf-connecting-ip': '198.51.100.8' } }), { ...(env as object), USERCHECK_API_KEY: 'secret-key' } as never, exec);
    const j = (await res.json()) as { ok: boolean; data: EmailCheck };
    assert.equal(j.ok, true);
    assert.equal(j.data.email, 'a@evil.example');
    assert.equal(j.data.domainAgeDays, 4);
    assert.equal(j.data.mx, false);
    assert.equal(j.data.disposable, true);
    assert.equal(j.data.spam, true);
    assert.equal(seenAuth, 'Bearer secret-key');
    assert.equal(seenUrl, '/email/a@evil.example');
  });
  it('validates the address', async () => {
    const res = await worker.fetch(new Request('https://app.test/api/email/usercheck?email=nope'), env, exec);
    assert.equal(res.status, 400);
  });
});
