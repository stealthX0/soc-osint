/** IPQualityScore Email Validation: mapping, findings and the sender-stage endpoint. */
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { cleanKey, keyHint, mapIpqs } from '../worker/api/email/ipqs';
import { convertIpqs, labelOf, idOf } from '../shared/phishing/sender';
import { computeVerdict } from '../shared/phishing/verdict';
import { groupOf, POINTS } from '../shared/phishing/verdictRules';
import type { EmailReputation } from '../shared/types';
import { jsonRes, mockFetch } from './helpers';
import { resetRateLimitMemory, takeProviderBudget } from '../worker/_lib/ratelimit';

const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
const post = async (path: string, body: unknown, e: Record<string, unknown> = {}) => {
  const res = await worker.fetch(new Request(`https://app.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.9' }, body: JSON.stringify(body) }), { ...(env as object), ...e } as never, exec);
  return { res, json: (await res.json()) as { ok: boolean; data?: any; error?: { code: string; message: string } } };
};

/** A clean, verified mailbox as IPQS returns it. */
const RAW = {
  success: true, valid: true, timed_out: false, suspect: false, fraud_score: 10, recent_abuse: false, leaked: false, disposable: false,
  honeypot: false, spam_trap_score: 'none', frequent_complainer: false, catch_all: false, generic: false, common: false, dns_valid: true,
  deliverability: 'high', smtp_score: 3, overall_score: 4, domain_trust: 'neutral', risky_tld: false, suggested_domain: 'N/A',
  first_seen: { human: '3 years ago', timestamp: 1690000000, iso: '2023-07-22T04:26:40-04:00' },
  domain_age: { human: '10 years ago', timestamp: 1400000000, iso: '2014-05-13T12:53:20-04:00' }, request_id: 'x',
};
const rep = (over: Partial<EmailReputation> = {}): EmailReputation => ({ ...mapIpqs('a@evil.example', 'evil.example', RAW, 5), ...over });
const req = { check: 'ipqs' as const, email: 'a@evil.example', roles: ['from' as const] };

describe('IPQS key handling', () => {
  it('strips whitespace, line breaks and quotes pasted along with the key', () => {
    for (const k of ['abc123', ' abc123 ', 'abc123\n', 'abc123\r\n', '"abc123"', "'abc123'", '\tabc123  \n']) assert.equal(cleanKey(k), 'abc123', JSON.stringify(k));
    assert.equal(cleanKey(undefined), '');
  });
  it('sends the cleaned key to IPQS', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes(RAW) : undefined)]);
    try {
      await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_API_KEY: ' k123\n' });
      assert.match(m.calls.find((c) => c.includes('ipqualityscore'))!, /\/email\/k123\//);
    } finally { m.restore(); resetRateLimitMemory(); }
  });
});

describe('IPQS response mapping', () => {
  it('maps the documented fields', () => {
    const r = rep();
    assert.equal(r.valid, true); assert.equal(r.fraudScore, 10); assert.equal(r.smtpScore, 3); assert.equal(r.deliverability, 'high');
    assert.ok(!('domainTrust' in r), 'domain trust is not used'); assert.equal(r.suggestedDomain, null, '"N/A" means no suggestion');
    assert.equal(r.firstSeenHuman, '3 years ago'); assert.equal(r.domainAgeHuman, '10 years ago');
  });
  it('does not trust an "invalid" result after a timeout or temporary error', () => {
    assert.equal(mapIpqs('a@x.example', 'x.example', { ...RAW, valid: false, timed_out: true }, 1).valid, null);
    assert.equal(mapIpqs('a@x.example', 'x.example', { ...RAW, valid: false, suspect: true }, 1).valid, null);
    assert.equal(mapIpqs('a@x.example', 'x.example', { ...RAW, valid: false }, 1).valid, false);
  });
  it('ignores plan-restricted text in rating fields (e.g. "Upgraded plan required.")', () => {
    const r = mapIpqs('a@x.example', 'x.example', { ...RAW, deliverability: 'Enterprise required', spam_trap_score: 'High' }, 1);
    assert.equal(r.deliverability, null); assert.equal(r.spamTrapScore, 'high');
  });
  it('a rejected key is reported with a safe fingerprint (length and last 4), never the key', async () => {
    const key = 'abcdefghijklmnopqrstuvwxyz12WXYZ';
    assert.equal(keyHint(key), '32 characters, ending "…WXYZ"');
    assert.equal(keyHint('k123'), '4 characters', 'a short key is never shown');
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes({ success: false, message: 'Invalid or unauthorized key. Please check the API key and try again. (EID: 61771)' }) : undefined)]);
    try {
      const { json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_API_KEY: key });
      assert.match(json.data.checks[0].detail, /32 characters, ending "…WXYZ"/);
      assert.ok(!JSON.stringify(json).includes(key.slice(0, 20)));
    } finally { m.restore(); resetRateLimitMemory(); }
  });
  it('treats epoch dates as unknown', () => {
    const r = mapIpqs('a@x.example', 'x.example', { ...RAW, first_seen: { human: 'just now', timestamp: 0, iso: '1970-01-01' } }, 1);
    assert.equal(r.firstSeen, null); assert.equal(r.firstSeenHuman, null);
  });
});

describe('IPQS findings', () => {
  it('a clean mailbox gives no findings and a readable summary', () => {
    const c = convertIpqs(req, rep());
    assert.deepEqual(c.findings, []);
    assert.equal(c.check.status, 'complete');
    assert.match(c.check.result ?? '', /fraud score 10 · mailbox exists/);
    assert.equal(c.check.id, idOf(req)); assert.equal(c.check.label, labelOf(req));
  });
  it('fraud score: nothing below 75, low from 75, medium from 90', () => {
    assert.equal(convertIpqs(req, rep({ fraudScore: 74 })).findings.length, 0);
    assert.equal(convertIpqs(req, rep({ fraudScore: 80 })).findings[0].severity, 'low');
    assert.equal(convertIpqs(req, rep({ fraudScore: 95 })).findings[0].severity, 'medium');
  });
  it('flags recent abuse, missing mailboxes, typos and risky TLDs', () => {
    const ids = convertIpqs(req, rep({ recentAbuse: true, valid: false, suggestedDomain: 'paypal.com', riskyTld: true, disposable: true })).findings.map((f) => f.id).sort();
    assert.deepEqual(ids, ['sender_address_disposable', 'sender_address_mailbox_missing', 'sender_address_misspelt_domain', 'sender_address_recent_abuse', 'sender_address_risky_tld']);
  });
  it('a dead domain is reported once (no MX), not also as a missing mailbox', () => {
    assert.deepEqual(convertIpqs(req, rep({ valid: false, dnsValid: false })).findings.map((f) => f.id), ['sender_address_no_mx']);
  });
  it('breach exposure, spam traps and unknown validity are never findings', () => {
    assert.deepEqual(convertIpqs(req, rep({ leaked: true, honeypot: true, valid: null, timedOut: true })).findings, []);
  });
  it('reply-to addresses give related (not exact) findings, sourced to IPQualityScore', () => {
    const f = convertIpqs({ ...req, roles: ['reply_to'] }, rep({ recentAbuse: true })).findings[0];
    assert.equal(f.exactness, 'related'); assert.equal(f.source, 'IPQualityScore');
  });
  it('every IPQS finding is scored and grouped with the other address-reputation findings (no double counting with UserCheck)', () => {
    const fs = convertIpqs(req, rep({ recentAbuse: true, fraudScore: 95, valid: false, riskyTld: true })).findings;
    for (const f of fs) { assert.ok(f.id in POINTS, f.id); assert.equal(groupOf(f), 'address_reputation:a@evil.example', f.id); }
  });
  it('address reputation alone never makes a message Malicious', () => {
    const findings = convertIpqs(req, rep({ recentAbuse: true, fraudScore: 99, riskyTld: true })).findings;
    assert.notEqual(computeVerdict({ parse: null, findings, checks: [] } as never).label, 'malicious');
  });
});

describe('POST /api/phishing/sender with check "ipqs"', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); });

  it('looks the address up at IPQS (key in the path) and returns findings and data', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes({ ...RAW, fraud_score: 92, recent_abuse: true }) : undefined)]);
    restore = m.restore;
    const { res, json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'A@Evil.example', roles: ['from'] }, { IPQS_API_KEY: 'k123' });
    assert.equal(res.status, 200);
    assert.equal(json.data.checks[0].status, 'complete');
    assert.equal(json.data.data.check, 'ipqs');
    assert.equal(json.data.data.value.email, 'a@evil.example');
    assert.deepEqual(json.data.findings.map((f: { id: string }) => f.id).sort(), ['sender_address_fraud_score', 'sender_address_recent_abuse']);
    const call = m.calls.find((c) => new URL(c).hostname === 'www.ipqualityscore.com');
    assert.ok(call, 'IPQS was called');
    assert.match(call!, /\/api\/json\/email\/k123\/a%40evil\.example\?/);
    assert.ok(!JSON.stringify(json).includes('k123'), 'the key is not in the response');
  });

  it('reports an IPQS "success: false" answer as a failed check without leaking the key (no UserCheck configured)', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' ? jsonRes({ success: false, message: 'Invalid or unauthorized key k123. Please check the API key and try again.' }) : undefined)]);
    restore = m.restore;
    const { res, json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { IPQS_API_KEY: 'k123' });
    assert.equal(res.status, 200);
    assert.equal(json.data.checks[0].status, 'failed');
    assert.deepEqual(json.data.findings, []);
    assert.ok(!JSON.stringify(json).includes('k123'));
  });

  it('skips the check, saying why, when neither IPQS nor UserCheck has a key (nothing is sent anywhere)', async () => {
    const m = mockFetch([]);
    restore = m.restore;
    const { json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] });
    assert.equal(json.data.checks[0].status, 'skipped');
    assert.match(json.data.checks[0].detail, /not configured/);
    assert.equal(m.calls.length, 0);
  });

  it('rejects a malformed address', async () => {
    assert.equal((await post('/api/phishing/sender', { check: 'ipqs', email: 'nope' })).json.error?.code, 'INVALID_INPUT');
  });
});

describe('UserCheck fallback for the ipqs check', () => {
  let restore = () => {};
  afterEach(() => { restore(); resetRateLimitMemory(); });
  const UC = { email: 'a@evil.example', domain: 'evil.example', domain_age_in_days: 3, mx: true, disposable: true, spam: false, public_domain: false, relay_domain: false, free_subdomain: false, role_account: false, did_you_mean: null };
  const keys = { IPQS_API_KEY: 'k123', USERCHECK_API_KEY: 'uc-key' };
  /** IPQS answers with `ipqs`; UserCheck with the sample; every call is recorded by host. */
  const providers = (ipqs: () => Response) => {
    const m = mockFetch([
      (u) => (u.hostname === 'www.ipqualityscore.com' ? ipqs() : undefined),
      (u) => (u.hostname === 'api.usercheck.com' ? jsonRes(UC) : undefined),
    ]);
    restore = m.restore;
    return { hosts: () => m.calls.map((c) => new URL(c).hostname) };
  };
  const expectFallback = (json: any, reason: RegExp) => {
    assert.equal(json.data.checks[0].status, 'complete');
    assert.equal(json.data.data.check, 'usercheck', 'the data come from UserCheck');
    assert.equal(json.data.checks[0].id, 'sender.ipqs.a@evil.example', 'the check keeps its ipqs id');
    assert.match(json.data.checks[0].label, /UserCheck fallback/);
    assert.match(json.data.checks[0].detail, reason);
    assert.match(json.data.checks[0].detail, /Results come from UserCheck instead/);
    assert.ok(json.data.findings.some((f: { id: string; source: string }) => f.id === 'sender_address_disposable' && f.source === 'UserCheck.com'));
    assert.ok(!JSON.stringify(json).includes('k123') && !JSON.stringify(json).includes('uc-key'));
  };

  it('uses only IPQS when it answers (UserCheck is never called)', async () => {
    const p = providers(() => jsonRes(RAW));
    const { json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys);
    assert.equal(json.data.data.check, 'ipqs');
    assert.deepEqual(p.hosts(), ['www.ipqualityscore.com']);
  });

  it('falls back when the daily IPQS cap is spent, without calling IPQS', async () => {
    const p = providers(() => jsonRes(RAW));
    const e = { ...keys, IPQS_DAILY: '1' };
    assert.equal((await post('/api/phishing/sender', { check: 'ipqs', email: 'first@evil.example', roles: ['from'] }, e)).json.data.data.check, 'ipqs');
    const { json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, e);
    expectFallback(json, /IPQualityScore limit reached/);
    assert.deepEqual(p.hosts(), ['www.ipqualityscore.com', 'api.usercheck.com'], 'the second address went to UserCheck only');
  });

  it('the default IPQS cap is 35 a day (IPQS_DAILY overrides it)', async () => {
    const t = Date.UTC(2026, 10, 11, 12);
    for (let i = 0; i < 35; i++) assert.equal((await takeProviderBudget({} as never, 'ipqs', t)).ok, true, `lookup ${i + 1}`);
    assert.equal((await takeProviderBudget({} as never, 'ipqs', t)).ok, false, 'the 36th is refused');
    resetRateLimitMemory();
    for (let i = 0; i < 50; i++) assert.equal((await takeProviderBudget({ IPQS_DAILY: '50' } as never, 'ipqs', t)).ok, true);
  });

  it('falls back on an IPQS quota / limit error', async () => {
    providers(() => jsonRes({ success: false, message: 'You have exceeded your request quota of 1000 per month.' }));
    expectFallback((await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys)).json, /IPQualityScore limit reached: .*exceeded your request quota/);
  });

  it('falls back on an IPQS API error (success: false), an HTTP error and a rate-limit response', async () => {
    providers(() => jsonRes({ success: false, message: 'Invalid or unauthorized key k123.' }));
    expectFallback((await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys)).json, /IPQualityScore failed/);
    restore(); resetRateLimitMemory();
    providers(() => new Response('oops', { status: 500 }));
    expectFallback((await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys)).json, /IPQualityScore failed: .*HTTP 500/);
    restore(); resetRateLimitMemory();
    providers(() => new Response('slow down', { status: 429 }));
    expectFallback((await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys)).json, /rate limit/);
  });

  it('falls back when IPQS has no key', async () => {
    const p = providers(() => jsonRes(RAW));
    expectFallback((await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, { USERCHECK_API_KEY: 'uc-key' })).json, /not configured/);
    assert.deepEqual(p.hosts(), ['api.usercheck.com']);
  });

  it('reports failed (never clean) when IPQS and the UserCheck fallback both fail', async () => {
    const m = mockFetch([(u) => (u.hostname === 'www.ipqualityscore.com' || u.hostname === 'api.usercheck.com' ? new Response('down', { status: 503 }) : undefined)]);
    restore = m.restore;
    const { json } = await post('/api/phishing/sender', { check: 'ipqs', email: 'a@evil.example', roles: ['from'] }, keys);
    assert.equal(json.data.checks[0].status, 'failed');
    assert.match(json.data.checks[0].detail, /IPQualityScore failed.*UserCheck fallback also failed/);
    assert.deepEqual(json.data.findings, []);
  });
});
