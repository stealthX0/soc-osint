import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index';
import { parseSubmission } from '../shared/phishing/parse';
import { analyzeIdentity } from '../shared/phishing/brand';
import { dedupeFindings } from '../shared/phishing/findings';
import { analyzeUrlHeuristics, parseTargetUrl } from '../shared/url';
import type { UrlStageResult } from '../shared/phishing/urlTriage';
import { resetOpenPhishMemory } from '../worker/_lib/openphish';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';
import { jsonRes, mockFetch } from './helpers';

const heur = (host: string) => { const p = parseTargetUrl(`https://${host}/`); assert.ok(p.ok); return analyzeUrlHeuristics(p.value).map((s) => s.id); };

describe('hyphenated digit-swap brands (Step 3 gap, fixed in the shared heuristics)', () => {
  it('catches a leet-swapped brand hidden inside a hyphenated label', () => {
    assert.ok(heur('secure-paypa1-login.xyz').some((id) => id.startsWith('squat-')));
    assert.ok(heur('paypa1.com').some((id) => id.startsWith('squat-')));
  });
  it('does not misreport an ordinary brand mention or the real domain', () => {
    assert.ok(!heur('paypal-login.xyz').some((id) => id.startsWith('squat-')), 'a plain brand word is a brand-* signal, not a squat');
    assert.deepEqual(heur('paypal.com').filter((id) => /^(squat|brand|typo)-/.test(id)), []);
  });
  it('the sender identity analysis benefits too', () => {
    assert.ok(analyzeIdentity({ fromDomain: 'secure-paypa1-login.xyz', display: null, claimedDomain: null }).some((f) => f.id === 'sender_domain_lookalike'));
  });
});

describe('local link screening at parse time', () => {
  const html = '<p>Dear customer</p><a href="https://paypa1-secure.example/login">https://www.paypal.com/signin</a> <a href="https://www.paypal.com/help">Help</a>';
  const sub = { headers: 'From: "PayPal Support" <service@paypal-notify.example>\nSubject: Your PayPal account\nContent-Type: text/html; charset=utf-8', body: html };

  it('flags deceptive link text and a destination that is not the claimed brand, without any lookup', async () => {
    const m = mockFetch([]);
    try {
      const r = await parseSubmission(sub);
      const ids = r.findings.map((f) => f.id);
      assert.ok(ids.includes('link_text_mismatch'));
      assert.ok(ids.includes('url_brand_mismatch'));
      assert.ok(ids.includes('url_lookalike_domain'));
      assert.equal(m.calls.length, 0, 'parsing makes no network requests');
      assert.equal(r.checks.find((c) => c.id === 'urls.offline')?.status, 'complete');
    } finally { m.restore(); }
  });
  it('stays quiet for a normal message with no suspicious links', async () => {
    const r = await parseSubmission({ headers: 'From: Alice <alice@partner.example>\nSubject: Notes', body: 'Notes are at https://partner.example/notes' });
    assert.deepEqual(r.findings.filter((f) => f.dimension === 'url'), []);
  });
});

describe('merging the parse stage with the link investigation', () => {
  let restore = () => {};
  beforeEach(() => { resetOpenPhishMemory(); resetRateLimitMemory(); });
  afterEach(() => restore());
  const env = { ASSETS: { fetch: async () => new Response('asset') } } as never;
  const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;

  it('identical offline findings are not counted twice, and OpenPhish adds the exact-listing finding', async () => {
    const html = '<a href="https://evil-site.net/login.php">https://www.paypal.com/signin</a>';
    const input = { headers: 'From: "PayPal Support" <service@paypal-notify.example>\nSubject: Your PayPal account\nContent-Type: text/html', body: html, sender: { domain: 'paypal.com' } };
    const parsed = await parseSubmission(input);
    const m = mockFetch([(u) => (u.hostname === 'openphish.com' ? new Response('https://evil-site.net/login.php\n') : undefined)]);
    restore = m.restore;
    const body = {
      links: parsed.links.map((l) => ({ url: l.normalized, text: l.text, sources: l.sources, count: l.count, wrapped: !!l.wrapper })),
      context: { senderDomains: ['paypal-notify.example'], claimedDomains: ['paypal.com'], displayName: 'PayPal Support', subject: parsed.content.subject ?? undefined, text: parsed.content.text },
      maxDeep: 0,
    };
    const res = await worker.fetch(new Request('https://app.test/api/phishing/urls', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.10' }, body: JSON.stringify(body) }), env, exec);
    const j = (await res.json()) as { ok: boolean; data: UrlStageResult };
    assert.equal(j.ok, true);
    const merged = dedupeFindings([...parsed.findings, ...j.data.findings]);
    const count = (id: string) => merged.filter((f) => f.id === id).length;
    assert.equal(count('link_text_mismatch'), 1);
    assert.equal(count('url_brand_mismatch'), 1);
    assert.equal(count('url_listed_phishing'), 1);
    assert.equal(merged.find((f) => f.id === 'url_listed_phishing')!.severity, 'critical');
  });
});
