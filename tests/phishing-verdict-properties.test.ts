/**
 * Properties the verdict engine must keep whatever the weights are (12 Nov review):
 *  - a clean area (a harmless link, a clean attachment) never lowers risk, so padding a message cannot hide it;
 *  - adding a finding never lowers risk;
 *  - the risk number never contradicts the label (Malicious >= floor, everything else below it);
 *  - confidence describes the label: Inconclusive is never "high", and a borderline Suspicious is less certain than a clear one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeVerdict } from '../shared/phishing/verdict';
import { THRESHOLDS } from '../shared/phishing/verdictRules';
import { parseSubmission } from '../shared/phishing/parse';
import { dedupeFindings } from '../shared/phishing/findings';
import { CORPUS, lookup, mail, SENDER_DONE, LINKS_DONE } from './fixtures/phishing-corpus';
import type { Finding } from '../shared/phishing/types';

const verdictOf = async (input: Parameters<typeof parseSubmission>[0], extra: Finding[] = [], checks = SENDER_DONE) => {
  const r = await parseSubmission(input);
  return computeVerdict({ parse: r, findings: dedupeFindings([...r.findings, ...extra]), checks: [...r.checks, ...checks] });
};

const BEC = { headers: mail({ from: 'ap@vendor.example', replyTo: 'ap.vendor@gmail.com', subject: 'Overdue invoice' }), body: 'Please pay via ACH today. Attached is the overdue invoice.' };

test('a clean link does not lower the risk of a message (no padding)', async () => {
  const a = await verdictOf(BEC);
  const b = await verdictOf({ ...BEC, body: `${BEC.body} https://www.example.com/about` }, [], [...SENDER_DONE, ...LINKS_DONE]);
  assert.ok(b.dimensions.find((d) => d.dimension === 'url')!.active);
  assert.ok(b.risk >= a.risk, `${b.risk} >= ${a.risk}`);
});

test('adding a finding never lowers the risk (every corpus sample, every extra finding type)', async () => {
  const extras = [lookup('sender_domain_new', 'medium', 'infrastructure'), lookup('content_urgency', 'low', 'content'), lookup('url_shortener', 'low', 'url', { indicator: { type: 'url', value: 'https://s.example/x' } }), lookup('attachment_high_entropy', 'info', 'attachment')];
  for (const s of CORPUS) {
    const r = await parseSubmission(s.input);
    const base = dedupeFindings([...r.findings, ...(s.findings ?? [])]);
    const checks = [...r.checks, ...(s.checks ?? [])];
    const v0 = computeVerdict({ parse: r, findings: base, checks });
    for (const x of extras) {
      const v1 = computeVerdict({ parse: r, findings: dedupeFindings([...base, x]), checks });
      assert.ok(v1.risk >= v0.risk, `${s.id} + ${x.id}: ${v1.risk} < ${v0.risk}`);
    }
  }
});

test('the risk number never contradicts the label', async () => {
  const many = ['url_lookalike_domain', 'url_homograph_domain', 'attachment_double_extension', 'attachment_macro_present', 'auth_all_failed', 'sender_domain_new', 'content_payment_redirection', 'content_credential_request']
    .map((id, i) => lookup(id, 'high', id.split('_')[0] === 'url' ? 'url' : id.startsWith('attachment') ? 'attachment' : id.startsWith('content') ? 'content' : id.startsWith('auth') ? 'authentication' : 'infrastructure', { indicator: { type: 'url', value: `https://x${i}.example/` } }));
  const v = await verdictOf({ headers: mail({ from: 'a@b.example', spf: 'fail', dkim: 'none', dmarc: 'fail' }), body: 'x' }, many, [...SENDER_DONE, ...LINKS_DONE]);
  assert.notEqual(v.label, 'malicious');
  assert.ok(v.risk <= THRESHOLDS.nonMaliciousCap, `${v.risk}`);
  for (const s of CORPUS) {
    const r = await parseSubmission(s.input);
    const x = computeVerdict({ parse: r, findings: dedupeFindings([...r.findings, ...(s.findings ?? [])]), checks: [...r.checks, ...(s.checks ?? [])] });
    if (x.label === 'malicious') assert.ok(x.risk >= THRESHOLDS.maliciousFloor, s.id);
    else assert.ok(x.risk <= THRESHOLDS.nonMaliciousCap, s.id);
  }
});

test('confidence describes the label, not just how many checks ran', async () => {
  const weak = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: 'Hello there' }, [lookup('reply_to_mismatch', 'medium', 'authentication', { trust: 'derived' })]);
  assert.equal(weak.label, 'inconclusive');
  assert.notEqual(weak.confidence.level, 'high', 'a fully checked Inconclusive is not "high confidence"');
  const borderline = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: 'Hello' }, [lookup('attachment_double_extension', 'high', 'attachment', { reliability: 'medium', indicator: { type: 'hash', value: 'c'.repeat(64) } })]);
  const clear = await verdictOf(BEC, [lookup('sender_address_fraud_score', 'medium', 'infrastructure'), lookup('sender_domain_new', 'medium', 'infrastructure')]);
  assert.equal(borderline.label, 'suspicious');
  assert.equal(clear.label, 'suspicious');
  assert.ok(clear.confidence.score > borderline.confidence.score, `${clear.confidence.score} > ${borderline.confidence.score}`);
});
