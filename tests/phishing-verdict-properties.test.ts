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

/* ---- high-risk Suspicious (Sahil, 12 Nov: a corroborated BEC stays Suspicious, flagged high risk) ---- */
import { buildReport } from '../shared/phishing/report';

const corpusVerdict = async (id: string) => {
  const s = CORPUS.find((x) => x.id.startsWith(id))!;
  const r = await parseSubmission(s.input);
  return computeVerdict({ parse: r, findings: dedupeFindings([...r.findings, ...(s.findings ?? [])]), checks: [...r.checks, ...(s.checks ?? [])] });
};

test('a BEC with a corroborating sender signal is high-risk Suspicious, never Malicious', async () => {
  const v = await corpusVerdict('S28');
  assert.equal(v.label, 'suspicious');
  assert.equal(v.highRisk?.id, 'bec_pattern');
  assert.ok(v.risk >= THRESHOLDS.highRiskFloor && v.risk <= THRESHOLDS.nonMaliciousCap, String(v.risk));
  assert.match(v.headline, /business email compromise/);
  assert.match(v.actions[0], /Do not pay/);
});

test('the BEC pattern needs sender corroboration; a plain payment reminder is untouched', async () => {
  assert.equal((await corpusVerdict('S27')).highRisk, null, 'wording + Reply-To alone stays ordinary Suspicious');
  const legit = await corpusVerdict('L23');
  assert.equal(legit.label, 'likely_legitimate');
  assert.equal(legit.highRisk, null);
});

test('strong evidence from three independent areas is high-risk Suspicious', async () => {
  const fs = [lookup('url_lookalike_domain', 'high', 'url', { indicator: { type: 'url', value: 'https://x.example/' } }), lookup('url_homograph_domain', 'high', 'url', { indicator: { type: 'url', value: 'https://y.example/' } }),
    lookup('attachment_double_extension', 'high', 'attachment', { indicator: { type: 'hash', value: 'a'.repeat(64) } }), lookup('attachment_macro_present', 'high', 'attachment', { indicator: { type: 'hash', value: 'b'.repeat(64) } }),
    lookup('sender_domain_new', 'high', 'infrastructure'), lookup('sender_ip_abuse_reports', 'high', 'infrastructure', { indicator: { type: 'ip', value: '1.2.3.4' } })];
  const v = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: 'x https://x.example/ https://y.example/' }, fs, [...SENDER_DONE, ...LINKS_DONE]);
  assert.equal(v.label, 'suspicious');
  assert.equal(v.highRisk?.id, 'convergent_evidence');
});

/* ---- high-risk Suspicious: a security DNS block agreeing with a weak scanning-engine hit on the same URL (13 Nov) ---- */

test('a security DNS block and a weak scanning-engine hit on the same URL are high-risk Suspicious, never Malicious', async () => {
  const url = 'https://confirm-account.example/verify';
  const fs = [
    lookup('url_dns_blocked', 'high', 'url', { source: 'Cloudflare Security DNS', reliability: 'medium', indicator: { type: 'url', value: url } }),
    lookup('url_engine_detections', 'medium', 'url', { source: 'VirusTotal', reliability: 'low', indicator: { type: 'url', value: url } }),
  ];
  const v = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: `Please confirm: ${url}` }, fs, [...SENDER_DONE, ...LINKS_DONE]);
  assert.notEqual(v.label, 'malicious');
  assert.equal(v.label, 'suspicious');
  assert.equal(v.highRisk?.id, 'dns_block_with_engine_hit');
  assert.ok(v.risk >= THRESHOLDS.highRiskFloor && v.risk <= THRESHOLDS.nonMaliciousCap, String(v.risk));
  assert.match(v.headline, /security DNS block/);
});

test('the DNS-block + engine-hit pattern needs both signals on the same URL; either one alone is ordinary at most', async () => {
  const url = 'https://a.example/x';
  const dnsOnly = [lookup('url_dns_blocked', 'high', 'url', { indicator: { type: 'url', value: url } })];
  const v1 = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: `see ${url}` }, dnsOnly, [...SENDER_DONE, ...LINKS_DONE]);
  assert.equal(v1.highRisk, null, 'a DNS block with no corroborating engine hit does not trigger the pattern');

  const engineOnly = [lookup('url_engine_detections', 'medium', 'url', { indicator: { type: 'url', value: url } })];
  const v2 = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: `see ${url}` }, engineOnly, [...SENDER_DONE, ...LINKS_DONE]);
  assert.equal(v2.highRisk, null, 'a weak engine hit with no DNS block does not trigger the pattern');

  // same two findings, but on two different URLs: must not match across URLs
  const mismatched = [
    lookup('url_dns_blocked', 'high', 'url', { indicator: { type: 'url', value: 'https://one.example/' } }),
    lookup('url_engine_detections', 'medium', 'url', { indicator: { type: 'url', value: 'https://two.example/' } }),
  ];
  const v3 = await verdictOf({ headers: mail({ from: 'a@b.example' }), body: 'see https://one.example/ and https://two.example/' }, mismatched, [...SENDER_DONE, ...LINKS_DONE]);
  assert.equal(v3.highRisk, null, 'the DNS block and the engine hit must be on the exact same URL');
});

test('exports carry the high-risk label', async () => {
  const s = CORPUS.find((x) => x.id.startsWith('S28'))!;
  const parse = await parseSubmission(s.input);
  const findings = dedupeFindings([...parse.findings, ...(s.findings ?? [])]);
  const v = computeVerdict({ parse, findings, checks: [...parse.checks, ...(s.checks ?? [])] });
  const rep = buildReport({ verdict: v, parse, findings, checks: [] } as never);
  assert.equal(rep.verdict.labelText, 'SUSPICIOUS (HIGH RISK)');
});
