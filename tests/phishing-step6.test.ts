/**
 * Verdict engine tests.
 *
 * Besides unit tests of each rule, this file is the CALIBRATION CORPUS: realistic scenarios with the verdict a careful analyst
 * would give. The starting weights in shared/phishing/verdictRules.ts are unvalidated design values. When you collect real,
 * sanitised phishing and legitimate samples, add them here (as a parseSubmission input plus the lookup findings you got) and
 * adjust the rules until the corpus agrees with your judgement. A failing scenario means the weights need attention.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { computeVerdict, type CheckRow, type Verdict } from '../shared/phishing/verdict';
import { POINTS } from '../shared/phishing/verdictRules';
import { parseSubmission, type ParseStageResult } from '../shared/phishing/parse';
import { dedupeFindings, makeFinding } from '../shared/phishing/findings';
import type { Dimension, Finding, Severity } from '../shared/phishing/types';

/* ------------------------------------------------------------------ fixtures */

const M365 = `Received: from DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) by BN9PR12MB2222.namprd12.prod.outlook.com with HTTPS; Wed, 4 Nov 2026 09:00:05 +0000
Received: from mail-ej1-f43.google.com (209.85.218.43) by DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) with Microsoft SMTP Server; Wed, 4 Nov 2026 09:00:04 +0000
Authentication-Results: spf=pass (sender IP is 209.85.218.43) smtp.mailfrom=partner.example; dkim=pass (signature was verified) header.d=partner.example;dmarc=pass action=none header.from=partner.example;compauth=pass reason=100
Received: from mail-ej1-f43.google.com (mail-ej1-f43.google.com [209.85.218.43]) by mx.partner.example with ESMTPS; Wed, 4 Nov 2026 09:00:03 +0000
Return-Path: <bounce@partner.example>
From: Alice Partner <alice@partner.example>
To: me@corp.example
Subject: Meeting notes
Date: Wed, 4 Nov 2026 09:00:00 +0000
Message-ID: <1@partner.example>
Content-Type: text/plain`;

const PHISH = `Received: by 2002:a05:6a00:1 with SMTP id x1csp1; Tue, 3 Nov 2026 10:05:00 -0800 (PST)
Received: from mail-out.evil.example (mail-out.evil.example [45.33.32.156]) by mx.google.com with ESMTPS id abc123; Tue, 3 Nov 2026 10:04:50 -0800 (PST)
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@evil.example; dkim=none; dmarc=fail (p=REJECT) header.from=paypal.com
Return-Path: <bounce@evil.example>
From: "PayPal Support" <service@paypal.com>
Reply-To: help.desk.9921@gmail.com
To: victim@gmail.com
Subject: Action required: verify your account
Date: Tue, 3 Nov 2026 17:58:00 +0000
Content-Type: text/html; charset=utf-8`;

const ok = (id: string, label = id): CheckRow => ({ id, label, status: 'complete', result: 'ok' });
const failed = (id: string, label = id): CheckRow => ({ id, label, status: 'failed', result: null, detail: 'provider error' });

/** The lookups that complete for a normal run: sender IP / domain / DNS / SPF re-check. */
const senderOk = [ok('sender.ip.1'), ok('sender.domain.1'), ok('sender.auth.1'), ok('sender.spf.1')];
const linksChecked = [ok('urls.openphish'), ok('urls.provider.virustotal')];

const F = (id: string, severity: Severity, dimension: Dimension, over: Partial<Finding> = {}): Finding =>
  makeFinding({ id, dimension, severity, title: id.replace(/_/g, ' '), detail: `${id} detail`, source: 'test', exactness: 'exact', reliability: 'high', trust: 'independently_verified', ...over });

async function verdict(input: Parameters<typeof parseSubmission>[0], extra: { findings?: Finding[]; checks?: CheckRow[] } = {}): Promise<{ v: Verdict; r: ParseStageResult }> {
  const r = await parseSubmission(input);
  const findings = dedupeFindings([...r.findings, ...(extra.findings ?? [])]);
  const checks: CheckRow[] = [...r.checks, ...(extra.checks ?? [])];
  return { v: computeVerdict({ parse: r, findings, checks, now: Date.parse('2026-11-07') }), r };
}

/* ---------------------------------------------------------------- the corpus */

describe('calibration corpus: legitimate mail', () => {
  it('a genuine authenticated message with full coverage is likely legitimate, with supporting evidence listed', async () => {
    const { v } = await verdict({ headers: M365, body: 'Notes from today are on the wiki. Thanks, Alice.' }, { checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'likely_legitimate');
    assert.ok(v.mitigating.length >= 2);
    assert.ok(v.risk < 12);
    assert.ok(v.headline.includes('not a guarantee'));
  });
  it('a real password-reset notice (credential wording, no other signals) is not flagged', async () => {
    const body = 'You recently asked to reset your password. Use the button below to choose a new one. If you did not make this request, ignore this email.';
    const { v } = await verdict({ headers: M365.replace('Subject: Meeting notes', 'Subject: Reset your password'), body }, { checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'likely_legitimate');
  });
  it('a bulk mailer with a different Return-Path but aligned DKIM is not suspicious', async () => {
    const f = [F('return_path_mismatch', 'info', 'authentication'), F('sender_infra_shared_provider', 'info', 'infrastructure')];
    const { v } = await verdict({ headers: M365, body: 'Our November newsletter is out.' }, { findings: f, checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'likely_legitimate');
  });
  it('a bad-reputation IP on shared mail infrastructure does not sink an otherwise clean message', async () => {
    const f = [F('sender_infra_shared_provider', 'info', 'infrastructure'), F('sender_ip_abuse_reports', 'medium', 'infrastructure', { exactness: 'exact' })];
    const { v } = await verdict({ headers: M365, body: 'See you at 10.' }, { findings: f, checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'likely_legitimate');
    assert.ok(v.contributions.find((c) => c.findingId === 'sender_ip_abuse_reports')!.multipliers.context < 1);
  });
});

describe('calibration corpus: phishing', () => {
  const lureBody = '<a href="https://evil-site.net/login">https://www.paypal.com/signin</a> Your account will be suspended within 24 hours unless you verify your password.';
  it('a spoofed brand with failed authentication and a reply-to mismatch is suspicious until the links are checked', async () => {
    const { v } = await verdict({ headers: PHISH, body: lureBody, sender: { domain: 'paypal.com' } }, { checks: senderOk });
    assert.equal(v.label, 'suspicious');
    assert.ok(v.reasons.length >= 3);
    assert.ok(v.gaps.some((g) => g.critical && /not checked for reputation/.test(g.text)), 'the unchecked link is listed as a gap');
  });
  it('the same message becomes MALICIOUS when the destination is listed by a trusted feed', async () => {
    const listed = F('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: { type: 'url', value: 'https://evil-site.net/login' } });
    const { v } = await verdict({ headers: PHISH, body: lureBody }, { findings: [listed], checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'malicious');
    assert.equal(v.rule?.id, 'exact_url_confirmed');
    assert.ok(v.indicators.some((i) => i.value === 'https://evil-site.net/login'));
    assert.ok(v.actions.some((a) => /reset the password/.test(a)));
  });
  it('perfect authentication does not rescue a message whose link is confirmed phishing', async () => {
    const listed = F('url_listed_phishing', 'critical', 'url', { source: 'Google Safe Browsing', indicator: { type: 'url', value: 'https://evil-site.net/a' } });
    const { v } = await verdict({ headers: M365, body: 'Please review: https://evil-site.net/a' }, { findings: [listed], checks: [...senderOk, ...linksChecked] });
    assert.equal(v.label, 'malicious');
    assert.ok(v.mitigating.length > 0, 'authentication is shown as supporting evidence');
    assert.ok(v.notes.some((n) => /authenticated sender can still send phishing/.test(n)));
  });
  it('a confirmed-malware attachment hash is malicious even when other checks failed', async () => {
    const f = F('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: 'a'.repeat(64) } });
    const { v } = await verdict({ headers: M365, body: 'invoice attached' }, { findings: [f], checks: [failed('sender.ip.1'), failed('sender.domain.1')] });
    assert.equal(v.label, 'malicious');
    assert.equal(v.rule?.id, 'exact_malware_hash');
    assert.ok(v.confidence.level !== 'low');
  });
  it('two independent sources against the same exact URL confirm it', async () => {
    const at = { indicator: { type: 'url' as const, value: 'https://x.example/p' } };
    const fs = [F('url_engine_detections', 'high', 'url', { source: 'VirusTotal', ...at }), F('url_scan_malicious', 'high', 'url', { source: 'urlscan.io', ...at })];
    const { v } = await verdict({ headers: M365, body: 'https://x.example/p' }, { findings: fs, checks: [...senderOk, ...linksChecked] });
    assert.equal(v.rule?.id, 'independent_confirmation');
    assert.equal(v.label, 'malicious');
  });
  it('impersonation plus an externally flagged destination is malicious; impersonation with only local heuristics is suspicious', async () => {
    const imp = F('display_name_brand_spoof', 'high', 'content', { source: 'identity-analysis', trust: 'derived' });
    const ext = F('url_threat_intel_rating', 'high', 'url', { source: 'Pulsedive', exactness: 'related' });
    const heur = F('url_lookalike_domain', 'medium', 'url', { source: 'url-heuristics', trust: 'derived', indicator: { type: 'url', value: 'https://p.example' } });
    assert.equal((await verdict({ headers: PHISH, body: 'x' }, { findings: [imp, ext], checks: [...senderOk, ...linksChecked] })).v.rule?.id, 'impersonation_with_bad_destination');
    const h = await verdict({ headers: PHISH, body: 'https://p.example' }, { findings: [imp, heur], checks: [...senderOk, ...linksChecked] });
    assert.equal(h.v.label, 'suspicious');
  });
  it('an HTML attachment with a sign-in form plus impersonation is malicious; alone it is suspicious', async () => {
    const form = F('attachment_html_credential_form', 'high', 'attachment', { trust: 'derived', indicator: { type: 'hash', value: 'b'.repeat(64) } });
    const imp = F('sender_domain_lookalike', 'medium', 'content', { trust: 'derived' });
    assert.equal((await verdict({ headers: M365, body: 'see attached' }, { findings: [form, imp], checks: senderOk })).v.rule?.id, 'credential_form_attachment');
    assert.equal((await verdict({ headers: M365, body: 'see attached' }, { findings: [form], checks: senderOk })).v.label, 'suspicious');
  });
  it('a sextortion message with a wallet is an extortion scam; one weak hit is not', async () => {
    const strong = F('content_extortion', 'medium', 'content', { evidence: ['hacked your webcam ... bitcoin', '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'] });
    const weak = F('content_extortion', 'medium', 'content', { evidence: ['bitcoin'] });
    assert.equal((await verdict({ headers: M365, body: 'pay' }, { findings: [strong], checks: senderOk })).v.rule?.id, 'extortion_scam');
    assert.notEqual((await verdict({ headers: M365, body: 'pay' }, { findings: [weak], checks: senderOk })).v.label, 'malicious');
  });
  it('payment-redirection wording with a clean sender is suspicious (business-email-compromise style)', async () => {
    const { v } = await verdict({ headers: M365, body: 'Our bank details have changed. Please remit payment to the new account below and do not use the old account.' }, { checks: senderOk });
    assert.equal(v.label, 'suspicious');
    assert.ok(v.reasons.some((r) => /bank details/i.test(r.title)));
  });
});

describe('verdict rules from the design document', () => {
  it('authentication failure alone is never malicious, and the verdict says why', async () => {
    const { v } = await verdict({ headers: PHISH.replace('From: "PayPal Support" <service@paypal.com>', 'From: Bob <bob@vendor.example>').replace('header.from=paypal.com', 'header.from=vendor.example').replace('Reply-To: help.desk.9921@gmail.com\n', ''), body: 'Hello' }, { checks: senderOk });
    assert.equal(v.label, 'suspicious');
    assert.ok(v.notes.some((n) => /failure alone is never enough/.test(n)));
    assert.ok(v.headline.includes('does not prove'));
  });
  it('a bad IP alone is Suspicious at most', async () => {
    const f = [F('sender_ip_abuse_reports', 'high', 'infrastructure'), F('sender_ip_vt_detections', 'high', 'infrastructure')];
    const { v } = await verdict({ headers: M365, body: 'Hi' }, { findings: f, checks: senderOk });
    assert.ok(v.label === 'suspicious' || v.label === 'inconclusive');
    assert.notEqual(v.label, 'malicious');
  });
  it('failed checks make the result inconclusive, never clean', async () => {
    const { v } = await verdict({ headers: M365, body: 'Hi' }, { checks: [failed('sender.ip.1'), failed('sender.domain.1'), failed('sender.auth.1')] });
    assert.equal(v.label, 'inconclusive');
    assert.ok(v.gaps.some((g) => g.critical && /None of the sender/.test(g.text)));
  });
  it('links that were never investigated prevent a clean verdict', async () => {
    const { v } = await verdict({ headers: M365, body: 'Details: https://partner.example/notes' }, { checks: senderOk });
    assert.equal(v.label, 'inconclusive');
    assert.ok(v.gaps.some((g) => g.critical && /not checked for reputation/.test(g.text)));
    const done = await verdict({ headers: M365, body: 'Details: https://partner.example/notes' }, { checks: [...senderOk, ...linksChecked] });
    assert.equal(done.v.label, 'likely_legitimate');
  });
  it('an attachment that was not assessed prevents a clean verdict', async () => {
    const { v } = await verdict({ headers: M365, body: 'see attached', attachments: [{ name: 'invoice.pdf' }] }, { checks: senderOk });
    assert.equal(v.label, 'inconclusive');
    assert.ok(v.gaps.some((g) => g.critical && /invoice\.pdf/.test(g.text)));
  });
  it('no headers means the sender cannot be vouched for', async () => {
    const { v } = await verdict({ body: 'Hello, please see the notes.' });
    assert.equal(v.label, 'inconclusive');
    assert.ok(v.gaps.some((g) => g.critical && /No usable headers/.test(g.text)));
  });
  it('conflicting evidence forces inconclusive when nothing else is alarming', async () => {
    const f = [F('auth_conflict', 'medium', 'authentication', { trust: 'derived', detail: 'DMARC says pass but nothing aligns' })];
    const { v } = await verdict({ headers: M365, body: 'Hi' }, { findings: f, checks: senderOk });
    assert.equal(v.label, 'inconclusive');
    assert.equal(v.conflicts.length, 1);
  });
  it('is provisional while lookups are still running, with lower confidence', async () => {
    const r = await parseSubmission({ headers: PHISH, body: 'x' });
    const a = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...senderOk] });
    const b = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...senderOk, { id: 'sender.ip.2', label: 'IP', status: 'running' }] });
    assert.equal(a.provisional, false);
    assert.equal(b.provisional, true);
    assert.ok(b.confidence.score < a.confidence.score);
  });
  it('reports analysis unavailable when nothing could be parsed', () => {
    const v = computeVerdict({ parse: null, findings: [], checks: [] });
    assert.equal(v.label, 'analysis_unavailable');
  });
});

describe('scoring properties', () => {
  const base = async () => (await parseSubmission({ headers: M365, body: 'Hi' }));
  it('is deterministic', async () => {
    const r = await base();
    const mk = () => computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...senderOk], now: 1 });
    assert.deepEqual(mk(), mk());
  });
  it('never lowers risk when a finding is added', async () => {
    const r = await base();
    const ids = ['reply_to_mismatch', 'dmarc_fail', 'sender_domain_new', 'content_urgency', 'url_shortener', 'link_text_mismatch', 'attachment_dangerous_type'] as const;
    let prev = -1;
    const acc: Finding[] = [];
    for (const id of ids) {
      acc.push(F(id, 'medium', id.startsWith('url') || id.startsWith('link') ? 'url' : id.startsWith('attach') ? 'attachment' : 'authentication'));
      const v = computeVerdict({ parse: r, findings: acc, checks: [...r.checks, ...senderOk] });
      assert.ok(v.risk >= prev, `${id}: ${v.risk} < ${prev}`);
      prev = v.risk;
    }
  });
  it('counts findings about the same fact once, not three times', async () => {
    const r = await base();
    const one = computeVerdict({ parse: r, findings: [F('sender_domain_lookalike', 'medium', 'content')], checks: senderOk });
    const three = computeVerdict({ parse: r, findings: [F('sender_domain_lookalike', 'medium', 'content'), F('display_name_brand_spoof', 'medium', 'content', { title: 'b' }), F('content_brand_impersonation', 'medium', 'content', { title: 'c' })], checks: senderOk });
    const pts = (v: Verdict) => v.dimensions.find((d) => d.dimension === 'content')!.points;
    assert.ok(pts(three) <= pts(one) * 1.5 + 0.01);
    assert.ok(pts(three) > pts(one));
  });
  it('never counts negative points, so passing authentication cannot lower risk', async () => {
    const r = await base();
    const v = computeVerdict({ parse: r, findings: [F('spf_independent_pass', 'info', 'authentication'), F('attachment_hash_known_good', 'info', 'attachment')], checks: senderOk });
    assert.ok(v.contributions.every((c) => c.counted >= 0));
    assert.equal(v.risk, 0);
  });
  it('renormalises the weights over the dimensions that apply', async () => {
    const r = await base();
    const v = computeVerdict({ parse: r, findings: [], checks: senderOk });
    const sum = v.dimensions.filter((d) => d.coverage >= 0).reduce((s, d) => s + d.effectiveWeight, 0);
    assert.ok(Math.abs(sum - 1) < 1e-9);
    assert.equal(v.dimensions.find((d) => d.dimension === 'attachment')!.active, false);
  });
  it('discounts stale reports', async () => {
    const r = await base();
    const mk = (observedAt: string) => computeVerdict({ parse: r, findings: [F('url_engine_detections', 'high', 'url', { observedAt, indicator: { type: 'url', value: 'https://a.example' } })], checks: senderOk, now: Date.parse('2026-11-07') }).contributions[0].value;
    assert.ok(mk('2024-01-01') < mk('2026-11-01'));
  });
  it('lists unmapped finding ids so a new rule cannot silently score by severity alone', async () => {
    const r = await base();
    const v = computeVerdict({ parse: r, findings: [F('brand_new_rule', 'high', 'content')], checks: senderOk });
    assert.deepEqual(v.unmapped, ['brand_new_rule']);
  });
});

describe('every emitted finding id has a scoring rule', () => {
  it('maps all finding ids found in the stage sources', () => {
    const dir = join(process.cwd(), 'shared/phishing');
    const src = readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.startsWith('verdict')).map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
    const ids = new Set<string>();
    for (const m of src.matchAll(/\bid: '([a-z0-9_]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/\bF\(\s*'([a-z0-9_]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/\bm\('([a-z0-9_]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/'(url_final_[a-z_]+)'/g)) ids.add(m[1]);
    // not findings: internal rule ids, check ids, signal ids and configuration keys that share the `id:` spelling
    const notFindings = /^(headers|auth|parse|sender|urls|attach|content)\.|^(consequence_account|deadline_or_else|urgency_words|verify_credentials|password_expiry_or_quota|security_alert_lure|signin_call_to_action|update_payment_details|overdue_payment|refund_lure|transfer_rails|gift_card_request|bank_details_changed|remit_to_new_account|payroll_change|availability_probe|secrecy_or_no_calls|crypto_threat|btc_wallet|delivery_problem|delivery_fee|prize_or_inheritance|document_share|attached_lure|qr_instruction|image_only|hidden_text|obfuscation|unknown|virustotal|malwarebazaar|circl|hybrid)$/;
    const missing = [...ids].filter((id) => !notFindings.test(id)).map((id) => id.replace(/^url_final_/, 'url_')).filter((id) => /^(attachment_|url_|link_|sender_|spf_|dkim_|dmarc_|auth_|arc_|content_|display_|role_|reply_|return_|multiple_|from_|supplied_|received_|date_|message_|untrusted_|x_|dangerous_|headers_)/.test(id) && !(id in POINTS));
    assert.deepEqual([...new Set(missing)].sort(), []);
  });
});
