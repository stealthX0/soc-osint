import { test } from 'node:test';
import assert from 'node:assert/strict';
import { glance } from '../src/pages/phishing/keyFindingGlance';
import type { Finding } from '../shared/phishing/types';

const f = (id: string, severity: Finding['severity'], title: string) => ({ id, severity, title } as Finding);

test('a known finding gets its plain-language headline and its title as the summary', () => {
  assert.deepEqual(glance('url', 'bad', true, [f('url_listed_phishing', 'critical', 'Link is on a phishing blocklist')]), { headline: 'Known Phishing Link', summary: 'Link is on a phishing blocklist' });
  assert.equal(glance('url', 'warn', true, [f('url_redirect_cross_domain', 'medium', 'x')]).headline, 'Redirecting Link');
  assert.equal(glance('authentication', 'warn', true, [f('display_name_brand_spoof', 'high', 'x')]).headline, 'Impersonated Sender');
});

test('an unmapped or minor finding falls back to a headline by area and risk', () => {
  assert.equal(glance('content', 'bad', true, [f('something_new', 'high', 'x')]).headline, 'Phishing Wording');
  assert.equal(glance('url', 'info', true, [f('url_shortener', 'low', 'Uses a link shortener')]).headline, 'Minor Link Notes');
});

test('quiet areas say so without calling the message safe', () => {
  assert.equal(glance('infrastructure', 'good', true, []).headline, 'No Warning Signs');
  assert.equal(glance('attachment', 'neutral', false, []).headline, 'Not Checked');
  assert.equal(glance('authentication', 'good', true, [f('internal_m365_message', 'info', 'Internal Microsoft 365 message')]).headline, 'Internal Message');
  for (const g of [glance('url', 'good', true, []), glance('url', 'neutral', false, [])]) assert.doesNotMatch(`${g.headline} ${g.summary}`, /safe|clean|legitimate/i);
});

const row = (id: string, status: 'complete' | 'skipped', result: string | null = null) => ({ id, label: id, status, result });

test('a clean area gets a positive headline only from checks that ran and passed', () => {
  const auth = [row('auth.spf', 'complete', 'pass (receiver)'), row('auth.dkim', 'complete', 'pass, pass (receiver)'), row('auth.dmarc', 'complete', 'pass (receiver)')];
  assert.deepEqual(glance('authentication', 'good', true, [], auth), { headline: 'Sender Verified', summary: 'SPF, DKIM and DMARC all passed.' });
  assert.equal(glance('authentication', 'good', true, [], [row('auth.spf', 'complete', 'pass (receiver)'), row('auth.dkim', 'skipped')]).headline, 'Sender Checks Passed');
  assert.equal(glance('authentication', 'good', true, [], [row('auth.spf', 'complete', 'softfail (receiver)')]).headline, 'No Warning Signs', 'a non-pass result is never called verified');
  assert.equal(glance('url', 'good', true, [], [row('urls.deep', 'complete', '2 of 2 links')]).headline, 'No Known-Bad Links');
  assert.equal(glance('url', 'good', true, [], [row('urls.offline', 'complete')]).headline, 'No Link Warnings');
  assert.equal(glance('attachment', 'good', true, [], [row('attach.0.hash.virustotal', 'complete', 'not found')]).headline, 'No Known Malware');
  assert.equal(glance('content', 'good', true, [], [row('content.rules', 'complete')]).headline, 'No Phishing Wording');
});

test('a positive headline never hides a real finding', () => {
  const auth = [row('auth.spf', 'complete', 'pass (receiver)'), row('auth.dkim', 'complete', 'pass (receiver)'), row('auth.dmarc', 'complete', 'pass (receiver)')];
  assert.equal(glance('authentication', 'warn', true, [f('reply_to_mismatch', 'medium', 'Replies go elsewhere')], auth).headline, 'Replies Go Elsewhere');
  assert.equal(glance('authentication', 'good', true, [f('dkim_weak_algorithm', 'low', 'Weak DKIM key')], auth).headline, 'Minor Sender Notes');
  for (const g of [glance('authentication', 'good', true, [], auth), glance('url', 'good', true, [], [row('urls.deep', 'complete')])]) assert.doesNotMatch(`${g.headline} ${g.summary}`, /safe|clean|legitimate/i);
});

test('reputation hits say "Malicious" only when critical, or high on a Malicious verdict', () => {
  const dns = [f('url_dns_blocked', 'high', 'Blocked by Cloudflare Security DNS')];
  assert.equal(glance('url', 'warn', true, dns, [], false).headline, 'Flagged Link', 'Suspicious verdict: no overclaim');
  assert.equal(glance('url', 'warn', true, dns, [], true).headline, 'Malicious Link');
  assert.equal(glance('url', 'warn', true, [f('url_engine_detections', 'medium', 'x')], [], true).headline, 'Flagged Link');
  assert.equal(glance('url', 'bad', true, [f('url_engine_detections', 'critical', 'x')], [], false).headline, 'Malicious Link');
  assert.equal(glance('infrastructure', 'warn', true, [f('sender_ip_abuse_reports', 'medium', 'x')]).headline, 'Flagged Sender IP');
  assert.equal(glance('url', 'bad', true, [f('something_new', 'high', 'x')], [], false).headline, 'High-Risk Link');
  assert.equal(glance('url', 'bad', true, [f('something_new', 'high', 'x')], [], true).headline, 'Malicious Link');
});

test('factual checks keep strong wording at high severity and soften at medium', () => {
  assert.equal(glance('attachment', 'warn', true, [f('attachment_dangerous_type', 'high', 'x')]).headline, 'Dangerous Attachment');
  assert.equal(glance('attachment', 'warn', true, [f('attachment_dangerous_type', 'medium', 'x')]).headline, 'Risky Attachment Type');
  assert.equal(glance('authentication', 'warn', true, [f('sender_domain_lookalike', 'medium', 'x')]).headline, 'Possible Impersonation');
});
