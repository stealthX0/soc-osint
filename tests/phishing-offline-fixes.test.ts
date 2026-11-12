/** Fixes found by the 12 Nov offline sanity run (300 recent phishing samples, 400 SpamAssassin genuine messages). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSubmission } from '../shared/phishing/parse';
import { groupOf } from '../shared/phishing/verdictRules';
import { makeFinding } from '../shared/phishing/findings';

const hdr = (extra: string) => `From: Paul <pll@member.example>
To: users@lists.example
Subject: Re: config question
Date: Wed, 4 Nov 2026 09:00:00 +0000
Message-ID: <1@member.example>
${extra}
Content-Type: text/plain

Thanks, that fixed it.`;

test('a mailing list that sets Reply-To to the list is not a Reply-To redirect', async () => {
  const r = await parseSubmission({ headers: hdr('Reply-To: users@lists.example\nList-Id: Users list <users.lists.example>\nList-Post: <mailto:users@lists.example>') });
  assert.ok(!r.findings.some((f) => f.id === 'reply_to_mismatch'));
});

test('adding a List-Id header does not hide a Reply-To redirect aimed at the recipient', async () => {
  const raw = hdr('Reply-To: payments.desk@gmail.com\nList-Id: fake <x.lists.example>').replace('To: users@lists.example', 'To: victim@corp.example');
  const r = await parseSubmission({ headers: raw });
  assert.ok(r.findings.some((f) => f.id === 'reply_to_mismatch'));
});

test('weak brand mismatches (ordinary links) are one fact, action links stay separate', () => {
  const f = (severity: 'low' | 'medium', url: string) => makeFinding({ id: 'url_brand_mismatch', dimension: 'url', severity, title: 't', detail: 'd', indicator: { type: 'url', value: url } });
  assert.equal(groupOf(f('low', 'https://a.example/')), groupOf(f('low', 'https://b.example/')));
  assert.notEqual(groupOf(f('medium', 'https://a.example/')), groupOf(f('medium', 'https://b.example/')));
});
