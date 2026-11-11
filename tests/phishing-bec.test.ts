import { test } from 'node:test';
import assert from 'node:assert/strict';
import { latinLookalikes, quotedThread, stripReceiverBanners } from '../shared/phishing/content';

test('look-alike spellings are caught only when they spell a sensitive word', () => {
  assert.deepEqual(latinLookalikes('Attached is lnvoice P917891').map((x) => x[1]), ['invoice']);
  assert.deepEqual(latinLookalikes('lNVP917891.pdf').map((x) => x[1]), ['INVP917891']);
  assert.deepEqual(latinLookalikes('Sign in to paypa1 now').map((x) => x[1]), ['paypal']);
  assert.deepEqual(latinLookalikes('The lion and the lime stood at the line'), []);
});

test('receiver banners are removed, the sender text is kept', () => {
  const t = "[You don't often get email from a@b.example. Learn why this is important at https://aka.ms/LearnAboutSenderIdentification ]\n\nCaution: This email came from outside the company. Do not click links.\n\nPlease pay via ACH today.";
  const r = stripReceiverBanners(t);
  assert.ok(r.removed >= 2);
  assert.equal(r.text.trim(), 'Please pay via ACH today.');
  assert.equal(stripReceiverBanners('Hello there').removed, 0);
});

test('a quoted thread header is found with the forwarder note length', () => {
  const q = quotedThread('Please pay.\n\nFrom: Jo <jo@other.example>\nSent: Monday\nTo: Me\nSubject: x');
  assert.equal(q?.domain, 'other.example');
  assert.equal(q?.noteChars, 11);
  assert.equal(quotedThread('No thread here.'), null);
});

import { analyzeContent } from '../shared/phishing/content';
const ids = (text: string) => analyzeContent({ subject: null, text, html: null, linkCount: 0, attachments: [], displayName: null, fromDomain: 'vendor.example', fromIsFreeMail: false }).findings.map((f) => `${f.id}:${f.severity}`);

test('payment instructions are recognised on payment rails worldwide', () => {
  for (const rail of ['ACH', 'RTGS', 'NEFT', 'UPI', 'SEPA', 'BACS', 'CHAPS', 'Faster Payments', 'PIX', 'SPEI', 'Interac e-Transfer', 'PayNow', 'PromptPay', 'Zengin', 'telegraphic transfer']) {
    assert.ok(ids(`Please pay the balance via ${rail} today.`).includes('content_payment_demand:medium'), rail);
  }
  assert.ok(ids('Kindly remit by RTGS.').includes('content_payment_demand:low'));
  assert.ok(ids('Our IFSC code has changed, please note it.').some((x) => x.startsWith('content_financial_request')));
});

test('ordinary wording does not look like a payment instruction', () => {
  for (const t of ['We will process this with fast turnaround.', 'Send it by post today.', 'Make sure to bring the giro form to the meeting.']) {
    assert.ok(!ids(t).some((x) => x.startsWith('content_payment_demand')), t);
  }
});
