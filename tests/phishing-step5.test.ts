import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeContent, type ContentInput } from '../shared/phishing/content';
import { parseSubmission } from '../shared/phishing/parse';

const run = (over: Partial<ContentInput> & { text: string }) => {
  const r = analyzeContent({ subject: null, html: null, linkCount: 1, attachments: [], displayName: null, fromDomain: 'sender.example', fromIsFreeMail: false, ...over });
  return { ...r, ids: r.findings.map((f) => f.id), cats: r.analysis.categories.map((c) => c.id) };
};

describe('lure detection', () => {
  it('flags a classic credential phish: urgency with consequences + verify credentials', () => {
    const r = run({ subject: 'Action required: your mailbox will be suspended', text: 'Your account will be suspended within 24 hours unless you verify your password. Click here to verify your account now.' });
    assert.ok(r.ids.includes('content_urgency') && r.ids.includes('content_credential_request'));
    assert.equal(r.findings.find((f) => f.id === 'content_urgency')!.severity, 'low');
    assert.ok(r.findings.find((f) => f.id === 'content_urgency')!.evidence![0].toLowerCase().includes('suspended'));
    assert.equal(r.analysis.intents[0].id, 'credential_harvesting');
  });
  it('flags payment-redirection (invoice fraud) as medium', () => {
    const r = run({ text: 'Please note our bank details have changed. Kindly remit payment to the new account below and do not use the old account.', linkCount: 0 });
    assert.equal(r.findings.find((f) => f.id === 'content_payment_redirection')!.severity, 'medium');
    assert.equal(r.analysis.intents[0].id, 'financial_fraud');
  });
  it('flags gift-card requests, payroll diversion and sextortion', () => {
    assert.ok(run({ text: 'I need you to purchase 5 Google Play gift cards and send me the codes.', linkCount: 0 }).ids.includes('content_gift_card_request'));
    assert.ok(run({ text: 'I would like to update my direct deposit details before the next payroll run.', linkCount: 0 }).ids.includes('content_payroll_diversion'));
    const ext = run({ text: 'I hacked your webcam and recorded a video of you. Send $1500 in bitcoin to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT within 48 hours.', linkCount: 0 });
    assert.ok(ext.ids.includes('content_extortion'));
    assert.equal(ext.analysis.intents[0].id, 'extortion');
  });
  it('flags delivery, document-share, attachment and QR lures', () => {
    assert.ok(run({ text: 'We could not deliver your parcel. Reschedule delivery and pay the customs fee.' }).ids.includes('content_delivery_scam'));
    assert.ok(run({ text: 'A secure document has been shared with you. Review and sign here.' }).ids.includes('content_document_share_lure'));
    assert.ok(run({ text: 'Please find attached the payment receipt and remittance advice.' }).ids.includes('content_attachment_lure'));
    const qr = run({ text: 'To keep your account active, scan the QR code below with your phone to verify your login.', linkCount: 0 });
    assert.ok(qr.ids.includes('content_qr_lure'));
  });
  it('treats a short, link-free "are you available?" as a BEC probe, stronger from a consumer mailbox', () => {
    const a = run({ text: 'Are you available? I need a quick favor. Keep this confidential.', linkCount: 0, fromIsFreeMail: true });
    assert.equal(a.findings.find((f) => f.id === 'content_bec_request')!.severity, 'medium');
    const b = run({ text: 'Are you available? I need a quick favor.', linkCount: 0 });
    assert.equal(b.findings.find((f) => f.id === 'content_bec_request')!.severity, 'low');
    assert.ok(!run({ text: 'Are you available? I need a quick favor. ' + 'More text. '.repeat(120), linkCount: 3 }).ids.includes('content_bec_request'), 'long, link-heavy mail is not a BEC probe');
  });
  it('escalates to a combined finding when several lure types appear together', () => {
    const r = run({ text: 'Final notice: your account will be suspended within 24 hours. Verify your password and update your payment details. See the attached invoice.' });
    const f = r.findings.find((x) => x.id === 'content_multiple_lure_signals')!;
    assert.equal(f.severity, 'medium');
    assert.ok(f.evidence!.length >= 3);
  });
  it('flags a brand the sender does not own, but not the brand\'s own mail or a mere display-name case', () => {
    assert.ok(run({ subject: 'Your PayPal account is limited', text: 'Log in to restore access.', fromDomain: 'billing-support.example' }).ids.includes('content_brand_impersonation'));
    assert.ok(!run({ subject: 'Your PayPal account is limited', text: 'Log in to restore access.', fromDomain: 'paypal.com' }).ids.includes('content_brand_impersonation'));
    assert.ok(!run({ subject: 'Your PayPal account', text: 'x', fromDomain: 'billing-support.example', displayName: 'PayPal Support' }).ids.includes('content_brand_impersonation'), 'covered by display_name_brand_spoof');
  });
});

describe('evasion and structure', () => {
  it('detects look-alike letters and invisible characters', () => {
    const mixed = run({ text: 'Please verify your \u0440assword now.' }); // Cyrillic "р"
    assert.equal(mixed.findings.find((f) => f.id === 'content_text_obfuscation')!.severity, 'medium');
    assert.ok(run({ text: 'pass\u200b\u200bw\u200bo\u200br\u200bd \u200bre\u200bset\u200b' }).ids.includes('content_text_obfuscation'));
  });
  it('detects a large block of CSS-hidden text, but not a short pre-header', () => {
    const hidden = '<div style="display:none">' + 'lorem ipsum dolor sit amet '.repeat(12) + '</div><p>Hello</p>';
    assert.ok(run({ text: 'Hello', html: hidden }).ids.includes('content_hidden_text'));
    assert.ok(!run({ text: 'Hello', html: '<span style="display:none">Preview text &zwnj;&nbsp;&zwnj;</span><p>Hello</p>' }).ids.includes('content_hidden_text'));
  });
  it('flags an image-only body', () => {
    const r = run({ text: 'See below', linkCount: 0, attachments: [{ filename: null, inline: true, declaredType: 'image/png' }] });
    assert.ok(r.ids.includes('content_image_only_body'));
  });
  it('says so, instead of looking clean, when the text is not in a supported language', () => {
    const r = run({ text: 'Ваш аккаунт будет заблокирован в течение 24 часов. Подтвердите пароль немедленно, пожалуйста, перейдите по ссылке.' });
    assert.equal(r.analysis.languageSupported, false);
    assert.ok(r.ids.includes('content_language_not_analysed'));
  });
  it('reports nothing to analyse for an empty body', () => {
    const r = run({ text: '' });
    assert.equal(r.analysis.analysed, false);
    assert.equal(r.findings.length, 0);
  });
});

describe('legitimate mail stays quiet', () => {
  it('a genuine password reset produces at most low-level indicators and no combined finding', () => {
    const r = run({ subject: 'Reset your password', text: 'You recently asked to reset your password. Use the button below to choose a new one. This link expires in 24 hours. If you did not make this request, you can ignore this email.', fromDomain: 'accounts.example' });
    assert.ok(!r.ids.includes('content_multiple_lure_signals'));
    assert.ok(r.findings.every((f) => f.severity === 'low' || f.severity === 'info'));
  });
  it('a normal invoice reminder and meeting note raise nothing serious', () => {
    const inv = run({ text: 'Hello, your invoice 4411 for October is attached. Payment is due on 15 November. Thanks for your business.', attachments: [{ filename: 'invoice.pdf', inline: false, declaredType: 'application/pdf' }] });
    assert.ok(inv.findings.every((f) => f.severity === 'low' || f.severity === 'info'));
    assert.deepEqual(run({ text: 'Notes from today\'s planning meeting are on the team wiki. Please add your actions before Friday.' }).findings, []);
  });
  it('findings never carry a verdict-level severity from wording alone', () => {
    const r = run({ text: 'URGENT final notice: account will be suspended within 24 hours. Verify password. Update bank details. Gift cards. Invoice attached. Scan the QR code.' });
    assert.ok(r.findings.every((f) => f.severity !== 'high' && f.severity !== 'critical'));
  });
});

describe('ordinary bulk and internal mail', () => {
  it('a promotional newsletter with an in-store QR code is not a QR phish', () => {
    const r = run({ subject: 'Weekly digest', text: 'Act now to save 20%, sale ends today! Scan the QR code in store for a free coffee. Unsubscribe any time.', fromDomain: 'shop.example' });
    assert.equal(r.findings.find((f) => f.id === 'content_qr_lure')!.severity, 'low');
    assert.ok(r.findings.every((f) => f.severity !== 'medium'));
  });
  it('an HR payroll calendar is not payroll diversion', () => {
    assert.deepEqual(run({ text: 'The payroll for November will be processed on the 28th. Salary details are available in the HR portal.' }).findings, []);
    assert.ok(run({ text: 'Please switch my salary to my new bank account before the 28th.', linkCount: 0 }).ids.includes('content_payroll_diversion'));
  });
  it('a QR code that asks you to verify a login is medium once a real lure is present', () => {
    const r = run({ text: 'Your password expires today. Scan the QR code to verify your login and keep your account active.', linkCount: 0 });
    assert.equal(r.findings.find((f) => f.id === 'content_qr_lure')!.severity, 'medium');
  });
});

describe('parse stage integration', () => {
  it('adds the wording analysis, findings and a check row to the parse result', async () => {
    const r = await parseSubmission({
      headers: 'From: "IT Helpdesk" <helpdesk@gmail.com>\nSubject: Mailbox full\nContent-Type: text/plain',
      body: 'Your mailbox is full and your account will be disabled within 24 hours. Verify your password here: https://example.org/x',
    });
    assert.ok(r.findings.some((f) => f.id === 'content_credential_request'));
    assert.ok(r.findings.some((f) => f.id === 'role_impersonation_freemail'));
    assert.equal(r.content.analysis.analysed, true);
    assert.equal(r.checks.find((c) => c.id === 'content.rules')!.status, 'complete');
  });
  it('skips the check for a message with no text', async () => {
    const r = await parseSubmission({ urls: ['https://example.org/a'] });
    assert.equal(r.checks.find((c) => c.id === 'content.rules')!.status, 'skipped');
  });
});
