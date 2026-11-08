/**
 * Calibration corpus for the phishing verdict engine.
 *
 * Each sample is a realistic (synthetic, fully anonymised) scenario with the verdict(s) a careful analyst would accept.
 * Lookup results are described declaratively (findings + check rows), because the real providers cannot be called from a test.
 *
 * HOW TO ADD A REAL SAMPLE
 *  1. Take the headers and body of a real message and anonymise them (see docs/phishing-calibration.md): replace people,
 *     internal hosts and your own domains; keep the structure, the authentication results and the wording.
 *  2. Run it through the page, note which lookups returned what, and write them below as `findings` (use `lookup(...)`) and `checks`.
 *  3. Set `expect` to the verdict(s) you would accept. More than one value means "either is defensible".
 *  4. `npm run calibrate:phishing` shows how the engine does; `npm test` fails if a sample regresses.
 */
import { makeFinding } from '../../shared/phishing/findings';
import type { Dimension, Finding, PhishingInput, Severity } from '../../shared/phishing/types';
import type { CheckRow, VerdictLabel } from '../../shared/phishing/verdict';

export interface MailSpec {
  from: string; fromName?: string; replyTo?: string; returnPath?: string; subject?: string;
  recv?: 'gmail' | 'm365'; ip?: string; spf?: 'pass' | 'fail' | 'softfail' | 'none'; dkim?: 'pass' | 'fail' | 'none'; dkimDomain?: string; dmarc?: 'pass' | 'fail' | 'none';
  ct?: string; extra?: string;
}

/** Builds realistic headers delivered to Gmail (named authserv-id) or Microsoft 365 (no authserv-id). */
export function mail(s: MailSpec): string {
  const ip = s.ip ?? '198.51.100.25';
  const fromDomain = s.from.split('@')[1];
  const rp = s.returnPath ?? s.from;
  const dkimDomain = s.dkimDomain ?? fromDomain;
  const spf = s.spf ?? 'pass'; const dkim = s.dkim ?? 'pass'; const dmarc = s.dmarc ?? (spf === 'pass' || dkim === 'pass' ? 'pass' : 'fail');
  const recv = s.recv ?? 'gmail';
  const lines: string[] = [];
  if (recv === 'gmail') {
    lines.push(`Received: by 2002:a05:6a00:1 with SMTP id x1csp1; Tue, 3 Nov 2026 10:05:00 -0800 (PST)`);
    lines.push(`Received: from mail.${fromDomain} (mail.${fromDomain} [${ip}]) by mx.google.com with ESMTPS id abc123; Tue, 3 Nov 2026 10:04:50 -0800 (PST)`);
    lines.push(`Authentication-Results: mx.google.com; dkim=${dkim} header.i=@${dkimDomain} header.s=s1; spf=${spf} (google.com: domain of ${rp} designates ${ip} as permitted sender) smtp.mailfrom=${rp}; dmarc=${dmarc} (p=REJECT sp=REJECT dis=NONE) header.from=${fromDomain}`);
  } else {
    lines.push('Received: from DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) by BN9PR12MB2222.namprd12.prod.outlook.com with HTTPS; Wed, 4 Nov 2026 09:00:05 +0000');
    lines.push(`Received: from mail.${fromDomain} (${ip}) by DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) with Microsoft SMTP Server; Wed, 4 Nov 2026 09:00:04 +0000`);
    lines.push(`Authentication-Results: spf=${spf} (sender IP is ${ip}) smtp.mailfrom=${rp.split('@')[1] ?? rp}; dkim=${dkim} header.d=${dkimDomain};dmarc=${dmarc} action=none header.from=${fromDomain};compauth=pass reason=100`);
  }
  lines.push(`Return-Path: <${rp}>`);
  lines.push(`From: ${s.fromName ? `"${s.fromName}" ` : ''}<${s.from}>`);
  if (s.replyTo) lines.push(`Reply-To: ${s.replyTo}`);
  lines.push('To: user@corp.example', `Subject: ${s.subject ?? 'Hello'}`, 'Date: Wed, 4 Nov 2026 09:00:00 +0000', `Message-ID: <m1@${fromDomain}>`, `Content-Type: ${s.ct ?? 'text/plain'}`);
  if (s.extra) lines.push(s.extra);
  return lines.join('\n');
}

export const ok = (id: string, label = id): CheckRow => ({ id, label, status: 'complete', result: 'ok' });
export const bad = (id: string, label = id): CheckRow => ({ id, label, status: 'failed', result: null, detail: 'provider error' });

/** A finding as a lookup stage would have produced it. */
export function lookup(id: string, severity: Severity, dimension: Dimension, over: Partial<Finding> = {}): Finding {
  return makeFinding({ id, dimension, severity, title: id.replace(/_/g, ' '), detail: `${id}`, source: 'corpus', exactness: 'exact', reliability: 'high', trust: 'independently_verified', ...over });
}

/** Every sender lookup completed. */
export const SENDER_DONE: CheckRow[] = [ok('sender.ip.x', 'IP intelligence'), ok('sender.domain.x', 'Domain registration'), ok('sender.auth.x', 'Mail security DNS'), ok('sender.spf.x', 'SPF re-check')];
/** The link investigation ran and finished. */
export const LINKS_DONE: CheckRow[] = [ok('urls.openphish', 'OpenPhish'), ok('urls.provider.virustotal', 'VirusTotal')];
/** The only attachment (index 0) was assessed: static analysis and a hash lookup. */
export const ATTACHMENT_DONE: CheckRow[] = [ok('attach.0.static', 'Static analysis'), ok('attach.0.hash.virustotal', 'VirusTotal hash lookup')];

export interface CorpusSample {
  id: string;
  description: string;
  /** Verdicts an analyst would accept. */
  expect: VerdictLabel[];
  input: PhishingInput;
  findings?: Finding[];
  checks?: CheckRow[];
}

const url = (value: string) => ({ type: 'url' as const, value });
const sha = (c: string) => c.repeat(64);

export const CORPUS: CorpusSample[] = [
  /* ------------------------------------------------------------ legitimate */
  { id: 'L01-partner-authenticated', description: 'Authenticated mail from a known partner, no links', expect: ['likely_legitimate'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365', subject: 'Meeting notes' }), body: 'Notes from today are on the wiki. Thanks, Alice.' }, checks: SENDER_DONE },
  { id: 'L02-password-reset', description: 'Genuine SaaS password reset (credential wording, aligned DKIM through a mailing service)', expect: ['likely_legitimate'], input: { headers: mail({ from: 'no-reply@accounts.saas.example', returnPath: 'bounce@mail.saas.example', dkimDomain: 'saas.example', subject: 'Reset your password' }), body: 'You asked to reset your password. Choose a new one with the button below. If you did not ask for this, ignore this email.' }, checks: SENDER_DONE },
  { id: 'L03-newsletter-esp', description: 'Newsletter through a mailing service: Return-Path differs, DKIM aligned, shared platform IP', expect: ['likely_legitimate'], input: { headers: mail({ from: 'news@brand.example', returnPath: 'bounce@esp-mail.example', subject: 'November newsletter' }), body: 'Our November newsletter is out. Unsubscribe any time.' }, findings: [lookup('sender_infra_shared_provider', 'info', 'infrastructure'), lookup('return_path_mismatch', 'info', 'authentication', { trust: 'derived' })], checks: SENDER_DONE },
  { id: 'L04-internal-invite', description: 'Calendar-style internal note with no links', expect: ['likely_legitimate'], input: { headers: mail({ from: 'bob@corp.example', recv: 'm365', subject: 'Sync tomorrow' }), body: 'Can we move our sync to 3pm tomorrow? Same room.' }, checks: SENDER_DONE },
  { id: 'L05-shipping-notice', description: 'Courier notice with a tracking link, investigated and clean', expect: ['likely_legitimate'], input: { headers: mail({ from: 'tracking@courier.example', subject: 'Your parcel is on its way' }), body: 'Your parcel has shipped and delivery is expected Friday. Track it: https://courier.example/track/123' }, checks: [...SENDER_DONE, ...LINKS_DONE] },
  { id: 'L06-vendor-invoice', description: 'Invoice from a known vendor with a PDF attachment, hash looked up, nothing found', expect: ['likely_legitimate'], input: { headers: mail({ from: 'billing@vendor.example', subject: 'Invoice 4411' }), body: 'Hello, your invoice 4411 for October is attached. Payment is due on 15 November.', attachments: [{ name: 'invoice-4411.pdf', hash: sha('a') }] }, findings: [lookup('attachment_hash_unknown', 'info', 'attachment', { indicator: { type: 'hash', value: sha('a') } })], checks: [...SENDER_DONE, ok('attach.0.hash.virustotal', 'VirusTotal hash lookup')] },
  { id: 'L07-hr-calendar', description: 'HR payroll calendar announcement (payroll wording, no request to change anything)', expect: ['likely_legitimate'], input: { headers: mail({ from: 'hr@corp.example', recv: 'm365', subject: 'Payroll calendar' }), body: 'The payroll for November will be processed on the 28th. Salary details are available in the HR portal.' }, checks: SENDER_DONE },
  { id: 'L08-bad-ip-shared-infra', description: 'Clean authenticated mail whose sending IP (a large shared platform) has abuse reports', expect: ['likely_legitimate'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365', subject: 'Notes' }), body: 'See you at 10.' }, findings: [lookup('sender_infra_shared_provider', 'info', 'infrastructure'), lookup('sender_ip_abuse_reports', 'medium', 'infrastructure')], checks: SENDER_DONE },

  /* ----------------------------------------------------------- suspicious */
  { id: 'S01-bec-freemail', description: 'Executive-style "are you available?" from a consumer mailbox', expect: ['suspicious'], input: { headers: mail({ from: 'ceo.office@gmail.com', fromName: 'Dana Smith, CEO', subject: 'Quick task' }), body: 'Are you available? I need a quick favor. Keep this confidential.' }, checks: SENDER_DONE },
  { id: 'S02-invoice-redirect-authentic', description: 'Vendor mailbox that authenticates correctly asks to pay a NEW bank account (account takeover)', expect: ['suspicious'], input: { headers: mail({ from: 'billing@vendor.example', recv: 'm365', subject: 'Updated payment details' }), body: 'Please note our bank details have changed. Remit payment to the new account below and do not use the old account.' }, checks: SENDER_DONE },
  { id: 'S03-credential-phish-unchecked', description: 'Spoofed bank: failed authentication, urgent credential wording, link not yet investigated', expect: ['suspicious'], input: { headers: mail({ from: 'security@bank.example', fromName: 'Bank Security', ip: '203.0.113.50', returnPath: 'bounce@mailer.badhost.example', spf: 'fail', dkim: 'none', dmarc: 'fail', replyTo: 'support.desk77@gmail.com', subject: 'Your account is locked', ct: 'text/html' }), body: '<a href="https://bank-secure-login.example/verify">https://www.bank.example/login</a> Your account will be suspended within 24 hours unless you verify your password.' }, checks: SENDER_DONE },
  { id: 'S04-lookalike-domain', description: 'Look-alike sender domain imitating a payments brand, otherwise unremarkable', expect: ['suspicious'], input: { headers: mail({ from: 'service@paypa1.example', fromName: 'PayPal', subject: 'Receipt for your payment' }), body: 'Thanks for your payment. View your receipt in your account.' }, findings: [lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },
  { id: 'S05-auth-only-failure', description: 'Plain note whose only problem is SPF, DKIM and DMARC all failing', expect: ['suspicious', 'inconclusive'], input: { headers: mail({ from: 'carol@vendor.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Hello' }), body: 'Hi, just checking in about next week.' }, checks: SENDER_DONE },
  { id: 'S06-freemail-brand-display', description: 'Free mailbox using a Microsoft support display name', expect: ['suspicious'], input: { headers: mail({ from: 'ms.accountteam@outlook.com', fromName: 'Microsoft Account Team', subject: 'Unusual sign-in activity' }), body: 'We detected unusual sign-in activity. Please review your account.' }, findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },
  { id: 'S07-delivery-scam', description: 'Failed-delivery notice from an unrelated domain with a shortened link, not investigated', expect: ['suspicious', 'inconclusive'], input: { headers: mail({ from: 'delivery@track-parcel.example', subject: 'Delivery problem' }), body: 'We could not deliver your parcel. Reschedule delivery and pay the customs fee: https://bit.ly/3xYz' }, checks: SENDER_DONE },
  { id: 'S08-nonenglish-spoof', description: 'Russian-language account threat with failed authentication', expect: ['suspicious'], input: { headers: mail({ from: 'support@bank.example', spf: 'fail', dkim: 'none', dmarc: 'fail', ip: '203.0.113.77', subject: 'Важное уведомление' }), body: 'Ваш аккаунт будет заблокирован в течение 24 часов. Подтвердите пароль немедленно, пожалуйста, перейдите по ссылке и введите данные.' }, checks: SENDER_DONE },
  { id: 'S09-impersonation-heuristic-link', description: 'Brand impersonation with a link flagged only by local heuristics (no external confirmation)', expect: ['suspicious'], input: { headers: mail({ from: 'support@account-help.example', fromName: 'PayPal Support', subject: 'Verify your account' }), body: 'Verify your account: https://account-help.example/paypal/login' }, findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_brand_mismatch', 'medium', 'url', { source: 'url-heuristics', trust: 'derived', indicator: url('https://account-help.example/paypal/login') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ------------------------------------------------------------ malicious */
  { id: 'M01-listed-url-authentic-sender', description: 'Compromised but fully authenticated mailbox sending a link listed by OpenPhish', expect: ['malicious'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365', subject: 'Shared document' }), body: 'I shared a document with you: https://docs-share.example/open?id=9' }, findings: [lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: url('https://docs-share.example/open?id=9') })], checks: [...SENDER_DONE, ...LINKS_DONE] },
  { id: 'M02-malware-attachment', description: 'Attachment whose exact hash is confirmed malware', expect: ['malicious'], input: { headers: mail({ from: 'accounts@supplier.example', subject: 'Payment advice' }), body: 'Payment advice attached.', attachments: [{ name: 'advice.xlsm', hash: sha('b') }] }, findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('b') } })], checks: [...SENDER_DONE, ok('attach.0.hash.malwarebazaar')] },
  { id: 'M03-impersonation-bad-destination', description: 'Brand impersonation whose link is rated high-risk by a threat-intelligence feed', expect: ['malicious'], input: { headers: mail({ from: 'noreply@acct-update.example', fromName: 'Microsoft 365', subject: 'Password expires today' }), body: 'Your password expires today. Keep it: https://acct-update.example/o365' }, findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_threat_intel_rating', 'high', 'url', { source: 'Pulsedive', exactness: 'related', indicator: url('https://acct-update.example/o365') })], checks: [...SENDER_DONE, ...LINKS_DONE] },
  { id: 'M04-html-credential-attachment', description: 'HTML attachment with a password form, from a look-alike sender', expect: ['malicious'], input: { headers: mail({ from: 'docs@sharepoint-docs.example', subject: 'Remittance advice' }), body: 'Open the attached remittance advice.', attachments: [{ name: 'remittance.html', hash: sha('c') }] }, findings: [lookup('attachment_html_credential_form', 'high', 'attachment', { trust: 'derived', indicator: { type: 'hash', value: sha('c') } }), lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },
  { id: 'M05-sextortion', description: 'Bulk sextortion message with a Bitcoin wallet', expect: ['malicious'], input: { headers: mail({ from: 'x1y2z3@mailbox.example', subject: 'I recorded you' }), body: 'I hacked your webcam and recorded a video of you. Send $1500 in bitcoin to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT within 48 hours or I will expose it to your contacts.' }, checks: SENDER_DONE },
  { id: 'M06-two-sources', description: 'The same URL flagged by two independent providers', expect: ['malicious'], input: { headers: mail({ from: 'notice@service.example', subject: 'Action needed' }), body: 'Please confirm: https://confirm-now.example/a' }, findings: [lookup('url_engine_detections', 'high', 'url', { source: 'VirusTotal', indicator: url('https://confirm-now.example/a') }), lookup('url_scan_malicious', 'high', 'url', { source: 'urlscan.io', indicator: url('https://confirm-now.example/a') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* --------------------------------------------------------- inconclusive */
  { id: 'I01-no-headers', description: 'Only a body was pasted: nothing vouches for the sender', expect: ['inconclusive'], input: { body: 'Hello, please see the notes on the wiki.' } },
  { id: 'I02-links-not-checked', description: 'Clean-looking message whose link has not been investigated', expect: ['inconclusive'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365' }), body: 'Details are at https://partner.example/notes' }, checks: SENDER_DONE },
  { id: 'I03-lookups-failed', description: 'Every sender lookup failed (provider outage)', expect: ['inconclusive'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365' }), body: 'Hi.' }, checks: [bad('sender.ip.x', 'IP intelligence'), bad('sender.domain.x', 'Domain registration'), bad('sender.auth.x', 'Mail security DNS')] },
  { id: 'I04-conflicting-auth', description: 'Headers report DMARC pass but nothing aligns with the From domain', expect: ['inconclusive', 'suspicious'], input: { headers: mail({ from: 'alice@partner.example', recv: 'm365' }), body: 'Hi.' }, findings: [lookup('auth_conflict', 'medium', 'authentication', { trust: 'derived', detail: 'DMARC pass but no aligned SPF or DKIM' })], checks: SENDER_DONE },
  { id: 'I05-attachment-unassessed', description: 'Invoice with an attachment that was never looked up', expect: ['inconclusive'], input: { headers: mail({ from: 'billing@vendor.example' }), body: 'Invoice attached.', attachments: [{ name: 'invoice.pdf' }] }, checks: SENDER_DONE },
];
