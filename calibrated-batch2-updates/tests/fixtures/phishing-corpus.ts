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

  /* ================================================================= */
  /* EXPANDED CORPUS — real-world patterns from Nazario, SpamAssassin, */
  /* PhishingPot, EPVME, Enron and documented attack campaigns.       */
  /* ================================================================= */

  /* ------------------------------------------- legitimate (real-world) */

  // Pattern: Enron-style internal business discussion (Enron Corpus)
  { id: 'L09-internal-biz-discussion', description: 'Internal business discussion about energy trading (Enron-style)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'john.lavorato@corp.example', recv: 'm365', subject: 'Re: West desk P&L' }), body: 'The west desk is showing $1.2M above plan for October. Can you pull the summary for the Monday meeting? Thanks, John' }, checks: SENDER_DONE },

  // Pattern: SpamAssassin ham — mailing list (Apache mailing list style)
  { id: 'L10-mailing-list', description: 'Public mailing list post with list headers (SpamAssassin corpus pattern)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'contributor@opensource.example', subject: 'Re: [dev] RFC: new cache layer', extra: 'List-Id: <dev.lists.opensource.example>\nList-Unsubscribe: <mailto:dev-unsubscribe@lists.opensource.example>' }), body: 'I agree with the approach. The LRU eviction policy makes sense for our workload. One concern: should we cap at 512MB or make it configurable?' }, checks: SENDER_DONE },

  // Pattern: Authenticated transactional SaaS notification
  { id: 'L11-saas-usage-alert', description: 'SaaS usage alert (authenticated, no action required)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'alerts@monitoring.saas.example', dkimDomain: 'saas.example', subject: 'Storage usage: 80% of quota' }), body: 'Your team workspace has reached 80% of the 50 GB storage quota. Consider archiving old files. This is an informational message; no action is required.' }, checks: SENDER_DONE },

  // Pattern: Legitimate marketing from ESP (SendGrid/Mailchimp-style)
  { id: 'L12-marketing-esp', description: 'Marketing email through ESP with clean link investigated', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'offers@shop.example', returnPath: 'bounce-1234@sendgrid.example', dkimDomain: 'shop.example', subject: 'Weekend sale: 20% off everything' }), body: 'Shop our weekend sale! Use code SAVE20 at checkout. https://shop.example/sale  Unsubscribe: https://shop.example/unsub' },
    findings: [lookup('sender_infra_shared_provider', 'info', 'infrastructure'), lookup('return_path_mismatch', 'info', 'authentication', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Authenticated ticket update from support system
  { id: 'L13-support-ticket', description: 'Support ticket update from authenticated helpdesk system', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'support@helpdesk.vendor.example', recv: 'm365', dkimDomain: 'vendor.example', subject: 'Re: [Ticket #8891] API rate limit question' }), body: 'Hi, your rate limit has been increased to 10,000 requests/hour as requested. The change is effective immediately. Please let us know if you have any further questions. — Support Team' }, checks: SENDER_DONE },

  // Pattern: GitHub/GitLab notification (platform notification)
  { id: 'L14-github-notification', description: 'Legitimate GitHub-style platform notification about PR merge', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'notifications@github.example', dkimDomain: 'github.example', subject: '[repo/project] Pull request #423 merged' }), body: 'johndoe merged pull request #423: Fix null pointer in auth handler. 3 commits, 2 files changed. View it on GitHub: https://github.example/repo/project/pull/423' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Cloud billing notification
  { id: 'L15-cloud-billing', description: 'Cloud provider billing notification with authenticated sender', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'billing@cloud-provider.example', dkimDomain: 'cloud-provider.example', subject: 'Your invoice for October 2026 is available' }), body: 'Your October 2026 invoice for account 1234-5678 totals $847.23. View and download your invoice at https://cloud-provider.example/billing/invoices. Payment will be charged to your card on file.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Recruiter outreach (legitimate cold email)
  { id: 'L16-recruiter-outreach', description: 'Recruiter outreach from corporate domain with investigated link', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'sarah.jones@recruiting.bigcorp.example', dkimDomain: 'bigcorp.example', subject: 'Engineering opportunity at BigCorp' }), body: 'Hi, I came across your profile and think you would be a great fit for our senior backend engineering role. Would you be open to a 15-minute call? You can see the job description here: https://careers.bigcorp.example/jobs/12345' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Legitimate document shared via Box/Dropbox (real file-sharing)
  { id: 'L17-legit-file-share', description: 'Authenticated file-sharing notification from Box/Dropbox-style service', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'noreply@fileshare.example', dkimDomain: 'fileshare.example', subject: 'Alice shared "Q3 Budget.xlsx" with you' }), body: 'Alice (alice@partner.example) shared a file with you. Click to view: https://fileshare.example/s/abc123def456. This link expires in 7 days.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Subscription renewal reminder (legitimate)
  { id: 'L18-subscription-renewal', description: 'Authenticated subscription renewal notice with financial wording', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'billing@software.example', dkimDomain: 'software.example', subject: 'Your subscription renews on Dec 1' }), body: 'Your annual Pro plan ($299/year) renews on December 1, 2026. If you would like to change or cancel your plan, visit https://software.example/account/billing before the renewal date.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ------------------------------------------- suspicious (real-world) */

  // Pattern: Nazario corpus — PayPal phishing (spoofed but links not yet investigated)
  { id: 'S10-paypal-spoof-unchecked', description: 'Spoofed PayPal account limitation notice, auth failed, links not checked (Nazario pattern)', expect: ['suspicious'],
    input: { headers: mail({ from: 'service@paypal.example', fromName: 'PayPal', spf: 'fail', dkim: 'none', dmarc: 'fail', ip: '203.0.113.90', subject: 'Your account access has been limited', ct: 'text/html' }), body: 'Dear PayPal Customer, We have noticed unusual activity on your account. Your account has been limited until we hear from you. Restore access: <a href="https://paypal-verify.example/restore">https://www.paypal.example/restore</a>. If you do not respond within 48 hours your account will be permanently suspended.' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  // Pattern: Nazario corpus — eBay/auction site phishing
  { id: 'S11-auction-spoof', description: 'eBay-style auction dispute from spoofed domain with urgency (Nazario pattern)', expect: ['suspicious'],
    input: { headers: mail({ from: 'resolution@ebay-center.example', fromName: 'eBay Resolution Center', spf: 'softfail', dkim: 'none', dmarc: 'fail', subject: 'Case opened: Item Not Received #4892771' }), body: 'A case has been opened against you for item #389012345678. If you do not respond within 3 days, a refund will be issued to the buyer automatically. Respond now: https://ebay-center.example/case/4892771' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  // Pattern: BEC wire transfer (from compromised vendor — authenticated!)
  { id: 'S12-bec-wire-transfer', description: 'Authenticated vendor asking for urgent wire transfer to a new account (BEC pattern)', expect: ['suspicious'],
    input: { headers: mail({ from: 'cfo@vendor.example', recv: 'm365', subject: 'Urgent: Wire transfer needed today' }), body: 'We have a time-sensitive payment that needs to go out today. Please wire $47,500 to the following account: Bank: First National, Account: 9182736450, Routing: 021000021. This is confidential — please do not discuss with others until completed.' },
    findings: [lookup('content_financial_request', 'high', 'content', { trust: 'derived' }), lookup('content_bec_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: EPVME — subdomain spoofing (SPF bypass via subdomain)
  { id: 'S13-subdomain-spoof', description: 'Subdomain spoofing attack: security.bank.example has no SPF, DMARC passes on org domain', expect: ['suspicious'],
    input: { headers: mail({ from: 'alert@security.bank.example', fromName: 'Bank Security Alert', spf: 'none', dkim: 'none', dmarc: 'pass', subject: 'Suspicious login detected' }), body: 'We detected a login from an unrecognized device in Moscow, Russia. If this was not you, secure your account immediately: https://security.bank.example/verify-identity' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: QR code phishing (documented in incident response reports)
  { id: 'S14-qr-code-phish', description: 'QR code MFA re-enrollment phish from spoofed IT department', expect: ['suspicious'],
    input: { headers: mail({ from: 'it-security@corp.example', recv: 'm365', subject: 'ACTION REQUIRED: MFA re-enrollment by Friday', ct: 'text/html' }), body: 'Due to our security upgrade, all employees must re-enroll in Multi-Factor Authentication by this Friday. Scan the QR code below with your phone camera to begin the enrollment process. [QR code image] Failure to re-enroll will result in account lockout.' },
    findings: [lookup('content_qr_lure', 'high', 'content', { trust: 'derived' }), lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Gift card scam BEC (common real-world attack)
  { id: 'S15-gift-card-scam', description: 'CEO impersonation asking to buy gift cards (BEC gift card pattern)', expect: ['suspicious'],
    input: { headers: mail({ from: 'ceo.dana.smith@gmail.com', fromName: 'Dana Smith', subject: 'Favor needed' }), body: 'Hi, I need you to purchase 5 Apple gift cards at $100 each for a client appreciation event. Please buy them today and send me photos of the card numbers and PINs. I will reimburse you. This is urgent, I am in a meeting and cannot call. Thanks, Dana' },
    findings: [lookup('content_gift_card_request', 'high', 'content', { trust: 'derived' }), lookup('content_bec_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: Voicemail notification phish
  { id: 'S16-voicemail-phish', description: 'Fake voicemail notification with credential-harvesting link, auth failed', expect: ['suspicious'],
    input: { headers: mail({ from: 'voicemail@phone-system.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'New voicemail from +1 (555) 012-3456' }), body: 'You have a new voicemail message (duration: 0:47). Listen to your voicemail: https://phone-system.example/vm/play?id=8837. This message will be deleted in 24 hours.' },
    findings: [lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: Payroll diversion (authenticated sender — compromised HR)
  { id: 'S17-payroll-diversion', description: 'Authenticated HR mailbox requesting direct deposit change (payroll diversion)', expect: ['suspicious'],
    input: { headers: mail({ from: 'hr@corp.example', recv: 'm365', subject: 'Action Required: Verify direct deposit' }), body: 'We are updating our payroll system. Please confirm your direct deposit information by filling out the form at https://hr-forms.example/deposit-update. If we do not receive your updated information by Friday, your pay may be delayed.' },
    findings: [lookup('content_payroll_diversion', 'medium', 'content', { trust: 'derived' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: Shared document lure with mismatch text (link says OneDrive, goes elsewhere)
  { id: 'S18-document-share-lure', description: 'Document sharing lure where link text says Microsoft but href goes to a different domain', expect: ['suspicious'],
    input: { headers: mail({ from: 'no-reply@notification.example', subject: 'Document shared: Q4 Report.docx', ct: 'text/html' }), body: 'Alice shared a document with you via OneDrive. <a href="https://doc-viewer.example/open?f=q4report">https://onedrive.live.com/view/Q4Report</a> Click to view the document.' },
    findings: [lookup('link_text_mismatch', 'high', 'url', { trust: 'derived', source: 'url-heuristics', indicator: url('https://doc-viewer.example/open?f=q4report') }), lookup('content_document_share_lure', 'medium', 'content', { trust: 'derived' }), lookup('content_brand_impersonation', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Tax refund scam (seasonal phishing)
  { id: 'S19-tax-refund-scam', description: 'Tax refund notification from spoofed government domain with urgency', expect: ['suspicious'],
    input: { headers: mail({ from: 'refund@irs-gov.example', fromName: 'Internal Revenue Service', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Tax Refund Notification - Action Required' }), body: 'After the last annual calculation, we have determined you are eligible for a tax refund of $3,847.50. To receive your refund, submit your updated information within 5 business days: https://irs-gov.example/refund/claim' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  // Pattern: Cryptocurrency airdrop / Web3 scam
  { id: 'S20-crypto-airdrop', description: 'Fake cryptocurrency airdrop notification from disposable domain', expect: ['suspicious'],
    input: { headers: mail({ from: 'airdrop@web3-rewards.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Congratulations! You qualified for 500 TOKEN airdrop' }), body: 'Your wallet has been selected for an exclusive airdrop of 500 TOKEN (current value: $2,350). Connect your wallet to claim before the deadline: https://web3-rewards.example/claim. Only 24 hours remaining!' },
    findings: [lookup('sender_domain_new', 'high', 'infrastructure', { trust: 'independently_verified' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' }), lookup('content_financial_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Shared Google Doc with OAuth consent phishing
  { id: 'S21-oauth-consent-phish', description: 'Fake Google Docs sharing requesting OAuth permissions', expect: ['suspicious'],
    input: { headers: mail({ from: 'drive-shares@docs-google.example', fromName: 'Google Drive', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'alice@partner.example has shared a document with you' }), body: 'alice@partner.example has shared "Financial Projections 2027.xlsx" with you. You need to sign in with your Google account to view this document. Open document: https://docs-google.example/d/share/view' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  /* ------------------------------------------- malicious (real-world) */

  // Pattern: Nazario corpus — banking credential harvester with confirmed phishing URL
  { id: 'M07-bank-credential-harvest', description: 'Bank credential harvester with spoofed auth and URL listed by OpenPhish (Nazario pattern)', expect: ['malicious'],
    input: { headers: mail({ from: 'security@online-banking.example', fromName: 'Chase Online Banking', spf: 'fail', dkim: 'none', dmarc: 'fail', ip: '203.0.113.44', subject: 'Urgent: Verify Your Account Information', ct: 'text/html' }), body: 'Dear Customer, We have detected unauthorized access to your account. For your protection, we have temporarily limited your account. Please verify your identity: <a href="https://chase-secure-login.example/verify">Verify Now</a>. If you do not verify within 24 hours your account will be permanently restricted.' },
    findings: [lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: url('https://chase-secure-login.example/verify') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: PhishingPot — Office 365 credential phish with malicious attachment
  { id: 'M08-o365-macro-doc', description: 'Macro-enabled Word doc from spoofed sender, hash confirmed malware (PhishingPot pattern)', expect: ['malicious'],
    input: { headers: mail({ from: 'scanner@copier.corp.example', recv: 'm365', subject: 'Scanned document from MFP-3F', spf: 'fail', dkim: 'none', dmarc: 'fail' }), body: 'You have received a scanned document. Please see the attached file.', attachments: [{ name: 'scan_20261104.docm', hash: sha('d') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('d') } }), lookup('attachment_macro_present', 'high', 'attachment', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: Nigerian advance-fee fraud (419 scam from Nigerian Fraud corpus)
  { id: 'M09-advance-fee-419', description: 'Classic advance-fee fraud (Nigerian 419 pattern) with extortion-style payment demand', expect: ['malicious'],
    input: { headers: mail({ from: 'barr.williams@mailbox.example', subject: 'Confidential Business Proposal' }), body: 'I am Barrister James Williams, a solicitor representing the estate of the late Engineer David Morrison. Before his death he deposited $15.5M in a security vault. I need a foreign partner to receive these funds. You will receive 30% of the total sum. Send $2,500 in bitcoin to 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5 to cover legal filing fees and I will initiate the transfer immediately. If I do not hear from you within 72 hours I will find another partner and you will lose this opportunity.' },
    findings: [lookup('content_extortion', 'high', 'content', { trust: 'derived', evidence: ['Send $2,500 in bitcoin', 'If I do not hear from you within 72 hours'] })], checks: SENDER_DONE },

  // Pattern: Compromised SharePoint sending credential-harvesting attachment
  { id: 'M10-sharepoint-html-attach', description: 'Credential form in HTML attachment impersonating SharePoint login', expect: ['malicious'],
    input: { headers: mail({ from: 'sharepoint@m365-portal.example', fromName: 'SharePoint Online', subject: 'You have a new document to review' }), body: 'A new document has been shared with you on SharePoint. Open the attachment to access the secure document.', attachments: [{ name: 'SharePoint_Document.html', hash: sha('e') }] },
    findings: [lookup('attachment_html_credential_form', 'high', 'attachment', { trust: 'derived', indicator: { type: 'hash', value: sha('e') } }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: PDF with active JavaScript redirecting to credential harvester
  { id: 'M11-pdf-active-content', description: 'PDF with embedded JavaScript confirmed malicious, impersonating DocuSign', expect: ['malicious'],
    input: { headers: mail({ from: 'docusign@sign-documents.example', fromName: 'DocuSign', subject: 'Please review and sign: NDA Agreement' }), body: 'You have a document to review and sign. Open the attached PDF to view the agreement.', attachments: [{ name: 'NDA_Agreement.pdf', hash: sha('f') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'VirusTotal', indicator: { type: 'hash', value: sha('f') } }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: URL confirmed by VirusTotal with critical detections
  { id: 'M12-vt-critical-detections', description: 'URL with critical VirusTotal detections (15+ engines) from spoofed shipping notice', expect: ['malicious'],
    input: { headers: mail({ from: 'tracking@dhl-delivery.example', fromName: 'DHL Express', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'DHL Shipment Notification: AWB 7892345671' }), body: 'Your shipment with AWB 7892345671 requires customs clearance. Track and pay customs fee: https://dhl-delivery.example/track/7892345671' },
    findings: [lookup('url_engine_detections', 'critical', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://dhl-delivery.example/track/7892345671') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Double extension malware attachment (zip containing .pdf.exe)
  { id: 'M13-double-extension', description: 'Double-extension archive attachment with malicious hash, impersonating invoice', expect: ['malicious'],
    input: { headers: mail({ from: 'invoicing@supplier.example', subject: 'Overdue Invoice #INV-90412' }), body: 'Please find the overdue invoice attached. Payment was due on October 15.', attachments: [{ name: 'INV-90412.pdf.zip', hash: sha('g') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('g') } }), lookup('attachment_double_extension', 'high', 'attachment', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: Authenticated sender (compromised) with link flagged by two independent sources
  { id: 'M14-compromised-two-sources', description: 'Compromised authenticated mailbox with link flagged by both VirusTotal and urlscan.io', expect: ['malicious'],
    input: { headers: mail({ from: 'admin@trusted-vendor.example', recv: 'm365', subject: 'Updated contract — please review' }), body: 'Hi, I have updated the contract with the new terms. Please review and sign at https://contract-review.example/sign/doc-9281' },
    findings: [lookup('url_engine_detections', 'high', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://contract-review.example/sign/doc-9281') }), lookup('url_scan_malicious', 'high', 'url', { source: 'urlscan.io', exactness: 'exact', indicator: url('https://contract-review.example/sign/doc-9281') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Brand impersonation + threat intel on URL (Microsoft password expiry)
  { id: 'M15-ms-password-expiry', description: 'Microsoft 365 password expiry impersonation with Pulsedive-rated domain', expect: ['malicious'],
    input: { headers: mail({ from: 'no-reply@microsoftonline-auth.example', fromName: 'Microsoft 365', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Your password will expire in 2 hours' }), body: 'Your Microsoft 365 password will expire in 2 hours. To keep your password, click here: https://microsoftonline-auth.example/keep-password' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_threat_intel_rating', 'high', 'url', { source: 'Pulsedive', exactness: 'related', indicator: url('https://microsoftonline-auth.example/keep-password') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Sextortion variant with Ethereum wallet
  { id: 'M16-sextortion-eth', description: 'Sextortion blackmail demanding Ethereum payment', expect: ['malicious'],
    input: { headers: mail({ from: 'anon_user@proton.example', subject: 'About your browsing habits' }), body: 'I installed a RAT on your device through a compromised website you visited. I have footage of you and a record of the websites you visited. Transfer 0.8 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD14 within 48 hours. If you do not pay, I will send the footage to all your contacts. Do not try to contact the police; I will know and release everything immediately.' },
    findings: [lookup('content_extortion', 'high', 'content', { trust: 'derived', evidence: ['Transfer 0.8 ETH', 'If you do not pay, I will send the footage'] })], checks: SENDER_DONE },

  // Pattern: Password-protected archive (common malware delivery)
  { id: 'M17-password-protected-zip', description: 'Password-protected ZIP with dangerous content, from new domain, hash confirmed', expect: ['malicious'],
    input: { headers: mail({ from: 'docs@secure-transfer.example', subject: 'Confidential: Board meeting materials' }), body: 'The board meeting materials are in the attached archive. Password: Board2026! Please do not forward.', attachments: [{ name: 'board_materials.zip', hash: sha('h') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('h') } }), lookup('attachment_password_protected', 'medium', 'attachment', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: Homograph domain attack (internationalized domain name)
  { id: 'M18-homograph-attack', description: 'Homograph domain (IDN) impersonating Apple, link confirmed phishing', expect: ['malicious'],
    input: { headers: mail({ from: 'support@xn--pple-43d.example', fromName: 'Apple Support', subject: 'Your Apple ID has been locked' }), body: 'Your Apple ID has been locked due to too many failed login attempts. Unlock your account: https://xn--pple-43d.example/unlock' },
    findings: [lookup('sender_domain_homograph', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: url('https://xn--pple-43d.example/unlock') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ------------------------------------------- inconclusive (real-world) */

  // Pattern: Forwarded email (headers stripped by forwarder)
  { id: 'I06-forwarded-stripped-headers', description: 'Message forwarded via webmail: original authentication headers stripped', expect: ['inconclusive'],
    input: { headers: mail({ from: 'unknown@forward.example', subject: 'Fwd: Contract renewal' }), body: '---------- Forwarded message ----------\nFrom: legal@bigcorp.example\nSubject: Contract renewal\n\nPlease review the attached contract renewal terms and let us know if you have questions.' }, checks: [bad('sender.domain.x', 'Domain registration')] },

  // Pattern: Email with only body and a URL (common user paste)
  { id: 'I07-body-with-url-only', description: 'Only body pasted, contains a URL that has not been checked', expect: ['inconclusive'],
    input: { body: 'Please click this link to verify your account: https://verify-account.example/id/12345' } },

  // Pattern: Authentic sender, attachment present but not assessed, link present but not checked
  { id: 'I08-mixed-unchecked', description: 'Authenticated message with both unchecked link and unassessed attachment', expect: ['inconclusive'],
    input: { headers: mail({ from: 'partner@vendor.example', recv: 'm365', subject: 'Proposal and link' }), body: 'Here is the proposal. Also see the online version: https://proposals.vendor.example/draft/42', attachments: [{ name: 'proposal.docx' }] }, checks: SENDER_DONE },

  // Pattern: Most lookups failed (provider outage) — not enough evidence to call clean
  { id: 'I09-partial-lookups', description: 'Only IP lookup succeeded, everything else failed (provider outage)', expect: ['inconclusive'],
    input: { headers: mail({ from: 'info@news.example', subject: 'Weekly digest' }), body: 'Here is your weekly digest. Unsubscribe at any time.' }, checks: [bad('sender.ip.x', 'IP intelligence'), bad('sender.domain.x', 'Domain registration'), bad('sender.auth.x', 'Mail security DNS'), bad('sender.spf.x', 'SPF re-check')] },

  // Pattern: SPF softfail with no other signals
  { id: 'I10-spf-softfail-only', description: 'SPF softfail with no DKIM, otherwise clean — insufficient evidence either way', expect: ['inconclusive', 'suspicious'],
    input: { headers: mail({ from: 'newsletter@smallbiz.example', spf: 'softfail', dkim: 'none', dmarc: 'fail', subject: 'Monthly update' }), body: 'Here is our monthly update. We hope you enjoy it.' }, checks: SENDER_DONE },

  /* ================================================================= */
  /* MORE COVERAGE — edge cases and modern attack patterns              */
  /* ================================================================= */

  /* ---- legitimate edge cases ---- */

  // Pattern: Legitimate alert with urgency wording (should not be over-penalized)
  { id: 'L19-legit-security-alert', description: 'Authenticated cloud provider security alert with urgent wording', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'security@cloud-provider.example', dkimDomain: 'cloud-provider.example', recv: 'm365', subject: 'URGENT: Unusual API activity detected' }), body: 'We detected unusual API activity in your account between 02:00-02:45 UTC today. 47,000 API calls were made from IP 198.51.100.99. If you do not recognize this activity, rotate your API keys immediately at https://cloud-provider.example/security/keys. This is an automated alert from Cloud Provider Security.' },
    findings: [lookup('content_urgency', 'low', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Legitimate email with reply-to mismatch (support ticketing system)
  { id: 'L20-legit-replyto-different', description: 'Support email with Reply-To pointing to ticket system (common in helpdesks)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'support@vendor.example', replyTo: 'ticket-8891@helpdesk.vendor.example', dkimDomain: 'vendor.example', subject: 'Your ticket has been updated' }), body: 'Your support ticket #8891 has been updated. Our engineer has posted a response. Reply to this email to add a comment.' },
    findings: [lookup('reply_to_mismatch', 'low', 'authentication', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: Legitimate bulk mail that triggers urgency heuristic
  { id: 'L21-legit-deadline-notice', description: 'Authenticated conference registration deadline notice (triggers urgency but is legitimate)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'registration@conference.example', dkimDomain: 'conference.example', subject: 'LAST DAY: Early bird registration closes today' }), body: 'This is your final reminder: early bird pricing for TechConf 2027 ends today at 11:59 PM EST. Register now to save $200: https://conference.example/register. After today, standard pricing of $899 applies.' },
    findings: [lookup('content_urgency', 'low', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Legitimate email with multiple links (newsletter with many URLs)
  { id: 'L22-multi-link-newsletter', description: 'Newsletter with many links, all investigated and clean', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'digest@techblog.example', dkimDomain: 'techblog.example', returnPath: 'bounce@mail.techblog.example', subject: 'Weekly Tech Digest #412' }), body: 'This week: How Rust is changing systems programming (https://techblog.example/rust-2027), Interview with the SQLite creator (https://techblog.example/sqlite), and 5 tools every DevOps engineer needs (https://techblog.example/devops-tools). Unsubscribe: https://techblog.example/unsub' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ---- suspicious edge cases ---- */

  // Pattern: Platform abuse (legitimate platform used for phishing — passes all auth)
  { id: 'S22-platform-abuse', description: 'Phishing content sent through legitimate marketing platform (passes SPF/DKIM/DMARC)', expect: ['suspicious', 'inconclusive'],
    input: { headers: mail({ from: 'campaign@marketing-platform.example', dkimDomain: 'marketing-platform.example', subject: 'Account verification required' }), body: 'Your account security needs to be verified. Complete verification now: https://marketing-platform.example/r/abc123-redirect-to-phish. Failure to verify will result in account suspension within 24 hours.' },
    findings: [lookup('sender_infra_shared_provider', 'info', 'infrastructure'), lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' }), lookup('url_redirect_chain', 'medium', 'url', { trust: 'derived', source: 'url-heuristics', indicator: url('https://marketing-platform.example/r/abc123-redirect-to-phish') })], checks: [...SENDER_DONE, ...LINKS_DONE] },
  // NOTE: Platform abuse with full auth is genuinely hard to detect; 'inconclusive' is defensible

  // Pattern: Image-only body (zero text content, only an image with phishing lure)
  { id: 'S23-image-only-body', description: 'Email body is a single image (evades text analysis), auth failed', expect: ['suspicious'],
    input: { headers: mail({ from: 'noreply@notification.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Important notification', ct: 'text/html' }), body: '<img src="https://notification.example/img/lure.png" width="600">' },
    findings: [lookup('content_image_only_body', 'low', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: Reply-to freemail mismatch (common in scams: corporate From, gmail Reply-To)
  { id: 'S24-replyto-freemail', description: 'Corporate sender domain but Reply-To is a personal Gmail address', expect: ['suspicious'],
    input: { headers: mail({ from: 'procurement@bigcorp.example', replyTo: 'procurement.bigcorp@gmail.com', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Purchase order #PO-2026-4411' }), body: 'Please process the attached purchase order and send the invoice to the reply address. Payment will be issued within 30 days.' },
    findings: [lookup('reply_to_mismatch', 'medium', 'authentication', { trust: 'derived' })], checks: SENDER_DONE },

  // Pattern: URL with IP address as host (common in phishing kits)
  { id: 'S25-url-ip-host', description: 'Message with URL pointing to raw IP address, auth failed', expect: ['suspicious'],
    input: { headers: mail({ from: 'admin@webmail.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Mailbox storage full' }), body: 'Your mailbox is full. Click to expand storage: https://198.51.100.55/webmail/upgrade' },
    findings: [lookup('url_ip_host', 'medium', 'url', { trust: 'derived', indicator: url('https://198.51.100.55/webmail/upgrade') }), lookup('content_credential_request', 'high', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Multiple lure signals combined (urgency + credential + financial)
  { id: 'S26-multi-lure-signals', description: 'Multiple lure signals: urgency, credential request, and financial wording combined', expect: ['suspicious'],
    input: { headers: mail({ from: 'accounts@billing-portal.example', spf: 'softfail', dkim: 'none', dmarc: 'fail', subject: 'Payment failed - update your card immediately' }), body: 'Your payment of $49.99 failed. Your account will be suspended in 12 hours unless you update your payment method and verify your identity. Update now: https://billing-portal.example/update-card' },
    findings: [lookup('content_urgency', 'medium', 'content', { trust: 'derived' }), lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_financial_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ---- malicious edge cases ---- */

  // Pattern: Malware in password-protected archive delivered through legitimate ESP
  { id: 'M19-malware-via-esp', description: 'Malware attachment sent through authenticated ESP (shared infra does not excuse malware)', expect: ['malicious'],
    input: { headers: mail({ from: 'billing@legit-company.example', returnPath: 'bounce@esp-mail.example', dkimDomain: 'legit-company.example', subject: 'Invoice attached' }), body: 'Please find the invoice attached.', attachments: [{ name: 'invoice.xlsm', hash: sha('i') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('i') } }), lookup('sender_infra_shared_provider', 'info', 'infrastructure')], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: URL on newly registered domain confirmed by threat intel
  { id: 'M20-new-domain-confirmed', description: 'URL on 2-day-old domain confirmed malicious by VirusTotal', expect: ['malicious'],
    input: { headers: mail({ from: 'security@account-review.example', subject: 'Security alert: confirm your identity' }), body: 'We detected suspicious activity. Confirm your identity: https://account-review.example/secure-login' },
    findings: [lookup('url_engine_detections', 'critical', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://account-review.example/secure-login') }), lookup('sender_domain_new', 'high', 'infrastructure', { trust: 'independently_verified' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Pattern: Credential form in HTML + content credential request (no impersonation needed)
  { id: 'M21-html-cred-form-content', description: 'HTML attachment with credential form and credential-harvesting body wording', expect: ['malicious'],
    input: { headers: mail({ from: 'admin@portal.example', subject: 'Verify your account' }), body: 'Your account requires verification. Open the attached form to verify your credentials and prevent account suspension.', attachments: [{ name: 'verify.html', hash: sha('j') }] },
    findings: [lookup('attachment_html_credential_form', 'high', 'attachment', { trust: 'derived', indicator: { type: 'hash', value: sha('j') } }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Pattern: URL listed as malware distribution
  { id: 'M22-malware-url', description: 'Link points to a URL listed as distributing malware', expect: ['malicious'],
    input: { headers: mail({ from: 'updates@software-update.example', subject: 'Critical security patch available' }), body: 'A critical vulnerability has been found. Download and install the patch immediately: https://software-update.example/patch/critical-fix.exe' },
    findings: [lookup('url_listed_malware', 'critical', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://software-update.example/patch/critical-fix.exe') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* ---- inconclusive edge cases ---- */

  // Pattern: Legitimate-looking email but DKIM key has been revoked
  { id: 'I11-dkim-revoked', description: 'Otherwise clean email but DKIM signature cannot be verified (key revoked/rotated)', expect: ['inconclusive', 'suspicious'],
    input: { headers: mail({ from: 'hr@corp.example', recv: 'm365', dkim: 'fail', dmarc: 'fail', subject: 'Benefits enrollment reminder' }), body: 'Open enrollment for 2027 benefits ends December 15. Visit the HR portal to make your selections.' }, checks: SENDER_DONE },

  // Pattern: Auto-forwarded message loses authentication
  { id: 'I12-autoforward-breaks-auth', description: 'Auto-forwarded message where forwarding broke DKIM (common with mail rules)', expect: ['inconclusive'],
    input: { headers: mail({ from: 'notifications@ci-system.example', dkim: 'fail', dmarc: 'fail', spf: 'softfail', subject: 'Build #4521 passed' }), body: 'Build #4521 for main branch completed successfully. All 847 tests passed in 3m 42s. View details: https://ci-system.example/builds/4521' },
    findings: [lookup('auth_conflict', 'medium', 'authentication', { trust: 'derived', detail: 'DKIM fail suggests message was modified in transit (forwarding)' })], checks: SENDER_DONE },

  /* ================================================================= */
  /* BATCH 2 — 50 additional samples for deeper calibration coverage    */
  /* ================================================================= */

  /* -------------------- LEGITIMATE (L23–L42, 20 samples) ----------- */

  // Automated CI/CD pipeline notification
  { id: 'L23-ci-deploy-notification', description: 'Authenticated CI/CD deployment success notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'deploy@ci.devops.example', dkimDomain: 'devops.example', recv: 'm365', subject: 'Deploy v4.12.3 to production succeeded' }), body: 'Deployment v4.12.3 to production completed at 14:32 UTC. 0 errors, 0 warnings. Rollback window: 4 hours. Dashboard: https://ci.devops.example/deploys/4123' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Calendar meeting accepted
  { id: 'L24-calendar-accept', description: 'Authenticated calendar meeting acceptance from colleague', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'priya.mehta@corp.example', recv: 'm365', dkimDomain: 'corp.example', subject: 'Accepted: Weekly Sync @ Tue Nov 10, 10:00 AM' }), body: 'priya.mehta@corp.example has accepted your meeting invitation.\n\nWeekly Sync\nWhen: Tuesday, November 10, 2026 10:00 AM - 10:30 AM\nWhere: Conference Room B' }, checks: SENDER_DONE },

  // Domain registrar renewal notification
  { id: 'L25-domain-renewal', description: 'Authenticated domain registrar renewal reminder', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'billing@registrar.example', dkimDomain: 'registrar.example', subject: 'Domain Renewal: corp.example expires in 30 days' }), body: 'Your domain corp.example is set to expire on December 8, 2026. To ensure uninterrupted service, please renew before expiration. Log in to manage your domains: https://registrar.example/account/domains' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Two-factor authentication code (transactional)
  { id: 'L26-2fa-code', description: 'Authenticated 2FA verification code email', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'noreply@auth.service.example', dkimDomain: 'service.example', subject: 'Your verification code is 847291' }), body: 'Your one-time verification code is: 847291. This code expires in 10 minutes. If you did not request this code, you can safely ignore this email.' }, checks: SENDER_DONE },

  // Internal IT maintenance window notice
  { id: 'L27-it-maintenance', description: 'Internal IT maintenance window notification from corp domain', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'it-ops@corp.example', recv: 'm365', dkimDomain: 'corp.example', subject: 'Scheduled Maintenance: ERP System — Nov 15, 2:00-6:00 AM IST' }), body: 'Please be advised that the ERP system will undergo scheduled maintenance on November 15, 2026 from 2:00 AM to 6:00 AM IST. During this window, SAP access will be unavailable. No action is required from your end. Contact the IT helpdesk if you have questions.' }, checks: SENDER_DONE },

  // Vendor contract signed via DocuSign (authenticated)
  { id: 'L28-docusign-completed', description: 'Authenticated DocuSign completion notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'dse@docusign.example', dkimDomain: 'docusign.example', subject: 'Completed: Service Agreement - ACME Corp' }), body: 'All parties have signed the document "Service Agreement - ACME Corp". You can download the completed document from https://docusign.example/documents/abc123. This document will be available for 30 days.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // LinkedIn-style professional network notification
  { id: 'L29-linkedin-notification', description: 'Authenticated professional network connection request', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'notifications@professional-network.example', dkimDomain: 'professional-network.example', subject: 'Rajesh Kumar wants to connect with you' }), body: 'Rajesh Kumar, CTO at TechStartup Inc., would like to connect with you. View profile: https://professional-network.example/in/rajesh-kumar. You are receiving this email because you have a Professional Network account.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // E-commerce order confirmation (legitimate)
  { id: 'L30-order-confirmation', description: 'Authenticated e-commerce order confirmation email', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'orders@store.example', dkimDomain: 'store.example', returnPath: 'bounce@mail.store.example', subject: 'Order Confirmed: #ORD-2026-78451' }), body: 'Thank you for your order! Order #ORD-2026-78451 has been confirmed. Items: Wireless Keyboard (x1) - $49.99, USB-C Hub (x1) - $34.99. Estimated delivery: Nov 12-14. Track your order: https://store.example/orders/78451' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Internal company announcement (all-hands)
  { id: 'L31-company-announcement', description: 'Internal all-hands announcement from HR on corp domain', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'hr@corp.example', recv: 'm365', dkimDomain: 'corp.example', subject: 'All Hands Meeting: Q3 Results — Nov 20 at 3 PM' }), body: 'You are invited to the quarterly All Hands meeting on November 20 at 3:00 PM IST. Agenda: Q3 business results, upcoming initiatives, and Q&A with leadership. Teams link: https://teams.microsoft.com/meet/abcdef. Please join on time.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Bank statement notification (authenticated)
  { id: 'L32-bank-statement', description: 'Authenticated bank e-statement availability notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'statements@bank.example', dkimDomain: 'bank.example', subject: 'Your October 2026 statement is ready' }), body: 'Your account statement for October 2026 is now available. Log in to your online banking at https://bank.example/statements to view and download your statement. For security, we will never ask you to provide your password via email.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Slack-style workspace notification
  { id: 'L33-slack-notification', description: 'Authenticated Slack-style workspace mention notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'notification@slack-workspace.example', dkimDomain: 'slack-workspace.example', subject: 'New mention in #engineering' }), body: 'Amit mentioned you in #engineering: "Can you review the API changes before the release?" Reply in Slack: https://slack-workspace.example/archives/C1234/p1699000000' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Jira/project tracker notification
  { id: 'L34-jira-ticket-update', description: 'Authenticated project tracker ticket assignment notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'jira@project-tracker.example', dkimDomain: 'project-tracker.example', subject: '[PROJ-1234] Assigned to you: Fix login timeout issue' }), body: 'Priya assigned PROJ-1234 to you. Priority: High. Summary: Fix login timeout issue on mobile app. Due: Nov 15, 2026. View issue: https://project-tracker.example/browse/PROJ-1234' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Password change confirmation (not a reset request)
  { id: 'L35-password-changed', description: 'Authenticated password change confirmation (informational, no link)', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'security@service.example', dkimDomain: 'service.example', subject: 'Your password was changed' }), body: 'The password for your account sahil@service.example was successfully changed on November 8, 2026 at 2:15 PM IST. If you did not make this change, contact support immediately at support@service.example.' }, checks: SENDER_DONE },

  // Software license key delivery
  { id: 'L36-license-key', description: 'Authenticated software license key delivery email', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'licenses@software-vendor.example', dkimDomain: 'software-vendor.example', subject: 'Your license key for ProTool Enterprise' }), body: 'Thank you for your purchase. Your license key for ProTool Enterprise (5 seats) is: XXXX-YYYY-ZZZZ-1234. Activation instructions: https://software-vendor.example/docs/activate. This key is valid for 1 year from activation.' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Travel booking confirmation
  { id: 'L37-travel-booking', description: 'Authenticated travel booking confirmation from agency', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'bookings@travel-agency.example', dkimDomain: 'travel-agency.example', subject: 'Booking Confirmed: DEL → NRT, Nov 25' }), body: 'Your flight booking is confirmed. Flight: AI 306, DEL → NRT, Nov 25 2026, Departure: 12:30 PM IST. Booking reference: PNR7X9. View your itinerary: https://travel-agency.example/bookings/PNR7X9' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Webinar registration confirmation
  { id: 'L38-webinar-confirmation', description: 'Authenticated webinar registration confirmation', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'events@learning-platform.example', dkimDomain: 'learning-platform.example', subject: 'Registration confirmed: Cloud Security Best Practices' }), body: 'You are registered for "Cloud Security Best Practices" on Nov 18, 2026 at 11:00 AM IST. Join link: https://learning-platform.example/webinar/cs-2026. Add to calendar: https://learning-platform.example/cal/cs-2026.ics' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Expense report approved
  { id: 'L39-expense-approved', description: 'Internal expense report approval notification', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'expenses@corp.example', recv: 'm365', dkimDomain: 'corp.example', subject: 'Expense Report #EXP-2026-091 Approved' }), body: 'Your expense report #EXP-2026-091 for $342.50 has been approved by your manager. Reimbursement will be processed in the next payroll cycle. View details: https://expenses.corp.example/reports/091' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // DMARC aggregate report notification (legitimate security)
  { id: 'L40-dmarc-report', description: 'DMARC aggregate report from Google for corp domain', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'noreply-dmarc-support@google.example', dkimDomain: 'google.example', subject: 'Report domain: corp.example Submitter: google.example' }), body: 'This is an aggregate report from Google for the domain corp.example. The report covers the period 2026-11-01 to 2026-11-02. See attached XML for full details.', attachments: [{ name: 'google.example!corp.example!1730419200!1730505600.xml.gz' }] }, checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Automated monitoring alert (Datadog/PagerDuty style)
  { id: 'L41-monitoring-alert', description: 'Authenticated infrastructure monitoring alert', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'alerts@monitoring.example', dkimDomain: 'monitoring.example', subject: 'RESOLVED: High CPU on web-prod-03 (was 94%, now 23%)' }), body: 'Alert RESOLVED: High CPU usage on web-prod-03. Peak: 94% at 14:02 UTC. Current: 23%. Duration: 12 minutes. Root cause: batch job overlap. Dashboard: https://monitoring.example/dashboards/infra/web-prod-03' }, checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Reply in an existing email thread (Re: prefix, authenticated)
  { id: 'L42-email-reply-thread', description: 'Authenticated reply in ongoing business email thread', expect: ['likely_legitimate'],
    input: { headers: mail({ from: 'vendor.contact@partner.example', recv: 'm365', dkimDomain: 'partner.example', subject: 'Re: Re: Quotation for annual maintenance contract', extra: 'In-Reply-To: <m1@corp.example>\nReferences: <m1@corp.example> <m2@partner.example>' }), body: 'Hi Sahil,\n\nThanks for the clarification. I have updated the quotation as discussed. The revised total comes to INR 4,85,000 + GST for the annual maintenance contract. Please let me know if this works.\n\nBest regards,\nAmit Shah\nPartner Corp' }, checks: SENDER_DONE },

  /* -------------------- MALICIOUS (M23–M38, 16 samples) ------------ */

  // ISO attachment with confirmed malicious hash
  { id: 'M23-iso-malware', description: 'ISO disk image attachment with confirmed malware hash, impersonating Windows Update', expect: ['malicious'],
    input: { headers: mail({ from: 'updates@windows-update.example', fromName: 'Microsoft Update', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Critical Windows Security Patch KB5029991' }), body: 'A critical security vulnerability has been found in your version of Windows. Install the attached patch immediately to protect your system.', attachments: [{ name: 'KB5029991_SecurityPatch.iso', hash: sha('k') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('k') } }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Callback phishing (phone number instead of URL)
  { id: 'M24-callback-phish', description: 'Fake subscription renewal with callback number, extortion-style demand for payment', expect: ['malicious'],
    input: { headers: mail({ from: 'billing@geeksquad-renewal.example', fromName: 'Geek Squad', subject: 'Auto-Renewal Confirmation: $449.99 charged' }), body: 'Your Geek Squad Total Protection plan has been auto-renewed for $449.99. The charge has been applied to your account. If you did not authorize this transaction, call our cancellation line immediately at +1-888-555-0199. Failure to call within 24 hours means you accept the charge. Pay immediately or face collection action on your account.' },
    findings: [lookup('content_extortion', 'high', 'content', { trust: 'derived', evidence: ['$449.99 charged', 'Failure to call within 24 hours', 'face collection action'] }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  // OneNote phishing with confirmed URL
  { id: 'M25-onenote-phish', description: 'Fake OneNote sharing notification with URL confirmed phishing by OpenPhish', expect: ['malicious'],
    input: { headers: mail({ from: 'share@onenote-cloud.example', fromName: 'Microsoft OneNote', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Shared notebook: HR Policies 2027' }), body: 'A OneNote notebook has been shared with you. Click to open: https://onenote-cloud.example/notebooks/hr-policies-2027' },
    findings: [lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: url('https://onenote-cloud.example/notebooks/hr-policies-2027') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Emotet-style reply chain hijack with malicious ZIP
  { id: 'M26-reply-chain-hijack', description: 'Reply chain hijack with malicious ZIP (Emotet pattern) — reuses real thread subject', expect: ['malicious'],
    input: { headers: mail({ from: 'contact@legit-supplier.example', recv: 'm365', subject: 'RE: Purchase Order #PO-2026-331', extra: 'In-Reply-To: <original@corp.example>' }), body: 'Please see the updated documents per our earlier discussion.', attachments: [{ name: 'PO-2026-331_updated.zip', hash: sha('l') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'VirusTotal', indicator: { type: 'hash', value: sha('l') } })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Fake court summons / legal threat
  { id: 'M27-fake-legal-notice', description: 'Fake court summons with malware attachment impersonating a law firm', expect: ['malicious'],
    input: { headers: mail({ from: 'service@lawfirm-notices.example', subject: 'URGENT: Court Summons — Case #2026-CV-88412' }), body: 'You are hereby notified that a civil complaint has been filed against you. Court appearance is mandatory. See the attached summons for details and court date.', attachments: [{ name: 'Court_Summons_2026-CV-88412.pdf.exe', hash: sha('m') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('m') } }), lookup('attachment_double_extension', 'high', 'attachment', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Zoom meeting invite with phishing URL confirmed by VT
  { id: 'M28-zoom-phish', description: 'Fake Zoom meeting invite with URL flagged by VirusTotal (critical)', expect: ['malicious'],
    input: { headers: mail({ from: 'invite@zoom-meeting.example', fromName: 'Zoom', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'You have been invited to a Zoom meeting' }), body: 'Rohini Vig is inviting you to a scheduled Zoom meeting.\n\nTopic: Project Review\nTime: Nov 10, 2026 02:00 PM IST\n\nJoin Meeting: https://zoom-meeting.example/j/83928471234' },
    findings: [lookup('url_engine_detections', 'critical', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://zoom-meeting.example/j/83928471234') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // WeTransfer impersonation with phishing link
  { id: 'M29-wetransfer-phish', description: 'Fake WeTransfer download notification with confirmed phishing URL', expect: ['malicious'],
    input: { headers: mail({ from: 'noreply@we-transfer.example', fromName: 'WeTransfer', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'priya@partner.example sent you files' }), body: 'priya@partner.example sent you some files.\n\n3 items, 12.4 MB in total. Download link expires in 7 days.\n\nDownload files: https://we-transfer.example/dl/a8b3c2' },
    findings: [lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', indicator: url('https://we-transfer.example/dl/a8b3c2') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // HWP / RTF exploit attachment (targeted APT style)
  { id: 'M30-rtf-exploit', description: 'RTF attachment with confirmed exploit code, from spoofed government domain', expect: ['malicious'],
    input: { headers: mail({ from: 'admin@gov-portal.example', fromName: 'Government Portal', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Tax Assessment Notice FY 2025-26' }), body: 'Your income tax assessment for FY 2025-26 has been completed. Please review the attached notice.', attachments: [{ name: 'Assessment_Notice_FY2025-26.rtf', hash: sha('n') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'VirusTotal', indicator: { type: 'hash', value: sha('n') } }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Fake shipping with URL flagged by DNS block
  { id: 'M31-fedex-dns-blocked', description: 'FedEx impersonation with URL resolved to DNS sinkhole', expect: ['malicious'],
    input: { headers: mail({ from: 'track@fedex-delivery.example', fromName: 'FedEx', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'FedEx: Package delivery failed — reschedule now' }), body: 'We attempted to deliver your package today but no one was available to sign. Reschedule delivery: https://fedex-delivery.example/reschedule/PKG-881234' },
    findings: [lookup('sender_domain_lookalike', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_dns_blocked', 'high', 'url', { source: 'DNS-sinkhole', exactness: 'exact', indicator: url('https://fedex-delivery.example/reschedule/PKG-881234') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Payroll direct deposit phishing with HTML credential form
  { id: 'M32-payroll-cred-form', description: 'Payroll update with HTML credential form attachment impersonating ADP', expect: ['malicious'],
    input: { headers: mail({ from: 'payroll@adp-portal.example', fromName: 'ADP Payroll', subject: 'Update Your Direct Deposit — Action Required' }), body: 'Your employer requires you to verify your direct deposit information. Open the attached form to update your bank details.', attachments: [{ name: 'Direct_Deposit_Verification.html', hash: sha('o') }] },
    findings: [lookup('attachment_html_credential_form', 'high', 'attachment', { trust: 'derived', indicator: { type: 'hash', value: sha('o') } }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Multi-stage redirect ending at confirmed phishing page
  { id: 'M33-multi-redirect', description: 'Multi-stage redirect through legitimate service landing on confirmed phishing URL', expect: ['malicious'],
    input: { headers: mail({ from: 'noreply@survey.example', subject: 'Complete your annual review', spf: 'fail', dkim: 'none', dmarc: 'fail' }), body: 'Your annual employee satisfaction survey is ready. Begin survey: https://redirect-service.example/r?u=https://hr-survey-phish.example/login' },
    findings: [lookup('url_listed_phishing', 'critical', 'url', { source: 'OpenPhish', exactness: 'exact', indicator: url('https://hr-survey-phish.example/login') }), lookup('url_redirect_chain', 'medium', 'url', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Fake antivirus alert with malicious installer
  { id: 'M34-fake-av-alert', description: 'Fake antivirus expiry alert with malicious installer download link', expect: ['malicious'],
    input: { headers: mail({ from: 'renewal@norton-security.example', fromName: 'Norton Security', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Your Norton protection has expired!' }), body: 'Your Norton 360 subscription expired yesterday. Your device is now at risk. Renew now to restore protection: https://norton-security.example/renew/install' },
    findings: [lookup('url_listed_malware', 'critical', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://norton-security.example/renew/install') }), lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // WhatsApp impersonation with credential harvesting
  { id: 'M35-whatsapp-impersonation', description: 'WhatsApp backup notification impersonation with URL confirmed malicious by two sources', expect: ['malicious'],
    input: { headers: mail({ from: 'backup@whatsapp-cloud.example', fromName: 'WhatsApp', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Your WhatsApp backup is ready to download' }), body: 'Your WhatsApp chat backup (2.3 GB) is ready. Download your backup before it expires: https://whatsapp-cloud.example/backup/download' },
    findings: [lookup('url_engine_detections', 'high', 'url', { source: 'VirusTotal', exactness: 'exact', indicator: url('https://whatsapp-cloud.example/backup/download') }), lookup('url_scan_malicious', 'high', 'url', { source: 'urlscan.io', exactness: 'exact', indicator: url('https://whatsapp-cloud.example/backup/download') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Excel attachment with macros, hash confirmed
  { id: 'M36-excel-macro-malware', description: 'Excel macro-enabled file impersonating a purchase order with confirmed malware hash', expect: ['malicious'],
    input: { headers: mail({ from: 'purchasing@vendor-corp.example', subject: 'PO #90881 — Please confirm availability' }), body: 'Please review the attached purchase order and confirm item availability by end of week. Enable editing to view the full document.', attachments: [{ name: 'PO_90881.xlsm', hash: sha('p') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'MalwareBazaar', indicator: { type: 'hash', value: sha('p') } }), lookup('attachment_macro_present', 'high', 'attachment', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // Deepfake voice note phishing (SVG attachment with embedded script)
  { id: 'M37-svg-script-malware', description: 'SVG attachment with embedded JavaScript, confirmed malicious', expect: ['malicious'],
    input: { headers: mail({ from: 'voicemail@messaging.example', subject: 'New voice message from +91 98765 43210' }), body: 'You received a new voice message. Duration: 1:23. Open the attached file to listen.', attachments: [{ name: 'voice_message.svg', hash: sha('q') }] },
    findings: [lookup('attachment_hash_malicious', 'critical', 'attachment', { source: 'VirusTotal', indicator: { type: 'hash', value: sha('q') } })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  // LinkedIn impersonation with Pulsedive-flagged domain + impersonation
  { id: 'M38-linkedin-impersonation', description: 'LinkedIn impersonation with domain rated malicious by Pulsedive', expect: ['malicious'],
    input: { headers: mail({ from: 'invitations@linkedln-mail.example', fromName: 'LinkedIn', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'You have 5 pending connection requests' }), body: 'You have 5 pending connection requests. Accept them before they expire: https://linkedln-mail.example/mynetwork/invitations' },
    findings: [lookup('sender_domain_homograph', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('url_threat_intel_rating', 'high', 'url', { source: 'Pulsedive', exactness: 'related', indicator: url('https://linkedln-mail.example/mynetwork/invitations') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  /* -------------------- SUSPICIOUS (S27–S36, 10 samples) ----------- */

  // CEO impersonation from lookalike domain asking for W-2/PAN details
  { id: 'S27-ceo-w2-request', description: 'CEO impersonation from lookalike domain requesting employee tax documents', expect: ['suspicious'],
    input: { headers: mail({ from: 'ceo@corp-group.example', fromName: 'Rohini Vig', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Employee records needed urgently' }), body: 'I need you to send me the PAN details and Form 16 for all employees in the Gurugram office. This is for an urgent audit. Please send by end of day. Do not discuss this with others until the audit is complete. — Rohini' },
    findings: [lookup('sender_domain_lookalike', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_bec_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Fake HR benefits enrollment from external domain
  { id: 'S28-fake-hr-enrollment', description: 'Benefits enrollment email from non-corporate domain with credential request', expect: ['suspicious'],
    input: { headers: mail({ from: 'hr-benefits@enrollment-portal.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Open Enrollment 2027: Select Your Benefits Plan' }), body: 'Open enrollment for the 2027 benefits year closes on November 30. Log in with your corporate credentials to make your selections: https://enrollment-portal.example/login. If you do not enroll, you will be assigned the default plan.' },
    findings: [lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Tech support scam (Microsoft style)
  { id: 'S29-tech-support-scam', description: 'Fake Microsoft tech support warning about detected virus', expect: ['suspicious'],
    input: { headers: mail({ from: 'support@microsoft-helpdesk.example', fromName: 'Microsoft Support', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Warning: Virus detected on your device' }), body: 'Our security system has detected malicious activity on your device associated with this email address. Your device may be compromised. Call our certified technician at +1-800-555-0147 for immediate assistance. Case ID: MS-2026-771234' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('sender_domain_lookalike', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: SENDER_DONE },

  // Fake shared drive alert with link text mismatch
  { id: 'S30-shared-drive-lure', description: 'Google Drive sharing notification with href pointing to different domain', expect: ['suspicious'],
    input: { headers: mail({ from: 'drive-sharing@google-docs.example', fromName: 'Google Drive', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Important document shared with you', ct: 'text/html' }), body: 'A document has been shared with you on Google Drive.\n\n<a href="https://doc-login.example/view">https://drive.google.com/file/d/1ABC/view</a>\n\nOpen and review the document.' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('link_text_mismatch', 'high', 'url', { trust: 'derived', source: 'url-heuristics', indicator: url('https://doc-login.example/view') })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Compromised vendor — authenticated but anomalous content
  { id: 'S31-compromised-vendor-anomalous', description: 'Authenticated vendor mailbox sending off-topic request for personal info', expect: ['suspicious'],
    input: { headers: mail({ from: 'accounts@trusted-supplier.example', recv: 'm365', dkimDomain: 'trusted-supplier.example', subject: 'Urgent: Confirm your personal details' }), body: 'Due to a system migration, we need all contacts to verify their personal details including date of birth, phone number, and home address. Please reply with these details or fill in the form: https://trusted-supplier.example/verify-contact' },
    findings: [lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_urgency', 'high', 'content', { trust: 'derived' }), lookup('content_impersonation_internal', 'medium', 'content', { trust: 'derived', source: 'identity-analysis' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Fake SSL certificate expiry
  { id: 'S32-ssl-expiry-scam', description: 'Fake SSL certificate expiry warning from lookalike registrar', expect: ['suspicious'],
    input: { headers: mail({ from: 'ssl@domain-security.example', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'URGENT: SSL Certificate for corp.example expires in 24 hours' }), body: 'The SSL/TLS certificate for corp.example expires in 24 hours. Failure to renew will cause your website to show security warnings to all visitors. Renew now: https://domain-security.example/ssl/renew?domain=corp.example' },
    findings: [lookup('content_urgency', 'high', 'content', { trust: 'derived' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Fake cloud storage full notification
  { id: 'S33-cloud-storage-scam', description: 'Fake OneDrive storage full alert from non-Microsoft domain', expect: ['suspicious'],
    input: { headers: mail({ from: 'alerts@onedrive-storage.example', fromName: 'Microsoft OneDrive', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Your OneDrive storage is full (15.0/15.0 GB)' }), body: 'Your OneDrive storage has reached its limit. You can no longer receive emails or sync files. Upgrade your storage for free: https://onedrive-storage.example/upgrade' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_credential_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Fake job offer from free email
  { id: 'S34-fake-job-offer', description: 'Unsolicited high-salary job offer from Gmail address with urgency', expect: ['suspicious'],
    input: { headers: mail({ from: 'hr.hiring.globaltech@gmail.com', fromName: 'GlobalTech HR', subject: 'Job Offer: Senior IT Manager — CTC 45 LPA' }), body: 'Dear Candidate, We reviewed your profile and would like to offer you the position of Senior IT Manager at GlobalTech Solutions. CTC: INR 45,00,000/year. To accept, fill out the onboarding form within 48 hours: https://forms.example/globaltech-onboarding. Sincerely, HR Team' },
    findings: [lookup('content_urgency', 'high', 'content', { trust: 'derived' }), lookup('content_credential_request', 'high', 'content', { trust: 'derived' }), lookup('content_financial_request', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...LINKS_DONE] },

  // Package held at customs scam (India-specific)
  { id: 'S35-customs-scam', description: 'Fake customs duty notification for held package', expect: ['suspicious'],
    input: { headers: mail({ from: 'customs@india-post-delivery.example', fromName: 'India Post', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Your parcel is held at customs — pay duty to release' }), body: 'Your international parcel (tracking: CP123456789IN) is being held at Mumbai customs. Outstanding customs duty: INR 2,450. Pay now to release your package: https://india-post-delivery.example/customs/pay?track=CP123456789IN. Package will be returned to sender after 5 days.' },
    findings: [lookup('display_name_brand_spoof', 'high', 'content', { trust: 'derived', source: 'identity-analysis' }), lookup('content_urgency', 'medium', 'content', { trust: 'derived' }), lookup('content_financial_request', 'medium', 'content', { trust: 'derived' })], checks: SENDER_DONE },

  // Fake printer/scanner notification from unknown IP
  { id: 'S36-printer-scan-lure', description: 'Fake printer scan notification from external IP with suspicious attachment', expect: ['suspicious'],
    input: { headers: mail({ from: 'scanner@mfp.example', ip: '203.0.113.77', spf: 'fail', dkim: 'none', dmarc: 'fail', subject: 'Scan from HP MFP M233sdw [10:42 AM]' }), body: 'Attached is a scanned document from HP LaserJet MFP M233sdw. Pages: 3. Format: PDF.', attachments: [{ name: 'Scan_20261108_1042.pdf' }] },
    findings: [lookup('content_impersonation_internal', 'medium', 'content', { trust: 'derived' })], checks: [...SENDER_DONE, ...ATTACHMENT_DONE] },

  /* -------------------- INCONCLUSIVE (I13–I16, 4 samples) ---------- */

  // Encrypted email with no readable content
  { id: 'I13-encrypted-body', description: 'S/MIME encrypted message — body cannot be analyzed', expect: ['inconclusive'],
    input: { headers: mail({ from: 'secure@partner.example', subject: 'Encrypted: Contract terms', ct: 'application/pkcs7-mime' }), body: '[S/MIME encrypted content — cannot be read without recipient private key]' }, checks: [bad('sender.ip.x', 'IP intelligence'), bad('sender.domain.x', 'Domain registration'), bad('sender.auth.x', 'Mail security DNS'), bad('sender.spf.x', 'SPF re-check'), bad('content.nlp', 'Content analysis'), bad('content.brand', 'Brand impersonation check'), bad('urls.openphish', 'OpenPhish'), bad('urls.provider.virustotal', 'VirusTotal')] },

  // Legitimate-looking but from entirely unknown domain with no intel
  { id: 'I14-unknown-domain-no-intel', description: 'Professional-looking email from completely unknown domain with no threat intel available', expect: ['inconclusive'],
    input: { headers: mail({ from: 'partnership@newstartup.example', subject: 'Partnership Opportunity' }), body: 'Hi, I am reaching out from NewStartup to discuss a potential partnership. We believe our solutions would complement your operations. Would you be available for a 15-minute call next week? Best, Alex Chen, Business Development' }, checks: [bad('sender.ip.x', 'IP intelligence'), bad('sender.domain.x', 'Domain registration'), bad('sender.auth.x', 'Mail security DNS'), bad('urls.provider.virustotal', 'VirusTotal'), bad('urls.openphish', 'OpenPhish')] },

  // Attachment-only email with no body text
  { id: 'I15-attachment-no-body', description: 'Email with attachment but completely empty body — cannot determine intent', expect: ['inconclusive'],
    input: { headers: mail({ from: 'unknown@external.example', subject: '(no subject)' }), body: '', attachments: [{ name: 'document.pdf' }] }, checks: SENDER_DONE },

  // Mixed signals: authenticated but IP is flagged, content is benign
  { id: 'I16-mixed-signals-auth-ip', description: 'Authenticated email but sending IP has low reputation — mixed signals', expect: ['inconclusive', 'suspicious'],
    input: { headers: mail({ from: 'newsletter@smallbiz.example', recv: 'm365', dkimDomain: 'smallbiz.example', ip: '203.0.113.66', subject: 'November Newsletter' }), body: 'Here is our November newsletter. We have some exciting updates to share about our product roadmap.' },
    findings: [lookup('ip_reputation_low', 'medium', 'infrastructure', { trust: 'independently_verified' })], checks: SENDER_DONE },
];
