/**
 * Plain-language wording for the Key Findings cards: a short headline and one summary line per area, so an analyst can
 * read the outcome at a glance. Everything is derived from the verdict engine's findings and area scores; nothing is
 * scored again, and the technical detail stays in the tabs.
 */
import type { Tone } from '../../components/ui';
import type { Dimension, Finding } from '../../../shared/phishing/types';
import type { CheckRow } from '../../../shared/phishing/verdict';
import { tidy } from '../../../shared/phishing/summary';

/**
 * Headline for the strongest finding of an area, matched by finding id (exact id, or an id prefix ending in "_").
 * A third entry is the softer wording used unless the finding is critical, or high on an email whose verdict is
 * Malicious, so a single weak detection under a Suspicious verdict reads "Flagged Link", not "Malicious Link".
 * A fourth entry `true` marks a factual check (file type, look-alike domain): its strong wording holds at high severity
 * and softens only at medium.
 */
const BY_FINDING: [string, string, string?, boolean?][] = [
  // attachments
  ['attachment_hash_malicious', 'Known Malware Attachment', 'Flagged Attachment'],
  ['attachment_html_credential_form', 'Fake Login Attachment'],
  ['attachment_macro_present', 'Macro-Enabled Attachment'],
  ['attachment_double_extension', 'Disguised Attachment'],
  ['attachment_type_mismatch', 'Disguised Attachment'],
  ['attachment_archive_dangerous_content', 'Executable Inside Archive'],
  ['attachment_password_protected', 'Locked Attachment'],
  ['attachment_hash_suspicious', 'Suspicious Attachment'],
  // links
  ['url_listed_phishing', 'Known Phishing Link', 'Possible Phishing Link'],
  ['url_listed_malware', 'Known Malware Link', 'Possible Malware Link'],
  ['url_engine_detections', 'Malicious Link', 'Flagged Link'],
  ['url_scan_malicious', 'Malicious Link', 'Flagged Link'],
  ['url_host_scan_malicious', 'Malicious Link', 'Flagged Link'],
  ['url_dns_blocked', 'Malicious Link', 'Flagged Link'],
  ['url_blocklisted_host', 'Malicious Link', 'Flagged Link'],
  ['url_host_listed', 'Malicious Link', 'Flagged Link'],
  ['url_brand_mismatch', 'Look-alike Link'],
  ['url_lookalike_domain', 'Look-alike Link'],
  ['url_homograph_domain', 'Look-alike Link'],
  ['url_deceptive_userinfo', 'Disguised Link'],
  ['link_text_mismatch', 'Disguised Link'],
  ['url_redirect_', 'Redirecting Link'],
  ['url_open_redirect_param', 'Redirecting Link'],
  ['url_credential_wording', 'Login-Page Link'],
  ['url_risky_file_type', 'Download Link'],
  ['url_download_on_open', 'Download Link'],
  ['url_double_extension', 'Download Link'],
  ['url_domain_young', 'Brand-New Link Domain'],
  ['url_shortener', 'Shortened Link'],
  ['url_ip_host', 'Link to Raw IP'],
  ['url_obfuscated_ip', 'Link to Raw IP'],
  ['dangerous_link_scheme', 'Dangerous Link'],
  // sender identity (authentication / infrastructure)
  ['display_name_brand_spoof', 'Impersonated Sender', 'Possible Impersonation', true],
  ['sender_domain_lookalikes_claimed_org', 'Impersonated Sender', 'Possible Impersonation', true],
  ['sender_domain_lookalike', 'Impersonated Sender', 'Possible Impersonation', true],
  ['sender_domain_homograph', 'Impersonated Sender', 'Possible Impersonation', true],
  ['sender_domain_brand_misuse', 'Impersonated Sender', 'Possible Impersonation', true],
  ['role_impersonation_freemail', 'Impersonated Sender', 'Possible Impersonation', true],
  ['auth_all_failed', 'Sender Not Verified'],
  ['spf_fail', 'Sender Not Verified'],
  ['dkim_fail', 'Sender Not Verified'],
  ['dmarc_fail', 'Sender Not Verified'],
  ['auth_missing', 'Sender Not Verified'],
  ['multiple_from_headers', 'Forged Headers'],
  ['from_missing', 'Forged Headers'],
  ['reply_to_mismatch', 'Replies Go Elsewhere'],
  ['return_path_mismatch', 'Bounces Go Elsewhere'],
  ['internal_m365_message', 'Internal Message'],
  ['sender_domain_new', 'Brand-New Sender Domain'],
  ['sender_domain_unregistered', 'Unregistered Domain'],
  ['sender_domain_expired', 'Expired Domain'],
  ['sender_address_disposable', 'Throwaway Address'],
  ['sender_address_fraud_score', 'Risky Sender Address', 'Flagged Sender Address'],
  ['sender_address_recent_abuse', 'Risky Sender Address', 'Flagged Sender Address'],
  ['sender_address_', 'Questionable Sender Address'],
  ['sender_ip_known_abuser', 'Risky Sender IP', 'Flagged Sender IP'],
  ['sender_ip_abuse_reports', 'Risky Sender IP', 'Flagged Sender IP'],
  ['sender_ip_vt_detections', 'Risky Sender IP', 'Flagged Sender IP'],
  ['sender_ip_compromised', 'Risky Sender IP', 'Flagged Sender IP'],
  ['sender_ip_pulsedive', 'Risky Sender IP', 'Flagged Sender IP'],
  ['sender_ip_tor', 'Sent via Anonymiser'],
  ['sender_ip_anonymizer', 'Sent via Anonymiser'],
  // content
  ['bec_payment_reply_redirect', 'Payment Fraud Request'],
  ['content_bec_request', 'Payment Fraud Request'],
  ['content_payment_redirection', 'Payment Fraud Request'],
  ['content_payroll_diversion', 'Payroll Fraud Request'],
  ['content_payment_demand', 'Payment Demand'],
  ['content_financial_request', 'Asks for Money'],
  ['content_gift_card_request', 'Gift Card Scam'],
  ['content_credential_request', 'Asks for Login Details'],
  ['content_extortion', 'Extortion Threat'],
  ['content_brand_impersonation', 'Brand Impersonation'],
  ['content_delivery_scam', 'Delivery Scam'],
  ['content_advance_fee', 'Advance-Fee Scam'],
  ['content_document_share_lure', 'Fake Document Share'],
  ['content_attachment_lure', 'Attachment Lure'],
  ['content_qr_lure', 'QR Code Lure'],
  ['content_multiple_lure_signals', 'Phishing Lures'],
  ['content_urgency', 'Pressure Tactics'],
  ['content_hidden_text', 'Hidden Text'],
  ['content_text_obfuscation', 'Disguised Wording'],
  ['content_image_only_body', 'Image-Only Message'],
  ['content_language_not_analysed', 'Wording Not Checked'],
];

/** Headline when no specific finding matches, by area and how strongly that area scored. */
const BY_AREA: Record<Dimension, { bad: string; warn: string; minor: string }> = {
  authentication: { bad: 'Sender Not Trustworthy', warn: 'Suspicious Sender', minor: 'Minor Sender Notes' },
  infrastructure: { bad: 'Risky Infrastructure', warn: 'Questionable Infrastructure', minor: 'Minor Infrastructure Notes' },
  url: { bad: 'High-Risk Link', warn: 'Suspicious Link', minor: 'Minor Link Notes' },
  attachment: { bad: 'High-Risk Attachment', warn: 'Suspicious Attachment', minor: 'Minor Attachment Notes' },
  content: { bad: 'Phishing Wording', warn: 'Suspicious Wording', minor: 'Minor Wording Notes' },
};

const AREA_NOUN: Record<Dimension, string> = {
  authentication: 'sender', infrastructure: 'sending infrastructure', url: 'links', attachment: 'attachments', content: 'wording',
};

/** Informational findings that still describe the area best (they explain why it scored nothing). */
const ALWAYS_NAMED = new Set(['internal_m365_message', 'content_language_not_analysed']);

/**
 * File-type findings say what the file is ("Executable Attachment"), not that it is harmful: legitimate senders do
 * occasionally send installers or tools. "Malware" wording is kept for files that reputation lookups actually flag.
 */
function attachmentTypeHeadline(f: Finding): string {
  const ext = (/\(\.([a-z0-9]+)\)/i.exec(f.title)?.[1] ?? '').toLowerCase();
  if (ext === 'lnk') return 'Shortcut Attachment';
  if (['js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'bat', 'cmd', 'reg'].includes(ext)) return 'Script Attachment';
  if (['zip', 'rar', '7z', 'gz', 'cab'].includes(ext)) return 'Archive Attachment';
  if (['iso', 'img', 'vhd', 'vhdx'].includes(ext)) return 'Disk Image Attachment';
  if (['html', 'htm', 'shtml', 'svg'].includes(ext)) return 'Web-Page Attachment';
  if (['docm', 'xlsm', 'pptm', 'xlam'].includes(ext)) return 'Macro-Enabled Attachment';
  if (ext === 'one') return 'OneNote Attachment';
  if (ext) return 'Executable Attachment';
  return /\b(script|shortcut)\b/i.test(f.title) && !/\bprogram\b/i.test(f.title) ? 'Script Attachment' : 'Executable Attachment';
}

/** Findings that best explain an area when tied on severity with its top finding (a disguise says more than the type). */
const PREFERRED = new Set(['attachment_double_extension', 'attachment_type_mismatch']);

function findingHeadline(f: Finding, verdictMalicious: boolean): string | null {
  const n = f.id.toLowerCase();
  if (n === 'attachment_dangerous_type') return attachmentTypeHeadline(f);
  const sevHigh = f.severity === 'critical' || f.severity === 'high';
  for (const [key, text, softer, factual] of BY_FINDING) {
    if (!(key.endsWith('_') ? n.startsWith(key) : n === key)) continue;
    const strong = factual ? sevHigh : f.severity === 'critical' || (f.severity === 'high' && verdictMalicious);
    return strong || !softer ? text : softer;
  }
  return null;
}

export interface Glance { headline: string; summary: string }

const done = (checks: CheckRow[], id: string) => checks.find((c) => c.id === id && c.status === 'complete');
const passed = (c: CheckRow | undefined) => !!c?.result && c.result.split(',').every((x) => /^\s*pass\b/i.test(x));

/**
 * A positive headline for an area with no warning signs, stated only from checks that actually ran and passed. It never
 * calls the message safe: it says what was checked and that it raised nothing.
 */
function positive(dim: Dimension, checks: CheckRow[]): Glance | null {
  if (dim === 'authentication') {
    const rows = (['spf', 'dkim', 'dmarc'] as const).map((k) => ({ k: k.toUpperCase(), c: done(checks, `auth.${k}`) })).filter((x) => x.c);
    const ok = rows.filter((x) => passed(x.c));
    if (rows.length === 3 && ok.length === 3) return { headline: 'Sender Verified', summary: 'SPF, DKIM and DMARC all passed.' };
    if (ok.length && ok.length === rows.length) return { headline: 'Sender Checks Passed', summary: `${ok.map((x) => x.k).join(' and ')} passed.` };
    return null;
  }
  if (dim === 'url') {
    if (done(checks, 'urls.deep')) return { headline: 'No Known-Bad Links', summary: 'Reputation lookups flagged none of the links.' };
    if (done(checks, 'urls.openphish') || done(checks, 'urls.offline')) return { headline: 'No Link Warnings', summary: 'Screened locally only; no full reputation lookup yet.' };
    return null;
  }
  if (dim === 'attachment') {
    if (checks.some((c) => /^attach\.\d+\.(hash|scan|vt)/.test(c.id) && c.status === 'complete')) return { headline: 'No Known Malware', summary: 'Hash and scan lookups flagged none of the attachments.' };
    if (checks.some((c) => /^attach\.\d+\.static$/.test(c.id) && c.status === 'complete')) return { headline: 'No Attachment Warnings', summary: 'Inspected locally; no reputation result yet.' };
    return null;
  }
  if (dim === 'infrastructure') {
    if (done(checks, 'sender.ip') || done(checks, 'sender.domain')) return { headline: 'No Infrastructure Warnings', summary: 'The sender IP and domain raised no warnings.' };
    return null;
  }
  if (done(checks, 'content.rules')) return { headline: 'No Phishing Wording', summary: 'The message wording raised no warning signs.' };
  return null;
}

/** Short headline and one summary line for an area card. */
export function glance(dim: Dimension, tone: Tone, active: boolean, findings: Finding[], checks: CheckRow[] = [], verdictMalicious = false): Glance {
  const top = findings[0];
  if (!active && !top) return { headline: 'Not Checked', summary: `No data was available to check the ${AREA_NOUN[dim]}.` };
  const named = !!top && ALWAYS_NAMED.has(top.id.toLowerCase());
  const onlyInfo = findings.every((f) => f.severity === 'info');
  if (!named && onlyInfo && (tone === 'good' || !top)) return positive(dim, checks) ?? { headline: 'No Warning Signs', summary: `The ${AREA_NOUN[dim]} raised no warning signs.` };
  if (!top) return { headline: 'No Warning Signs', summary: `The ${AREA_NOUN[dim]} raised no warning signs.` };
  const lead = findings.find((f) => f.severity === top.severity && PREFERRED.has(f.id.toLowerCase())) ?? top;
  const minor = (top.severity === 'info' || top.severity === 'low') && !named;
  const fallback = dim === 'url' && tone === 'bad' && verdictMalicious ? 'Malicious Link' : BY_AREA[dim][tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : 'minor'];
  const headline = (!minor && findingHeadline(lead, verdictMalicious)) || fallback;
  return { headline, summary: tidy(lead.title) };
}
