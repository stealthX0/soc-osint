/**
 * Plain-language wording for the Key Findings cards: a short headline and one summary line per area, so an analyst can
 * read the outcome at a glance. Everything is derived from the verdict engine's findings and area scores; nothing is
 * scored again, and the technical detail stays in the tabs.
 */
import type { Tone } from '../../components/ui';
import type { Dimension, Finding } from '../../../shared/phishing/types';
import { tidy } from '../../../shared/phishing/summary';

/** Headline for the strongest finding of an area, matched by finding id (exact id, or an id prefix ending in "_"). */
const BY_FINDING: [string, string][] = [
  // attachments
  ['attachment_hash_malicious', 'Known Malware Attachment'],
  ['attachment_html_credential_form', 'Fake Login Attachment'],
  ['attachment_macro_present', 'Macro-Enabled Attachment'],
  ['attachment_double_extension', 'Disguised Attachment'],
  ['attachment_type_mismatch', 'Disguised Attachment'],
  ['attachment_dangerous_type', 'Dangerous Attachment'],
  ['attachment_archive_dangerous_content', 'Dangerous Attachment'],
  ['attachment_password_protected', 'Locked Attachment'],
  ['attachment_hash_suspicious', 'Suspicious Attachment'],
  // links
  ['url_listed_phishing', 'Known Phishing Link'],
  ['url_listed_malware', 'Known Malware Link'],
  ['url_engine_detections', 'Malicious Link'],
  ['url_scan_malicious', 'Malicious Link'],
  ['url_host_scan_malicious', 'Malicious Link'],
  ['url_dns_blocked', 'Malicious Link'],
  ['url_blocklisted_host', 'Malicious Link'],
  ['url_host_listed', 'Malicious Link'],
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
  ['display_name_brand_spoof', 'Impersonated Sender'],
  ['sender_domain_lookalikes_claimed_org', 'Impersonated Sender'],
  ['sender_domain_lookalike', 'Impersonated Sender'],
  ['sender_domain_homograph', 'Impersonated Sender'],
  ['sender_domain_brand_misuse', 'Impersonated Sender'],
  ['role_impersonation_freemail', 'Impersonated Sender'],
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
  ['sender_address_fraud_score', 'Risky Sender Address'],
  ['sender_address_recent_abuse', 'Risky Sender Address'],
  ['sender_address_', 'Questionable Sender Address'],
  ['sender_ip_known_abuser', 'Risky Sender IP'],
  ['sender_ip_abuse_reports', 'Risky Sender IP'],
  ['sender_ip_vt_detections', 'Risky Sender IP'],
  ['sender_ip_compromised', 'Risky Sender IP'],
  ['sender_ip_pulsedive', 'Risky Sender IP'],
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
  url: { bad: 'Malicious Link', warn: 'Suspicious Link', minor: 'Minor Link Notes' },
  attachment: { bad: 'Dangerous Attachment', warn: 'Suspicious Attachment', minor: 'Minor Attachment Notes' },
  content: { bad: 'Phishing Wording', warn: 'Suspicious Wording', minor: 'Minor Wording Notes' },
};

const AREA_NOUN: Record<Dimension, string> = {
  authentication: 'sender', infrastructure: 'sending infrastructure', url: 'links', attachment: 'attachments', content: 'wording',
};

/** Informational findings that still describe the area best (they explain why it scored nothing). */
const ALWAYS_NAMED = new Set(['internal_m365_message', 'content_language_not_analysed']);

function findingHeadline(id: string): string | null {
  const n = id.toLowerCase();
  for (const [key, text] of BY_FINDING) if (key.endsWith('_') ? n.startsWith(key) : n === key) return text;
  return null;
}

export interface Glance { headline: string; summary: string }

/** Short headline and one summary line for an area card. */
export function glance(dim: Dimension, tone: Tone, active: boolean, findings: Finding[]): Glance {
  const top = findings[0];
  if (!active && !top) return { headline: 'Not Checked', summary: `No data was available to check the ${AREA_NOUN[dim]}.` };
  const minorTop = !top || top.severity === 'info' || top.severity === 'low';
  if (!top || (tone === 'good' && minorTop && !ALWAYS_NAMED.has(top.id.toLowerCase()))) return { headline: 'No Warning Signs', summary: `The ${AREA_NOUN[dim]} raised no warning signs.` };
  const minor = (top.severity === 'info' || top.severity === 'low') && !ALWAYS_NAMED.has(top.id.toLowerCase());
  const headline = (!minor && findingHeadline(top.id)) || BY_AREA[dim][tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : 'minor'];
  return { headline, summary: tidy(top.title) };
}
