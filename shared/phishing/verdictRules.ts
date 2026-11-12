/**
 * Step 6: the tunable part of the verdict engine, kept apart from the logic so it can be calibrated without touching it.
 *
 * EVERY NUMBER IN THIS FILE IS AN INITIAL DESIGN PROPOSAL. They come from the starting values in the design document and
 * have NOT been validated against labelled phishing and legitimate mail. They are not probabilities. Calibrate them with
 * the labelled corpus in tests/fixtures (see docs in tests/phishing-step6.test.ts) before relying on the score.
 */
import type { Dimension, Finding, Severity } from './types';

/** Share of the risk score each dimension can carry. Dimensions with nothing to assess are dropped and the rest renormalised. */
export const DIMENSION_WEIGHTS: Record<Dimension, number> = {
  authentication: 0.2,
  infrastructure: 0.2,
  url: 0.3,
  attachment: 0.2,
  content: 0.15, // raised from 0.1 (12 Nov): invoice / BEC fraud is decided mostly by wording and Reply-To
};

/** Used when a finding id has no entry below. The audit trail lists such findings as "unmapped". */
export const SEVERITY_POINTS: Record<Severity, number> = { critical: 45, high: 20, medium: 10, low: 4, info: 0 };
export const UNMAPPED_FACTOR = 0.8;

type Spec = number | Partial<Record<Severity, number>>;
const by = (s: Partial<Record<Severity, number>>): Spec => s;

/**
 * Base points per finding id (before the context multipliers). Numbers marked "doc" are the example values from the design
 * document; the rest were interpolated so related findings stay in a sensible order. A confirmed hit on the exact URL or
 * file is worth about 45, a strong impersonation signal about 25, an authentication failure about 15 and ordinary lure
 * wording well under 10.
 *
 * Authentication results that PASS never subtract risk (they appear as supporting evidence only): an authenticated sender
 * can still send a malicious message.
 */
export const POINTS: Record<string, Spec> = {
  /* ---- attachments */
  attachment_hash_malicious: by({ critical: 45, high: 30 }), // doc: +45
  attachment_hash_suspicious: 12,
  attachment_hash_known_good: 0,
  attachment_hash_unknown: 0,
  attachment_dangerous_type: by({ high: 18, medium: 8 }),
  attachment_double_extension: 25,
  attachment_type_mismatch: by({ high: 22, medium: 12 }),
  attachment_macro_present: by({ high: 20, medium: 12 }),
  attachment_html_credential_form: 28,
  attachment_pdf_active_content: 10,
  attachment_archive_dangerous_content: 22,
  attachment_password_protected: 10,
  attachment_embedded_urls: 0,
  attachment_high_entropy: 2,
  attachment_not_inspected: 0,

  /* ---- URLs and destinations (url_final_* uses the same points: it is the same observation about the redirect destination) */
  url_listed_phishing: 45, // doc: +45
  url_listed_malware: 45,
  url_engine_detections: by({ critical: 40, high: 25, medium: 12, low: 5 }),
  url_engine_suspicious: 5,
  url_scan_malicious: 20,
  url_host_scan_malicious: 8,
  url_threat_intel_rating: by({ high: 14, medium: 8, low: 3 }),
  url_dns_blocked: 15,
  url_host_listed: 10,
  url_blocklisted_host: 10,
  url_brand_mismatch: 14,
  url_lookalike_domain: by({ high: 18, medium: 14, low: 6 }),
  url_homograph_domain: 20,
  url_deceptive_userinfo: 15,
  url_userinfo: 4,
  url_ip_host: 6,
  url_obfuscated_ip: 12,
  url_redirect_to_ip: 10,
  url_redirect_cross_domain: 2,
  url_redirect_chain: 2,
  url_open_redirect_param: 3,
  url_obfuscation_pattern: 2,
  url_credential_wording: 5,
  url_login_without_tls: 5,
  url_double_extension: 15,
  url_risky_file_type: 12,
  url_download_on_open: 10,
  url_shortener: 3,
  url_unusual_tld: 3,
  url_domain_young: by({ high: 10, medium: 7, low: 3 }), // doc: newly registered +5
  url_domain_dead: 3,
  link_text_mismatch: 14,
  dangerous_link_scheme: 8,

  /* ---- sender authenticity and authentication */
  auth_all_failed: 22, // doc example: DMARC failure with sender mismatch +15; raised because header-derived results are discounted (as-supplied) before they count
  spf_fail: 6,
  spf_softfail: 2,
  spf_none: 0,
  dkim_fail: 4,
  dmarc_fail: 8,
  dmarc_none: 2,
  dmarc_policy_not_applied: 8,
  spf_independent_fail: by({ medium: 6, low: 2 }),
  spf_independent_disagrees: by({ medium: 6, low: 2 }),
  spf_independent_pass: 0,
  auth_conflict: 6,
  arc_chain_failed: 6,
  multiple_from_headers: 20,
  from_missing: 3,
  reply_to_mismatch: by({ medium: 10, low: 3 }), // doc: +10
  return_path_mismatch: by({ low: 2, info: 0 }),
  dkim_domain_mismatch: 3,
  dkim_not_covering_from: 3,
  dkim_weak_algorithm: 0,
  spf_domain_mismatch: 2,
  sender_header_differs: 2,
  message_id_domain_mismatch: 0,
  auth_results_unverified: 2,
  auth_results_extra_headers: 0,
  auth_missing: 0,
  headers_unparsable: 0,
  supplied_sender_mismatch: 8,
  supplied_ip_not_in_headers: 0,
  date_header_skewed: 2,
  received_timestamps_inconsistent: 3,
  untrusted_received_hops: 0,
  x_originating_ip_present: 0,

  /* ---- sender infrastructure and identity */
  sender_domain_lookalikes_claimed_org: 25, // doc: strong sender-domain impersonation +25
  sender_domain_homograph: 25,
  sender_domain_lookalike: 18,
  sender_domain_brand_misuse: 15,
  sender_domain_differs_from_claimed_org: 12,
  sender_domain_credential_words: 6,
  sender_domain_risky_tld: 3,
  display_name_brand_spoof: by({ high: 18, medium: 12 }),
  display_name_embeds_address: 10,
  role_impersonation_freemail: 14,
  sender_domain_new: by({ high: 12, medium: 8, low: 3 }), // doc: newly registered +5
  sender_domain_unregistered: by({ medium: 8, low: 3 }),
  sender_domain_expired: 3,
  sender_domain_unprotected: 3,
  sender_domain_spoofable: 2,
  sender_domain_no_mail_setup: 3,
  sender_ip_abuse_reports: by({ high: 12, medium: 6 }), // doc: malicious sender IP reputation +12
  sender_ip_vt_detections: by({ high: 12, medium: 6, low: 2 }),
  sender_ip_pulsedive: by({ high: 10, medium: 5, low: 2 }),
  sender_ip_known_abuser: 5,
  sender_ip_tor: 8,
  sender_ip_anonymizer: 3,
  sender_ip_compromised: 12,
  sender_ip_no_ptr: 2,
  sender_ip_residential_ptr: 3,
  sender_infra_shared_provider: 0,
  sender_address_spam_domain: 8,
  sender_address_disposable: 3,
  sender_address_no_mx: 3,
  sender_address_misspelt_domain: 6,
  sender_address_free_subdomain: 2,
  sender_address_recent_abuse: 8,
  sender_address_fraud_score: by({ medium: 6, low: 3 }),
  sender_address_mailbox_missing: 4,
  sender_address_risky_tld: 2,

  /* ---- content and behaviour */
  content_urgency: by({ low: 4, info: 0 }),
  content_credential_request: 8, // doc: suspicious credential-harvesting language +8
  content_financial_request: 5,
  content_gift_card_request: 22,
  content_payment_redirection: 24,
  content_payroll_diversion: 22,
  content_bec_request: by({ medium: 14, low: 6 }),
  content_extortion: 22,
  content_delivery_scam: 4,
  content_advance_fee: 4,
  content_document_share_lure: 4,
  content_attachment_lure: 4,
  content_qr_lure: by({ medium: 12, low: 5 }),
  content_image_only_body: 4,
  content_hidden_text: 4,
  content_text_obfuscation: by({ medium: 10, low: 3 }),
  content_brand_impersonation: 10,
  content_multiple_lure_signals: 14,
  content_payment_demand: by({ medium: 10, low: 4 }),
  content_forwarded_thread: 3,
  bec_payment_reply_redirect: 20,
  content_language_not_analysed: 0,
};

/** Ids whose points are zero by design (context only). Listed so the audit can tell "mapped to zero" from "unmapped". */
export const pointsFor = (f: Finding, overrides?: Record<string, number>): { points: number; mapped: boolean } => {
  const id = f.id.replace(/^url_final_/, 'url_');
  if (overrides && id in overrides) return { points: overrides[id], mapped: true };
  const spec = POINTS[id];
  if (spec === undefined) return { points: SEVERITY_POINTS[f.severity] * UNMAPPED_FACTOR, mapped: false };
  if (typeof spec === 'number') return { points: spec, mapped: true };
  return { points: spec[f.severity] ?? SEVERITY_POINTS[f.severity] * UNMAPPED_FACTOR, mapped: true };
};

/* ------------------------------------------------------- independence groups */

/**
 * Findings that describe the SAME underlying fact must not add up as if they were separate evidence (a failing DMARC and a
 * failing SPF are one authentication problem; a look-alike sender domain seen by three detectors is one impersonation).
 * Within a group: the strongest counts in full and the rest at 25%, capped at 150% of the strongest.
 */
const SENDER_IMPERSONATION = new Set([
  'sender_domain_lookalikes_claimed_org', 'sender_domain_homograph', 'sender_domain_lookalike', 'sender_domain_brand_misuse', 'sender_domain_differs_from_claimed_org',
  'display_name_brand_spoof', 'content_brand_impersonation', 'sender_domain_credential_words',
]);
const AUTH_FAILURE = new Set(['auth_all_failed', 'spf_fail', 'spf_softfail', 'dkim_fail', 'dmarc_fail', 'dmarc_policy_not_applied', 'spf_independent_fail', 'spf_independent_disagrees', 'dkim_domain_mismatch', 'spf_domain_mismatch', 'arc_chain_failed']);
const IP_REPUTATION = new Set(['sender_ip_abuse_reports', 'sender_ip_vt_detections', 'sender_ip_pulsedive', 'sender_ip_known_abuser', 'sender_ip_tor', 'sender_ip_anonymizer', 'sender_ip_compromised']);
const ADDRESS_REPUTATION = new Set(['sender_address_spam_domain', 'sender_address_disposable', 'sender_address_no_mx', 'sender_address_misspelt_domain', 'sender_address_free_subdomain', 'sender_address_recent_abuse', 'sender_address_fraud_score', 'sender_address_mailbox_missing', 'sender_address_risky_tld']);
const URL_REPUTATION = new Set(['url_listed_phishing', 'url_listed_malware', 'url_engine_detections', 'url_engine_suspicious', 'url_scan_malicious', 'url_host_scan_malicious', 'url_threat_intel_rating', 'url_dns_blocked', 'url_host_listed', 'url_blocklisted_host']);
const LINK_IMPERSONATION = new Set(['url_brand_mismatch', 'url_lookalike_domain', 'url_homograph_domain', 'url_deceptive_userinfo', 'link_text_mismatch']);
const LURE_WORDING = new Set(['content_urgency', 'content_credential_request', 'content_financial_request', 'content_delivery_scam', 'content_advance_fee', 'content_document_share_lure', 'content_attachment_lure', 'content_qr_lure', 'content_multiple_lure_signals']);
/** One request for money, however many rules describe it: the BEC combination includes the payment ask it is built from. */
const PAYMENT_REQUEST = new Set(['bec_payment_reply_redirect', 'content_payment_demand', 'content_payment_redirection', 'content_payroll_diversion', 'content_gift_card_request']);

export function groupOf(f: Finding): string | null {
  const id = f.id.replace(/^url_final_/, 'url_');
  const at = f.indicator?.value ?? '';
  if (SENDER_IMPERSONATION.has(id)) return 'sender_impersonation';
  if (AUTH_FAILURE.has(id)) return 'auth_failure';
  if (IP_REPUTATION.has(id)) return `ip_reputation:${at}`;
  if (ADDRESS_REPUTATION.has(id)) return `address_reputation:${at}`;
  if (id === 'sender_domain_new' || id === 'sender_domain_unregistered' || id === 'sender_domain_expired') return `domain_registration:${at}`;
  if (URL_REPUTATION.has(id)) return `url_reputation:${f.id.startsWith('url_final_') ? 'final:' : ''}${at}`;
  // A LOW brand mismatch is an ordinary link (not a call to action, form or look-alike) that is not on the claimed brand's
  // domain. Newsletters that mention a brand have dozens of these, so together they are one weak fact, not one per link.
  if (id === 'url_brand_mismatch' && f.severity === 'low') return 'brand_mismatch_weak';
  if (LINK_IMPERSONATION.has(id)) return `link_impersonation:${at}`;
  if (id.startsWith('url_')) return `url_hygiene:${f.id.startsWith('url_final_') ? 'final:' : ''}${at}`;
  if (id.startsWith('attachment_')) return `attachment:${at}`;
  if (LURE_WORDING.has(id)) return 'lure_wording';
  if (PAYMENT_REQUEST.has(id)) return 'payment_request';
  return null;
}

export const GROUP_REST_FACTOR = 0.25;
export const GROUP_CAP = 1.5;

/* ------------------------------------------------------------ multipliers */

export const EXACTNESS_FACTOR = { exact: 1, related: 0.6, contextual: 0.3 } as const;
export const RELIABILITY_FACTOR = { high: 1, medium: 0.8, low: 0.55 } as const;
export const TRUST_FACTOR = { receiver_reported: 0.9, derived: 0.9, independently_verified: 1, unverified: 0.55 } as const;

/** Findings about an IP that sits on shared mail infrastructure say little about the individual message. */
export const SHARED_INFRA_FACTOR = 0.4;
export const SHARED_INFRA_AFFECTED = new Set(['sender_ip_abuse_reports', 'sender_ip_vt_detections', 'sender_ip_pulsedive', 'sender_ip_known_abuser', 'sender_ip_no_ptr', 'sender_ip_residential_ptr', 'sender_ip_anonymizer']);

export function freshnessFactor(observedAt: string | null | undefined, now: number): number {
  if (!observedAt) return 1;
  const t = Date.parse(observedAt);
  if (!Number.isFinite(t)) return 1;
  const days = (now - t) / 86_400_000;
  return days > 365 ? 0.6 : days > 90 ? 0.8 : days > 30 ? 0.9 : 1;
}

/* --------------------------------------------------------------- thresholds */

export const THRESHOLDS = {
  /** Dimension score = 100 * (1 - e^(-points / SATURATION)) */
  saturation: 35,
  /**
   * How much an area counts towards the headline risk, as an exponent derived from its weight relative to the heaviest area:
   * risk = 100 * (1 - PRODUCT over areas of (1 - score/100) ^ e),  e = (combineFloor + (1 - combineFloor) * weight / maxWeight) * combineScale.
   * An area with nothing found contributes a factor of 1, so clean areas can never dilute the others, and any extra
   * evidence can only raise the risk.
   */
  combineScale: 1,
  /** Smallest exponent any area gets (0 = purely by weight); keeps light areas such as content from being ignored. */
  combineFloor: 0.5,
  /** Highest risk a message that no verdict rule calls Malicious can show (Malicious is floored at maliciousFloor). */
  nonMaliciousCap: 84,
  /** High-risk Suspicious (BEC pattern or convergent evidence) shows at least this risk. */
  highRiskFloor: 75,
  /** Convergent evidence: this many areas (3) each scoring at least convergentAreaScore, with risk at least convergentRisk. */
  convergentAreaScore: 50,
  convergentRisk: 70,
  maliciousFloor: 85,
  /** Risk at or above this is Suspicious. (28 on the combined scale introduced 12 Nov; the earlier average-based scale used 25.) */
  suspiciousRisk: 28,
  /** A single strong indicator (counted points) is enough for Suspicious. */
  strongSingle: 15,
  /** A signal this big counts as a "meaningful" warning sign (a Reply-To mismatch is 10; ordinary lure wording is below it). */
  meaningful: 10,
  /** Two meaningful signals plus this much risk is Suspicious. */
  twoSignalsRisk: 20,
  /** Likely legitimate needs risk below this and no meaningful warning sign. */
  legitimateRisk: 15,
  /** ... and at least this much overall coverage. */
  legitimateCoverage: 0.55,
  highConfidence: 75,
  mediumConfidence: 50,
} as const;

export type Thresholds = { -readonly [K in keyof typeof THRESHOLDS]: number };
