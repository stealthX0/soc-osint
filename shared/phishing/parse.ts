/**
 * Stage 0/1 orchestration: validate the submission, split headers from body, run header forensics, read the MIME body,
 * extract links and attachments, and assemble the indicator set every later stage consumes.
 *
 * Pure apart from SHA-256 hashing (WebCrypto). No network access: this stage never contacts a third party.
 */
import { extractMessage } from './mime';
import { analyzeIdentity } from './brand';
import { offlineLinkFindings } from './urlTriage';
import { analyzeContent, stripReceiverBanners, RECEIVER_BANNER_LINK, type ContentAnalysis } from './content';
import { isFreeMail } from './domains';
import { analyzeEmailHeaders, type HeaderForensics } from './forensics';
import { extractLinks, type ExtractedLink, type SkippedLink } from './links';
import { check, dedupeFindings, makeFinding, sortFindings } from './findings';
import { parseHeaderBlock } from '../headers';
import { normalizeHostname, parseEmail } from '../domain';
import { normalizeIP } from '../ip';
import { analyzeAttachmentSet, type AttachmentStaticSummary } from './attachments';
import { LIMITS } from './types';
import type { AttachmentRef, CheckResult, Finding, HashType, IndicatorSet, PhishingInput, SuppliedAttachment } from './types';

export interface AttachmentMeta {
  filename: string | null;
  extension: string | null;
  declaredType: string | null;
  size: number | null;
  inline: boolean;
  hash: string | null;
  hashType: HashType | null;
  origin: 'embedded' | 'supplied';
}

export interface ParseStageResult {
  received: { headerBytes: number; bodyChars: number };
  forensics: HeaderForensics | null;
  content: { subject: string | null; text: string; hasHtml: boolean; bodyKind: 'none' | 'plain' | 'html' | 'multipart'; partCount: number; truncated: boolean; warnings: string[]; analysis: ContentAnalysis };
  links: ExtractedLink[];
  skippedLinks: SkippedLink[];
  /** What was cut off for size. The verdict treats truncation as an evidence gap: a message can hide one bad link among many. */
  truncation: { links: boolean; text: boolean; mime: boolean };
  attachments: AttachmentMeta[];
  /** Static analysis summary per attachment (detected type, entropy, URLs/IPs found inside). Index matches `attachments`. */
  attachmentStatic: AttachmentStaticSummary[];
  indicators: IndicatorSet;
  findings: Finding[];
  checks: CheckResult[];
  limits: string[];
}

/* ------------------------------------------------------------ validation */

const str = (v: unknown, max: number): string | undefined => (typeof v === 'string' && v.trim() ? v.slice(0, max) : undefined);

export function validateInput(raw: unknown): { ok: true; value: PhishingInput } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, error: 'Request body must be a JSON object.' };
  const r = raw as Record<string, unknown>;
  for (const k of ['headers', 'subject', 'body'] as const) if (r[k] !== undefined && typeof r[k] !== 'string') return { ok: false, error: `"${k}" must be a string.` };
  const headers = typeof r.headers === 'string' ? r.headers : undefined;
  if (headers && new TextEncoder().encode(headers).length > LIMITS.headerBytes * 2) return { ok: false, error: `Headers must be under ${LIMITS.headerBytes / 1000} KB.` };
  const body = typeof r.body === 'string' ? r.body : undefined;
  if (body && body.length > LIMITS.bodyChars) return { ok: false, error: 'The message body is too large.' };

  const s = (r.sender && typeof r.sender === 'object' ? r.sender : {}) as Record<string, unknown>;
  const urls = Array.isArray(r.urls) ? r.urls.filter((u): u is string => typeof u === 'string' && !!u.trim()).map((u) => u.trim().slice(0, 2048)) : [];
  if (urls.length > LIMITS.urls) return { ok: false, error: `At most ${LIMITS.urls} URLs can be submitted.` };
  const att = Array.isArray(r.attachments) ? (r.attachments as unknown[]).filter((a): a is Record<string, unknown> => !!a && typeof a === 'object') : [];
  if (att.length > LIMITS.attachments) return { ok: false, error: `At most ${LIMITS.attachments} attachments can be listed.` };

  const value: PhishingInput = {
    headers, body,
    subject: str(r.subject, LIMITS.field),
    sender: { email: str(s.email, LIMITS.field), displayName: str(s.displayName, LIMITS.field), domain: str(s.domain, LIMITS.field), ip: str(s.ip, 64) },
    urls,
    attachments: att.map((a) => ({ name: str(a.name, 255), hash: str(a.hash, 128) })).filter((a) => a.name || a.hash),
  };
  const hasSender = !!(value.sender?.email || value.sender?.domain || value.sender?.ip || value.sender?.displayName);
  if (!value.headers?.trim() && !value.body?.trim() && !urls.length && !value.attachments?.length && !hasSender) {
    return { ok: false, error: 'Nothing to analyse: paste the email headers, the body, or at least a sender, URL or attachment.' };
  }
  return { ok: true, value };
}

/* ---------------------------------------------------------------- helpers */

/** A pasted .eml puts the body after the first blank line of the header box; use it when no separate body was given. */
function splitSubmission(headersIn: string, bodyIn: string): { headers: string; body: string } {
  const h = headersIn.replace(/\r\n?/g, '\n').replace(/^\s*\n/, '');
  const i = h.indexOf('\n\n');
  if (i < 0) return { headers: h, body: bodyIn };
  return { headers: h.slice(0, i), body: bodyIn.trim() ? bodyIn : h.slice(i + 2) };
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const hashTypeOf = (h: string): HashType | null => (/^[a-f0-9]{64}$/i.test(h) ? 'sha256' : /^[a-f0-9]{40}$/i.test(h) ? 'sha1' : /^[a-f0-9]{32}$/i.test(h) ? 'md5' : null);
const extOf = (name: string | null) => { const m = name?.toLowerCase().match(/\.([a-z0-9]{1,8})$/); return m ? m[1] : null; };

/* ------------------------------------------------------------------- main */

export async function parseSubmission(input: PhishingInput): Promise<ParseStageResult> {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const limits: string[] = [];

  const { headers: headersText, body: bodyText } = splitSubmission(input.headers ?? '', input.body ?? '');
  const sender = input.sender ?? {};

  /* headers */
  const forensics = headersText.trim() ? analyzeEmailHeaders(headersText, sender) : null;
  if (forensics) {
    findings.push(...forensics.findings);
    checks.push(...forensics.checks);
    limits.push(...forensics.limits);
  } else {
    checks.push(check('headers.parse', 'headers', 'Header parsing', 'skipped', null, 'No headers supplied: routing and authentication analysis were skipped. Headers are the most valuable input.'));
    limits.push('No headers were supplied, so the sending infrastructure and SPF / DKIM / DMARC results could not be assessed.');
  }

  /* sender identity (local, no network): brand misuse, look-alikes, display-name spoofing */
  const suppliedEmail = sender.email ? parseEmail(sender.email.replace(/^.*<|>.*$/g, '').trim()) : null;
  const identityFrom = forensics?.addresses.from[0]?.domain ?? suppliedEmail?.domain ?? null;
  if (identityFrom) {
    findings.push(...analyzeIdentity({ fromDomain: identityFrom, display: forensics?.addresses.from[0]?.display ?? sender.displayName ?? null, claimedDomain: sender.domain ? normalizeHostname(sender.domain) : null }));
    checks.push(check('sender.identity', 'sender', 'Sender identity (brand / look-alike analysis)', 'complete', 'no impersonation indicators', 'Compares the sender domain and display name with well-known brands and the organisation you said the message claims to be.'));
    const idf = findings.filter((f) => f.source === 'identity-analysis').length;
    if (idf) checks[checks.length - 1].result = `${idf} indicator(s)`;
  } else {
    checks.push(check('sender.identity', 'sender', 'Sender identity (brand / look-alike analysis)', 'skipped', null, 'No sender address or domain to analyse.'));
  }

  /* body */
  const topPairs = headersText.trim() ? parseHeaderBlock(headersText) : [];
  const msg = extractMessage(topPairs, bodyText);
  const subject = forensics?.summary.subject ?? input.subject ?? null;
  if (forensics && input.subject?.trim() && forensics.summary.subject && input.subject.trim().replace(/\s+/g, ' ').toLowerCase() !== forensics.summary.subject.replace(/\s+/g, ' ').toLowerCase()) {
    forensics.discrepancies.push({ field: 'subject', supplied: input.subject.trim(), extracted: forensics.summary.subject, kind: 'mismatch', note: 'The subject you entered differs from the Subject header; the header was used.' });
  }
  checks.push(msg.bodyKind === 'none'
    ? check('parse.body', 'parse', 'Message body', 'not_applicable', null, 'No body supplied: content, link and attachment analysis will rely on what you entered.')
    : check('parse.body', 'parse', 'Message body', 'complete', `${msg.bodyKind}, ${msg.text.length.toLocaleString('en-US')} characters${msg.partCount > 1 ? `, ${msg.partCount} MIME parts` : ''}`, msg.warnings.join(' ') || undefined));
  if (msg.truncated) limits.push(`The message text was truncated to ${LIMITS.textChars.toLocaleString('en-US')} characters.`);

  /* banners the RECEIVING system added (Microsoft first-contact tip, "external sender" cautions) are not the sender's
     words or links: remove them before reading the content */
  const banner = stripReceiverBanners(msg.text);
  const htmlBanner = msg.html ? stripReceiverBanners(msg.html) : { text: msg.html, removed: 0 };
  const senderText = banner.text;
  const senderHtml = htmlBanner.text;

  /* links */
  const ext = extractLinks({ text: senderText, html: senderHtml, manual: input.urls });
  const bannerLinks = ext.links.filter((l) => RECEIVER_BANNER_LINK.test(l.normalized) && !l.sources.includes('manual' as never));
  if (bannerLinks.length) ext.links = ext.links.filter((l) => !bannerLinks.includes(l));
  const bannerNote = banner.removed || htmlBanner.removed || bannerLinks.length ? `Ignored a notice added by the receiving mail system (such as "You don't often get email from…" or an external-sender caution)${bannerLinks.length ? ` and its ${bannerLinks.length} link(s)` : ''}.` : '';
  checks.push(check('parse.links', 'parse', 'Link extraction', 'complete', `${ext.links.length} unique link(s)${ext.skipped.length ? `, ${ext.skipped.length} skipped` : ''}`, [ext.truncated ? `Only the first ${LIMITS.links} links were kept.` : '', bannerNote].filter(Boolean).join(' ') || undefined));
  if (ext.truncated) limits.push(`The message has more links than could be analysed (at most ${LIMITS.links} unique links are kept). Review the rest manually: a bad link can hide among many harmless ones.`);
  if (ext.links.length) {
    const roles = ['from', 'return_path', 'dkim', 'sender_header'];
    const off = offlineLinkFindings(
      ext.links.map((l) => ({ url: l.normalized, text: l.text, sources: l.sources, count: l.count, wrapped: !!l.wrapper })),
      {
        senderDomains: (forensics?.domains ?? []).filter((d) => d.roles.some((x) => roles.includes(x))).map((d) => d.domain),
        claimedBrands: [],
        claimedDomains: sender.domain ? [sender.domain] : [],
        displayName: sender.displayName || forensics?.addresses.from[0]?.display || undefined,
        subject: subject ?? undefined,
        text: senderText.slice(0, 20_000),
      },
    );
    findings.push(...off.findings);
    checks.push(check('urls.offline', 'urls', 'Local link screening', 'complete', `${off.linkCount} link(s) screened${off.findings.length ? `, ${off.findings.length} finding(s)` : ''}`, 'Look-alike domains, link text that shows a different site, brand mismatches and raw IPs. No lookups: use the Links tab to check reputation.'));
  }
  for (const s of ext.skipped.filter((x) => x.reason.startsWith('javascript') || x.reason.startsWith('data'))) {
    findings.push(makeFinding({ id: 'dangerous_link_scheme', dimension: 'url', severity: 'medium', title: `A link uses a ${s.reason.split(':')[0]}: scheme`, detail: 'Links that run script or embed data are not normal in e-mail and are used to evade link scanners.', exactness: 'exact', source: 'link-extraction', evidence: [s.value.slice(0, 120)] }));
  }

  /* wording: urgency, credential / payment requests, extortion, QR and other lures (local, deterministic) */
  const wording = analyzeContent({
    subject, text: senderText, html: senderHtml, linkCount: ext.links.length,
    attachments: msg.attachments.map((a) => ({ filename: a.filename, inline: a.inline, declaredType: a.declaredType })),
    displayName: forensics?.addresses.from[0]?.display ?? sender.displayName ?? null,
    fromDomain: identityFrom, fromIsFreeMail: isFreeMail(identityFrom),
  });
  findings.push(...wording.findings);
  /* the classic invoice-fraud pairing: replies go to a different organisation AND the message asks for money */
  const replyRedirect = findings.find((f) => f.id === 'reply_to_mismatch' && f.severity === 'medium');
  const moneyAsk = wording.findings.filter((f) => ['content_payment_demand', 'content_payment_redirection', 'content_financial_request', 'content_payroll_diversion', 'content_gift_card_request'].includes(f.id));
  if (replyRedirect && moneyAsk.length) {
    findings.push(makeFinding({
      id: 'bec_payment_reply_redirect', dimension: 'content', severity: 'high',
      title: 'Asks for payment while routing replies to a different organisation',
      detail: 'The message requests money and its Reply-To sends your answer to a mailbox the sender does not control. This is the typical shape of invoice fraud and business-email compromise: any query about the payment reaches the fraudster, not the real company. Confirm through a contact you already hold before paying.',
      exactness: 'exact', source: 'content-analysis',
      evidence: [...(replyRedirect.evidence ?? []).slice(0, 2), ...moneyAsk.map((f) => f.title)].slice(0, 4),
    }));
  }
  checks.push(!wording.analysis.analysed
    ? check('content.rules', 'content', 'Message wording analysis', 'skipped', null, 'No message text to read.')
    : check('content.rules', 'content', 'Message wording analysis', 'complete', wording.analysis.languageSupported ? `${wording.analysis.categories.length} lure type(s) recognised` : 'language not supported', wording.analysis.notes.join(' ') || 'Pattern rules for urgency, credential and payment requests, extortion, QR and delivery lures. Indicators for review, not a verdict.'));
  if (!wording.analysis.languageSupported) limits.push('The message is mostly not in Latin script, so the wording rules (written for English) could not assess it.');

  /* attachments */
  const attachments: AttachmentMeta[] = [];
  for (const a of msg.attachments) {
    attachments.push({
      filename: a.filename, extension: extOf(a.filename), declaredType: a.declaredType, size: a.size, inline: a.inline,
      hash: a.bytes && a.bytes.byteLength ? await sha256(a.bytes) : null, hashType: a.bytes && a.bytes.byteLength ? 'sha256' : null, origin: 'embedded',
    });
  }
  let invalidHashes = 0;
  for (const a of input.attachments ?? ([] as SuppliedAttachment[])) {
    const hash = a.hash?.trim().toLowerCase() ?? null;
    const ht = hash ? hashTypeOf(hash) : null;
    if (hash && !ht) invalidHashes++;
    attachments.push({ filename: a.name ?? null, extension: extOf(a.name ?? null), declaredType: null, size: null, inline: false, hash: ht ? hash : null, hashType: ht, origin: 'supplied' });
  }
  // Step 4: static analysis of the embedded bytes (and filename rules for supplied entries); no network.
  const attStatic = analyzeAttachmentSet(msg.attachments, attachments);
  findings.push(...attStatic.findings);
  checks.push(...attStatic.checks);
  limits.push(...attStatic.limits);
  const real = attachments.filter((a) => !a.inline);
  checks.push(attachments.length
    ? check('parse.attachments', 'parse', 'Attachment inventory', 'complete', `${real.length} attachment(s), ${attachments.filter((a) => a.hash).length} hashed`, invalidHashes ? `${invalidHashes} supplied hash(es) were not valid MD5 / SHA-1 / SHA-256 and were ignored.` : undefined)
    : check('parse.attachments', 'parse', 'Attachment inventory', 'not_applicable', null, 'No attachments found or supplied.'));

  /* indicators */
  const indicators: IndicatorSet = {
    emails: forensics?.emails ?? [],
    domains: forensics?.domains ?? [],
    ips: forensics?.ips ?? [],
    urls: ext.links.map((l) => l.normalized),
    attachments: attachments.map<AttachmentRef>((a) => ({ filename: a.filename, hash: a.hash, hashType: a.hashType, size: a.size, origin: a.origin, declaredType: a.declaredType })),
  };
  if (!forensics) {
    const e = sender.email ? parseEmail(sender.email.replace(/^.*<|>.*$/g, '').trim()) : null;
    if (e) { indicators.emails.push({ address: `${e.local}@${e.domain}`.toLowerCase(), roles: ['supplied'] }); indicators.domains.push({ domain: e.domain, roles: ['supplied'] }); }
    const d = sender.domain ? normalizeHostname(sender.domain) : null;
    if (d) { const ex = indicators.domains.find((x) => x.domain === d); if (ex) ex.roles.push('claimed_org'); else indicators.domains.push({ domain: d, roles: ['claimed_org'] }); }
    const ip = sender.ip ? normalizeIP(sender.ip.replace(/^\[|\]$/g, '')) : null;
    if (ip) indicators.ips.push({ ip, role: 'supplied', trust: 'unverified', hop: null, note: 'Entered by the analyst; no headers to confirm it.' });
  }

  return {
    received: { headerBytes: new TextEncoder().encode(headersText).length, bodyChars: bodyText.length },
    forensics,
    content: { subject, text: msg.text, hasHtml: !!msg.html, bodyKind: msg.bodyKind, partCount: msg.partCount, truncated: msg.truncated, warnings: msg.warnings, analysis: wording.analysis },
    links: ext.links,
    skippedLinks: ext.skipped,
    truncation: { links: ext.truncated, text: msg.truncated, mime: msg.warnings.some((w) => /limit reached|deeper than/i.test(w)) },
    attachments,
    attachmentStatic: attStatic.summaries,
    indicators,
    findings: sortFindings(dedupeFindings(findings)),
    checks,
    limits,
  };
}
