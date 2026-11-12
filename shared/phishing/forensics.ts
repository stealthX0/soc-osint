/**
 * Stage 1: e-mail header forensics. Pure function from raw headers (+ what the analyst typed in) to structured evidence.
 *
 * Principles
 *  - Reuse shared/headers.ts for parsing; add what phishing triage needs on top (trust boundary, labelled authentication,
 *    mismatch detectors, comparison against analyst-supplied values).
 *  - Manually supplied sender data is a CLUE, never authority: it is compared against the headers and discrepancies are shown.
 *  - A mismatch is a signal, not a verdict: bulk mailers legitimately use different Return-Path / DKIM domains, so findings
 *    carry the context needed to weigh them later.
 */
import { analyzeHeaders, parseAuthResults, parseHeaderBlock } from '../headers';
import { normalizeHostname, parseEmail } from '../domain';
import { classifyIP, normalizeIP } from '../ip';
import { parseAddressList, parseMailbox, decodeMimeWords, type Mailbox } from './addresses';
import { assessAuthentication, type AuthAssessment } from './auth';
import { isFreeMail, sameOrg } from './domains';
import { check, makeFinding } from './findings';
import { determineTrust, type TrustBoundary, type TrustedHop } from './trust';
import type { CheckResult, DomainIndicator, DomainRole, EmailIndicator, EmailRole, Finding, IpIndicator, IpRole, SuppliedSender, TrustLevel } from './types';

export interface Discrepancy {
  field: 'sender_email' | 'sender_domain' | 'sender_ip' | 'subject';
  supplied: string;
  extracted: string | null;
  kind: 'match' | 'partial' | 'mismatch' | 'not_in_headers';
  note: string;
}

export interface HeaderForensics {
  headerCount: number;
  summary: { from: string | null; to: string | null; subject: string | null; date: string | null; messageId: string | null; returnPath: string | null; replyTo: string | null; sender: string | null; xMailer: string | null };
  addresses: { from: Mailbox[]; replyTo: Mailbox[]; returnPath: Mailbox | null; sender: Mailbox | null; to: Mailbox[] };
  hops: TrustedHop[];
  trust: TrustBoundary;
  authentication: AuthAssessment;
  totalDelaySeconds: number | null;
  ips: IpIndicator[];
  domains: DomainIndicator[];
  emails: EmailIndicator[];
  discrepancies: Discrepancy[];
  /**
   * Set when the message never crossed the internet: it was sent by a signed-in user inside the same Microsoft 365
   * organisation (Exchange marked it AuthAs: Internal and every Received hop is a Microsoft server). SPF / DKIM / DMARC do
   * not apply to such mail; the sender's own client IP (recorded by Exchange) is the one worth checking.
   */
  internal: InternalMessage | null;
  findings: Finding[];
  checks: CheckResult[];
  limits: string[];
}

export interface InternalMessage {
  platform: 'microsoft365';
  /** How Exchange accepted it (X-MS-Exchange-Organization-AuthMechanism / "with mapi" etc.), for the report. */
  submittedVia: string | null;
  /** Public IP of the device that submitted the message (x-ms-exchange-organization-originalclientipaddress). */
  clientIp: string | null;
}

/** Microsoft 365 / Exchange Online server names (mailbox and transport servers inside Microsoft's datacentres). */
const MS_INTERNAL_HOST = /(?:^|\.)(?:[a-z0-9-]+\.)*prod\.(?:outlook\.com|exchangelabs\.com)$/i;
/** Exchange's own name for a transport hop, stripped of the bracketed address it records ("HOST (2603:...)" / "HOST ([fe80::...])"). */
const hostOf = (s: string | null) => (s ?? '').trim().split(/[\s(]/)[0].toLowerCase();

/**
 * Internal Microsoft 365 message: all three must hold, so a forged header alone cannot make external mail look internal.
 *  1. X-MS-Exchange-Organization-AuthAs: Internal. Exchange Online removes X-MS-Exchange-Organization-* headers from mail
 *     arriving from the internet and sets AuthAs to Anonymous for it.
 *  2. Every Received hop is from and by a Microsoft 365 server (external mail's first hop is "from <the sender's server>").
 *  3. No Authentication-Results / Received-SPF: Microsoft adds them to every message that arrives from outside.
 */
function detectInternalM365(pairs: [string, string][], hops: { from: string | null; by: string | null; with: string | null }[], hasAuthResults: boolean): InternalMessage | null {
  const authAs = first(pairs, 'x-ms-exchange-organization-authas')?.trim().toLowerCase();
  if (authAs !== 'internal' || hasAuthResults || !hops.length) return null;
  if (!hops.every((h) => MS_INTERNAL_HOST.test(hostOf(h.by)) && MS_INTERNAL_HOST.test(hostOf(h.from)))) return null;
  const raw = first(pairs, 'x-ms-exchange-organization-originalclientipaddress')?.replace(/[[\]\s]/g, '') ?? null;
  const ip = raw ? normalizeIP(raw) : null;
  const cls = ip ? classifyIP(ip) : null;
  const mapi = hops.some((h) => /\bmapi\b/i.test(h.with ?? ''));
  return { platform: 'microsoft365', submittedVia: mapi ? 'Outlook / Exchange (MAPI)' : first(pairs, 'x-ms-exchange-organization-authmechanism') ? 'authenticated Exchange submission' : null, clientIp: ip && cls?.public ? ip : null };
}

const first = (p: [string, string][], name: string) => p.find(([n]) => n.toLowerCase() === name)?.[1] ?? null;
const all = (p: [string, string][], name: string) => p.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
const cap = (s: string | null, n = 300) => (s && s.length > n ? `${s.slice(0, n)}…` : s);

const trustFor = (t: TrustLevel): { trust: TrustLevel; reliability: 'medium' | 'low' } => ({ trust: t, reliability: t === 'receiver_reported' ? 'medium' : 'low' });

export function analyzeEmailHeaders(raw: string, supplied: SuppliedSender = {}): HeaderForensics {
  const base = analyzeHeaders(raw);
  const pairs = parseHeaderBlock(raw);
  const findings: Finding[] = [];
  const limits: string[] = [];

  /* ---- addresses ---- */
  const fromHeaders = all(pairs, 'from');
  const fromList = parseAddressList(fromHeaders[0]);
  const from = fromList[0] ?? null;
  const replyTo = parseAddressList(first(pairs, 'reply-to'));
  const rpRaw = first(pairs, 'return-path');
  const returnPath = rpRaw ? parseMailbox(rpRaw) : null;
  const senderHdr = first(pairs, 'sender') ? parseMailbox(first(pairs, 'sender')!) : null;
  const to = parseAddressList(first(pairs, 'to'));
  const fromDomain = from?.domain ?? null;
  const subject = (() => { const s = first(pairs, 'subject'); return s ? decodeMimeWords(s) : null; })();

  /* ---- trust boundary + authentication ---- */
  const firstAr = all(pairs, 'authentication-results')[0];
  const topAuthservId = firstAr ? parseAuthResults([firstAr]).authservId : null;
  const xo = first(pairs, 'x-originating-ip')?.replace(/[[\]\s]/g, '') ?? null;
  const { boundary: trust, hops } = determineTrust(base.hops, topAuthservId, xo);
  const auth = assessAuthentication(pairs, trust, fromDomain, returnPath?.domain ?? null);
  const internal = detectInternalM365(pairs, hops, auth.source !== 'none' || auth.headers.length > 0);

  const F = (f: Parameters<typeof makeFinding>[0]) => findings.push(makeFinding(f));

  /* ---- structure / spoofing patterns ---- */
  if (!pairs.length) F({ id: 'headers_unparsable', dimension: 'authentication', severity: 'info', title: 'No valid header lines found', detail: 'Paste the full raw headers ("Show original" / "View message source"), not the visible From/To/Subject lines.' });
  if (fromHeaders.length > 1) {
    F({ id: 'multiple_from_headers', dimension: 'authentication', severity: 'high', title: 'Message has more than one From header', detail: 'RFC 5322 allows exactly one From header. Duplicates are a known trick to make mail clients and authentication checks look at different senders.', exactness: 'exact', reliability: 'high', evidence: fromHeaders.map((v) => `From: ${cap(v)}`) });
  }
  if (pairs.length && !from) F({ id: 'from_missing', dimension: 'authentication', severity: 'low', title: 'No usable From address', detail: 'The From header is missing or could not be parsed as an e-mail address.', exactness: 'exact' });
  if (senderHdr?.domain && fromDomain && !sameOrg(senderHdr.domain, fromDomain)) {
    F({ id: 'sender_header_differs', dimension: 'authentication', severity: 'low', title: 'Sender header names a different domain than From', detail: `The Sender header (${senderHdr.domain}) differs from the From domain (${fromDomain}). Legitimate on behalf-of mail does this, so weigh it with authentication results.`, exactness: 'exact', evidence: [`From: ${cap(fromHeaders[0])}`, `Sender: ${cap(first(pairs, 'sender'))}`] });
  }

  // Display-name spoofing: the display name shows an address / domain that is not the real one.
  if (from?.display) {
    const m = from.display.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})|\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|co|gov|edu|bank|[a-z]{2}))\b/i);
    const shown = m?.[1] ?? m?.[2] ?? null;
    if (shown && fromDomain && !sameOrg(shown, fromDomain)) {
      F({ id: 'display_name_embeds_address', dimension: 'content', severity: 'medium', title: 'Display name shows a different address or domain than the real sender', detail: `The display name mentions "${shown}" but the message was sent from ${fromDomain}. Mail clients often show only the display name.`, exactness: 'exact', reliability: 'high', evidence: [`From: ${cap(fromHeaders[0])}`], indicator: { type: 'domain', value: fromDomain } });
    }
  }

  /* ---- From / Return-Path / Reply-To / DKIM / SPF consistency ---- */
  const dkimAligned = auth.alignment.dkimAligned;
  if (returnPath?.domain && fromDomain && !sameOrg(returnPath.domain, fromDomain)) {
    F({ id: 'return_path_mismatch', dimension: 'authentication', severity: dkimAligned === true ? 'info' : 'low', title: 'Return-Path domain differs from the From domain', detail: `Bounces go to ${returnPath.domain}, not ${fromDomain}. Normal for mailing services; check whether DKIM aligns with the From domain.${dkimAligned === true ? ' A DKIM signature does align here.' : ''}`, exactness: 'exact', evidence: [`From: ${cap(fromHeaders[0])}`, `Return-Path: ${cap(rpRaw)}`] });
  }
  // Mailing lists set Reply-To to the list itself. That is only accepted when the message carries List-Id AND the Reply-To
  // is the list address the message was sent to (To / Cc / List-Post), so adding a List-Id header alone cannot hide a BEC
  // Reply-To (an attacker writes to the victim, not to the list).
  const listId = first(pairs, 'list-id');
  const listAddrs = new Set([...to, ...parseAddressList(first(pairs, 'cc')), ...parseAddressList((first(pairs, 'list-post') ?? '').replace(/mailto:/gi, ''))].map((a) => a.address?.toLowerCase()).filter(Boolean) as string[]);
  const isListReply = (r: { address: string | null }) => !!listId && !!r.address && listAddrs.has(r.address.toLowerCase());
  const badReply = replyTo.filter((r) => r.domain && fromDomain && !sameOrg(r.domain, fromDomain) && !isListReply(r));
  if (badReply.length) {
    const free = badReply.some((r) => isFreeMail(r.domain)) && !isFreeMail(fromDomain);
    const esp = badReply.every((r) => returnPath?.domain && sameOrg(r.domain, returnPath.domain)) && dkimAligned === true;
    F({
      id: 'reply_to_mismatch', dimension: 'authentication', severity: esp ? 'low' : 'medium',
      title: free ? 'Replies are routed to a free mailbox provider' : 'Replies are routed to a different organisation',
      detail: `Reply-To (${badReply.map((r) => r.address).join(', ')}) is not at the From domain (${fromDomain}), so a reply goes somewhere the visible sender does not control.${free ? ' A consumer mailbox in Reply-To is a common business-email-compromise pattern.' : ''}${esp ? ' It matches the Return-Path domain and DKIM aligns, which is typical of a helpdesk or mailing service.' : ''}`,
      exactness: 'exact', reliability: 'high', evidence: [`From: ${cap(fromHeaders[0])}`, `Reply-To: ${cap(first(pairs, 'reply-to'))}`], indicator: { type: 'email', value: badReply[0].address ?? badReply[0].raw },
    });
  }
  const sigDomains = auth.dkimSignatures.map((s) => s.domain).filter((d): d is string => !!d);
  const dkimAnyAligned = auth.dkim.length ? dkimAligned === true : sigDomains.some((d) => sameOrg(d, fromDomain));
  if (fromDomain && sigDomains.length && !dkimAnyAligned) {
    F({ id: 'dkim_domain_mismatch', dimension: 'authentication', severity: 'low', title: 'No DKIM signature belongs to the From domain', detail: `Signed by ${[...new Set(sigDomains)].join(', ')}, not ${fromDomain}. A signature from another domain does not authenticate the visible sender.`, exactness: 'exact', evidence: auth.dkimSignatures.map((s) => `DKIM-Signature: d=${s.domain} s=${s.selector}`) });
  }
  for (const s of auth.dkimSignatures) {
    if (!s.coversFrom && s.signedHeaders.length) F({ id: 'dkim_not_covering_from', dimension: 'authentication', severity: 'low', title: 'A DKIM signature does not cover the From header', detail: `The signature by ${s.domain ?? 'unknown'} does not sign From, so the visible sender could be changed without breaking it.`, exactness: 'exact' });
    if (s.weakAlgorithm) F({ id: 'dkim_weak_algorithm', dimension: 'authentication', severity: 'info', title: 'DKIM signature uses SHA-1', detail: `${s.domain ?? 'A signer'} signs with ${s.algorithm}; SHA-1 is deprecated for DKIM.`, exactness: 'exact' });
  }
  if (auth.spf?.result === 'pass' && auth.spf.domain && fromDomain && !sameOrg(auth.spf.domain, fromDomain)) {
    F({ id: 'spf_domain_mismatch', dimension: 'authentication', severity: 'low', title: 'SPF passed for a domain other than the From domain', detail: `SPF authenticated ${auth.spf.domain}, not ${fromDomain}. That does not establish that the visible sender is genuine (DMARC requires alignment).`, exactness: 'exact', ...trustFor(auth.spf.trust) });
  }
  const mid = first(pairs, 'message-id')?.match(/@([^>\s]+)/)?.[1] ?? null;
  if (mid && fromDomain && !sameOrg(mid, fromDomain)) {
    F({ id: 'message_id_domain_mismatch', dimension: 'authentication', severity: 'info', title: 'Message-ID was generated by a different domain', detail: `Message-ID host ${mid} differs from the From domain ${fromDomain}. Informational: mailbox providers and mailing services generate their own IDs.`, exactness: 'exact' });
  }

  /* ---- authentication results ---- */
  const bad = (r: string | null | undefined) => !!r && ['fail', 'hardfail', 'permerror'].includes(r);
  const spfBad = bad(auth.spf?.result);
  const dkimFail = auth.dkim.some((d) => d.result === 'fail') || (auth.dkim.length > 0 && auth.dkim.every((d) => d.result !== 'pass'));
  const dmarcBad = auth.dmarc?.result === 'fail';
  if (spfBad && dkimFail && dmarcBad) {
    F({ id: 'auth_all_failed', dimension: 'authentication', severity: 'high', title: 'SPF, DKIM and DMARC all failed', detail: 'The receiving server reported failures for all three checks: the message could not be tied to the From domain by any mechanism. This is the typical signature of spoofing, though forwarding and misconfiguration can also cause it.', exactness: 'exact', ...trustFor(auth.dmarc!.trust), evidence: [`spf=${auth.spf!.result}`, ...auth.dkim.map((d) => `dkim=${d.result}${d.domain ? ` (${d.domain})` : ''}`), `dmarc=${auth.dmarc!.result}${auth.dmarc!.policy ? ` p=${auth.dmarc!.policy}` : ''}`] });
  } else {
    if (auth.spf) {
      const r = auth.spf.result;
      if (spfBad) F({ id: 'spf_fail', dimension: 'authentication', severity: 'medium', title: `SPF ${r}`, detail: `The sending IP${auth.spf.ip ? ` ${auth.spf.ip}` : ''} is not authorised by the SPF policy of ${auth.spf.domain ?? 'the envelope sender domain'}.`, exactness: 'exact', ...trustFor(auth.spf.trust), evidence: [cap(auth.spf.detail, 200) ?? ''] });
      else if (r === 'softfail') F({ id: 'spf_softfail', dimension: 'authentication', severity: 'low', title: 'SPF softfail', detail: `${auth.spf.domain ?? 'The domain'} flags this sender IP as probably not authorised (~all).`, exactness: 'exact', ...trustFor(auth.spf.trust) });
      else if (r === 'none' || r === 'neutral') F({ id: 'spf_none', dimension: 'authentication', severity: 'info', title: `SPF ${r}`, detail: 'The envelope sender domain publishes no usable SPF verdict for this IP.', exactness: 'exact', ...trustFor(auth.spf.trust) });
    }
    if (auth.dkim.length && dkimFail) F({ id: 'dkim_fail', dimension: 'authentication', severity: 'medium', title: 'No DKIM signature verified', detail: `Reported DKIM results: ${auth.dkim.map((d) => `${d.result}${d.domain ? ` (${d.domain})` : ''}`).join(', ')}.`, exactness: 'exact', ...trustFor(auth.dkim[0].trust) });
    if (auth.dmarc && dmarcBad) F({ id: 'dmarc_fail', dimension: 'authentication', severity: 'medium', title: 'DMARC failed', detail: `The From domain${auth.dmarc.headerFrom ? ` (${auth.dmarc.headerFrom})` : ''} did not get SPF or DKIM alignment${auth.dmarc.policy ? `; its policy is p=${auth.dmarc.policy}` : ''}. A DMARC failure alone does not prove the message is malicious.`, exactness: 'exact', ...trustFor(auth.dmarc.trust) });
    else if (auth.dmarc && ['none', 'permerror', 'temperror'].includes(auth.dmarc.result)) F({ id: 'dmarc_none', dimension: 'authentication', severity: 'low', title: `DMARC ${auth.dmarc.result}`, detail: 'No enforceable DMARC result: the From domain can be spoofed more easily.', exactness: 'exact', ...trustFor(auth.dmarc.trust) });
  }
  for (const c of auth.conflicts) F({ id: 'auth_conflict', dimension: 'authentication', severity: 'medium', title: 'Authentication evidence conflicts', detail: `${c} Either the headers were altered or the receiving policy differs from the standard rules; treat the authentication result as unreliable.`, exactness: 'exact', trust: 'derived', reliability: 'high' });
  if (auth.arc.newestChainValidation === 'fail') F({ id: 'arc_chain_failed', dimension: 'authentication', severity: 'medium', title: 'ARC chain reported as failed', detail: 'The newest ARC seal records a failed chain validation, so earlier authentication results cannot be relied on after forwarding.', exactness: 'exact', ...trustFor('receiver_reported') });

  const unverifiedOnly = auth.headers.length > 0 && !auth.headers.some((h) => h.trust === 'receiver_reported');
  if (unverifiedOnly) F({ id: 'auth_results_unverified', dimension: 'authentication', severity: 'low', title: 'Authentication-Results could not be tied to the receiving server', detail: `The header names ${auth.headers[0].authservId ?? 'no server'}, which does not match the server that accepted the message. It may have been added upstream or edited, so it is treated as unverified.`, exactness: 'exact', trust: 'unverified', reliability: 'low' });
  else if (auth.headers.slice(1).length) F({ id: 'auth_results_extra_headers', dimension: 'authentication', severity: 'info', title: `${auth.headers.length - 1} older Authentication-Results header(s) ignored`, detail: 'Only the newest header (added by the receiving server) is used. Older ones were written by earlier systems or by the sender.', exactness: 'exact' });
  if (internal) {
    F({ id: 'internal_m365_message', dimension: 'authentication', severity: 'info', title: 'Sent from inside the organisation (Microsoft 365)', detail: `Exchange accepted this message from a signed-in user of the same Microsoft 365 organisation${internal.submittedVia ? ` (${internal.submittedVia})` : ''}, and every hop is a Microsoft server: it never crossed the internet, so SPF, DKIM and DMARC do not apply. The risk with internal mail is a compromised colleague's account, which would pass any authentication check${internal.clientIp ? `; the sending device's IP (${internal.clientIp}) is checked instead` : ''}.`, exactness: 'exact', trust: 'receiver_reported', reliability: 'high', evidence: ['X-MS-Exchange-Organization-AuthAs: Internal', ...hops.slice(0, 1).map((h) => `Received: from ${hostOf(h.from)} by ${hostOf(h.by)}${h.with ? ` with ${h.with}` : ''}`), ...(internal.clientIp ? [`x-ms-exchange-organization-originalclientipaddress: ${internal.clientIp}`] : [])] });
  } else if (pairs.length && auth.source === 'none') {
    F({ id: 'auth_missing', dimension: 'authentication', severity: 'info', title: 'No authentication results in these headers', detail: 'There is no Authentication-Results or Received-SPF header, so SPF / DKIM / DMARC outcomes cannot be read. Paste the complete headers from the receiving mailbox.' });
  }

  /* ---- delivery path ---- */
  if (trust.untrustedHops > 0) F({ id: 'untrusted_received_hops', dimension: 'infrastructure', severity: 'info', title: `${trust.untrustedHops} Received header(s) precede the trusted boundary`, detail: 'Hops older than the point where the receiving organisation accepted the message can be forged by the sender; only the trusted connection is used as the sending infrastructure.' });
  if (xo) F({ id: 'x_originating_ip_present', dimension: 'infrastructure', severity: 'info', title: 'X-Originating-IP present', detail: 'Some webmail systems record the user\'s IP here. It is an unverified clue.', indicator: { type: 'ip', value: xo }, trust: 'unverified', reliability: 'low' });
  if (hops.some((h) => (h.delaySeconds ?? 0) < -60)) F({ id: 'received_timestamps_inconsistent', dimension: 'infrastructure', severity: 'low', title: 'Received timestamps go backwards', detail: 'A later hop is timestamped earlier than the hop before it: clock skew, or Received headers written by hand.', exactness: 'exact' });
  const stamps = hops.map((h) => h.timestamp).filter((t): t is string => !!t);
  const dateHdr = first(pairs, 'date');
  if (dateHdr && stamps.length && Math.abs(Date.parse(dateHdr) - Date.parse(stamps[0])) > 86_400_000) F({ id: 'date_header_skewed', dimension: 'infrastructure', severity: 'low', title: 'Date header differs from the first Received time by more than a day', detail: 'A mismatched Date header is common in forged or replayed mail.', exactness: 'exact' });

  /* ---- supplied values vs headers ---- */
  const discrepancies: Discrepancy[] = [];
  const suppliedEmail = supplied.email ? parseEmail(supplied.email.replace(/^.*<|>.*$/g, '').trim()) : null;
  if (supplied.email?.trim()) {
    const s = suppliedEmail ? `${suppliedEmail.local}@${suppliedEmail.domain}`.toLowerCase() : supplied.email.trim();
    const real = from?.address?.toLowerCase() ?? null;
    const others = [returnPath?.address, ...replyTo.map((r) => r.address), senderHdr?.address].filter(Boolean).map((a) => a!.toLowerCase());
    if (!from) discrepancies.push({ field: 'sender_email', supplied: s, extracted: null, kind: 'not_in_headers', note: 'The headers have no readable From address to compare with.' });
    else if (s === real) discrepancies.push({ field: 'sender_email', supplied: s, extracted: real, kind: 'match', note: 'Matches the From header.' });
    else if (others.includes(s)) discrepancies.push({ field: 'sender_email', supplied: s, extracted: real, kind: 'partial', note: `The address you entered appears in another header (Return-Path / Reply-To / Sender) but the From header says ${real}.` });
    else {
      discrepancies.push({ field: 'sender_email', supplied: s, extracted: real, kind: 'mismatch', note: `You entered ${s} but the From header says ${real ?? 'something else'}.` });
      F({ id: 'supplied_sender_mismatch', dimension: 'authentication', severity: 'medium', title: 'Sender address you entered differs from the headers', detail: `You entered ${s}; the headers say the message was from ${real ?? 'an unreadable address'}. The headers are used for the investigation.`, exactness: 'exact', trust: 'derived', reliability: 'high', evidence: [`Entered: ${s}`, `From: ${cap(fromHeaders[0])}`] });
    }
  }
  const claimedHost = supplied.domain?.trim() ? normalizeHostname(supplied.domain) : null;
  if (claimedHost) {
    if (!fromDomain) discrepancies.push({ field: 'sender_domain', supplied: claimedHost, extracted: null, kind: 'not_in_headers', note: 'No From domain to compare with.' });
    else if (sameOrg(claimedHost, fromDomain)) discrepancies.push({ field: 'sender_domain', supplied: claimedHost, extracted: fromDomain, kind: 'match', note: 'The sender belongs to the organisation it claims to be.' });
    else {
      discrepancies.push({ field: 'sender_domain', supplied: claimedHost, extracted: fromDomain, kind: 'mismatch', note: `The message claims to be from ${claimedHost} but was sent from ${fromDomain}.` });
      F({ id: 'sender_domain_differs_from_claimed_org', dimension: 'content', severity: 'medium', title: 'Sender is not at the organisation it claims to be from', detail: `You identified the claimed organisation as ${claimedHost}, but the From domain is ${fromDomain}. This is the core pattern of brand impersonation, unless ${fromDomain} is a legitimate third-party sender for that organisation.`, exactness: 'related', trust: 'derived', reliability: 'medium', indicator: { type: 'domain', value: fromDomain }, evidence: [`Claimed: ${claimedHost}`, `From: ${cap(fromHeaders[0])}`] });
    }
  }
  const suppliedIp = supplied.ip?.trim() ? normalizeIP(supplied.ip.trim().replace(/^\[|\]$/g, '')) : null;
  if (suppliedIp) {
    const chain = hops.flatMap((h) => h.ips.map((ip) => ({ ip: normalizeIP(ip) ?? ip, hop: h.index, trust: h.trust })));
    const hit = chain.find((c) => c.ip === suppliedIp);
    if (trust.connectingIp && suppliedIp === normalizeIP(trust.connectingIp)) discrepancies.push({ field: 'sender_ip', supplied: suppliedIp, extracted: trust.connectingIp, kind: 'match', note: 'Matches the IP that connected to the receiving server.' });
    else if (hit) discrepancies.push({ field: 'sender_ip', supplied: suppliedIp, extracted: trust.connectingIp, kind: 'partial', note: `The IP you entered appears in Received hop ${hit.hop} (${hit.trust}), but it is not the IP that connected to the receiving server${trust.connectingIp ? ` (${trust.connectingIp})` : ''}.` });
    else {
      discrepancies.push({ field: 'sender_ip', supplied: suppliedIp, extracted: trust.connectingIp, kind: 'not_in_headers', note: `The IP you entered does not appear in the headers${trust.connectingIp ? `; the connecting IP is ${trust.connectingIp}` : ''}. It is investigated only as an unverified clue.` });
      F({ id: 'supplied_ip_not_in_headers', dimension: 'infrastructure', severity: 'info', title: 'Sender IP you entered is not in the headers', detail: 'The IP is kept as an unverified clue; the connecting IP from the trusted Received header is the one that counts.', trust: 'unverified', reliability: 'low', indicator: { type: 'ip', value: suppliedIp } });
    }
  } else if (supplied.ip?.trim()) {
    discrepancies.push({ field: 'sender_ip', supplied: supplied.ip.trim(), extracted: trust.connectingIp, kind: 'mismatch', note: 'That is not a valid IPv4 or IPv6 address and was ignored.' });
  }

  /* ---- indicators ---- */
  const ipRoles = new Map<string, IpIndicator>();
  const rank: Record<IpRole, number> = { sender_client: 0, connecting: 1, claimed_origin: 2, x_originating: 3, supplied: 4 };
  const addIp = (ip: string | null, role: IpRole, trustL: TrustLevel, hop: number | null, note?: string) => {
    const n = ip ? normalizeIP(ip) : null;
    if (!n) return;
    const cur = ipRoles.get(n);
    if (!cur || rank[role] < rank[cur.role]) ipRoles.set(n, { ip: n, role, trust: trustL, hop, ...(note ? { note } : {}) });
  };
  addIp(trust.connectingIp, trust.connectingIpSource === 'x_originating_ip' ? 'x_originating' : 'connecting', trust.connectingIpSource === 'trusted_received' ? 'receiver_reported' : 'unverified', trust.boundaryHop, trust.connectingIpSource === 'trusted_received' ? 'IP that connected to the receiving server' : undefined);
  addIp(trust.claimedOriginIp, 'claimed_origin', 'unverified', null, 'Named only in untrusted Received headers');
  addIp(xo && trust.connectingIp !== xo ? xo : null, 'x_originating', 'unverified', null);
  addIp(suppliedIp, 'supplied', 'unverified', null, 'Entered by the analyst');
  addIp(internal?.clientIp ?? null, 'sender_client', 'receiver_reported', null, 'Device that sent this internal message (recorded by Microsoft 365)');

  const domMap = new Map<string, Set<DomainRole>>();
  const addDom = (d: string | null | undefined, role: DomainRole) => {
    const n = d ? normalizeHostname(d) : null;
    if (!n || !n.includes('.')) return;
    (domMap.get(n) ?? domMap.set(n, new Set()).get(n)!).add(role);
  };
  addDom(fromDomain, 'from'); addDom(returnPath?.domain, 'return_path'); replyTo.forEach((r) => addDom(r.domain, 'reply_to')); addDom(senderHdr?.domain, 'sender_header');
  auth.dkimSignatures.forEach((s) => addDom(s.domain, 'dkim')); auth.dkim.forEach((d) => addDom(d.domain, 'dkim')); addDom(auth.spf?.domain, 'spf'); addDom(mid, 'message_id');
  addDom(claimedHost, 'claimed_org'); addDom(suppliedEmail?.domain, 'supplied');

  const emMap = new Map<string, Set<EmailRole>>();
  const addEm = (a: string | null | undefined, role: EmailRole) => { if (a) (emMap.get(a.toLowerCase()) ?? emMap.set(a.toLowerCase(), new Set()).get(a.toLowerCase())!).add(role); };
  addEm(from?.address, 'from'); addEm(returnPath?.address, 'return_path'); replyTo.forEach((r) => addEm(r.address, 'reply_to')); addEm(senderHdr?.address, 'sender_header');
  addEm(suppliedEmail ? `${suppliedEmail.local}@${suppliedEmail.domain}` : null, 'supplied');

  /* ---- checks + limits ---- */
  const checks: CheckResult[] = [];
  checks.push(pairs.length
    ? check('headers.parse', 'headers', 'Header parsing', 'complete', `${pairs.length} headers, ${hops.length} Received hop(s)`)
    : check('headers.parse', 'headers', 'Header parsing', 'failed', null, 'No valid header lines were found.'));
  checks.push(hops.length
    ? internal
      ? check('headers.trust', 'headers', 'Trusted receiver boundary', 'complete', `internal Microsoft 365 message${internal.clientIp ? `; sent from ${internal.clientIp}` : ''}`, 'Every hop is inside Microsoft 365; there is no internet connection to trace.')
      : check('headers.trust', 'headers', 'Trusted receiver boundary', 'complete', `${trust.confidence} confidence${trust.connectingIp ? `; connecting IP ${trust.connectingIp}` : '; no public connecting IP'}`, trust.notes.join(' ') || undefined)
    : check('headers.trust', 'headers', 'Trusted receiver boundary', 'skipped', null, 'No Received headers to analyse.'));
  const label = (t: TrustLevel) => (t === 'receiver_reported' ? 'receiver-reported' : t === 'unverified' ? 'unverified' : t);
  const NA_INTERNAL = 'Sent inside the organisation\'s Microsoft 365 (never crossed the internet), so this check does not apply.';
  if (internal && !auth.spf && !auth.dkim.length && !auth.dmarc) {
    checks.push(check('auth.spf', 'authentication', 'SPF', 'not_applicable', null, NA_INTERNAL));
    checks.push(check('auth.dkim', 'authentication', 'DKIM', 'not_applicable', null, NA_INTERNAL));
    checks.push(check('auth.dmarc', 'authentication', 'DMARC', 'not_applicable', null, NA_INTERNAL));
  } else {
  checks.push(auth.spf ? check('auth.spf', 'authentication', 'SPF', 'complete', `${auth.spf.result} (${label(auth.spf.trust)})`) : check('auth.spf', 'authentication', 'SPF', 'skipped', null, 'No SPF result in the supplied headers.'));
  checks.push(auth.dkim.length ? check('auth.dkim', 'authentication', 'DKIM', 'complete', `${auth.dkim.map((d) => d.result).join(', ')} (${label(auth.dkim[0].trust)})`) : check('auth.dkim', 'authentication', 'DKIM', 'skipped', null, auth.dkimSignatures.length ? 'The message is signed, but the headers carry no verification result.' : 'No DKIM result in the supplied headers.'));
  checks.push(auth.dmarc ? check('auth.dmarc', 'authentication', 'DMARC', 'complete', `${auth.dmarc.result} (${label(auth.dmarc.trust)})`) : check('auth.dmarc', 'authentication', 'DMARC', 'skipped', null, 'No DMARC result in the supplied headers.'));
  }
  checks.push(auth.arc.present ? check('auth.arc', 'authentication', 'ARC', 'complete', `${auth.arc.instances} hop(s), newest chain ${auth.arc.newestChainValidation ?? 'unknown'}`) : check('auth.arc', 'authentication', 'ARC', 'not_applicable', null, 'No ARC headers: the message was not forwarded through an ARC-aware system.'));
  checks.push(discrepancies.length ? check('headers.supplied', 'headers', 'Supplied values vs headers', 'complete', `${discrepancies.filter((d) => d.kind === 'match').length} of ${discrepancies.length} match`) : check('headers.supplied', 'headers', 'Supplied values vs headers', 'not_applicable', null, 'No sender details were entered.'));

  if (pairs.length) {
    limits.push('Authentication results are read from the pasted headers. Spectrix cannot re-run the receiving server\'s SPF check or verify DKIM signatures from headers alone, and pasted headers can be edited.');
    if (internal) limits.push('This is an internal Microsoft 365 message: authentication checks do not apply, and a message from a compromised colleague\'s account would look exactly like this. Check the sending device\'s IP and confirm unusual requests with the colleague by another channel.');
    else if (trust.confidence === 'low') limits.push('The sending infrastructure could not be established from these headers.');
  }

  return {
    headerCount: pairs.length,
    summary: { from: first(pairs, 'from') ? decodeMimeWords(first(pairs, 'from')!) : null, to: first(pairs, 'to') ? decodeMimeWords(first(pairs, 'to')!) : null, subject, date: dateHdr, messageId: first(pairs, 'message-id'), returnPath: rpRaw, replyTo: first(pairs, 'reply-to') ? decodeMimeWords(first(pairs, 'reply-to')!) : null, sender: first(pairs, 'sender'), xMailer: base.summary.xMailer },
    addresses: { from: fromList, replyTo, returnPath, sender: senderHdr, to },
    hops, trust, authentication: auth, totalDelaySeconds: base.totalDelaySeconds,
    ips: [...ipRoles.values()].sort((a, b) => rank[a.role] - rank[b.role]),
    domains: [...domMap].map(([domain, roles]) => ({ domain, roles: [...roles] })),
    emails: [...emMap].map(([address, roles]) => ({ address, roles: [...roles] })),
    discrepancies, internal, findings, checks, limits,
  };
}

