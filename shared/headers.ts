/** E-mail header analysis (RFC 5322 / RFC 8601) – pure functions, no I/O. */
import { classifyIP, parseIP } from './ip';
import type { Issue } from './emailAuth';

export interface Hop {
  index: number;
  from: string | null;
  by: string | null;
  with: string | null;
  ips: string[];
  publicIps: string[];
  timestamp: string | null; // ISO
  /** seconds since previous hop (chronological order) */
  delaySeconds: number | null;
  raw: string;
}

export interface AuthResult { method: string; result: string; detail: string; props: Record<string, string> }

export interface HeaderAnalysis {
  headerCount: number;
  summary: {
    from: string | null;
    to: string | null;
    subject: string | null;
    date: string | null;
    messageId: string | null;
    returnPath: string | null;
    replyTo: string | null;
    xMailer: string | null;
  };
  authentication: { spf: string | null; dkim: string | null; dmarc: string | null; results: AuthResult[]; authservId: string | null };
  hops: Hop[];
  originIp: string | null;
  totalDelaySeconds: number | null;
  findings: Issue[];
  dkimSignatures: { domain: string | null; selector: string | null; algorithm: string | null }[];
}

export const MAX_HEADER_BYTES = 100_000;

/** Unfolds continuation lines and returns [name, value] pairs in original order. */
export function parseHeaderBlock(raw: string): [string, string][] {
  const headerPart = raw.replace(/\r\n?/g, '\n').split(/\n\n/)[0] ?? '';
  const out: [string, string][] = [];
  for (const line of headerPart.split('\n')) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1][1] += ' ' + line.trim();
    else {
      const i = line.indexOf(':');
      if (i > 0 && /^[!-9;-~]+$/.test(line.slice(0, i))) out.push([line.slice(0, i), line.slice(i + 1).trim()]);
    }
  }
  return out;
}

const first = (h: [string, string][], name: string) => h.find(([n]) => n.toLowerCase() === name)?.[1] ?? null;
const all = (h: [string, string][], name: string) => h.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);

function emailDomain(v: string | null): string | null {
  if (!v) return null;
  const m = v.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  return m ? m[1].toLowerCase() : null;
}

/** Naive organisational domain (last two labels). Good enough for mismatch hints. */
const orgDomain = (d: string) => d.split('.').slice(-2).join('.');

function parseReceived(value: string, index: number): Hop {
  const [body, datePart] = (() => {
    const i = value.lastIndexOf(';');
    return i >= 0 ? [value.slice(0, i), value.slice(i + 1)] : [value, ''];
  })();
  const grab = (kw: string) => body.match(new RegExp(`\\b${kw}\\s+([^\\s;(]+)`, 'i'))?.[1] ?? null;
  const ips = new Set<string>();
  for (const m of body.matchAll(/\[?((?:\d{1,3}\.){3}\d{1,3})\]?|\[(?:IPv6:)?([0-9a-f:]{3,39})\]/gi)) {
    const cand = m[1] ?? m[2];
    if (cand && parseIP(cand)) ips.add(cand);
  }
  const ts = Date.parse(datePart.replace(/\([^)]*\)/g, '').trim());
  return {
    index,
    from: grab('from'),
    by: grab('by'),
    with: grab('with'),
    ips: [...ips],
    publicIps: [...ips].filter((ip) => classifyIP(ip)?.public),
    timestamp: Number.isNaN(ts) ? null : new Date(ts).toISOString(),
    delaySeconds: null,
    raw: value,
  };
}

export function parseAuthResults(values: string[]): { results: AuthResult[]; authservId: string | null } {
  const results: AuthResult[] = [];
  let authservId: string | null = null;
  for (const v of values) {
    const segs = v.split(';').map((s) => s.trim()).filter(Boolean);
    if (!segs.length) continue;
    // Microsoft 365 (and a few others) omit the authserv-id: the header starts straight with "spf=pass ...".
    const head = segs[0].split(/\s+/)[0] ?? '';
    const hasId = !/^[a-z0-9-]+=/i.test(head);
    if (hasId) authservId ??= head || null;
    for (const seg of hasId ? segs.slice(1) : segs) {
      const m = seg.match(/^([a-z0-9-]+)\s*=\s*([a-z]+)\s*(.*)$/i);
      if (!m) continue;
      const props: Record<string, string> = {};
      for (const p of m[3].matchAll(/([a-z0-9_.-]+\.[a-z0-9_-]+)\s*=\s*("[^"]*"|\S+)/gi)) {
        props[p[1].toLowerCase()] = p[2].replace(/^"|"$/g, '');
      }
      results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), detail: m[3].trim(), props });
    }
  }
  return { results, authservId };
}

export function analyzeHeaders(raw: string): HeaderAnalysis {
  const headers = parseHeaderBlock(raw);
  const findings: Issue[] = [];

  const summary = {
    from: first(headers, 'from'),
    to: first(headers, 'to'),
    subject: first(headers, 'subject'),
    date: first(headers, 'date'),
    messageId: first(headers, 'message-id'),
    returnPath: first(headers, 'return-path'),
    replyTo: first(headers, 'reply-to'),
    xMailer: first(headers, 'x-mailer') ?? first(headers, 'user-agent'),
  };

  // Received chain: newest first in the file -> reverse for chronological order
  const received = all(headers, 'received').map((v, i) => parseReceived(v, i));
  const hops = received.reverse().map((h, i) => ({ ...h, index: i + 1 }));
  for (let i = 1; i < hops.length; i++) {
    const a = hops[i - 1].timestamp;
    const b = hops[i].timestamp;
    if (a && b) hops[i].delaySeconds = Math.round((Date.parse(b) - Date.parse(a)) / 1000);
  }
  const stamps = hops.map((h) => h.timestamp).filter(Boolean) as string[];
  const totalDelaySeconds = stamps.length >= 2 ? Math.round((Date.parse(stamps[stamps.length - 1]) - Date.parse(stamps[0])) / 1000) : null;

  const originHop = hops.find((h) => h.publicIps.length > 0);
  const xOrig = first(headers, 'x-originating-ip')?.replace(/[[\]\s]/g, '') ?? null;
  const originIp = originHop?.publicIps[0] ?? (xOrig && classifyIP(xOrig)?.public ? xOrig : null);

  // Authentication results
  const { results, authservId } = parseAuthResults(all(headers, 'authentication-results'));
  const pick = (m: string) => results.find((r) => r.method === m)?.result ?? null;
  const receivedSpf = first(headers, 'received-spf')?.split(/\s+/)[0]?.toLowerCase() ?? null;
  const authentication = { spf: pick('spf') ?? receivedSpf, dkim: pick('dkim'), dmarc: pick('dmarc'), results, authservId };

  const dkimSignatures = all(headers, 'dkim-signature').map((v) => {
    const tag = (t: string) => v.match(new RegExp(`(?:^|;)\\s*${t}=([^;\\s]+)`))?.[1] ?? null;
    return { domain: tag('d'), selector: tag('s'), algorithm: tag('a') };
  });

  /* ---- findings ---- */
  if (!headers.length) findings.push({ level: 'error', message: 'No valid header lines found. Paste the full raw headers ("Show original" / "View source").' });
  if (!authentication.results.length && !receivedSpf) findings.push({ level: 'info', message: 'No Authentication-Results header: this message may not have passed through a receiving MTA, or the headers were trimmed.' });
  for (const [name, res] of [['SPF', authentication.spf], ['DKIM', authentication.dkim], ['DMARC', authentication.dmarc]] as const) {
    if (!res) continue;
    if (res === 'pass') continue;
    const bad = ['fail', 'permerror', 'temperror', 'hardfail'].includes(res);
    findings.push({ level: bad ? 'error' : 'warn', message: `${name} result is "${res}".` });
  }
  const fromDomain = emailDomain(summary.from);
  const rpDomain = emailDomain(summary.returnPath);
  const rtDomain = emailDomain(summary.replyTo);
  if (fromDomain && rpDomain && orgDomain(fromDomain) !== orgDomain(rpDomain)) {
    findings.push({ level: 'warn', message: `From domain (${fromDomain}) differs from Return-Path domain (${rpDomain}). Normal for mailing services, but check SPF/DMARC alignment.` });
  }
  if (fromDomain && rtDomain && orgDomain(fromDomain) !== orgDomain(rtDomain)) {
    findings.push({ level: 'warn', message: `Reply-To domain (${rtDomain}) differs from From domain (${fromDomain}): replies go somewhere else.` });
  }
  if (summary.from && /^"?[^"<]*@[^"<]*"?\s*</.test(summary.from)) {
    findings.push({ level: 'warn', message: 'Display name contains an e-mail address, a common spoofing trick.' });
  }
  if (!summary.messageId) findings.push({ level: 'warn', message: 'No Message-ID header.' });
  if (hops.length === 0 && headers.length) findings.push({ level: 'info', message: 'No Received headers found.' });
  const slow = hops.filter((h) => (h.delaySeconds ?? 0) > 300);
  if (slow.length) findings.push({ level: 'info', message: `${slow.length} hop(s) took more than 5 minutes (largest ${Math.max(...slow.map((h) => h.delaySeconds!))}s).` });
  const negative = hops.filter((h) => (h.delaySeconds ?? 0) < -60);
  if (negative.length) findings.push({ level: 'warn', message: 'Timestamps go backwards between hops: clock skew or forged Received headers.' });
  if (summary.date && stamps.length) {
    const d = Date.parse(summary.date);
    if (!Number.isNaN(d) && Math.abs(d - Date.parse(stamps[0])) > 86_400_000) {
      findings.push({ level: 'warn', message: 'Date header differs from the first Received timestamp by more than 24 hours.' });
    }
  }
  if (authentication.dkim === null && dkimSignatures.length === 0 && headers.length) findings.push({ level: 'info', message: 'Message carries no DKIM signature.' });

  return { headerCount: headers.length, summary, authentication, hops, originIp, totalDelaySeconds, findings, dkimSignatures };
}
