/**
 * Step 7: a chronological timeline of everything the investigation knows the TIME of. Pure.
 *
 * Only real timestamps become events: Received hops, the Date header, domain registration, abuse reports, VirusTotal
 * analysis dates, a finding's own observation time, and the moments the page itself recorded (investigation started,
 * sender checks finished, links investigated). Unparsable dates are ignored and no time is ever invented.
 */
import type { ParseStageResult } from './parse';
import type { SenderCheckResponse } from './sender';
import type { AttachmentHashResponse } from './attachments';
import type { Finding } from './types';

export type TimelineKind = 'message' | 'delivery' | 'registration' | 'reputation' | 'scan' | 'finding' | 'investigation';
export interface TimelineEvent { at: string; label: string; detail: string; source: string; kind: TimelineKind }

export interface TimelineMarks {
  /** Epoch milliseconds or an ISO string, recorded by the page's hooks. */
  investigationStartedAt?: number | string | null;
  senderChecksFinishedAt?: number | string | null;
  linksInvestigatedAt?: number | string | null;
}

export interface TimelineInput {
  parse: ParseStageResult | null;
  senderResults?: SenderCheckResponse[];
  attachmentResults?: Pick<AttachmentHashResponse, 'data'>[];
  findings?: Finding[];
  marks?: TimelineMarks;
}

const MIN_YEAR = 1990;
const MAX_YEAR = 2100;

/** ISO string for a usable date, or null. Rejects NaN, bare numbers in strings, and absurd years. */
export function toIso(v: unknown): string | null {
  let t: number;
  if (typeof v === 'number') t = v;
  else if (typeof v === 'string') {
    if (v.length < 8 || !/\d{4}/.test(v)) return null;
    t = Date.parse(v);
  } else return null;
  if (!Number.isFinite(t)) return null;
  const y = new Date(t).getUTCFullYear();
  return y >= MIN_YEAR && y <= MAX_YEAR ? new Date(t).toISOString() : null;
}

const KIND_ORDER: Record<TimelineKind, number> = { message: 0, registration: 1, reputation: 2, scan: 3, finding: 4, delivery: 5, investigation: 6 };
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function buildTimeline(input: TimelineInput): TimelineEvent[] {
  const out: TimelineEvent[] = [];
  const add = (at: unknown, label: string, detail: string, source: string, kind: TimelineKind) => {
    const t = toIso(at);
    if (t) out.push({ at: t, label, detail, source, kind });
  };

  const fx = input.parse?.forensics ?? null;
  if (fx) {
    add(fx.summary.date, 'Message sent (Date header)', 'The time the sender’s mail software claims. Anyone can set it, so it is not verified.', 'Date header', 'message');
    for (const h of fx.hops) {
      const who = h.by ?? 'unknown server';
      add(h.timestamp, `Received by ${who}`, `Hop ${h.index}${h.from ? ` from ${h.from}` : ''}${h.with ? ` via ${h.with}` : ''}${h.trust === 'trusted' ? '' : ' (written before the receiving system: untrusted claim)'}.`, 'Received header', 'delivery');
    }
  }

  for (const res of input.senderResults ?? []) {
    const data = res.data;
    if (!data) continue;
    if (data.check === 'domain') {
      add(data.value.dates?.registered, `Domain registered: ${data.value.domain}`, `Registration date from RDAP/WHOIS${data.value.registrar?.name ? ` (registrar ${data.value.registrar.name})` : ''}.`, 'RDAP / WHOIS', 'registration');
    } else if (data.check === 'ip') {
      const ip = data.value.ip;
      add(data.value.reputation?.lastReportedAt, `Last abuse report for ${ip}`, `AbuseIPDB: ${data.value.reputation?.totalReports ?? 0} report(s) in total.`, 'AbuseIPDB', 'reputation');
      add(data.value.virustotal?.lastAnalysis, `VirusTotal last analysed ${ip}`, `${data.value.virustotal?.malicious ?? 0} malicious / ${data.value.virustotal?.suspicious ?? 0} suspicious at that time.`, 'VirusTotal', 'scan');
    }
  }

  for (const res of input.attachmentResults ?? []) {
    const vt = res.data?.virustotal;
    if (vt?.observed) add(vt.lastAnalysis, `VirusTotal last analysed attachment ${res.data!.hash.slice(0, 12)}…`, `${vt.malicious} of ${vt.malicious + vt.suspicious + vt.harmless + vt.undetected} engines flagged it at that time.`, 'VirusTotal', 'scan');
  }

  for (const f of input.findings ?? []) add(f.observedAt, `Evidence observed: ${clip(f.title, 120)}`, clip(f.detail, 200), f.source, 'finding');

  const m = input.marks;
  if (m) {
    add(m.investigationStartedAt, 'Investigation started', 'The message was submitted for analysis.', 'Spectrix', 'investigation');
    add(m.senderChecksFinishedAt, 'Sender checks finished', 'All sender and infrastructure lookups returned.', 'Spectrix', 'investigation');
    add(m.linksInvestigatedAt, 'Links investigated', 'The link investigation returned.', 'Spectrix', 'investigation');
  }

  const seen = new Set<string>();
  return out
    .filter((e) => { const k = `${e.at}|${e.label}|${e.source}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || a.label.localeCompare(b.label)));
}
