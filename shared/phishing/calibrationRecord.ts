/**
 * Analyst-labelled calibration records.
 *
 * After an investigation the analyst can record their own verdict ("phishing", "BEC / fraud", "legitimate", "unsure").
 * The record keeps only what the verdict engine scores (finding ids, severities, multiplier inputs, check statuses and a
 * few structural facts about the message) so the investigation can be REPLAYED through a newer engine later. It never
 * contains the message body, subjects, addresses, URLs or evidence text: indicators are reduced to a short one-way hash,
 * which still lets the engine see that two findings concern the same URL or file.
 *
 * `npm run calibrate:labels -- <file.json>` replays an exported set and reports agreement (scripts/calibrate-labels.ts).
 */
import type { Finding } from './types';
import type { ParseStageResult } from './parse';
import type { CheckRow, Verdict, VerdictLabel } from './verdict';

export const CALIBRATION_SCHEMA = 'spectrix.calibration.v1';

export type AnalystLabel = 'phishing' | 'bec' | 'legitimate' | 'unsure';
export const ANALYST_LABELS: { id: AnalystLabel; text: string; hint: string }[] = [
  { id: 'phishing', text: 'Phishing / malicious', hint: 'Credential theft, malware, scam or brand impersonation' },
  { id: 'bec', text: 'BEC / payment fraud', hint: 'Invoice, payment, payroll or gift-card fraud' },
  { id: 'legitimate', text: 'Legitimate', hint: 'Genuine mail, including wanted marketing' },
  { id: 'unsure', text: 'Unsure', hint: 'Kept, but not used for agreement' },
];

/** Engine outcomes an analyst label accepts as correct. */
export const ACCEPTED: Record<AnalystLabel, VerdictLabel[]> = {
  phishing: ['malicious', 'suspicious'],
  bec: ['suspicious', 'malicious'],
  legitimate: ['likely_legitimate', 'inconclusive'],
  unsure: [],
};

export interface CalibrationRecord {
  id: string;
  labelledAt: string;
  analyst: AnalystLabel;
  note?: string;
  /** What the engine said when the label was given (for drift reports). */
  engine: { label: VerdictLabel; risk: number; confidence: number; highRisk: string | null };
  /** evidenceCount: how many evidence lines the finding had (some rules need corroboration), never the lines themselves. */
  findings: (Pick<Finding, 'id' | 'dimension' | 'severity' | 'exactness' | 'reliability' | 'trust' | 'source'> & { evidenceCount: number; indicator?: { type: string; value: string } })[];
  checks: { id: string; label: string; status: CheckRow['status']; detail?: string }[];
  /** The few structural facts the engine reads from the parsed message. */
  message: {
    hasForensics: boolean; hasText: boolean; languageSupported: boolean; linkCount: number;
    truncation: { links: boolean; text: boolean; mime: boolean };
    attachments: { inline: boolean; hasHash: boolean }[];
    indicatorCounts: { emails: number; domains: number; ips: number };
    auth: { dmarcPassReported: boolean; dkimAligned: boolean; spfAligned: boolean };
  };
}

/** Short, one-way digest of an indicator value (FNV-1a, 2 x 32 bit): equal values stay equal, nothing is recoverable. */
export function digest(value: string): string {
  let h1 = 0x811c9dc5, h2 = 0x01000193 ^ value.length;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x5bd1e995) >>> 0;
  }
  return `h:${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

export function toCalibrationRecord(a: { analyst: AnalystLabel; note?: string; verdict: Verdict; parse: ParseStageResult; findings: Finding[]; checks: CheckRow[]; now?: Date }): CalibrationRecord {
  const { parse: p, verdict: v } = a;
  const auth = p.forensics?.authentication;
  const findings = a.findings.map((f) => ({
    id: f.id, dimension: f.dimension, severity: f.severity, exactness: f.exactness, reliability: f.reliability, trust: f.trust, source: f.source,
    evidenceCount: f.evidence?.length ?? 0,
    ...(f.indicator ? { indicator: { type: f.indicator.type, value: digest(f.indicator.value.toLowerCase()) } } : {}),
  }));
  const at = (a.now ?? new Date()).toISOString();
  return {
    id: digest(`${at}|${findings.map((f) => f.id).join(',')}|${v.risk}`),
    labelledAt: at, analyst: a.analyst, ...(a.note ? { note: a.note.slice(0, 200) } : {}),
    engine: { label: v.label, risk: v.risk, confidence: v.confidence.score, highRisk: v.highRisk?.id ?? null },
    findings,
    // check labels can name a host or an address ("IP intelligence: 1.2.3.4"): keep only the kind of check
    checks: a.checks.filter((c) => c.status !== 'running').map((c) => ({ id: c.id.replace(/^(sender\.[a-z]+)\..*$/, '$1.x'), label: c.id.split('.').slice(0, 2).join('.'), status: c.status, ...(/not configured/i.test(c.detail ?? '') ? { detail: 'not configured' } : {}) })),
    message: {
      hasForensics: !!p.forensics, hasText: !!p.content.text, languageSupported: p.content.analysis.languageSupported, linkCount: p.links.length,
      truncation: { ...p.truncation },
      attachments: p.attachments.map((x) => ({ inline: !!x.inline, hasHash: !!x.hash })),
      indicatorCounts: { emails: p.indicators.emails.length, domains: p.indicators.domains.length, ips: p.indicators.ips.length },
      auth: { dmarcPassReported: auth?.dmarc?.result === 'pass' && auth.dmarc.trust === 'receiver_reported', dkimAligned: !!auth?.alignment.dkimAligned, spfAligned: !!auth?.alignment.spfAligned },
    },
  };
}

/** Rebuild just enough of a parsed message for computeVerdict to replay a record. */
export function replayInput(rec: CalibrationRecord): { parse: ParseStageResult; findings: Finding[]; checks: CheckRow[] } {
  const m = rec.message;
  const parse = {
    forensics: m.hasForensics ? { authentication: {
      dmarc: m.auth.dmarcPassReported ? { result: 'pass', trust: 'receiver_reported' } : null,
      alignment: { dkimAligned: m.auth.dkimAligned, spfAligned: m.auth.spfAligned },
    } } : null,
    content: { text: m.hasText ? 'x' : '', analysis: { languageSupported: m.languageSupported } },
    links: Array.from({ length: m.linkCount }, () => ({})),
    truncation: m.truncation,
    attachments: m.attachments.map((x, i) => ({ inline: x.inline, filename: `attachment ${i + 1}`, hash: x.hasHash ? 'h' : null })),
    indicators: { emails: Array(m.indicatorCounts.emails).fill({}), domains: Array(m.indicatorCounts.domains).fill({}), ips: Array(m.indicatorCounts.ips).fill({}) },
  } as unknown as ParseStageResult;
  const findings = rec.findings.map(({ evidenceCount, ...f }, i) => ({ title: `${f.id} #${i + 1}`, detail: `${f.id} #${i + 1}`, evidence: Array.from({ length: evidenceCount ?? 0 }, (_, i) => `evidence ${i + 1}`), observedAt: null, ...f })) as unknown as Finding[];
  return { parse, findings, checks: rec.checks as CheckRow[] };
}

/** Validates an imported file; unknown or malformed records are dropped. */
export function parseCalibrationFile(raw: unknown): CalibrationRecord[] {
  const list = Array.isArray(raw) ? raw : raw && typeof raw === 'object' && Array.isArray((raw as { records?: unknown }).records) ? (raw as { records: unknown[] }).records : [];
  return list.filter((r): r is CalibrationRecord => !!r && typeof r === 'object' && typeof (r as CalibrationRecord).analyst === 'string'
    && Array.isArray((r as CalibrationRecord).findings) && Array.isArray((r as CalibrationRecord).checks) && !!(r as CalibrationRecord).message);
}
