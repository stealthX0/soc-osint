/**
 * Step 7: the exportable evidence report. Pure (no DOM, no network) so it is unit-tested and shared by the page, the
 * history store and the three renderers (ticket text, Markdown, JSON). Everything is rendered from ONE plain object.
 *
 * Rules enforced here, not left to the UI:
 *  - every URL, domain, IP and e-mail address in the report is defanged (hxxps://, [.], [@]);
 *  - the report never contains the pasted message body, the raw headers or attachment bytes: only the short evidence
 *    excerpts that findings already carry, plus a few summary fields;
 *  - it states that the scoring weights are uncalibrated decision support, and never calls a message "safe" or "clean".
 */
import { defang } from '../domain';
import { VERDICT_TEXT, type Verdict, type VerdictLabel } from './verdict';
import type { ParseStageResult } from './parse';
import type { Dimension, Finding, Severity, TrustLevel } from './types';

export const REPORT_SCHEMA_VERSION = 1 as const;
export const REPORT_TOOL = 'Spectrix Phishing Investigation';

export type ReportStatus = 'complete' | 'failed' | 'skipped' | 'not_applicable' | 'running';
export interface ReportCheckInput { id: string; label: string; stage: string; status: ReportStatus; result?: string | null; detail?: string }

export interface ReportInput {
  verdict: Verdict;
  findings: Finding[];
  checks: ReportCheckInput[];
  parse: ParseStageResult;
  generatedAt?: Date | string | number;
}

export interface ReportFinding {
  id: string; severity: Severity; dimension: Dimension; title: string; detail: string; source: string; trust: TrustLevel; exactness: string;
  evidence: string[]; indicator: { type: string; value: string } | null; observedAt: string | null;
}
export interface ReportCheck { id: string; label: string; stage: string; status: ReportStatus; result: string | null; detail: string | null }

export interface Report {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  tool: string;
  generatedAt: string;
  verdict: {
    label: VerdictLabel; labelText: string; headline: string; risk: number;
    confidence: { level: 'low' | 'medium' | 'high'; score: number; notes: string[] };
    coverage: number; provisional: boolean; rule: string | null;
  };
  reasons: { title: string; detail: string; severity: Severity; dimension: Dimension; points: number }[];
  mitigating: string[];
  conflicts: string[];
  gaps: { critical: boolean; text: string }[];
  actions: string[];
  message: { from: string | null; fromDomain: string | null; subject: string | null; date: string | null; connectingIp: string | null; linkCount: number; attachmentCount: number; headersSupplied: boolean };
  indicators: { type: string; value: string; reason: string | null; severity: Severity | null }[];
  findings: ReportFinding[];
  checks: ReportCheck[];
  checkSummary: Record<ReportStatus | 'total', number>;
  disclaimers: string[];
}

/* ----------------------------------------------------------------- defanging */

const URL_RE = /\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+/gi;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const IPV6_RE = /\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}/gi;

/** Defangs every URL, e-mail address, IPv4/IPv6 address and domain-looking token inside free text. Idempotent. */
export function defangText(s: string): string {
  return s
    .replace(URL_RE, (m) => defang(m))
    .replace(EMAIL_RE, (m) => defang(m))
    .replace(IPV4_RE, (m) => defang(m))
    .replace(DOMAIN_RE, (m) => defang(m))
    .replace(IPV6_RE, (m) => m.replace(/:/g, '[:]'));
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const d = (s: string | null | undefined, n: number): string | null => (s ? defangText(clip(s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u202a-\u202e\u2066-\u2069]/g, ''), n)) : null);
const iso = (v: Date | string | number | undefined): string => {
  const t = v === undefined ? new Date() : new Date(v);
  return Number.isNaN(t.getTime()) ? new Date().toISOString() : t.toISOString();
};

export const REPORT_DISCLAIMERS: readonly string[] = [
  'The scoring weights behind the risk figure are initial, uncalibrated values. This report is decision support, not a determination: read the reasons, the evidence and what is missing.',
  'The absence of findings only describes the checks that completed. Failed, skipped and not-run checks are listed in the check summary and lower the confidence.',
  'Indicators are defanged (hxxp, [.], [@]) so they cannot be opened or clicked by accident.',
  'This report contains no message body, no full headers and no attachment content: only summary fields and the short evidence excerpts attached to findings.',
];

/* -------------------------------------------------------------- build report */

export function buildReport(input: ReportInput): Report {
  const { verdict: v, parse } = input;
  const fx = parse.forensics;
  const fromMailbox = fx?.addresses.from[0] ?? null;
  const fromEmail = parse.indicators.emails.find((e) => e.roles.includes('from'))?.address ?? null;
  const fromDomain = fromMailbox?.registrable ?? fromMailbox?.domain ?? parse.indicators.domains.find((x) => x.roles.includes('from'))?.domain ?? null;
  const dateRaw = fx?.summary.date ?? null;
  const dateIso = dateRaw && !Number.isNaN(Date.parse(dateRaw)) ? new Date(dateRaw).toISOString() : dateRaw;

  const seen = new Set<string>();
  const indicators: Report['indicators'] = [];
  const addInd = (type: string, value: string, reason: string | null, severity: Severity | null) => {
    const k = `${type}|${value.toLowerCase()}`;
    if (seen.has(k) || indicators.length >= 200) return;
    seen.add(k);
    indicators.push({ type, value: defangText(clip(value, 300)), reason: d(reason, 200), severity });
  };
  for (const i of v.indicators) addInd(i.type, i.value, i.reason, i.severity);
  for (const i of parse.indicators.ips) addInd('ip', i.ip, `${i.role.replace(/_/g, ' ')} (${i.trust.replace(/_/g, ' ')})`, null);
  for (const x of parse.indicators.domains) addInd('domain', x.domain, x.roles.join(', '), null);
  for (const x of parse.indicators.emails) addInd('email', x.address, x.roles.join(', '), null);
  for (const u of parse.indicators.urls) addInd('url', u, null, null);

  const checks: ReportCheck[] = input.checks.map((c) => ({ id: c.id, label: d(c.label, 200) ?? c.id, stage: c.stage, status: c.status, result: d(c.result ?? null, 200), detail: d(c.detail ?? null, 300) }));
  const checkSummary: Report['checkSummary'] = { total: checks.length, complete: 0, failed: 0, skipped: 0, not_applicable: 0, running: 0 };
  for (const c of checks) checkSummary[c.status]++;

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: REPORT_TOOL,
    generatedAt: iso(input.generatedAt),
    verdict: {
      label: v.label, labelText: VERDICT_TEXT[v.label].label, headline: d(v.headline, 400) ?? '',
      risk: Math.max(0, Math.min(100, Math.round(v.risk))),
      confidence: { level: v.confidence.level, score: Math.round(v.confidence.score * 100) / 100, notes: v.confidence.notes.slice(0, 10).map((n) => d(n, 300) ?? '') },
      coverage: Math.round(v.coverage * 100) / 100, provisional: v.provisional, rule: v.rule ? d(v.rule.text, 300) : null,
    },
    reasons: v.reasons.slice(0, 20).map((r) => ({ title: d(r.title, 200) ?? '', detail: d(r.detail, 500) ?? '', severity: r.severity, dimension: r.dimension, points: Math.round(r.points * 10) / 10 })),
    mitigating: v.mitigating.slice(0, 20).map((m) => d(m, 300) ?? ''),
    conflicts: v.conflicts.slice(0, 20).map((m) => d(m, 300) ?? ''),
    gaps: v.gaps.slice(0, 30).map((g) => ({ critical: g.critical, text: d(g.text, 300) ?? '' })),
    actions: v.actions.slice(0, 20).map((a) => d(a, 300) ?? ''),
    message: {
      from: d(fx?.summary.from ?? fromEmail, 200), fromDomain: d(fromDomain, 120), subject: d(parse.content.subject ?? fx?.summary.subject ?? null, 200),
      date: dateIso, connectingIp: d(fx?.trust.connectingIp ?? null, 60),
      linkCount: parse.links.length, attachmentCount: parse.attachments.filter((a) => !a.inline).length, headersSupplied: parse.received.headerBytes > 0,
    },
    indicators,
    findings: input.findings.slice(0, 150).map((f) => ({
      id: f.id, severity: f.severity, dimension: f.dimension, title: d(f.title, 240) ?? '', detail: d(f.detail, 600) ?? '', source: f.source, trust: f.trust, exactness: f.exactness,
      evidence: (f.evidence ?? []).filter(Boolean).slice(0, 5).map((e) => d(e, 240) ?? ''),
      indicator: f.indicator ? { type: f.indicator.type, value: defangText(clip(f.indicator.value, 300)) } : null,
      observedAt: f.observedAt ?? null,
    })),
    checks,
    checkSummary,
    disclaimers: [...REPORT_DISCLAIMERS],
  };
}

/* ---------------------------------------------------------- stored reports */

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const DIMS: Dimension[] = ['authentication', 'infrastructure', 'url', 'attachment', 'content'];
const LABELS = Object.keys(VERDICT_TEXT) as VerdictLabel[];
const STATUSES: ReportStatus[] = ['complete', 'failed', 'skipped', 'not_applicable', 'running'];
const TRUST: TrustLevel[] = ['receiver_reported', 'unverified', 'independently_verified', 'derived'];
const isObj = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const s = (x: unknown, n: number): string => (typeof x === 'string' ? clip(x, n) : '');
const sn = (x: unknown, n: number): string | null => (typeof x === 'string' ? clip(x, n) : null);
const num = (x: unknown, lo: number, hi: number): number => (typeof x === 'number' && Number.isFinite(x) ? Math.max(lo, Math.min(hi, x)) : lo);
const arr = (x: unknown, max: number): unknown[] => (Array.isArray(x) ? x.slice(0, max) : []);
const strs = (x: unknown, max: number, n: number): string[] => arr(x, max).filter((i): i is string => typeof i === 'string').map((i) => clip(i, n));

/**
 * Rebuilds a Report from untrusted JSON (local storage, a file): checks the schema, clips every string and DROPS every
 * field that is not part of the report, so nothing but report data can ever come back out. Returns null when it is not a report.
 */
export function parseStoredReport(raw: unknown): Report | null {
  if (!isObj(raw) || raw.schemaVersion !== REPORT_SCHEMA_VERSION || !isObj(raw.verdict) || !isObj(raw.message)) return null;
  const v = raw.verdict;
  if (!LABELS.includes(v.label as VerdictLabel) || typeof raw.generatedAt !== 'string' || Number.isNaN(Date.parse(raw.generatedAt))) return null;
  const conf = isObj(v.confidence) ? v.confidence : {};
  const m = raw.message;
  const sev = (x: unknown): Severity => (SEVS.includes(x as Severity) ? (x as Severity) : 'info');
  const dim = (x: unknown): Dimension => (DIMS.includes(x as Dimension) ? (x as Dimension) : 'content');
  const status = (x: unknown): ReportStatus => (STATUSES.includes(x as ReportStatus) ? (x as ReportStatus) : 'skipped');
  const checks: ReportCheck[] = arr(raw.checks, 400).filter(isObj).map((c) => ({ id: s(c.id, 120), label: s(c.label, 200), stage: s(c.stage, 40), status: status(c.status), result: sn(c.result, 200), detail: sn(c.detail, 300) }));
  const checkSummary: Report['checkSummary'] = { total: checks.length, complete: 0, failed: 0, skipped: 0, not_applicable: 0, running: 0 };
  for (const c of checks) checkSummary[c.status]++;
  return {
    schemaVersion: REPORT_SCHEMA_VERSION, tool: REPORT_TOOL, generatedAt: new Date(raw.generatedAt).toISOString(),
    verdict: {
      label: v.label as VerdictLabel, labelText: VERDICT_TEXT[v.label as VerdictLabel].label, headline: s(v.headline, 400), risk: Math.round(num(v.risk, 0, 100)),
      confidence: { level: (['low', 'medium', 'high'] as const).includes(conf.level as 'low') ? (conf.level as 'low' | 'medium' | 'high') : 'low', score: num(conf.score, 0, 100), notes: strs(conf.notes, 10, 300) },
      coverage: num(v.coverage, 0, 1), provisional: v.provisional === true, rule: sn(v.rule, 300),
    },
    reasons: arr(raw.reasons, 20).filter(isObj).map((r) => ({ title: s(r.title, 200), detail: s(r.detail, 500), severity: sev(r.severity), dimension: dim(r.dimension), points: num(r.points, -1000, 1000) })),
    mitigating: strs(raw.mitigating, 20, 300), conflicts: strs(raw.conflicts, 20, 300),
    gaps: arr(raw.gaps, 30).filter(isObj).map((g) => ({ critical: g.critical === true, text: s(g.text, 300) })),
    actions: strs(raw.actions, 20, 300),
    message: { from: sn(m.from, 200), fromDomain: sn(m.fromDomain, 120), subject: sn(m.subject, 200), date: sn(m.date, 80), connectingIp: sn(m.connectingIp, 60), linkCount: Math.round(num(m.linkCount, 0, 100000)), attachmentCount: Math.round(num(m.attachmentCount, 0, 1000)), headersSupplied: m.headersSupplied === true },
    indicators: arr(raw.indicators, 200).filter(isObj).map((i) => ({ type: s(i.type, 20), value: s(i.value, 300), reason: sn(i.reason, 200), severity: SEVS.includes(i.severity as Severity) ? (i.severity as Severity) : null })),
    findings: arr(raw.findings, 150).filter(isObj).map((f) => ({
      id: s(f.id, 80), severity: sev(f.severity), dimension: dim(f.dimension), title: s(f.title, 240), detail: s(f.detail, 600), source: s(f.source, 80),
      trust: TRUST.includes(f.trust as TrustLevel) ? (f.trust as TrustLevel) : 'unverified', exactness: s(f.exactness, 20), evidence: strs(f.evidence, 5, 240),
      indicator: isObj(f.indicator) ? { type: s(f.indicator.type, 20), value: s(f.indicator.value, 300) } : null, observedAt: sn(f.observedAt, 40),
    })),
    checks, checkSummary, disclaimers: [...REPORT_DISCLAIMERS],
  };
}

/* ----------------------------------------------------------------- renderers */

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const day = (isoDate: string) => isoDate.slice(0, 10);
const utc = (isoDate: string) => `${isoDate.slice(0, 10)} ${isoDate.slice(11, 16)} UTC`;
const pct = (n: number) => `${Math.round(n * 100)}%`;
const oneLine = (x: string) => x.replace(/\s+/g, ' ').trim();

/** Plain text for pasting into a ticketing system. */
export function renderTicketText(r: Report): string {
  const L: string[] = [];
  const v = r.verdict;
  L.push(`${r.tool.toUpperCase()}`, `Date: ${utc(r.generatedAt)}`, '');
  L.push(`Verdict: ${v.labelText}${v.provisional ? ' (provisional: lookups were still running)' : ''}`);
  L.push(`Risk: ${v.risk}/100 · Confidence: ${v.confidence.level} · Check coverage: ${pct(v.coverage)}`);
  if (v.headline) L.push(v.headline);
  if (v.rule) L.push(`Decided by rule: ${v.rule}`);
  L.push('');
  L.push('MESSAGE');
  const m = r.message;
  L.push(`From: ${m.from ?? 'unknown'}`, `Subject: ${m.subject ?? 'unknown'}`, `Date header: ${m.date ?? 'unknown'}`, `Connecting IP: ${m.connectingIp ?? 'not established'}`, `Links: ${m.linkCount} · Attachments: ${m.attachmentCount}`);
  if (r.reasons.length) { L.push('', 'WHY'); r.reasons.forEach((x, i) => L.push(`${i + 1}. [${x.severity}] ${x.title}: ${oneLine(x.detail)}`)); }
  if (r.mitigating.length) { L.push('', 'MITIGATING'); r.mitigating.forEach((x) => L.push(`- ${x}`)); }
  if (r.conflicts.length) { L.push('', 'CONFLICTING EVIDENCE'); r.conflicts.forEach((x) => L.push(`- ${x}`)); }
  if (r.gaps.length) { L.push('', 'WHAT IS MISSING'); r.gaps.forEach((x) => L.push(`- ${x.critical ? '[important] ' : ''}${x.text}`)); }
  if (r.actions.length) { L.push('', 'RECOMMENDED ACTIONS'); r.actions.forEach((x) => L.push(`- ${x}`)); }
  if (r.indicators.length) { L.push('', 'INDICATORS (defanged)'); r.indicators.slice(0, 40).forEach((i) => L.push(`- ${i.type}: ${i.value}${i.reason ? ` (${i.reason})` : ''}`)); if (r.indicators.length > 40) L.push(`- … ${r.indicators.length - 40} more in the JSON export`); }
  const cs = r.checkSummary;
  L.push('', 'CHECKS', `${cs.total} total: ${cs.complete} complete, ${cs.failed} failed, ${cs.skipped} skipped, ${cs.running} running, ${cs.not_applicable} not applicable`);
  r.checks.filter((c) => c.status === 'failed' || c.status === 'skipped' || c.status === 'running').slice(0, 30).forEach((c) => L.push(`- ${c.status}: ${c.label}${c.detail ? ` (${oneLine(c.detail)})` : ''}`));
  L.push('', 'NOTES');
  r.disclaimers.forEach((x) => L.push(`- ${x}`));
  return L.join('\n');
}

const mdCell = (x: string | null | undefined) => (x ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
const mdText = (x: string) => x.replace(/([\\`*_{}[\]<>#])/g, '\\$1').replace(/\s+/g, ' ').trim();

/** Markdown evidence report. */
export function renderMarkdown(r: Report): string {
  const v = r.verdict;
  const L: string[] = [];
  L.push(`# ${r.tool}`, '', `Generated ${utc(r.generatedAt)}`, '');
  L.push(`## Verdict: ${v.labelText}`, '', `- Risk: **${v.risk}/100**`, `- Confidence: **${v.confidence.level}** (check coverage ${pct(v.coverage)})`);
  if (v.provisional) L.push('- Provisional: lookups were still running when this was exported');
  if (v.rule) L.push(`- Decided by rule: ${mdText(v.rule)}`);
  L.push('', mdText(v.headline), '');
  const m = r.message;
  L.push('## Message', '', '| Field | Value |', '| --- | --- |', `| From | ${mdCell(m.from) || 'unknown'} |`, `| Subject | ${mdCell(m.subject) || 'unknown'} |`, `| Date header | ${mdCell(m.date) || 'unknown'} |`, `| Connecting IP | ${mdCell(m.connectingIp) || 'not established'} |`, `| Links / attachments | ${m.linkCount} / ${m.attachmentCount} |`, '');
  const section = (title: string, items: string[]) => { if (items.length) L.push(`## ${title}`, '', ...items.map((x) => `- ${mdText(x)}`), ''); };
  if (r.reasons.length) { L.push('## Why', ''); r.reasons.forEach((x, i) => L.push(`${i + 1}. **[${x.severity}] ${mdText(x.title)}**: ${mdText(x.detail)}`)); L.push(''); }
  section('Mitigating evidence', r.mitigating);
  section('Conflicting evidence', r.conflicts);
  section('What is missing', r.gaps.map((g) => `${g.critical ? '**Important:** ' : ''}${g.text}`));
  section('Recommended actions', r.actions);
  if (r.indicators.length) { L.push('## Indicators (defanged)', '', '| Type | Value | Note |', '| --- | --- | --- |', ...r.indicators.map((i) => `| ${mdCell(i.type)} | \`${mdCell(i.value).replace(/`/g, "'")}\` | ${mdCell(i.reason)} |`), ''); }
  if (r.findings.length) {
    L.push('## Findings', '');
    for (const f of [...r.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])) {
      L.push(`### [${f.severity}] ${mdText(f.title)}`, '', `${mdText(f.detail)}`, '', `Dimension: ${f.dimension} · Source: ${mdText(f.source)} · Trust: ${f.trust.replace(/_/g, ' ')} · Exactness: ${f.exactness}`);
      if (f.evidence.length) L.push('', ...f.evidence.map((e) => `    ${e.replace(/\s+/g, ' ')}`));
      L.push('');
    }
  }
  const cs = r.checkSummary;
  L.push('## Checks', '', `${cs.total} total: ${cs.complete} complete, ${cs.failed} failed, ${cs.skipped} skipped, ${cs.running} running, ${cs.not_applicable} not applicable.`, '', '| Stage | Check | Status | Result |', '| --- | --- | --- | --- |', ...r.checks.map((c) => `| ${mdCell(c.stage)} | ${mdCell(c.label)} | ${c.status.replace(/_/g, ' ')} | ${mdCell(c.result ?? c.detail)} |`), '');
  L.push('## Notes', '', ...r.disclaimers.map((x) => `- ${mdText(x)}`), '');
  return L.join('\n');
}

export const renderJson = (r: Report): string => JSON.stringify(r, null, 2);

/** Lower-case, [a-z0-9-] only, no leading/trailing hyphen, bounded. */
export function sanitizeFilenameStem(input: string, max = 60): string {
  const out = input.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max).replace(/-+$/g, '');
  return out || 'report';
}

/** e.g. spectrix-phishing-suspicious-20261107-invoice-overdue.md */
export function reportFilename(r: Report, ext: 'md' | 'json' | 'txt'): string {
  const stem = sanitizeFilenameStem(`spectrix phishing ${r.verdict.label.replace(/_/g, '-')} ${day(r.generatedAt)} ${r.message.subject ?? ''}`, 80);
  return `${stem}.${ext}`;
}
