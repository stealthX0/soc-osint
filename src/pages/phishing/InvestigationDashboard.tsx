import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Badge, Card, Copyable, DataTable, KV, type Tone } from '../../components/ui';
import { Icon, type IconName } from '../../components/icons';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput, Finding, Severity, Dimension } from '../../../shared/phishing/types';
import type { Verdict, VerdictLabel } from '../../../shared/phishing/verdict';
import { VERDICT_TEXT } from '../../../shared/phishing/verdict';
import { dimensionLabel } from '../../../shared/phishing/findings';
import type { Report } from '../../../shared/phishing/report';
import type { TimelineEvent } from '../../../shared/phishing/timeline';
import type { CheckRowX, PipelineChip, ChipStatus } from './model';
import { ExportBar } from './ExportBar';
import { ContentPanel } from './ContentPanel';
import { HeadersTab } from './HeadersTab';
import { SenderTab } from './SenderTab';
import { UrlTab } from './UrlTab';
import { AttachmentTab } from './AttachmentPanel';
import { EvidenceTab } from './EvidenceTab';
import { sevTone, trustTone, trustLabel, FindingDetails } from './common';
import type { SenderStage, LinkStage } from './hooks';
import type { AttachmentStage } from './AttachmentPanel';

/* ─── colour maps ─── */
const verdictTone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };
const verdictRingColor: Record<VerdictLabel, string> = {
  malicious: 'stroke-rose', suspicious: 'stroke-amber', likely_legitimate: 'stroke-green',
  inconclusive: 'stroke-sky', analysis_unavailable: 'stroke-muted',
};
const verdictBg: Record<VerdictLabel, string> = {
  malicious: 'border-rose/30 bg-rose/5', suspicious: 'border-amber/30 bg-amber/5',
  likely_legitimate: 'border-green/30 bg-green/5', inconclusive: 'border-sky/20 bg-sky/5',
  analysis_unavailable: 'border-line bg-bg2/60',
};
const chipTone: Record<ChipStatus, Tone> = { complete: 'good', running: 'info', 'not run': 'neutral', failed: 'bad' };
const chipIcon: Record<ChipStatus, IconName> = { complete: 'check', running: 'refresh', 'not run': 'info', failed: 'x' };

/* ─── types ─── */
export type DetailTab = 'headers' | 'sender' | 'urls' | 'attachments' | 'evidence' | 'content';
const DETAIL_TABS: { id: DetailTab; label: string; icon: IconName }[] = [
  { id: 'headers', label: 'Headers', icon: 'mail' },
  { id: 'sender', label: 'Sender Intel', icon: 'globe' },
  { id: 'urls', label: 'URLs', icon: 'shield' },
  { id: 'attachments', label: 'Attachments', icon: 'file' },
  { id: 'content', label: 'Content', icon: 'eye' },
  { id: 'evidence', label: 'Evidence', icon: 'list' },
];

export interface DashboardProps {
  r: ParseStageResult;
  input: PhishingInput;
  verdict: Verdict;
  findings: Finding[];
  rows: CheckRowX[];
  pipeline: PipelineChip[];
  report: Report;
  timeline: TimelineEvent[];
  sender: SenderStage;
  links: LinkStage;
  att: AttachmentStage;
  startedAt: number;
  onNewAnalysis?: () => void;
}

/* ═══════════════════════════════════════════════════════════
   Risk Score Gauge – SVG donut
   ═══════════════════════════════════════════════════════════ */
function RiskGauge({ score, label }: { score: number; label: VerdictLabel }) {
  const r = 54, cx = 64, cy = 64, circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="relative inline-flex flex-col items-center">
      <svg width={128} height={128} viewBox="0 0 128 128" className="drop-shadow-lg">
        <circle cx={cx} cy={cy} r={r} fill="none" strokeWidth={10} className="stroke-line/40" />
        <circle cx={cx} cy={cy} r={r} fill="none" strokeWidth={10} strokeLinecap="round"
          className={`${verdictRingColor[label]} transition-all duration-700`}
          strokeDasharray={circ} strokeDashoffset={offset}
          transform={`rotate(-90 ${cx} ${cy})`} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums leading-none">{score}</span>
        <span className="text-[10px] uppercase tracking-wider text-muted">/100</span>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Summary Stat Card – the row of mini cards under the verdict
   ═══════════════════════════════════════════════════════════ */
function StatCard({ icon, label, value, tone = 'neutral' }: { icon: IconName; label: string; value: string; tone?: Tone }) {
  const border: Record<Tone, string> = { good: 'border-green/25', warn: 'border-amber/25', bad: 'border-rose/25', info: 'border-sky/25', accent: 'border-teal/25', neutral: 'border-line' };
  const iconColor: Record<Tone, string> = { good: 'text-green', warn: 'text-amber', bad: 'text-rose', info: 'text-sky', accent: 'text-teal', neutral: 'text-muted' };
  return (
    <div className={`flex items-center gap-3 rounded-lg border ${border[tone]} bg-panel/80 px-3 py-2.5`}>
      <Icon name={icon} size={18} className={iconColor[tone]} />
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider text-faint">{label}</div>
        <div className={`text-sm font-semibold ${iconColor[tone]}`}>{value}</div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Panel wrapper used throughout the dashboard grid
   ═══════════════════════════════════════════════════════════ */
function Panel({ title, icon, action, children, className = '' }: { title: string; icon?: IconName; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line bg-panel/80 ${className}`}>
      <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-2">
        <h3 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">
          {icon && <Icon name={icon} size={13} className="text-faint" />}
          {title}
        </h3>
        {action}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

/* ═══════════════════════════════════════════════════════════
   THE DASHBOARD
   ═══════════════════════════════════════════════════════════ */
export function InvestigationDashboard({ r, input, verdict, findings, rows, pipeline, report, timeline, sender, links, att, startedAt, onNewAnalysis }: DashboardProps) {
  const [detailTab, setDetailTab] = useState<DetailTab>('headers');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);

  const fx = r.forensics;
  const meta = VERDICT_TEXT[verdict.label];
  const from = fx?.summary.from ?? r.indicators.emails.find((e) => e.roles.includes('from'))?.address ?? '—';
  const subject = r.content.subject ?? fx?.summary.subject ?? '—';
  const counts = findings.reduce<Record<string, number>>((a, f) => ({ ...a, [f.severity]: (a[f.severity] ?? 0) + 1 }), {});
  const attachmentCount = r.attachments.filter((a) => !a.inline).length;
  const analysisTime = ((Date.now() - startedAt) / 1000).toFixed(1);

  /* dimension summary for stat cards */
  const dimSummary = (dim: Dimension): { tone: Tone; text: string } => {
    const ds = verdict.dimensions.find((d) => d.dimension === dim);
    if (!ds || !ds.active) return { tone: 'neutral', text: 'N/A' };
    if (ds.score <= 0) return { tone: 'good', text: 'Clean' };
    if (ds.score < 30) return { tone: 'info', text: 'Low risk' };
    if (ds.score < 60) return { tone: 'warn', text: 'Suspicious' };
    return { tone: 'bad', text: 'High risk' };
  };

  const authDim = dimSummary('authentication');
  const urlDim = dimSummary('url');
  const infraDim = dimSummary('infrastructure');
  const contentDim = dimSummary('content');
  const attachDim = dimSummary('attachment');

  /* auth check summary */
  const spf = r.checks.find((c) => c.id === 'spf');
  const dkim = r.checks.find((c) => c.id === 'dkim');
  const dmarc = r.checks.find((c) => c.id === 'dmarc');
  const authLabel = (c: typeof spf) => c ? (c.result === 'pass' ? 'Pass' : c.result === 'fail' || c.result === 'hardfail' ? 'Fail' : c.result ?? c.status) : '—';
  const authTone = (c: typeof spf): Tone => c ? (c.result === 'pass' ? 'good' : c.result === 'fail' || c.result === 'hardfail' ? 'bad' : 'warn') : 'neutral';

  return (
    <div className="ph-results ph-dashboard" role="region" aria-label="Investigation results">
      {/* ── TOP BAR: Verdict + Risk Gauge + Meta ── */}
      <div className={`ph-db-verdict rounded-xl border p-4 ${verdictBg[verdict.label]}`}>
        <div className="flex items-center gap-6">
          {/* Risk gauge */}
          <RiskGauge score={verdict.risk} label={verdict.label} />

          {/* Verdict text */}
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 ref={heading} tabIndex={-1} className="text-xl font-bold tracking-tight focus:outline-none">{meta.label}</h2>
              <Badge tone={verdictTone[verdict.label]}>{verdict.label.replace(/_/g, ' ')}</Badge>
              <Badge tone={verdict.confidence.level === 'high' ? 'good' : verdict.confidence.level === 'medium' ? 'warn' : 'neutral'}>
                Confidence: {verdict.confidence.level}
              </Badge>
              <Badge>Coverage: {Math.round(verdict.coverage * 100)}%</Badge>
            </div>
            <p className="mt-1.5 text-sm text-muted">{verdict.headline}</p>
            {verdict.rule && <p className="mt-1 text-xs text-faint">Decided by a verdict rule on direct evidence, not by the score.</p>}
          </div>

          {/* Investigation meta */}
          <div className="hidden shrink-0 text-right text-xs text-muted lg:block">
            <div><span className="text-faint">Analyzed:</span> {new Date(startedAt).toLocaleString()}</div>
            <div><span className="text-faint">Duration:</span> {analysisTime}s</div>
            <div><span className="text-faint">Findings:</span> {findings.length}</div>
            <div><span className="text-faint">Checks:</span> {rows.length}</div>
          </div>
        </div>
      </div>

      {/* ── SUMMARY STAT CARDS ── */}
      <div className="ph-db-stats grid grid-cols-2 gap-2 lg:grid-cols-5">
        <StatCard icon="lock" label="Authentication" value={authDim.text} tone={authDim.tone} />
        <StatCard icon="shield" label="URL Analysis" value={urlDim.text} tone={urlDim.tone} />
        <StatCard icon="globe" label="Infrastructure" value={infraDim.text} tone={infraDim.tone} />
        <StatCard icon="eye" label="Content" value={contentDim.text} tone={contentDim.tone} />
        <StatCard icon="file" label="Attachments" value={attachDim.text} tone={attachDim.tone} />
      </div>

      {/* ── MAIN GRID: Left column + Right column ── */}
      <div className="ph-db-main grid gap-3 lg:grid-cols-[1fr_320px]">
        {/* ──────── LEFT COLUMN ──────── */}
        <div className="space-y-3">
          {/* Key findings */}
          <Panel title="Key Findings" icon="warn" action={
            <span className="flex gap-1.5">
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).filter((s) => counts[s]).map((s) => (
                <Badge key={s} tone={sevTone[s]}>{counts[s]} {s}</Badge>
              ))}
            </span>
          }>
            {findings.length > 0 ? (
              <ul className="ph-db-findings space-y-1.5">
                {findings.slice(0, 8).map((f, i) => <FindingDetails key={`${f.id}${i}`} f={f} />)}
                {findings.length > 8 && (
                  <li className="pt-1 text-center text-xs text-faint">
                    + {findings.length - 8} more findings (see Evidence tab below)
                  </li>
                )}
              </ul>
            ) : (
              <p className="text-sm text-muted">No findings. The checks that completed found no issues. See pipeline and check status for coverage.</p>
            )}
          </Panel>

          {/* Reasons, actions, conflicts, gaps — collapsed into a compact "Verdict detail" panel */}
          <Panel title="Verdict Detail" icon="bolt">
            <div className="space-y-3">
              {/* Why */}
              {verdict.reasons.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">Reasons</div>
                  <ul className="space-y-1">
                    {verdict.reasons.map((rr) => (
                      <li key={rr.title + rr.findingIds.join()} className="flex flex-wrap items-baseline gap-2 text-sm">
                        <Badge tone={sevTone[rr.severity]}>{rr.severity}</Badge>
                        <span className="font-medium">{rr.title}</span>
                        <span className="text-[11px] text-faint">{dimensionLabel[rr.dimension]} · {rr.points} pts</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Mitigating */}
              {verdict.mitigating.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">Supporting Evidence</div>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm text-muted">{verdict.mitigating.map((m) => <li key={m}>{m}</li>)}</ul>
                </div>
              )}

              {/* Conflicts */}
              {verdict.conflicts.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-amber">Conflicting Evidence</div>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm text-amber">{verdict.conflicts.map((c) => <li key={c}>{c}</li>)}</ul>
                </div>
              )}

              {/* Actions */}
              {verdict.actions.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">Recommended Actions</div>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm">{verdict.actions.map((a) => <li key={a}>{a}</li>)}</ul>
                </div>
              )}

              {/* Gaps */}
              {verdict.gaps.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">Gaps</div>
                  <ul className="space-y-0.5 text-sm">
                    {verdict.gaps.filter((g) => g.critical).map((g) => (
                      <li key={g.text} className="flex gap-2 text-amber"><Icon name="warn" size={13} className="mt-0.5 shrink-0" />{g.text}</li>
                    ))}
                    {verdict.gaps.filter((g) => !g.critical).slice(0, 4).map((g) => (
                      <li key={g.text} className="pl-5 text-muted">{g.text}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </Panel>

          {/* Detail tabs section */}
          <Panel title="Detailed Analysis" icon="list">
            {/* Tab bar */}
            <div className="ph-db-detail-tabs mb-3 flex gap-1 overflow-x-auto rounded-lg border border-line bg-bg2/80 p-0.5">
              {DETAIL_TABS.map((t) => (
                <button key={t.id} type="button" onClick={() => setDetailTab(t.id)}
                  className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs transition-colors ${detailTab === t.id ? 'bg-sky/15 text-sky shadow-[0_0_0_1px_rgba(56,189,248,.3)]' : 'text-muted hover:text-fg'}`}>
                  <Icon name={t.icon} size={12} />{t.label}
                </button>
              ))}
            </div>
            {/* Tab content */}
            <div className="ph-db-detail-content">
              {detailTab === 'headers' && <HeadersTab r={r} />}
              {detailTab === 'sender' && <SenderTab slots={sender.slots} skipped={sender.plan.skipped} running={sender.running} findings={findings} />}
              {detailTab === 'urls' && <UrlTab r={r} links={links} />}
              {detailTab === 'attachments' && <AttachmentTab att={att} />}
              {detailTab === 'content' && <ContentPanel a={r.content.analysis} subject={r.content.subject} />}
              {detailTab === 'evidence' && <EvidenceTab findings={findings} checks={rows} timeline={timeline} raw={{ sender: sender.results, urls: links.stage, attachments: att.results }} />}
            </div>
          </Panel>
        </div>

        {/* ──────── RIGHT COLUMN (sidebar) ──────── */}
        <div className="space-y-3">
          {/* Email overview */}
          <Panel title="Email Overview" icon="mail">
            <dl className="space-y-2 text-sm">
              <SidebarRow label="From" value={<span className="font-mono text-xs break-all">{from}</span>} />
              <SidebarRow label="Subject" value={subject} />
              <SidebarRow label="Connecting IP" value={fx?.trust.connectingIp ? <Copyable value={fx.trust.connectingIp} ioc /> : '—'} />
              <SidebarRow label="Links" value={String(r.links.length)} />
              <SidebarRow label="Attachments" value={String(attachmentCount)} />
              <SidebarRow label="Headers" value={fx ? 'Supplied' : 'Not supplied'} />
            </dl>
          </Panel>

          {/* Authentication */}
          <Panel title="Authentication" icon="lock">
            <div className="space-y-1.5">
              <AuthRow label="SPF" status={authLabel(spf)} tone={authTone(spf)} />
              <AuthRow label="DKIM" status={authLabel(dkim)} tone={authTone(dkim)} />
              <AuthRow label="DMARC" status={authLabel(dmarc)} tone={authTone(dmarc)} />
            </div>
          </Panel>

          {/* Pipeline */}
          <Panel title="Pipeline Status" icon="pulse">
            <div className="space-y-1">
              {pipeline.map((c) => (
                <div key={c.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="flex items-center gap-1.5">
                    <Icon name={chipIcon[c.status]} size={12} className={`${c.status === 'complete' ? 'text-green' : c.status === 'failed' ? 'text-rose' : c.status === 'running' ? 'text-sky' : 'text-faint'}`} />
                    <span className="text-fg">{c.label}</span>
                  </span>
                  <Badge tone={chipTone[c.status]}>{c.status}{c.failed > 0 ? ` · ${c.failed} err` : ''}</Badge>
                </div>
              ))}
            </div>
          </Panel>

          {/* Indicators */}
          <Panel title="Indicators" icon="network">
            <div className="space-y-2 text-xs">
              {r.indicators.ips.length > 0 && (
                <div>
                  <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-faint">IPs</div>
                  <ul className="space-y-0.5">{r.indicators.ips.slice(0, 5).map((i) => <li key={i.ip} className="flex items-center gap-1.5"><Copyable value={i.ip} ioc /><Badge tone={trustTone(i.trust)}>{i.role.replace(/_/g, ' ')}</Badge></li>)}</ul>
                  {r.indicators.ips.length > 5 && <div className="text-faint">+ {r.indicators.ips.length - 5} more</div>}
                </div>
              )}
              {r.indicators.domains.length > 0 && (
                <div>
                  <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-faint">Domains</div>
                  <ul className="space-y-0.5">{r.indicators.domains.slice(0, 5).map((d) => <li key={d.domain} className="flex items-center gap-1.5"><Copyable value={d.domain} ioc /></li>)}</ul>
                  {r.indicators.domains.length > 5 && <div className="text-faint">+ {r.indicators.domains.length - 5} more</div>}
                </div>
              )}
              {r.indicators.emails.length > 0 && (
                <div>
                  <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-faint">Emails</div>
                  <ul className="space-y-0.5">{r.indicators.emails.slice(0, 3).map((e) => <li key={e.address} className="font-mono break-all">{e.address}</li>)}</ul>
                </div>
              )}
              {verdict.indicators.length > 0 && (
                <div>
                  <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-faint">Block/Hunt</div>
                  <ul className="space-y-0.5">{verdict.indicators.slice(0, 5).map((i) => <li key={`${i.type}:${i.value}`} className="flex items-center gap-1.5"><Badge>{i.type}</Badge><span className="font-mono break-all">{i.value}</span></li>)}</ul>
                </div>
              )}
              {r.indicators.ips.length === 0 && r.indicators.domains.length === 0 && r.indicators.emails.length === 0 && (
                <p className="text-muted">No indicators extracted.</p>
              )}
            </div>
          </Panel>

          {/* Timeline */}
          <Panel title="Timeline" icon="clock">
            {timeline.length > 0 ? (
              <ol className="ph-db-timeline space-y-1 text-xs">
                {timeline.slice(0, 10).map((ev, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="shrink-0 tabular-nums text-faint">{formatTime(ev.at)}</span>
                    <span className="text-muted">{ev.label}</span>
                  </li>
                ))}
                {timeline.length > 10 && <li className="text-faint">+ {timeline.length - 10} more events</li>}
              </ol>
            ) : <p className="text-xs text-muted">No timeline events.</p>}
          </Panel>

          {/* Export */}
          <Panel title="Export" icon="file">
            <ExportBar report={report} />
          </Panel>

          {/* How decided */}
          <details className="rounded-xl border border-line bg-panel/80">
            <summary className="cursor-pointer px-4 py-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted hover:text-fg">
              How was this decided?
            </summary>
            <div className="border-t border-line p-3 space-y-3">
              <p className="text-xs text-muted">Findings earn base points scaled by exactness, reliability and trust. Same-fact findings are grouped to avoid double counting.</p>
              <DataTable head={['Dimension', 'Wt', 'Pts', 'Score', 'Cov']} rows={verdict.dimensions.map((d) => [
                dimensionLabel[d.dimension],
                d.active ? `${Math.round(d.effectiveWeight * 100)}%` : <span key="n" className="text-faint">n/a</span>,
                d.points, d.score, `${Math.round(d.coverage * 100)}%`,
              ])} />
              {verdict.unmapped.length > 0 && <p className="text-xs text-amber">Scored by severity only: {verdict.unmapped.join(', ')}</p>}
            </div>
          </details>
        </div>
      </div>

      {/* ── DISCLAIMER ── */}
      <p className="ph-db-disclaimer text-center text-[11px] text-faint">
        {meta.short} Decision support for an analyst, not a guarantee. Scoring weights are initial values still being calibrated.
      </p>
    </div>
  );
}

/* ─── small helpers ─── */
function SidebarRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="shrink-0 text-faint">{label}</dt>
      <dd className="min-w-0 text-right">{value}</dd>
    </div>
  );
}

function AuthRow({ label, status, tone }: { label: string; status: string; tone: Tone }) {
  const iconName: IconName = tone === 'good' ? 'check' : tone === 'bad' ? 'x' : 'warn';
  const iconColor = tone === 'good' ? 'text-green' : tone === 'bad' ? 'text-rose' : 'text-amber';
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-sm text-fg">{label}</span>
      <span className={`flex items-center gap-1 text-sm font-medium ${iconColor}`}>
        <Icon name={iconName} size={13} />{status}
      </span>
    </div>
  );
}

function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return '—';
  }
}
