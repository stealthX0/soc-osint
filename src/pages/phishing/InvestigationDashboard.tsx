import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Badge, Copyable, type Tone } from '../../components/ui';
import { Icon, type IconName } from '../../components/icons';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput, Finding, Dimension } from '../../../shared/phishing/types';
import type { Verdict, VerdictLabel } from '../../../shared/phishing/verdict';
import { VERDICT_TEXT } from '../../../shared/phishing/verdict';
import { dimensionLabel } from '../../../shared/phishing/findings';
import type { Report } from '../../../shared/phishing/report';
import type { TimelineEvent } from '../../../shared/phishing/timeline';
import type { CheckRowX, PipelineChip } from './model';
import { ExportBar } from './ExportBar';
import { ContentPanel } from './ContentPanel';
import { HeadersTab } from './HeadersTab';
import { SenderTab } from './SenderTab';
import { UrlTab } from './UrlTab';
import { AttachmentTab } from './AttachmentPanel';
import { EvidenceTab } from './EvidenceTab';
import { sevTone } from './common';
import type { SenderStage, LinkStage } from './hooks';
import type { AttachmentStage } from './AttachmentPanel';

/* ─── colour maps ─── */
const verdictTone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };
const verdictAccent: Record<VerdictLabel, string> = {
  malicious: 'text-rose', suspicious: 'text-amber', likely_legitimate: 'text-green',
  inconclusive: 'text-sky', analysis_unavailable: 'text-muted',
};
const verdictBannerBg: Record<VerdictLabel, string> = {
  malicious: 'from-rose/25 to-rose/8 border-rose/30',
  suspicious: 'from-amber/25 to-amber/8 border-amber/30',
  likely_legitimate: 'from-green/25 to-green/8 border-green/30',
  inconclusive: 'from-sky/25 to-sky/8 border-sky/30',
  analysis_unavailable: 'from-line/30 to-line/10 border-line',
};
const verdictGaugeHex: Record<VerdictLabel, string> = {
  malicious: '#f87171', suspicious: '#fbbf24', likely_legitimate: '#34d399',
  inconclusive: '#38bdf8', analysis_unavailable: '#56688d',
};
const verdictIcon: Record<VerdictLabel, IconName> = {
  malicious: 'warn', suspicious: 'warn', likely_legitimate: 'check',
  inconclusive: 'info', analysis_unavailable: 'info',
};
const verdictCircleBg: Record<VerdictLabel, string> = {
  malicious: 'bg-rose/20', suspicious: 'bg-amber/20', likely_legitimate: 'bg-green/20',
  inconclusive: 'bg-sky/20', analysis_unavailable: 'bg-line/30',
};
const verdictPillBg: Record<VerdictLabel, string> = {
  malicious: 'border-rose/30 bg-rose/10 text-rose',
  suspicious: 'border-amber/30 bg-amber/10 text-amber',
  likely_legitimate: 'border-green/30 bg-green/10 text-green',
  inconclusive: 'border-sky/30 bg-sky/10 text-sky',
  analysis_unavailable: 'border-line bg-bg2 text-muted',
};

/* ─── tab definitions ─── */
type AnalysisTab = 'overview' | 'sender' | 'urls' | 'domain' | 'content' | 'evidence';
const ANALYSIS_TABS: { id: AnalysisTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'sender', label: 'Sender Analysis' },
  { id: 'urls', label: 'Link Analysis' },
  { id: 'domain', label: 'Domain & IP Intelligence' },
  { id: 'content', label: 'Content Analysis' },
  { id: 'evidence', label: 'Evidence' },
];

/* ─── props ─── */
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
   Semicircle Risk Gauge
   ═══════════════════════════════════════════════════════════ */
function SemiGauge({ score, label }: { score: number; label: VerdictLabel }) {
  const r = 62, cx = 80, cy = 82;
  const arc = Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = arc * (1 - pct / 100);
  const color = verdictGaugeHex[label];
  const riskWord = score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Low';
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 160 100" className="w-[170px]">
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" strokeWidth={13} stroke="#1c2a47" strokeLinecap="round" opacity={0.5} />
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" strokeWidth={13} stroke={color} strokeLinecap="round"
          strokeDasharray={arc} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s ease' }} />
        <text x={cx} y={cy - 20} textAnchor="middle" fill="#d8e2f6" fontSize="26" fontWeight="700">{score}</text>
        <text x={cx} y={cy - 4} textAnchor="middle" fill="#56688d" fontSize="11">/100</text>
      </svg>
      <div className="-mt-1 text-center">
        <div className="text-[10px] uppercase tracking-[.12em] text-faint">Risk Level</div>
        <div className={`text-sm font-semibold ${verdictAccent[label]}`}>{riskWord}</div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Reusable Panel
   ═══════════════════════════════════════════════════════════ */
function Panel({ title, icon, children, className = '' }: { title: string; icon?: IconName; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line/70 bg-[#0c1529] ${className}`}>
      <header className="flex items-center gap-2 border-b border-line/50 px-5 py-3.5">
        {icon && <Icon name={icon} size={16} className="text-muted" />}
        <h3 className="text-base font-bold text-fg">{title}</h3>
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}

/* ═══════════════════════════════════════════════════════════
   Key Finding Card
   ═══════════════════════════════════════════════════════════ */
function FindingCard({ icon, title, desc, tone }: { icon: IconName; title: string; desc: string; tone: Tone }) {
  const iconBg: Record<Tone, string> = { bad: 'bg-rose/15 text-rose', warn: 'bg-amber/15 text-amber', good: 'bg-green/15 text-green', info: 'bg-sky/15 text-sky', accent: 'bg-teal/15 text-teal', neutral: 'bg-line/20 text-muted' };
  return (
    <div className="rounded-xl border border-line/70 bg-[#0c1529] p-4">
      <div className="mb-3 flex items-start gap-3">
        <div className={`grid size-10 shrink-0 place-items-center rounded-full ${iconBg[tone]}`}>
          <Icon name={icon} size={20} />
        </div>
        <div className="min-w-0 pt-0.5">
          <div className="text-sm font-bold text-fg leading-tight">{title}</div>
          <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">{desc}</p>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   THE FULL-PAGE DASHBOARD
   ═══════════════════════════════════════════════════════════ */
export function InvestigationDashboard({ r, input, verdict, findings, rows, pipeline, report, timeline, sender, links, att, startedAt, onNewAnalysis }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<AnalysisTab>('overview');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);

  /* ── derived data ── */
  const fx = r.forensics;
  const meta = VERDICT_TEXT[verdict.label];
  const from = fx?.summary.from ?? r.indicators.emails.find((e) => e.roles.includes('from'))?.address ?? '—';
  const fromDomain = from.includes('@') ? from.split('@')[1] : '—';
  const senderIp = fx?.trust.connectingIp ?? '—';
  const linkCount = r.links.length;
  const attachmentCount = r.attachments.filter((a) => !a.inline).length;
  const analysisTime = useMemo(() => ((Date.now() - startedAt) / 1000).toFixed(1), [startedAt]);
  const caseId = `PHI-${new Date(startedAt).toISOString().slice(2, 10).replace(/-/g, '')}-${String(startedAt).slice(-4)}`;

  /* dimension helpers */
  const dimInfo = (dim: Dimension): { tone: Tone; top: Finding | null } => {
    const ds = verdict.dimensions.find((d) => d.dimension === dim);
    const df = findings.filter((f) => f.dimension === dim);
    const top = df[0] ?? null;
    if (!ds || !ds.active) return { tone: 'neutral', top };
    if (ds.score <= 0) return { tone: 'good', top };
    if (ds.score < 30) return { tone: 'info', top };
    if (ds.score < 60) return { tone: 'warn', top };
    return { tone: 'bad', top };
  };
  const authDim = dimInfo('authentication');
  const urlDim = dimInfo('url');
  const infraDim = dimInfo('infrastructure');
  const contentDim = dimInfo('content');

  /* threat type from dominant dimension */
  const threatType = (() => {
    const d = verdict.dimensions.filter(x => x.active).sort((a, b) => b.score - a.score)[0];
    if (!d) return 'Unknown';
    const m: Record<string, string> = { url: 'Credential Harvesting', attachment: 'Malware Delivery', content: 'Social Engineering', authentication: 'Sender Spoofing', infrastructure: 'Suspicious Infrastructure' };
    return m[d.dimension] ?? 'Phishing';
  })();

  /* reasoning text */
  const reasoning = verdict.reasons.length > 0
    ? verdict.reasons.map(x => x.title + (x.detail ? `. ${x.detail}` : '')).join(' ')
    : verdict.headline;

  /* auth results */
  const authOf = (id: string) => {
    const c = r.checks.find(x => x.id === id);
    if (!c) return { label: '—', ok: false };
    const ok = c.result === 'pass';
    return { label: ok ? 'Pass' : c.result === 'fail' || c.result === 'hardfail' ? 'Fail' : c.result ?? c.status, ok };
  };
  const spf = authOf('spf'), dkim = authOf('dkim'), dmarc = authOf('dmarc');

  /* checks for bottom panel */
  const topChecks = rows.slice(0, 8);

  return (
    <div className="ph-results flex min-h-screen bg-bg" role="region" aria-label="Investigation results">

      {/* ═══════════ LEFT SIDEBAR ═══════════ */}
      <aside className="ph-db-sidebar-scroll sticky top-0 hidden h-screen w-[300px] shrink-0 overflow-y-auto border-r border-line bg-[#070c19] lg:block">

        {/* ── Header banner ── */}
        <div className="flex items-center gap-3 border-b border-line px-5 py-4 bg-gradient-to-r from-sky/10 to-transparent">
          <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-sky/15 ring-1 ring-sky/30">
            <Icon name="shield" size={20} className="text-sky" />
          </div>
          <div>
            <div className="text-sm font-bold text-fg leading-tight">Email Investigation</div>
            <div className="text-[11px] text-muted">Dashboard</div>
          </div>
        </div>

        <div className="space-y-5 p-5">

          {/* ── Investigation Summary ── */}
          <div>
            <h3 className="text-base font-bold text-fg mb-3">Investigation Summary</h3>
            <div className="space-y-2.5">
              <SFieldRow label="Case ID" value={caseId} mono />
              <SFieldRow label="Analyzed At" value={new Date(startedAt).toLocaleString()} />
              <SFieldRow label="Analysis Time" value={`${analysisTime} seconds`} />
            </div>
          </div>

          <hr className="border-line/40" />

          {/* ── Input Details ── */}
          <div>
            <h3 className="text-base font-bold text-fg mb-3">Input Details</h3>
            <div className="space-y-3.5">
              <InputRow icon="mail" iconBg="bg-sky/15 text-sky" label="From" value={from} />
              <InputRow icon="globe" iconBg="bg-teal/15 text-teal" label="Domain" value={fromDomain} />
              <InputRow icon="network" iconBg="bg-amber/15 text-amber" label="Sender IP" value={senderIp} />
              <InputRow icon="shield" iconBg="bg-green/15 text-green" label="Links Found" value={String(linkCount)} />
              <InputRow icon="file" iconBg="bg-rose/15 text-rose" label="Attachments" value={String(attachmentCount)} />
            </div>
          </div>

        </div>
      </aside>

      {/* ═══════════ MAIN CONTENT ═══════════ */}
      <div className="flex-1 overflow-y-auto">

        {/* ── Verdict Banner ── */}
        <div className={`border-b border-line bg-gradient-to-r ${verdictBannerBg[verdict.label]} px-8 py-6`}>
          <div className="mx-auto flex max-w-[1200px] items-center justify-between gap-6">
            <div className="flex items-center gap-4 min-w-0">
              <Icon name={verdictIcon[verdict.label]} size={40} className={`shrink-0 ${verdictAccent[verdict.label]}`} />
              <div className="min-w-0">
                <h2 ref={heading} tabIndex={-1} className={`text-2xl font-bold tracking-tight focus:outline-none ${verdictAccent[verdict.label]}`}>
                  {meta.label}
                </h2>
                <p className="text-sm text-muted mt-0.5">{verdict.headline}</p>
              </div>
            </div>
            <div className={`shrink-0 rounded-full border px-5 py-2 text-base font-bold tabular-nums ${verdictPillBg[verdict.label]}`}>
              Risk Score: {verdict.risk} / 100
            </div>
          </div>
        </div>

        {/* ── Scrollable content ── */}
        <div className="mx-auto max-w-[1200px] space-y-5 p-5">

          {/* ── Mobile-only sidebar summary (hidden on lg) ── */}
          <div className="rounded-xl border border-line bg-bg2/60 p-4 lg:hidden">
            <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
              <span><span className="text-faint">Case:</span> <span className="font-mono">{caseId}</span></span>
              <span><span className="text-faint">From:</span> <span className="font-mono">{from}</span></span>
              <span><span className="text-faint">IP:</span> {senderIp}</span>
              <span><span className="text-faint">Links:</span> {linkCount}</span>
              <span><span className="text-faint">Time:</span> {analysisTime}s</span>
            </div>
          </div>

          {/* ── KEY FINDINGS ── */}
          <div>
            <h3 className="mb-4 text-lg font-bold text-fg">Key Findings</h3>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <FindingCard icon="lock" tone={authDim.tone}
                title={authDim.top?.title ?? 'Authentication'}
                desc={authDim.top?.detail ?? (authDim.tone === 'good' ? 'Email authentication checks passed.' : 'No authentication findings.')} />
              <FindingCard icon="shield" tone={urlDim.tone}
                title={urlDim.top?.title ?? 'URL Analysis'}
                desc={urlDim.top?.detail ?? (urlDim.tone === 'good' ? 'All URLs appear legitimate.' : 'No URL findings.')} />
              <FindingCard icon="globe" tone={infraDim.tone}
                title={infraDim.top?.title ?? 'Infrastructure'}
                desc={infraDim.top?.detail ?? (infraDim.tone === 'good' ? 'Sending infrastructure looks legitimate.' : 'No infrastructure findings.')} />
              <FindingCard icon="eye" tone={contentDim.tone}
                title={contentDim.top?.title ?? 'Content Analysis'}
                desc={contentDim.top?.detail ?? (contentDim.tone === 'good' ? 'Email content appears normal.' : 'No content findings.')} />
            </div>
          </div>

          {/* ── DETAILED ANALYSIS ── */}
          <Panel title="Detailed Analysis" icon="list">
            {/* Tab bar */}
            <div className="mb-4 flex gap-1 overflow-x-auto rounded-lg border border-line bg-bg2/80 p-0.5">
              {ANALYSIS_TABS.map((t) => (
                <button key={t.id} type="button" onClick={() => setActiveTab(t.id)}
                  className={`shrink-0 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    activeTab === t.id ? 'bg-sky/15 text-sky shadow-[0_0_0_1px_rgba(56,189,248,.3)]' : 'text-muted hover:text-fg'
                  }`}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="ph-db-detail-content">
              {activeTab === 'overview' && (
                <div className="grid gap-6 lg:grid-cols-[190px_1fr_1fr]">
                  {/* Semicircle gauge */}
                  <div className="flex items-start justify-center pt-2">
                    <SemiGauge score={verdict.risk} label={verdict.label} />
                  </div>

                  {/* Classification table */}
                  <div>
                    <h4 className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-faint">Classification</h4>
                    <div className="space-y-2.5">
                      <CRow label="Classification" value={<Badge tone={verdictTone[verdict.label]}>{verdict.label.replace(/_/g, ' ')}</Badge>} />
                      <CRow label="Confidence" value={
                        <span className="flex items-center gap-1.5">
                          <Badge tone={verdict.confidence.level === 'high' ? 'good' : verdict.confidence.level === 'medium' ? 'warn' : 'neutral'}>{verdict.confidence.level}</Badge>
                          <span className="text-xs text-muted">({Math.round(verdict.confidence.score * 100)}%)</span>
                        </span>
                      } />
                      <CRow label="Threat Type" value={<span className="text-sm text-fg">{threatType}</span>} />
                      <CRow label="Coverage" value={<span className="text-sm text-fg">{Math.round(verdict.coverage * 100)}%</span>} />
                      {verdict.rule && <CRow label="Decided By" value={<span className="text-xs text-faint">Verdict rule on direct evidence</span>} />}
                    </div>
                  </div>

                  {/* Reasoning */}
                  <div>
                    <h4 className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-faint">Reasoning</h4>
                    <p className="mb-3 text-sm leading-relaxed text-muted">{reasoning || verdict.headline}</p>

                    {verdict.conflicts.length > 0 && (
                      <div className="mb-3">
                        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-amber">Conflicting Evidence</div>
                        <ul className="space-y-0.5 text-xs text-amber">{verdict.conflicts.map((c) => <li key={c}>• {c}</li>)}</ul>
                      </div>
                    )}
                    {verdict.mitigating.length > 0 && (
                      <div className="mb-3">
                        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-green">Supporting Evidence</div>
                        <ul className="space-y-0.5 text-xs text-muted">{verdict.mitigating.map((m) => <li key={m}>• {m}</li>)}</ul>
                      </div>
                    )}
                    {verdict.actions.length > 0 && (
                      <div>
                        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-faint">Recommended Actions</div>
                        <ul className="space-y-0.5 text-xs text-muted">{verdict.actions.map((a) => <li key={a}>• {a}</li>)}</ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'sender' && <SenderTab slots={sender.slots} skipped={sender.plan.skipped} running={sender.running} findings={findings} />}
              {activeTab === 'urls' && <UrlTab r={r} links={links} />}
              {activeTab === 'domain' && <HeadersTab r={r} />}
              {activeTab === 'content' && <ContentPanel a={r.content.analysis} subject={r.content.subject} />}
              {activeTab === 'evidence' && <EvidenceTab findings={findings} checks={rows} timeline={timeline} raw={{ sender: sender.results, urls: links.stage, attachments: att.results }} />}
            </div>
          </Panel>

          {/* ── BOTTOM ROW: 3 panels ── */}
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Indicators Checked */}
            <Panel title="Indicators Checked" icon="check">
              <ul className="space-y-1.5">
                {topChecks.map((c) => {
                  const pass = c.status === 'complete' && (c.result === 'pass' || c.result === 'none');
                  const fail = c.status === 'complete' && (c.result === 'fail' || c.result === 'hardfail' || c.result === 'permerror');
                  return (
                    <li key={c.id} className="flex items-center justify-between gap-2 text-xs">
                      <span className="flex items-center gap-2 min-w-0">
                        <span className={pass ? 'text-green' : fail ? 'text-rose' : 'text-faint'}>{pass ? '✓' : fail ? '✗' : '–'}</span>
                        <span className="truncate text-fg/80">{c.label}</span>
                      </span>
                      <Badge tone={pass ? 'good' : fail ? 'bad' : c.status === 'complete' ? 'warn' : 'neutral'}>
                        {c.result ?? c.status}
                      </Badge>
                    </li>
                  );
                })}
                {rows.length > 8 && <li className="pt-1 text-[11px] text-faint">+ {rows.length - 8} more checks</li>}
              </ul>
            </Panel>

            {/* Link Details */}
            <Panel title="Link Details" icon="shield">
              {r.links.length > 0 ? (
                <div className="space-y-2.5">
                  {r.links.slice(0, 3).map((l, i) => (
                    <div key={i} className="rounded-lg border border-line bg-bg2/40 p-2.5">
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <code className="break-all font-mono text-[11px] text-fg/80 line-clamp-2">{l.url}</code>
                        <Badge tone={urlDim.tone === 'bad' ? 'bad' : urlDim.tone === 'warn' ? 'warn' : 'neutral'}>
                          {urlDim.tone === 'bad' ? 'Malicious' : urlDim.tone === 'warn' ? 'Suspicious' : 'Unknown'}
                        </Badge>
                      </div>
                      {l.text && <div className="text-[10px] text-faint truncate">Text: {l.text}</div>}
                    </div>
                  ))}
                  {r.links.length > 3 && <p className="text-[11px] text-faint">+ {r.links.length - 3} more links</p>}
                </div>
              ) : (
                <p className="text-sm text-muted">No links found in the email.</p>
              )}
            </Panel>

            {/* IP Reputation */}
            <Panel title="IP Reputation" icon="network">
              {senderIp !== '—' ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <Copyable value={senderIp} ioc />
                    <Badge tone={infraDim.tone}>
                      {infraDim.tone === 'bad' ? 'High Risk' : infraDim.tone === 'warn' ? 'Medium Risk' : infraDim.tone === 'good' ? 'Low Risk' : 'Unknown'}
                    </Badge>
                  </div>
                  <div className="space-y-1.5 text-xs">
                    <AuthLine label="SPF" result={spf.label} ok={spf.ok} />
                    <AuthLine label="DKIM" result={dkim.label} ok={dkim.ok} />
                    <AuthLine label="DMARC" result={dmarc.label} ok={dmarc.ok} />
                  </div>
                  {r.indicators.ips.length > 0 && (
                    <div className="border-t border-line pt-2">
                      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-faint">Other IPs</div>
                      <ul className="space-y-0.5 text-xs">
                        {r.indicators.ips.slice(0, 4).map((ip) => (
                          <li key={ip.ip} className="flex items-center gap-2 text-muted">
                            <span className="font-mono text-fg/80">{ip.ip}</span>
                            <span className="text-faint">{ip.role.replace(/_/g, ' ')}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted">No sender IP available.</p>
              )}
            </Panel>
          </div>

          {/* ── ACTION BAR ── */}
          <div className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-panel/60 px-5 py-3.5">
            <ExportBar report={report} />
            {onNewAnalysis && (
              <button type="button" onClick={onNewAnalysis}
                className="ml-auto inline-flex h-9 items-center gap-2 rounded-lg border border-line2 px-4 text-sm text-fg transition-colors hover:border-teal/50">
                <Icon name="arrow" size={14} className="rotate-180" /> New Analysis
              </button>
            )}
          </div>

          {/* ── DISCLAIMER ── */}
          <p className="pb-4 text-center text-[11px] text-faint">
            {meta.short} Decision support for an analyst, not a guarantee.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ─── small helpers ─── */
function SFieldRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs text-muted">{label}</span>
      <span className={`text-xs text-fg text-right ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}

function InputRow({ icon, iconBg, label, value }: { icon: IconName; iconBg: string; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className={`grid size-9 shrink-0 place-items-center rounded-full ${iconBg}`}>
        <Icon name={icon} size={18} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-[11px] text-muted mb-0.5">{label}</div>
        <div className="truncate text-sm font-medium text-fg">{value}</div>
      </div>
    </div>
  );
}

function CRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="shrink-0 text-xs text-faint">{label}</span>
      <span>{value}</span>
    </div>
  );
}

function AuthLine({ label, result, ok }: { label: string; result: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-faint">{label}</span>
      <span className={`font-medium ${ok ? 'text-green' : result === 'Fail' ? 'text-rose' : 'text-amber'}`}>{result}</span>
    </div>
  );
}

function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return '—'; }
}
