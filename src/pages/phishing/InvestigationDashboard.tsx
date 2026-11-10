import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Badge, Copyable, type Tone } from '../../components/ui';
import { Icon, type IconName } from '../../components/icons';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput, Finding, Dimension } from '../../../shared/phishing/types';
import type { Verdict, VerdictLabel } from '../../../shared/phishing/verdict';
import { VERDICT_TEXT } from '../../../shared/phishing/verdict';
import { summarizeReasoning } from '../../../shared/phishing/summary';
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
import type { IpLookup } from '../../../shared/types';

/* ─── colour maps ─── */
const verdictTone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };
const verdictAccent: Record<VerdictLabel, string> = {
  malicious: 'text-rose', suspicious: 'text-amber', likely_legitimate: 'text-green',
  inconclusive: 'text-sky', analysis_unavailable: 'text-muted',
};
/** Verdict card: tinted gradient, coloured border and a soft glow in the verdict colour. */
const verdictBannerBg: Record<VerdictLabel, string> = {
  malicious: 'border-rose/70 bg-gradient-to-r from-rose/30 via-rose/15 to-rose/10 shadow-[0_0_24px_-6px_rgba(248,113,113,0.45)]',
  suspicious: 'border-amber/70 bg-gradient-to-r from-amber/25 via-amber/12 to-amber/8 shadow-[0_0_24px_-6px_rgba(251,191,36,0.4)]',
  likely_legitimate: 'border-green/70 bg-gradient-to-r from-green/25 via-green/12 to-green/8 shadow-[0_0_24px_-6px_rgba(52,211,153,0.4)]',
  inconclusive: 'border-sky/70 bg-gradient-to-r from-sky/25 via-sky/12 to-sky/8 shadow-[0_0_24px_-6px_rgba(56,189,248,0.4)]',
  analysis_unavailable: 'border-line bg-gradient-to-r from-line/40 to-line/15',
};
/** Card title shown on the dashboard (the report and exports keep the short VERDICT_TEXT labels). */
const verdictTitle: Record<VerdictLabel, string> = {
  malicious: 'Malicious Email Detected',
  suspicious: 'Suspicious Email Detected',
  likely_legitimate: 'Likely Legitimate Email',
  inconclusive: 'Inconclusive Result',
  analysis_unavailable: 'Analysis Unavailable',
};
/** Solid fill for the verdict icon. */
const verdictFill: Record<VerdictLabel, string> = {
  malicious: '#ef4444', suspicious: '#f59e0b', likely_legitimate: '#22c55e', inconclusive: '#38bdf8', analysis_unavailable: '#56688d',
};
const verdictGaugeHex: Record<VerdictLabel, string> = {
  malicious: '#f87171', suspicious: '#fbbf24', likely_legitimate: '#34d399',
  inconclusive: '#38bdf8', analysis_unavailable: '#56688d',
};
const verdictPillBg: Record<VerdictLabel, string> = {
  malicious: 'bg-rose/35 text-white',
  suspicious: 'bg-amber/30 text-white',
  likely_legitimate: 'bg-green/30 text-white',
  inconclusive: 'bg-sky/30 text-white',
  analysis_unavailable: 'bg-line/60 text-fg',
};
/** Solid classification pill in the Detailed Analysis overview. */
const verdictSolidPill: Record<VerdictLabel, string> = {
  malicious: 'bg-[#b91c1c] text-white', suspicious: 'bg-[#b45309] text-white', likely_legitimate: 'bg-[#15803d] text-white',
  inconclusive: 'bg-[#0369a1] text-white', analysis_unavailable: 'bg-line text-fg',
};
const verdictWord: Record<VerdictLabel, string> = {
  malicious: 'Malicious', suspicious: 'Suspicious', likely_legitimate: 'Likely Legitimate', inconclusive: 'Inconclusive', analysis_unavailable: 'Unavailable',
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
  // Score sits low inside the arc, level with its ends; "Risk Score" sits just below the ends.
  const r = 92, cx = 110, cy = 104;
  const arc = Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = arc * (1 - pct / 100);
  const color = verdictGaugeHex[label];
  return (
    <svg viewBox="0 0 220 140" className="w-[240px]" role="img" aria-label={`Risk score ${score} out of 100`}>
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" strokeWidth={18} stroke="#2a3a5e" />
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" strokeWidth={18} stroke={color}
        strokeDasharray={arc} strokeDashoffset={offset} style={{ transition: 'stroke-dashoffset 1s ease' }} />
      <text x={cx} y={cy - 6} textAnchor="middle" fill="#f5f7fb" fontSize="25" fontWeight="600">{score} / 100</text>
      <text x={cx} y={cy + 25} textAnchor="middle" fill="#c7d2e8" fontSize="12.5">Risk Score</text>
    </svg>
  );
}

/* ═══════════════════════════════════════════════════════════
   Verdict glyph: solid warning triangle / check / info, filled in the verdict colour
   ═══════════════════════════════════════════════════════════ */
function VerdictGlyph({ label }: { label: VerdictLabel }) {
  const fill = verdictFill[label];
  if (label === 'malicious' || label === 'suspicious') {
    return (
      <svg viewBox="0 0 64 56" className="h-[40px] w-[46px] shrink-0" aria-hidden>
        <path d="M28.5 4.2a4 4 0 0 1 7 0l26.6 46a4 4 0 0 1-3.5 6H5.4a4 4 0 0 1-3.5-6z" fill={fill} />
        <rect x="29" y="18" width="6" height="21" rx="3" fill="#1a0b0b" />
        <circle cx="32" cy="46" r="3.6" fill="#1a0b0b" />
      </svg>
    );
  }
  return (
    <div className="grid size-10 shrink-0 place-items-center rounded-full" style={{ background: fill }}>
      <Icon name={label === 'likely_legitimate' ? 'check' : 'info'} size={24} className="text-[#0b1220]" strokeWidth={2.6} />
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Reusable Panel
   ═══════════════════════════════════════════════════════════ */
function Panel({ title, icon, children, className = '' }: { title: string; icon?: IconName; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line/70 bg-[#0c1529] ${className}`}>
      <header className="flex items-center gap-2 border-b border-line/50 px-4 py-2.5">
        {icon && <Icon name={icon} size={16} className="text-muted" />}
        <h3 className="text-base font-bold text-fg">{title}</h3>
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

/* ═══════════════════════════════════════════════════════════
   Key Finding Card
   ═══════════════════════════════════════════════════════════ */
function FindingCard({ icon, title, desc, tone }: { icon: IconName; title: string; desc: string; tone: Tone }) {
  const iconBg: Record<Tone, string> = { bad: 'bg-rose/15 text-rose', warn: 'bg-amber/15 text-amber', good: 'bg-green/15 text-green', info: 'bg-sky/15 text-sky', accent: 'bg-teal/15 text-teal', neutral: 'bg-line/20 text-muted' };
  return (
    <div className="rounded-xl border border-line/60 bg-[#0b1426] p-4">
      <div className="flex items-start gap-3">
        <div className={`grid size-10 shrink-0 place-items-center rounded-full ${iconBg[tone]}`}>
          <Icon name={icon} size={20} />
        </div>
        <div className="min-w-0 pt-0.5">
          <div className="text-sm font-bold text-fg leading-snug">{title}</div>
          <p className="mt-1 line-clamp-3 text-xs leading-relaxed text-muted">{desc}</p>
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
  // "Name <user@domain>" -> domain, without the closing bracket or trailing junk.
  const fromDomain = /@([^\s<>"';,]+)/.exec(from)?.[1]?.toLowerCase() ?? '—';
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

  /* reasoning: one-sentence summary, the strongest findings as short points, one caveat */
  const reasoning = useMemo(() => summarizeReasoning(verdict), [verdict]);
  const sevDot: Record<string, string> = { critical: 'bg-rose', high: 'bg-rose', medium: 'bg-amber', low: 'bg-sky', info: 'bg-faint' };


  return (
    <div className="ph-results flex min-h-screen flex-col bg-bg" role="region" aria-label="Investigation results">

      {/* ═══════════ TOP HEADER BAR (full width) ═══════════ */}
      <header className="flex shrink-0 items-center justify-between border-b border-line/50 bg-[#0a1128] px-6 py-3">
        <div className="flex items-center gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-sky/10 ring-1 ring-sky/25">
            <Icon name="shield" size={22} className="text-sky" />
          </div>
          <div className="text-base font-bold text-fg leading-snug">Email Investigation Dashboard</div>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted">
          <span>{new Date(startedAt).toLocaleString()}</span>
        </div>
      </header>

      {/* ═══════════ BODY: sidebar + main ═══════════ */}
      <div className="flex flex-1 overflow-hidden">

      {/* ═══════════ LEFT SIDEBAR ═══════════ */}
      <aside className="ph-db-sidebar-scroll hidden h-full w-[280px] shrink-0 overflow-y-auto border-r border-line/50 bg-[#060b18] lg:block">

        <div className="space-y-3 px-3 py-4">

          {/* ── Investigation Summary card ── */}
          <div className="rounded-xl border border-line/50 bg-[#0c1529]">
            <div className="px-4 pt-3 pb-2 border-b border-line/30">
              <h3 className="text-sm font-bold text-fg">Investigation Summary</h3>
            </div>
            <div className="space-y-2.5 px-4 py-3">
              <SFieldRow label="Case ID" value={caseId} mono />
              <SFieldRow label="Analyzed At" value={new Date(startedAt).toLocaleString()} />
              <SFieldRow label="Analysis Time" value={`${analysisTime} seconds`} />
            </div>
          </div>

          {/* ── Input Details card ── */}
          <div className="rounded-xl border border-line/50 bg-[#0c1529]">
            <div className="px-4 pt-3 pb-2">
              <h3 className="text-sm font-bold text-fg">Input Details</h3>
            </div>
            <div className="space-y-3 px-4 pb-4">
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

        {/* ── Scrollable content ── */}
        <div className="space-y-5 p-5">

          {/* ── Verdict card: its own bordered box, separated from the top header ── */}
          <div className={`flex items-center justify-between gap-5 rounded-xl border-2 px-5 py-3.5 ${verdictBannerBg[verdict.label]}`}>
            <div className="flex min-w-0 items-center gap-4">
              <VerdictGlyph label={verdict.label} />
              <div className="min-w-0">
                <h2 ref={heading} tabIndex={-1} className={`text-[22px] font-bold leading-tight tracking-tight focus:outline-none ${verdictAccent[verdict.label]}`}>
                  {verdictTitle[verdict.label]}
                </h2>
                <p className="mt-0.5 text-sm text-fg/85">{verdict.headline}</p>
              </div>
            </div>
            <div className={`shrink-0 rounded-full px-4 py-1.5 text-sm font-semibold tabular-nums ${verdictPillBg[verdict.label]}`}>
              Risk Score: {verdict.risk} / 100
            </div>
          </div>

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
            <h3 className="mb-3 text-lg font-bold text-fg">Key Findings</h3>
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
          <section className="rounded-xl border border-line/70 bg-[#0c1529] px-5 pb-5 pt-4">
            <h3 className="text-lg font-bold text-fg">Detailed Analysis</h3>
            {/* Tab bar */}
            <div className="mb-5 mt-2 flex gap-2 overflow-x-auto border-b border-line/50" role="tablist">
              {ANALYSIS_TABS.map((t) => (
                <button key={t.id} type="button" role="tab" aria-selected={activeTab === t.id} onClick={() => setActiveTab(t.id)}
                  className={`-mb-px shrink-0 border-b-[3px] px-5 py-2.5 text-sm font-medium transition-colors ${
                    activeTab === t.id ? 'border-sky text-sky' : 'border-transparent text-fg/75 hover:text-fg'
                  }`}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="ph-db-detail-content">
              {activeTab === 'overview' && (
                <div className="grid items-start gap-6 lg:grid-cols-[240px_minmax(0,300px)_minmax(0,1fr)]">
                  {/* Risk gauge */}
                  <div className="flex justify-center">
                    <SemiGauge score={verdict.risk} label={verdict.label} />
                  </div>

                  {/* Classification: label / value rows, values close to their labels */}
                  <dl className="grid grid-cols-[auto_1fr] items-center gap-x-8 gap-y-3.5 pt-2 text-[15px]">
                    <dt className="text-fg/80">Classification</dt>
                    <dd><span className={`inline-block rounded-full px-3.5 py-1 text-sm font-semibold ${verdictSolidPill[verdict.label]}`}>{verdictWord[verdict.label]}</span></dd>
                    <dt className="text-fg/80">Confidence</dt>
                    <dd className="font-bold text-fg" title={verdict.confidence.notes.join(' ') || undefined}>{verdict.confidence.score}% <span className="text-xs font-normal capitalize text-muted">({verdict.confidence.level})</span></dd>
                    <dt className="text-fg/80">Threat Type</dt>
                    <dd className="font-bold text-fg">{threatType}</dd>
                    <dt className="text-fg/80">Coverage</dt>
                    <dd className="font-bold text-fg">{Math.round(verdict.coverage * 100)}%</dd>
                  </dl>

                  {/* Reasoning card */}
                  <div className="rounded-xl border border-line/60 bg-[#0f1a31] p-4">
                    <h4 className="text-base font-bold text-fg">Reasoning</h4>
                    <p className="mt-1.5 text-sm leading-relaxed text-fg/90">{reasoning.summary}</p>
                    {reasoning.points.length > 0 && (
                      <ul className="mt-2 space-y-1 text-sm text-fg/85">
                        {reasoning.points.map((pt) => (
                          <li key={pt.text} className="flex items-start gap-2">
                            <span className={`mt-[7px] size-1.5 shrink-0 rounded-full ${sevDot[pt.severity]}`} aria-hidden />
                            <span>{pt.text}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {reasoning.caveat && <p className="mt-2 text-xs leading-relaxed text-muted">{reasoning.caveat}</p>}
                    {verdict.conflicts.length > 0 && verdict.label !== 'malicious' && (
                      <p className="mt-2 text-xs text-amber">Conflicting evidence: {verdict.conflicts[0]}</p>
                    )}
                    {verdict.actions.length > 0 && (
                      <div className="mt-3 border-t border-line/50 pt-2.5 text-xs">
                        <div className="mb-1 font-semibold uppercase tracking-wider text-faint">Recommended Actions</div>
                        <ul className="space-y-0.5 text-muted">{verdict.actions.slice(0, 3).map((x) => <li key={x}>• {x}</li>)}</ul>
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
          </section>

          {/* ── BOTTOM ROW: 2 panels ── */}
          <div className="grid gap-4 lg:grid-cols-2">

            {/* Link Details */}
            <Panel title="Link Details" icon="shield">
              {r.links.length > 0 ? (
                <div className="space-y-2">
                  {r.links.slice(0, 3).map((l, i) => (
                    <div key={i} className="rounded-lg border border-line bg-bg2/40 p-2">
                      <div className="flex items-start justify-between gap-2 mb-0.5">
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
                <p className="text-xs text-muted">No links found in the email.</p>
              )}
            </Panel>

            {/* IP Reputation — from actual IP intelligence API results */}
            <Panel title="IP Reputation" icon="network">
              {senderIp !== '—' ? (
                <IpReputationContent sender={sender} senderIp={senderIp} infraDim={infraDim} />
              ) : (
                <p className="text-xs text-muted">No sender IP available.</p>
              )}
            </Panel>
          </div>

          {/* ── ACTION BAR ── */}
          <div className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-panel/60 px-4 py-2.5">
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
      </div>{/* end main content */}
      </div>{/* end body flex (sidebar + main) */}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   IP Reputation Panel (uses real IP intelligence data)
   ═══════════════════════════════════════════════════════════ */
function IpReputationContent({ sender, senderIp, infraDim }: { sender: SenderStage; senderIp: string; infraDim: { tone: Tone; top: Finding | null } }) {
  /* find the IP lookup data from sender results */
  const ipData: IpLookup | null = useMemo(() => {
    for (const res of sender.results) {
      if (res.data?.check === 'ip') return res.data.value;
    }
    return null;
  }, [sender.results]);

  if (!ipData) {
    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Copyable value={senderIp} ioc />
          <Badge tone={infraDim.tone}>
            {infraDim.tone === 'bad' ? 'High Risk' : infraDim.tone === 'warn' ? 'Medium Risk' : infraDim.tone === 'good' ? 'Low Risk' : 'Unknown'}
          </Badge>
        </div>
        <p className="text-xs text-muted">{sender.running ? 'Looking up IP intelligence…' : 'No IP intelligence data available.'}</p>
      </div>
    );
  }

  const rep = ipData.reputation;
  const net = ipData.network;
  const geo = ipData.geo;
  const nt = ipData.netType;
  const vt = ipData.virustotal;
  const pd = ipData.pulsedive;

  /* determine overall reputation label from intelligence sources */
  const abuseScore = rep?.abuseConfidence ?? 0;
  const repLabel = abuseScore >= 75 ? 'High Risk' : abuseScore >= 25 ? 'Medium Risk' : 'Low Risk';
  const repTone: Tone = abuseScore >= 75 ? 'bad' : abuseScore >= 25 ? 'warn' : 'good';

  const flags: string[] = [];
  if (nt?.isVpn) flags.push('VPN');
  if (nt?.isProxy) flags.push('Proxy');
  if (nt?.isTor) flags.push('Tor');
  if (nt?.isDatacenter) flags.push('Datacenter');
  if (nt?.isAbuser) flags.push('Known Abuser');
  if (rep?.isTor) flags.push('Tor Exit');

  return (
    <div className="space-y-2.5">
      {/* IP + reputation badge */}
      <div className="flex items-center justify-between gap-2">
        <Copyable value={senderIp} ioc />
        <Badge tone={repTone}>{repLabel}</Badge>
      </div>

      {/* AbuseIPDB */}
      {rep && (
        <div className="space-y-1">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">AbuseIPDB</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            <IpKV label="Confidence" value={<span className={abuseScore >= 50 ? 'text-rose font-semibold' : abuseScore >= 25 ? 'text-amber' : 'text-green'}>{abuseScore}%</span>} />
            <IpKV label="Reports" value={<span className="text-fg">{rep.totalReports}</span>} />
            <IpKV label="Reporters" value={<span className="text-fg">{rep.distinctReporters}</span>} />
            <IpKV label="Last Reported" value={<span className="text-fg">{rep.lastReportedAt ? new Date(rep.lastReportedAt).toLocaleDateString() : '—'}</span>} />
            {rep.isWhitelisted && <IpKV label="Whitelisted" value={<span className="text-green">Yes</span>} />}
          </div>
        </div>
      )}

      {/* Network / ASN */}
      {net && (net.org || net.asn) && (
        <div className="space-y-1 border-t border-line/40 pt-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">Network</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            {net.org && <IpKV label="Org" value={<span className="text-fg truncate" title={net.org}>{net.org}</span>} />}
            {net.asn && <IpKV label="ASN" value={<span className="font-mono text-fg">{net.asn}</span>} />}
            {net.isp && net.isp !== net.org && <IpKV label="ISP" value={<span className="text-fg truncate" title={net.isp}>{net.isp}</span>} />}
            {geo?.countryCode && <IpKV label="Country" value={<span className="text-fg">{geo.country ?? geo.countryCode}</span>} />}
            {geo?.city && <IpKV label="City" value={<span className="text-fg">{geo.city}{geo.region ? `, ${geo.region}` : ''}</span>} />}
          </div>
        </div>
      )}

      {/* Network type flags */}
      {flags.length > 0 && (
        <div className="flex flex-wrap gap-1 border-t border-line/40 pt-2">
          {flags.map((f) => <Badge key={f} tone={f === 'Known Abuser' || f === 'Tor Exit' ? 'bad' : 'warn'}>{f}</Badge>)}
        </div>
      )}

      {/* VirusTotal */}
      {vt && vt.observed && (
        <div className="space-y-1 border-t border-line/40 pt-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">VirusTotal</div>
          <div className="flex items-center gap-3 text-xs">
            <span className={vt.malicious > 0 ? 'text-rose font-semibold' : 'text-green'}>{vt.malicious} malicious</span>
            <span className={vt.suspicious > 0 ? 'text-amber' : 'text-muted'}>{vt.suspicious} suspicious</span>
            <span className="text-muted">{vt.harmless} clean</span>
          </div>
        </div>
      )}

      {/* Pulsedive */}
      {pd && pd.observed && (
        <div className="space-y-1 border-t border-line/40 pt-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">Pulsedive</div>
          <div className="text-xs">
            <span className="text-muted">Risk: </span>
            <span className={pd.risk === 'critical' || pd.risk === 'high' ? 'text-rose font-semibold' : pd.risk === 'medium' ? 'text-amber' : 'text-green'}>{pd.risk}</span>
            {pd.threats.length > 0 && (
              <span className="ml-2 text-muted">· {pd.threats.map(t => t.name).join(', ')}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function IpKV({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 min-w-0">
      <span className="text-faint shrink-0">{label}:</span>
      {value}
    </div>
  );
}

/* ─── small helpers ─── */
function SFieldRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs text-muted">{label}</span>
      <span className={`text-xs text-fg text-right ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}

function InputRow({ icon, iconBg, label, value }: { icon: IconName; iconBg: string; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className={`grid size-8 shrink-0 place-items-center rounded-full ${iconBg}`}>
        <Icon name={icon} size={16} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-[10px] text-muted">{label}</div>
        <div className="truncate text-xs font-semibold text-fg">{value}</div>
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


function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return '—'; }
}
