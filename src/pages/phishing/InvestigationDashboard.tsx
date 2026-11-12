import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Badge, Copyable, type Tone } from '../../components/ui';
import { Icon, type IconName } from '../../components/icons';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput, Finding, Severity } from '../../../shared/phishing/types';
import type { Verdict, VerdictLabel } from '../../../shared/phishing/verdict';
import { VERDICT_TEXT } from '../../../shared/phishing/verdict';
import type { Report } from '../../../shared/phishing/report';
import type { CheckRowX, PipelineChip } from './model';
import { ExportBar } from './ExportBar';
import { AnalystLabel } from './AnalystLabel';
import { ContentPanel } from './ContentPanel';
import { HeadersTab } from './HeadersTab';
import { SenderTab } from './SenderTab';
import { UrlTab } from './UrlTab';
import { AttachmentTab } from './AttachmentPanel';
import { EvidenceTab } from './EvidenceTab';
import { TabFindings, SEV_RANK } from './common';
import { identityFindings } from './SenderTab';
import { KeyFindings, RiskByArea, ReasoningCard, areaStates, type AnalysisTab } from './OverviewParts';
import type { SenderStage, LinkStage } from './hooks';
import type { AttachmentStage } from './AttachmentPanel';

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
const ANALYSIS_TABS: { id: AnalysisTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'sender', label: 'Sender Analysis' },
  { id: 'urls', label: 'Link Analysis' },
  { id: 'attachments', label: 'Attachments' },
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
  sender: SenderStage;
  links: LinkStage;
  att: AttachmentStage;
  startedAt: number;
  onNewAnalysis?: () => void;
  /** Tab shown first (Overview unless set; used by previews and tests). */
  initialTab?: AnalysisTab;
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

/** Tab-bar count chip, tinted by the worst severity among that tab's findings. */
const countChip: Record<Severity, string> = {
  critical: 'bg-rose/20 text-rose', high: 'bg-rose/20 text-rose', medium: 'bg-amber/20 text-amber', low: 'bg-sky/15 text-sky', info: 'bg-line/50 text-muted',
};
const worst = (fs: Finding[]): Severity | null => fs.reduce<Severity | null>((w, f) => (w === null || SEV_RANK[f.severity] < SEV_RANK[w] ? f.severity : w), null);

/* ═══════════════════════════════════════════════════════════
   THE FULL-PAGE DASHBOARD
   ═══════════════════════════════════════════════════════════ */
export function InvestigationDashboard({ r, input, verdict, findings, rows, pipeline, report, sender, links, att, startedAt, onNewAnalysis, initialTab = 'overview' }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<AnalysisTab>(initialTab);
  const heading = useRef<HTMLHeadingElement>(null);
  const detail = useRef<HTMLElement>(null);
  /** Opens a tab and brings the Detailed Analysis section into view (used by the Key Findings cards and Risk by Area). */
  const openTab = (tab: AnalysisTab) => { setActiveTab(tab); detail.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  useEffect(() => { heading.current?.focus(); }, []);

  /* ── derived data ── */
  const fx = r.forensics;
  const meta = VERDICT_TEXT[verdict.label];
  // The sender's e-mail address only, never the display name ("Name <user@domain>" -> "user@domain").
  const fromHeader = fx?.summary.from ?? '';
  const from = fx?.addresses.from[0]?.address
    ?? r.indicators.emails.find((e) => e.roles.includes('from'))?.address
    ?? /<([^<>\s]+@[^<>\s]+)>/.exec(fromHeader)?.[1]
    ?? /[^\s<>"';,]+@[^\s<>"';,]+/.exec(fromHeader)?.[0]
    ?? '—';
  const fromDomain = /@([^\s<>"';,]+)/.exec(from)?.[1]?.toLowerCase() ?? '—';
  // The IP that connected to the receiving server; for internal Microsoft 365 mail, the sending device's IP.
  const senderIp = fx?.trust.connectingIp ?? fx?.internal?.clientIp ?? '—';
  const linkCount = r.links.length;
  const attachmentCount = r.attachments.filter((a) => !a.inline).length;
  const analysisTime = useMemo(() => ((Date.now() - startedAt) / 1000).toFixed(1), [startedAt]);
  const caseId = `PHI-${new Date(startedAt).toISOString().slice(2, 10).replace(/-/g, '')}-${String(startedAt).slice(-4)}`;

  /* per-area state (tone, score, findings) shared by Key Findings, Risk by Area and the bottom panels */
  const areas = useMemo(() => areaStates(verdict, findings), [verdict, findings]);

  /* findings shown in each tab, and the tab-bar counts */
  const tabFindings = useMemo(() => {
    const ident = identityFindings(findings);
    const identIds = new Set(ident);
    return {
      sender: ident,
      urls: findings.filter((f) => f.dimension === 'url'),
      attachments: findings.filter((f) => f.dimension === 'attachment'),
      domain: findings.filter((f) => f.dimension === 'authentication' || f.dimension === 'infrastructure'),
      content: findings.filter((f) => f.dimension === 'content' && !identIds.has(f)),
      evidence: findings,
    } as Partial<Record<AnalysisTab, Finding[]>>;
  }, [findings]);

  /* threat type from dominant dimension */
  const threatType = (() => {
    const d = verdict.dimensions.filter(x => x.active).sort((a, b) => b.score - a.score)[0];
    if (!d) return 'Unknown';
    const m: Record<string, string> = { url: 'Credential Harvesting', attachment: 'Malware Delivery', content: 'Social Engineering', authentication: 'Sender Spoofing', infrastructure: 'Suspicious Infrastructure' };
    return m[d.dimension] ?? 'Phishing';
  })();



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
      {/* No background or border of its own: the cards sit directly on the page. The width follows the longest value
          (e.g. a long sender address) between 280 and 400 px; past that the value wraps instead of being cut off. */}
      <aside className="ph-db-sidebar-scroll hidden h-full w-fit min-w-[280px] max-w-[400px] shrink-0 overflow-y-auto lg:block">

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
                  {verdict.highRisk ? 'High-Risk Suspicious Email' : verdictTitle[verdict.label]}
                </h2>
                <p className="mt-0.5 text-sm text-fg/85">{verdict.headline}</p>
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
              <div className="rounded-full border border-white/10 bg-black/20 px-3.5 py-1.5 text-sm tabular-nums text-fg/90" title={verdict.confidence.notes.join(' ') || undefined}>
                Confidence: <span className="font-semibold capitalize">{verdict.confidence.level}</span> <span className="text-fg/70">({verdict.confidence.score}%)</span>
              </div>
              <div className={`rounded-full px-4 py-1.5 text-sm font-semibold tabular-nums ${verdictPillBg[verdict.label]}`}>
                Risk Score: {verdict.risk} / 100
              </div>
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
            <KeyFindings areas={areas} onOpen={openTab} />
          </div>

          {/* ── DETAILED ANALYSIS ── */}
          {/* Sized to the active tab: Overview needs room for the gauge + classification + 960px reasoning card; the detail
              tabs keep a readable 1180px column, so the box shrinks to that instead of leaving empty space on the right. */}
          <section ref={detail} className={`${activeTab === 'overview' ? 'max-w-[1620px]' : 'max-w-[1222px]'} scroll-mt-4 rounded-xl border border-line/70 bg-[#0c1529] px-5 pb-5 pt-4`}>
            <h3 className="text-lg font-bold text-fg">Detailed Analysis</h3>
            {/* Tab bar */}
            <div className="mb-5 mt-2 flex gap-2 overflow-x-auto border-b border-line/50" role="tablist">
              {ANALYSIS_TABS.map((t) => (
                <button key={t.id} type="button" role="tab" aria-selected={activeTab === t.id} onClick={() => setActiveTab(t.id)}
                  className={`-mb-px shrink-0 border-b-[3px] px-5 py-2.5 text-sm font-medium transition-colors ${
                    activeTab === t.id ? 'border-sky text-sky' : 'border-transparent text-fg/75 hover:text-fg'
                  }`}>
                  {t.label}
                  {(() => {
                    const fs = tabFindings[t.id];
                    const w = fs ? worst(fs) : null;
                    return fs && fs.length > 0 && w ? <span className={`ml-2 rounded-full px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ${t.id === 'evidence' ? countChip.info : countChip[w]}`} aria-label={`${fs.length} findings`}>{fs.length}</span> : null;
                  })()}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="ph-db-detail-content">
              {activeTab === 'overview' && (
                <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,600px)_minmax(0,960px)]">
                  <div className="space-y-5">
                    <div className="grid items-center gap-6 sm:grid-cols-[240px_minmax(0,1fr)]">
                      {/* Risk gauge */}
                      <div className="flex justify-center">
                        <SemiGauge score={verdict.risk} label={verdict.label} />
                      </div>

                      {/* Classification: label / value rows, values close to their labels */}
                      <dl className="grid grid-cols-[auto_1fr] items-center gap-x-8 gap-y-3.5 text-[15px]">
                        <dt className="text-fg/80">Classification</dt>
                        <dd><span className={`inline-block rounded-full px-3.5 py-1 text-sm font-semibold ${verdictSolidPill[verdict.label]}`}>{verdictWord[verdict.label]}{verdict.highRisk ? ' · high risk' : ''}</span></dd>
                        <dt className="text-fg/80">Confidence</dt>
                        <dd className="font-bold text-fg" title={verdict.confidence.notes.join(' ') || undefined}>{verdict.confidence.score}% <span className="text-xs font-normal capitalize text-muted">({verdict.confidence.level})</span></dd>
                        <dt className="text-fg/80">Threat Type</dt>
                        <dd className="font-bold text-fg">{threatType}</dd>
                        <dt className="text-fg/80">Coverage</dt>
                        <dd className="font-bold text-fg" title="Share of the planned checks that returned an answer">{Math.round(verdict.coverage * 100)}%</dd>
                      </dl>
                    </div>
                    <RiskByArea areas={areas} onOpen={openTab} />
                  </div>

                  <ReasoningCard verdict={verdict} />
                </div>
              )}

              {/* Detail tabs keep a readable width instead of stretching rows and cards across very wide screens. */}
              {activeTab !== 'overview' && (
                <div className="max-w-[1180px]">
                  {activeTab === 'sender' && <SenderTab slots={sender.slots} skipped={sender.plan.skipped} running={sender.running} findings={findings} />}
                  {activeTab === 'urls' && (
                    <div className="space-y-6">
                      <TabFindings id="ph-url-findings" title="Link findings" findings={tabFindings.urls ?? []} />
                      <UrlTab r={r} links={links} />
                    </div>
                  )}
                  {activeTab === 'attachments' && (
                    <div className="space-y-6">
                      <TabFindings id="ph-att-findings" title="Attachment findings" findings={tabFindings.attachments ?? []}
                        empty={attachmentCount ? 'No attachment findings so far. Hash lookups and the VirusTotal scan are listed below.' : undefined} />
                      {attachmentCount > 0 || att.results.length > 0 ? <AttachmentTab att={att} /> : <p className="text-sm text-muted">The message has no attachments.</p>}
                    </div>
                  )}
                  {activeTab === 'domain' && (
                    <div className="space-y-6">
                      <TabFindings id="ph-domain-findings" title="Authentication and infrastructure findings" findings={tabFindings.domain ?? []} />
                      {/* a little extra space between the findings and the IP intelligence / authentication cards */}
                      <div className="pt-4"><HeadersTab r={r} sender={sender} findings={findings} /></div>
                    </div>
                  )}
                  {activeTab === 'content' && (
                    <div className="space-y-6">
                      <ContentPanel a={r.content.analysis} subject={r.content.subject} fallback={r.browserFallback} />
                      <TabFindings id="ph-content-findings" title="Scored content findings" findings={tabFindings.content ?? []} />
                    </div>
                  )}
                  {activeTab === 'evidence' && <EvidenceTab findings={findings} checks={rows} />}
                </div>
              )}
            </div>
          </section>

          {/* ── ANALYST VERDICT (calibration) ── */}
          <AnalystLabel verdict={verdict} parse={r} findings={findings} checks={rows} />

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
        <div className="text-xs font-semibold text-fg [overflow-wrap:anywhere]">{value}</div>
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
