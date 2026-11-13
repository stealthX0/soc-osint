/**
 * Pieces of the dashboard's verdict area: the Key Findings cards, the per-area risk breakdown and the Reasoning card.
 * Everything here is derived from the verdict engine's output; nothing is scored again.
 */
import { Badge, type Tone } from '../../components/ui';
import { Icon, type IconName } from '../../components/icons';
import type { Dimension, Finding, Severity } from '../../../shared/phishing/types';
import type { CheckRow, Verdict } from '../../../shared/phishing/verdict';
import { summarizeReasoning } from '../../../shared/phishing/summary';
import { bySeverity, sevTone } from './common';
import { glance } from './keyFindingGlance';

/** The analysis tabs. Exported so the dashboard and the Key Findings cards agree on ids. */
export type AnalysisTab = 'overview' | 'sender' | 'urls' | 'attachments' | 'domain' | 'content' | 'evidence';

export const AREA_LABEL: Record<Dimension, string> = {
  authentication: 'Authentication', infrastructure: 'Infrastructure', url: 'Links', attachment: 'Attachments', content: 'Content',
};
/** Where the detail for each area lives. */
export const AREA_TAB: Record<Dimension, AnalysisTab> = { authentication: 'domain', infrastructure: 'domain', url: 'urls', attachment: 'attachments', content: 'content' };
const AREA_ORDER: Dimension[] = ['authentication', 'url', 'attachment', 'infrastructure', 'content'];

export interface AreaState { dim: Dimension; active: boolean; score: number; tone: Tone; findings: Finding[] }

/** Tone of one area from its dimension score; an area with no data is neutral, never green. */
export function areaStates(verdict: Verdict, findings: Finding[]): AreaState[] {
  return AREA_ORDER.map((dim) => {
    const ds = verdict.dimensions.find((d) => d.dimension === dim);
    const mine = findings.filter((f) => f.dimension === dim).sort(bySeverity);
    const active = !!ds?.active;
    const score = ds?.score ?? 0;
    const tone: Tone = !active ? 'neutral' : score <= 0 ? 'good' : score < 30 ? 'info' : score < 60 ? 'warn' : 'bad';
    return { dim, active, score, tone, findings: mine };
  });
}

const glanceIcon: Record<Dimension, IconName> = { authentication: 'mail', infrastructure: 'globe', url: 'link', attachment: 'file', content: 'warn' };
const glanceColor: Record<Tone, string> = { bad: 'text-[#ef4444]', warn: 'text-[#facc15]', good: 'text-green', info: 'text-sky', accent: 'text-teal', neutral: 'text-muted' };

/**
 * One card per area that has findings or was assessed, strongest first: a big icon coloured by the area's risk, a short
 * plain-language headline and one summary line. The technical detail lives in the tab each card opens.
 */
export function KeyFindings({ areas, checks = [], onOpen }: { areas: AreaState[]; checks?: CheckRow[]; onOpen: (tab: AnalysisTab) => void }) {
  const shown = areas.filter((a) => a.active || a.findings.length > 0)
    .sort((a, b) => (b.active ? b.score : -1) - (a.active ? a.score : -1) || b.findings.length - a.findings.length);
  if (!shown.length) return <p className="text-sm text-muted">No area could be assessed. Paste the raw headers or the message body for a fuller analysis.</p>;
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[repeat(auto-fit,minmax(240px,1fr))]">
      {shown.map((a) => {
        const g = glance(a.dim, a.tone, a.active, a.findings, checks);
        const quiet = a.tone === 'neutral';
        return (
          <button key={a.dim} type="button" onClick={() => onOpen(AREA_TAB[a.dim])} title={`Open ${AREA_LABEL[a.dim]} details`}
            className={`flex items-start gap-4 rounded-xl border border-line/60 bg-[#0f1a31] px-5 py-4 text-left transition-colors hover:border-line2 hover:bg-[#13203b] focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky ${quiet ? 'opacity-75' : ''}`}>
            <span className={`mt-0.5 shrink-0 ${glanceColor[a.tone]}`}><Icon name={a.dim === 'content' && (quiet || a.tone === 'good') ? 'eye' : glanceIcon[a.dim]} size={30} strokeWidth={1.8} /></span>
            <span className="min-w-0 flex-1">
              <span className="block text-[15px] font-bold leading-snug text-fg">{g.headline}</span>
              <span className="mt-1 line-clamp-2 block text-sm leading-relaxed text-fg/75">{g.summary}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

const barFill: Record<Tone, string> = { bad: 'bg-[#ef4444]', warn: 'bg-[#facc15]', good: 'bg-green', info: 'bg-sky', accent: 'bg-teal', neutral: 'bg-line2' };

/** How much each area contributed: the dimension scores behind the overall risk score. */
export function RiskByArea({ areas, onOpen }: { areas: AreaState[]; onOpen: (tab: AnalysisTab) => void }) {
  return (
    <div className="rounded-xl border border-line/60 bg-[#0f1a31] p-4">
      <h4 className="text-base font-bold text-fg">Risk by Area</h4>
      <p className="mt-0.5 text-xs text-muted">Score of each area (0–100). The overall score weighs these together.</p>
      <ul className="mt-3 space-y-2.5">
        {areas.map((a) => (
          <li key={a.dim}>
            <button type="button" onClick={() => onOpen(AREA_TAB[a.dim])} className="grid w-full grid-cols-[110px_1fr_88px] items-center gap-3 text-left text-sm hover:text-sky focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky">
              <span className="text-fg/85">{AREA_LABEL[a.dim]}</span>
              <span className="h-2 overflow-hidden rounded-full bg-[#1b2844]" aria-hidden>
                <span className={`block h-full rounded-full ${barFill[a.tone]}`} style={{ width: `${a.active && a.score > 0 ? Math.max(2, Math.min(100, a.score)) : 0}%` }} />
              </span>
              <span className="text-right text-xs tabular-nums">
                {a.active ? <span className="font-semibold text-fg">{Math.round(a.score)}</span> : <span className="text-faint">not assessed</span>}
                {a.findings.length > 0 && <span className="ml-1 text-faint">· {a.findings.length}</span>}
              </span>
            </button>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] text-faint">The number after the score is how many findings that area raised. Click an area to open its details.</p>
    </div>
  );
}

const SEV_WORD: Record<Severity, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

/** Summary, the strongest evidence, caveat and conflicts, what is missing, and the recommended actions. */
export function ReasoningCard({ verdict }: { verdict: Verdict }) {
  const x = summarizeReasoning(verdict);
  const gaps = [...verdict.gaps].sort((a, b) => Number(b.critical) - Number(a.critical)).slice(0, 4);
  const showConflict = verdict.conflicts.length > 0 && verdict.label !== 'malicious';
  return (
    <div className="w-full rounded-xl border border-line/60 bg-[#0f1a31] p-5">
      <h4 className="text-base font-bold text-fg">Reasoning</h4>
      <p className="mt-1.5 text-[15px] leading-relaxed text-fg/90">{x.summary}</p>

      {x.points.length > 0 && (
        <div className="mt-4">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Key evidence</div>
          <ul className="divide-y divide-line/40 rounded-lg border border-line/50 bg-[#0b1426]">
            {x.points.map((pt) => (
              <li key={pt.text} className="flex items-center gap-3 px-3 py-2 text-sm">
                <span className="w-[62px] shrink-0"><Badge tone={sevTone[pt.severity]}>{SEV_WORD[pt.severity]}</Badge></span>
                <span className="min-w-0 flex-1 text-fg/90">{pt.text}</span>
                <span className="shrink-0 text-[11px] text-faint">{AREA_LABEL[pt.dimension]}</span>
              </li>
            ))}
          </ul>
          {verdict.reasons.length > x.points.length && <p className="mt-1 text-[11px] text-faint">+ {verdict.reasons.length - x.points.length} more in the Evidence tab.</p>}
        </div>
      )}

      {x.caveat && <p className="mt-3 text-xs leading-relaxed text-muted">{x.caveat}</p>}
      {showConflict && <p className="mt-2 rounded-md border border-amber/30 bg-amber/10 px-2.5 py-1.5 text-xs text-amber">Conflicting evidence: {verdict.conflicts[0]}</p>}

      {gaps.length > 0 && (
        <div className="mt-4 border-t border-line/50 pt-3">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">What is missing</div>
          <ul className="space-y-1 text-xs text-muted">
            {gaps.map((g) => (
              <li key={g.text} className="flex items-start gap-2">
                {g.critical ? <Badge tone="warn">important</Badge> : <span className="mt-[5px] size-1.5 shrink-0 rounded-full bg-faint" aria-hidden />}
                <span>{g.text.replace(/\.{2,}$/, '.')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {verdict.actions.length > 0 && (
        <div className="mt-4 border-t border-line/50 pt-3">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Recommended actions</div>
          <ol className="space-y-1.5 text-sm text-fg/85">
            {verdict.actions.slice(0, 5).map((a, i) => (
              <li key={a} className="flex items-start gap-2.5">
                <span className="mt-px grid size-5 shrink-0 place-items-center rounded-full bg-sky/15 text-[11px] font-semibold text-sky">{i + 1}</span>
                <span>{a}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
