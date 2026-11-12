import { Card, Badge, Copyable, DataTable, type Tone } from '../../components/ui';
import { Icon } from '../../components/icons';
import { VERDICT_TEXT, labelTextOf, type Verdict, type VerdictLabel } from '../../../shared/phishing/verdict';
import { dimensionLabel } from '../../../shared/phishing/findings';
import type { Severity } from '../../../shared/phishing/types';

const tone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };
const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const ring: Record<VerdictLabel, string> = { malicious: 'border-red/40 bg-red/5', suspicious: 'border-amber/40 bg-amber/5', likely_legitimate: 'border-green/40 bg-green/5', inconclusive: 'border-sky/30 bg-sky/5', analysis_unavailable: 'border-line bg-bg2/60' };
const riskBar = (r: number) => (r >= 60 ? 'bg-red' : r >= 30 ? 'bg-amber' : 'bg-green');

/** The investigation outcome: label, plain-language reasons, what is missing, what to do, and the full audit trail. */
export function VerdictCard({ v }: { v: Verdict }) {
  const meta = VERDICT_TEXT[v.label];
  const crit = v.gaps.filter((g) => g.critical);
  const minor = v.gaps.filter((g) => !g.critical);
  return (
    <div className={`rounded-xl border p-4 ${ring[v.label]}`} role="region" aria-label="Investigation verdict">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={tone[v.label]}><span className="text-sm font-semibold tracking-wide">{labelTextOf(v)}</span></Badge>
            <Badge tone={v.confidence.level === 'high' ? 'good' : v.confidence.level === 'medium' ? 'warn' : 'neutral'} title={v.confidence.notes.join(' ') || 'How much the evidence supports this outcome'}>confidence: {v.confidence.level} ({v.confidence.score})</Badge>
            <Badge title="Share of the expected checks that completed">coverage {Math.round(v.coverage * 100)}%</Badge>
            {v.provisional && <Badge tone="info">provisional: lookups still running</Badge>}
          </div>
          <p className="mt-2 text-sm">{v.headline}</p>
          {v.rule && <p className="mt-1 text-xs text-muted">Decided by a verdict rule on direct evidence, not by the score.</p>}
        </div>
        <div className="w-32 shrink-0 text-right">
          <div className="text-[11px] uppercase tracking-wider text-muted">risk score</div>
          <div className="text-2xl font-semibold tabular-nums">{v.risk}<span className="text-sm text-muted">/100</span></div>
          <div className="mt-1 h-1.5 overflow-hidden rounded bg-line" aria-hidden><div className={`h-full ${riskBar(v.risk)}`} style={{ width: `${v.risk}%` }} /></div>
        </div>
      </div>

      {v.reasons.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-muted">Why</h3>
          <ul className="space-y-1.5">{v.reasons.map((r) => (
            <li key={r.title + r.findingIds.join()} className="flex flex-wrap items-baseline gap-2 text-sm">
              <Badge tone={sevTone[r.severity]}>{r.severity}</Badge><span className="font-medium">{r.title}</span><span className="text-xs text-faint">{dimensionLabel[r.dimension]} · {r.points} pts</span>
              <span className="basis-full text-xs text-muted">{r.detail}</span>
            </li>
          ))}</ul>
        </div>
      )}

      {v.mitigating.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-muted">Supporting evidence</h3>
          <ul className="list-disc space-y-0.5 pl-5 text-sm text-muted">{v.mitigating.map((m) => <li key={m}>{m}</li>)}</ul>
          <p className="mt-1 text-xs text-faint">This never lowers the risk score: an authenticated sender can still send phishing.</p>
        </div>
      )}

      {v.conflicts.length > 0 && (
        <div className="mt-4"><h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-amber">Conflicting evidence</h3><ul className="list-disc space-y-0.5 pl-5 text-sm text-amber">{v.conflicts.map((c) => <li key={c}>{c}</li>)}</ul></div>
      )}

      {v.gaps.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-muted">What is missing</h3>
          <ul className="space-y-1 text-sm">
            {crit.map((g) => <li key={g.text} className="flex gap-2 text-amber"><Icon name="warn" size={14} className="mt-0.5 shrink-0" />{g.text}</li>)}
            {minor.slice(0, 6).map((g) => <li key={g.text} className="pl-6 text-muted">{g.text}</li>)}
            {minor.length > 6 && <li className="pl-6 text-faint">and {minor.length - 6} more (see Check status)</li>}
          </ul>
        </div>
      )}

      <div className="mt-4">
        <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-muted">What to do</h3>
        <ul className="list-disc space-y-0.5 pl-5 text-sm">{v.actions.map((a) => <li key={a}>{a}</li>)}</ul>
      </div>

      {v.indicators.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-muted">Indicators to block or hunt for</h3>
          <ul className="space-y-1">{v.indicators.slice(0, 10).map((i) => <li key={`${i.type}:${i.value}`} className="flex flex-wrap items-center gap-2 text-sm"><Badge>{i.type}</Badge><Copyable value={i.value} ioc /><span className="text-xs text-muted">{i.reason}</span></li>)}</ul>
        </div>
      )}

      <details className="mt-4 rounded-lg border border-line bg-bg2/40 p-3">
        <summary className="cursor-pointer text-sm text-muted hover:text-fg">How was this decided?</summary>
        <div className="mt-3 space-y-4">
          <p className="text-xs text-muted">Every finding earns base points from its type, scaled by how exact, reliable and trustworthy it is. Findings about the same fact are grouped so they cannot be counted twice. The weights and thresholds are initial design values that have not been validated against labelled mail: use the score as a guide, and the rules and reasons for the decision.</p>
          <DataTable head={['Dimension', 'Weight', 'Points', 'Score', 'Coverage']} rows={v.dimensions.map((d) => [dimensionLabel[d.dimension], d.active ? `${Math.round(d.effectiveWeight * 100)}%` : <span key="n" className="text-faint">not applicable</span>, d.points, d.score, `${Math.round(d.coverage * 100)}%`])} />
          <DataTable head={['Finding', 'Base', 'Exact', 'Source', 'Trust', 'Context', 'Counted']} rows={v.contributions.filter((c) => c.base > 0).slice(0, 14).map((c) => [<span key="f" title={c.findingId}>{c.title}</span>, c.base, c.multipliers.exactness, c.multipliers.reliability, c.multipliers.trust, c.multipliers.context, <strong key="c">{Math.round(c.counted * 10) / 10}</strong>])} />
          {v.unmapped.length > 0 && <p className="text-xs text-amber">Scored by severity only (no specific rule): {v.unmapped.join(', ')}</p>}
        </div>
      </details>
      <p className="mt-3 text-[11px] text-faint">{meta.short} Decision support for an analyst, not a guarantee in either direction.</p>
    </div>
  );
}
