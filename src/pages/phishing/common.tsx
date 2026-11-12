import type { ReactNode } from 'react';
import { Card, Badge, type Tone } from '../../components/ui';
import { dimensionLabel } from '../../../shared/phishing/findings';
import type { CheckResult, Finding, Severity, TrustLevel } from '../../../shared/phishing/types';

export const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
export const trustLabel: Record<TrustLevel, string> = { receiver_reported: 'receiver-reported', unverified: 'unverified', independently_verified: 'verified by Spectrix', derived: 'derived' };
export const trustTone = (t: TrustLevel): Tone => (t === 'receiver_reported' ? 'accent' : t === 'independently_verified' ? 'good' : t === 'unverified' ? 'warn' : 'neutral');
export const resTone = (r: string | null): Tone => (r === null ? 'neutral' : r === 'pass' ? 'good' : ['fail', 'hardfail', 'permerror'].includes(r) ? 'bad' : 'warn');

/** A check row as shown on the page. "running" is a lookup that has not returned yet. */
export type RowStatus = CheckResult['status'] | 'running';
export const statusTone: Record<RowStatus, Tone> = { complete: 'good', failed: 'bad', skipped: 'warn', not_applicable: 'neutral', running: 'info' };
/** A symbol AND a word, so status never depends on colour alone. */
export const statusMark: Record<RowStatus, string> = { complete: '✓', failed: '✕', skipped: '–', not_applicable: '·', running: '…' };
export const statusText = (s: RowStatus): string => `${statusMark[s]} ${s.replace(/_/g, ' ')}`;

export const label = 'mb-1 block text-[11px] font-medium uppercase tracking-wider text-muted';
export const field = 'w-full rounded-lg border border-line2 bg-bg2 p-2.5 text-sm placeholder:text-faint focus:border-teal/60';

export function Section({ n, title, hint, children }: { n: number; title: string; hint?: string; children: ReactNode }) {
  return (
    <Card title={<span><span className="mr-2 text-teal">{n}.</span>{title}</span>}>
      {hint && <p className="mb-3 text-sm text-muted">{hint}</p>}
      <div className="space-y-3">{children}</div>
    </Card>
  );
}

/** Most severe first. */
export const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const bySeverity = (a: Finding, b: Finding) => SEV_RANK[a.severity] - SEV_RANK[b.severity];
/** Left accent in the severity colour (the badge carries the word, so colour is never the only signal). */
export const sevEdge: Record<Severity, string> = { critical: 'border-l-rose', high: 'border-l-rose', medium: 'border-l-amber', low: 'border-l-sky', info: 'border-l-line2' };

export function FindingRow({ f }: { f: Finding }) {
  return (
    <li className={`rounded-lg border border-l-[3px] border-line bg-bg2/60 p-3 ${sevEdge[f.severity]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={sevTone[f.severity]}>{f.severity}</Badge>
        <span className="font-medium">{f.title}</span>
      </div>
      <p className="mt-1.5 text-sm text-muted">{f.detail}</p>
      {f.evidence && f.evidence.length > 0 && (
        <div className="mt-2 space-y-1">{f.evidence.filter(Boolean).map((e, i) => <code key={i} className="block break-all rounded border border-line bg-bg2 px-2 py-1 font-mono text-[11px] text-fg/80">{e}</code>)}</div>
      )}
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
        <Badge>{dimensionLabel[f.dimension]}</Badge>
        <Badge tone={trustTone(f.trust)} title="How far this evidence can be believed">{trustLabel[f.trust]}</Badge>
        <Badge title="Does it concern this exact sender / URL / file?">{f.exactness}</Badge>
        <Badge>{f.source}</Badge>
      </div>
    </li>
  );
}

/** A finding that expands to its evidence lines (used where there are many). */
export function FindingDetails({ f }: { f: Finding }) {
  const ev = (f.evidence ?? []).filter(Boolean);
  return (
    <li className={`rounded-lg border border-l-[3px] border-line bg-bg2/60 ${sevEdge[f.severity]}`}>
      <details className="group">
        <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 p-3 text-sm">
          <Badge tone={sevTone[f.severity]}>{f.severity}</Badge>
          <span className="min-w-0 flex-1 font-medium">{f.title}</span>
          <span className="text-[11px] text-faint">{dimensionLabel[f.dimension]} · {f.source}{ev.length ? ` · ${ev.length} evidence line${ev.length === 1 ? '' : 's'}` : ''}</span>
        </summary>
        <div className="border-t border-line px-3 pb-3 pt-2">
          <p className="text-sm text-muted">{f.detail}</p>
          {ev.length > 0 && <div className="mt-2 space-y-1">{ev.map((e, i) => <code key={i} className="block break-all rounded border border-line bg-bg2 px-2 py-1 font-mono text-[11px] text-fg/80">{e}</code>)}</div>}
          <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
            <Badge>{dimensionLabel[f.dimension]}</Badge>
            <Badge tone={trustTone(f.trust)} title="How far this evidence can be believed">{trustLabel[f.trust]}</Badge>
            <Badge title="Does it concern this exact sender / URL / file?">{f.exactness}</Badge>
            <Badge>{f.source}</Badge>
            <Badge title="Stable rule id used by the verdict engine">{f.id}</Badge>
          </div>
        </div>
      </details>
    </li>
  );
}


/**
 * The findings that belong to one analysis tab, most severe first, in a two-column grid on wide screens.
 * Renders `empty` (or nothing) when there are none.
 */
export function TabFindings({ id, title, findings, empty }: { id: string; title: string; findings: Finding[]; empty?: ReactNode }) {
  if (!findings.length && !empty) return null;
  const sorted = [...findings].sort(bySeverity);
  return (
    <section aria-labelledby={id}>
      <h3 id={id} className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">
        {title}{findings.length > 0 && <span className="ml-1.5 font-normal normal-case tracking-normal text-faint">({findings.length})</span>}
      </h3>
      {sorted.length ? <ul className="gap-3 lg:columns-2 [&>*]:mb-3 [&>*]:break-inside-avoid">{sorted.map((f, i) => <FindingRow key={`${f.id}${f.indicator?.value ?? ''}${i}`} f={f} />)}</ul> : <p className="text-sm text-muted">{empty}</p>}
    </section>
  );
}
