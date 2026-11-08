import { useMemo, useState } from 'react';
import { Badge, DataTable } from '../../components/ui';
import { dimensionLabel } from '../../../shared/phishing/findings';
import type { SenderCheckResponse } from '../../../shared/phishing/sender';
import type { AttachmentHashResponse } from '../../../shared/phishing/attachments';
import type { UrlStageResult } from '../../../shared/phishing/urlTriage';
import type { TimelineEvent } from '../../../shared/phishing/timeline';
import type { Dimension, Finding, Severity, Stage, TrustLevel } from '../../../shared/phishing/types';
import { FindingDetails, statusText, statusTone, trustLabel, type RowStatus } from './common';
import type { CheckRowX } from './model';

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const STAGE_ORDER: Stage[] = ['parse', 'headers', 'authentication', 'sender', 'urls', 'attachments', 'content', 'verdict'];
const STAGE_LABEL: Record<Stage, string> = { parse: 'Parse', headers: 'Headers', authentication: 'Authentication', sender: 'Sender intelligence', urls: 'Links', attachments: 'Attachments', content: 'Wording', verdict: 'Verdict' };
const STATUSES: RowStatus[] = ['complete', 'failed', 'skipped', 'running', 'not_applicable'];
const sel = 'rounded-md border border-line2 bg-bg2 px-2 py-1 text-xs text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal';
const RAW_CAP = 60_000;

export interface RawResults { sender: SenderCheckResponse[]; urls: UrlStageResult | null; attachments: AttachmentHashResponse[] }

function Filter({ id, label, value, onChange, options }: { id: string; label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <div className="flex items-center gap-1.5">
      <label htmlFor={id} className="text-[11px] uppercase tracking-wider text-muted">{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={sel}>
        <option value="all">all</option>
        {options.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
      </select>
    </div>
  );
}

const when = (iso: string) => `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
const pretty = (x: unknown): string => { const t = JSON.stringify(x, null, 2) ?? ''; return t.length > RAW_CAP ? `${t.slice(0, RAW_CAP)}\n… (truncated)` : t; };

/** All findings (filterable), the check status table (grouped by stage, filterable) and the timeline with the raw provider results. */
export function EvidenceTab({ findings, checks, timeline, raw }: { findings: Finding[]; checks: CheckRowX[]; timeline: TimelineEvent[]; raw: RawResults }) {
  const [sev, setSev] = useState('all');
  const [dim, setDim] = useState('all');
  const [src, setSrc] = useState('all');
  const [trust, setTrust] = useState('all');
  const [status, setStatus] = useState('all');

  const sources = useMemo(() => [...new Set(findings.map((f) => f.source))].sort(), [findings]);
  const shown = findings.filter((f) => (sev === 'all' || f.severity === sev) && (dim === 'all' || f.dimension === dim) && (src === 'all' || f.source === src) && (trust === 'all' || f.trust === trust));
  const rows = checks.filter((c) => status === 'all' || c.status === status);
  const counts = STATUSES.map((s) => [s, checks.filter((c) => c.status === s).length] as const).filter(([, n]) => n > 0);
  const hasRaw = raw.sender.length > 0 || !!raw.urls || raw.attachments.length > 0;

  return (
    <div className="space-y-8">
      <section aria-labelledby="ph-all-findings">
        <h3 id="ph-all-findings" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">All findings</h3>
        <div className="ph-noprint mb-3 flex flex-wrap gap-3">
          <Filter id="ph-f-sev" label="Severity" value={sev} onChange={setSev} options={SEVS.map((s) => [s, s])} />
          <Filter id="ph-f-dim" label="Dimension" value={dim} onChange={setDim} options={(Object.keys(dimensionLabel) as Dimension[]).map((d) => [d, dimensionLabel[d]])} />
          <Filter id="ph-f-src" label="Source" value={src} onChange={setSrc} options={sources.map((s) => [s, s])} />
          <Filter id="ph-f-trust" label="Trust" value={trust} onChange={setTrust} options={(Object.keys(trustLabel) as TrustLevel[]).map((t) => [t, trustLabel[t]])} />
        </div>
        <p role="status" className="mb-2 text-xs text-muted">Showing {shown.length} of {findings.length} finding{findings.length === 1 ? '' : 's'}. Open a finding to see its evidence lines.</p>
        {shown.length ? <ul className="space-y-2">{shown.map((f, i) => <FindingDetails key={`${f.id}${f.indicator?.value ?? ''}${i}`} f={f} />)}</ul> : <p className="text-sm text-muted">{findings.length ? 'No finding matches these filters.' : 'No findings so far. That only describes the checks that completed.'}</p>}
      </section>

      <section aria-labelledby="ph-check-status">
        <h3 id="ph-check-status" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Check status</h3>
        <div className="ph-noprint mb-2 flex flex-wrap items-center gap-3">
          <Filter id="ph-c-status" label="Status" value={status} onChange={setStatus} options={STATUSES.map((s) => [s, s.replace(/_/g, ' ')])} />
        </div>
        <p className="mb-2 flex flex-wrap gap-1.5 text-xs text-muted">{checks.length} checks: {counts.map(([s, n]) => <Badge key={s} tone={statusTone[s]}>{n} {statusText(s)}</Badge>)}</p>
        <p className="mb-3 text-xs text-muted">A failed, skipped or running check is not a negative result: the question it was meant to answer is still open.</p>
        {STAGE_ORDER.map((st) => {
          const mine = rows.filter((c) => c.stage === st);
          if (!mine.length) return null;
          return (
            <div key={st} className="mb-4 rounded-xl border border-line bg-panel/60">
              <h4 className="border-b border-line px-4 py-2 text-xs font-semibold uppercase tracking-wider text-muted">{STAGE_LABEL[st]} <span className="font-normal normal-case text-faint">({mine.length})</span></h4>
              <DataTable head={['Check', 'Status', 'Result']} rows={mine.map((c) => [
                <span key="l" className="text-sm">{c.label}</span>,
                <Badge key="s" tone={statusTone[c.status]}>{statusText(c.status)}</Badge>,
                <span key="r" className="text-sm">{c.status === 'running' ? '…' : c.result ?? '—'}{c.detail && <span className="mt-0.5 block text-xs text-muted">{c.detail}</span>}</span>,
              ])} />
            </div>
          );
        })}
        {!rows.length && <p className="text-sm text-muted">No check matches this status.</p>}
      </section>

      <section aria-labelledby="ph-timeline">
        <h3 id="ph-timeline" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Timeline</h3>
        {timeline.length ? (
          <ol className="space-y-2">
            {timeline.map((e, i) => (
              <li key={`${e.at}${e.label}${i}`} className="grid grid-cols-[max-content_1fr] gap-x-3 rounded-lg border border-line bg-bg2/60 p-2.5 text-sm">
                <time dateTime={e.at} className="font-mono text-xs text-muted">{when(e.at)}</time>
                <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge>{e.kind}</Badge><span className="font-medium">{e.label}</span></div><p className="text-xs text-muted">{e.detail}</p><p className="text-[11px] text-faint">{e.source}</p></div>
              </li>
            ))}
          </ol>
        ) : <p className="text-sm text-muted">No dated events yet. Only real timestamps are listed; none are estimated.</p>}

        <details className="mt-4 rounded-xl border border-line bg-panel/60">
          <summary className="cursor-pointer px-4 py-2.5 text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Raw provider results (read-only)</summary>
          <div className="space-y-3 border-t border-line p-4">
            {!hasRaw && <p className="text-sm text-muted">No provider results yet.</p>}
            {raw.sender.length > 0 && <div><h4 className="mb-1 text-xs font-semibold text-muted">Sender and infrastructure lookups ({raw.sender.length})</h4><pre className="max-h-96 overflow-auto rounded-lg border border-line bg-bg2 p-3 text-[11px] leading-snug">{pretty(raw.sender.map((s) => s.data))}</pre></div>}
            {raw.urls && <div><h4 className="mb-1 text-xs font-semibold text-muted">Link lookups ({Object.keys(raw.urls.lookups).length})</h4><pre className="max-h-96 overflow-auto rounded-lg border border-line bg-bg2 p-3 text-[11px] leading-snug">{pretty(raw.urls.lookups)}</pre></div>}
            {raw.attachments.length > 0 && <div><h4 className="mb-1 text-xs font-semibold text-muted">Attachment hash lookups ({raw.attachments.length})</h4><pre className="max-h-96 overflow-auto rounded-lg border border-line bg-bg2 p-3 text-[11px] leading-snug">{pretty(raw.attachments.map((a) => a.data))}</pre></div>}
          </div>
        </details>
      </section>
    </div>
  );
}
