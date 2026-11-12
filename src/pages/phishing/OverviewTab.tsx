import { Card, Badge, KV, Copyable, type Tone } from '../../components/ui';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { Report } from '../../../shared/phishing/report';
import type { Verdict } from '../../../shared/phishing/verdict';
import type { Finding, Severity } from '../../../shared/phishing/types';
import { VerdictCard } from './VerdictCard';
import { ContentPanel } from './ContentPanel';
import { ExportBar } from './ExportBar';
import { FindingRow, sevTone, trustTone } from './common';
import type { ChipStatus, PipelineChip } from './model';

const chipTone: Record<ChipStatus, Tone> = { complete: 'good', running: 'info', 'not run': 'neutral', failed: 'bad' };
const chipMark: Record<ChipStatus, string> = { complete: '✓', running: '…', 'not run': '·', failed: '✕' };
const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const TOP = 5;

export interface OverviewProps {
  r: ParseStageResult;
  verdict: Verdict;
  findings: Finding[];
  pipeline: PipelineChip[];
  report: Report;
  running: number;
  onOpenEvidence?: () => void;
}

/** The first screen: the outcome, how far the pipeline got, the key facts, the top findings, the indicators and the export. */
export function OverviewTab({ r, verdict, findings, pipeline, report, running, onOpenEvidence }: OverviewProps) {
  const fx = r.forensics;
  const counts = findings.reduce<Record<string, number>>((a, f) => ({ ...a, [f.severity]: (a[f.severity] ?? 0) + 1 }), {});
  const from = fx?.summary.from ?? r.indicators.emails.find((e) => e.roles.includes('from'))?.address ?? null;
  const attachmentCount = r.attachments.filter((a) => !a.inline).length;
  const top = findings.slice(0, TOP);

  return (
    <div className="space-y-4">
      <VerdictCard v={verdict} />
      <p className="text-xs text-faint">Preview: the scoring weights are initial values still being calibrated. Treat the verdict as decision support and read the reasons and what is missing.</p>

      <section aria-labelledby="ph-pipeline">
        <h3 id="ph-pipeline" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Pipeline</h3>
        <ol className="flex flex-wrap gap-2" aria-label="Investigation pipeline">
          {pipeline.map((c) => (
            <li key={c.id} className="rounded-lg border border-line bg-bg2/60 px-2.5 py-1.5 text-xs">
              <span className="font-medium">{c.label}</span>{' '}
              <Badge tone={chipTone[c.status]}>{chipMark[c.status]} {c.status}</Badge>
              {(c.failed > 0 || c.skipped > 0) && <span className="ml-1.5 text-muted">{[c.failed ? `${c.failed} failed` : '', c.skipped ? `${c.skipped} skipped` : ''].filter(Boolean).join(' · ')}</span>}
            </li>
          ))}
        </ol>
      </section>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        {SEVS.filter((s) => counts[s]).map((s) => <Badge key={s} tone={sevTone[s]}>{counts[s]} {s}</Badge>)}
        {!findings.length && running === 0 && <Badge tone="info">no findings so far</Badge>}
        {running > 0 && <Badge tone="info">{running} lookup(s) running</Badge>}
      </div>
      {r.limits.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{r.limits.map((l) => <li key={l}>{l}</li>)}</ul>}

      <section aria-labelledby="ph-facts">
        <h3 id="ph-facts" className="sr-only">Key facts</h3>
        <Card title="Key facts">
          <KV rows={[
            ['From', from], ['Subject', r.content.subject ?? fx?.summary.subject ?? null], ['Connecting IP', fx?.trust.connectingIp ? <Copyable key="ip" value={fx.trust.connectingIp} ioc /> : null],
            ['Links', String(r.links.length)], ['Attachments', String(attachmentCount)],
          ]} />
        </Card>
      </section>

      <section aria-labelledby="ph-top">
        <div className="mb-2 flex items-center justify-between gap-3">
          <h3 id="ph-top" className="text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Top findings</h3>
          {findings.length > TOP && onOpenEvidence && <button type="button" onClick={onOpenEvidence} className="ph-noprint text-xs text-teal hover:underline">All {findings.length} findings</button>}
        </div>
        {top.length ? <ul className="space-y-2">{top.map((f, i) => <FindingRow key={`${f.id}${i}`} f={f} />)}</ul> : <p className="text-sm text-muted">No findings so far. That only describes the checks that completed; see the pipeline above and the check status table.</p>}
      </section>

      <details className="rounded-xl border border-line bg-panel/60">
        <summary className="cursor-pointer px-4 py-2.5 text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Message wording analysis</summary>
        <div className="border-t border-line p-4"><ContentPanel a={r.content.analysis} subject={r.content.subject} fallback={r.browserFallback} /></div>
      </details>

      <section aria-labelledby="ph-ind">
        <h3 id="ph-ind" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Indicators</h3>
        <div className="grid gap-4 md:grid-cols-2">
          <Card title="IP addresses">{r.indicators.ips.length ? <ul className="space-y-2 text-sm">{r.indicators.ips.map((i) => <li key={i.ip}><Copyable value={i.ip} ioc /> <Badge tone={trustTone(i.trust)}>{i.role.replace(/_/g, ' ')}</Badge>{i.note && <p className="text-xs text-muted">{i.note}</p>}</li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="Domains">{r.indicators.domains.length ? <ul className="space-y-2 text-sm">{r.indicators.domains.map((d) => <li key={d.domain}><Copyable value={d.domain} ioc /> <span className="ml-1">{d.roles.map((x) => <Badge key={x}>{x.replace(/_/g, ' ')}</Badge>)}</span></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="E-mail addresses">{r.indicators.emails.length ? <ul className="space-y-2 text-sm">{r.indicators.emails.map((e) => <li key={e.address}><Copyable value={e.address} ioc /> <span className="ml-1">{e.roles.map((x) => <Badge key={x}>{x.replace(/_/g, ' ')}</Badge>)}</span></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="URLs">{r.indicators.urls.length ? <ul className="space-y-2 text-sm">{r.indicators.urls.map((u) => <li key={u}><Copyable value={u} ioc /></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
        </div>
      </section>

      <section aria-labelledby="ph-export">
        <h3 id="ph-export" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Export report</h3>
        <ExportBar report={report} />
        <p className="ph-noprint mt-2 text-xs text-faint">Indicators in the export are defanged. The export contains no message body, no full headers and no attachment content.</p>
      </section>
    </div>
  );
}
