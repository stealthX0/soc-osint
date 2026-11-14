import { Card, Badge, DataTable, type Tone } from '../../components/ui';
import type { Report, SenderDomainResult } from '../../../shared/phishing/report';
import type { VerdictLabel } from '../../../shared/phishing/verdict';
import { sevTone, statusText, statusTone, trustLabel } from './common';

const senderTone: Record<SenderDomainResult, Tone> = { malicious: 'bad', suspicious: 'warn', no_detections: 'good', not_assessed: 'neutral', heuristics_only: 'neutral', lookup_failed: 'bad' };
const labelTone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };

/** Read-only view of an exported (defanged) report, used for stored history entries. */
export function ReportView({ report }: { report: Report }) {
  const v = report.verdict;
  const m = report.message;
  return (
    <div className="space-y-3 rounded-xl border border-line bg-bg2/40 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={labelTone[v.label]}><span className="font-semibold">{v.labelText}</span></Badge>
        <Badge>risk {v.risk}/100</Badge>
        <Badge>confidence {v.confidence.level}</Badge>
        <Badge>coverage {Math.round(v.coverage * 100)}%</Badge>
        {v.provisional && <Badge tone="info">provisional</Badge>}
        <span className="text-xs text-faint">saved report · read-only</span>
      </div>
      <p>{v.headline}</p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs">
        <dt className="text-muted">From</dt><dd className="break-all font-mono">{m.from ?? 'unknown'}</dd>
        <dt className="text-muted">Subject</dt><dd className="break-words">{m.subject ?? 'unknown'}</dd>
        <dt className="text-muted">Connecting IP</dt><dd className="break-all font-mono">{m.connectingIp ?? 'not established'}</dd>
        <dt className="text-muted">Links / attachments</dt><dd>{m.linkCount} / {m.attachmentCount}</dd>
      </dl>
      {report.reasons.length > 0 && <Card title="Why"><ul className="space-y-1.5">{report.reasons.map((r, i) => <li key={i}><Badge tone={sevTone[r.severity]}>{r.severity}</Badge> <span className="font-medium">{r.title}</span> <span className="text-muted">{r.detail}</span></li>)}</ul></Card>}
      {report.gaps.length > 0 && <Card title="What is missing"><ul className="list-disc space-y-1 pl-5">{report.gaps.map((g, i) => <li key={i}>{g.critical && <Badge tone="warn">important</Badge>} {g.text}</li>)}</ul></Card>}
      {report.actions.length > 0 && <Card title="Recommended actions"><ul className="list-disc space-y-1 pl-5">{report.actions.map((a, i) => <li key={i}>{a}</li>)}</ul></Card>}
      {report.senderDomain && (() => {
        const sd = report.senderDomain;
        return (
          <Card title="Sender domain (looked up like a link)">
            <div className="flex flex-wrap items-center gap-2">
              <code className="break-all font-mono text-xs">{sd.url}</code>
              <Badge tone={senderTone[sd.result]} title={sd.summary ?? undefined}>{sd.resultText}{sd.sourcesAttempted !== null ? ` · ${sd.sourcesChecked}/${sd.sourcesAttempted} sources` : ''}</Badge>
              {sd.openphish === 'listed' && <Badge tone="bad">OpenPhish: listed</Badge>}
              {sd.openphish === 'host_listed' && <Badge tone="warn">OpenPhish: host listed</Badge>}
            </div>
            {sd.summary && <p className="mt-1 text-xs text-muted">{sd.summary}</p>}
            {sd.domainAgeDays !== null && <p className="mt-1 text-xs text-muted">Domain age: {sd.domainAgeDays} days{sd.finalUrl ? ` · redirects to ${sd.finalUrl}` : ''}</p>}
            {sd.reasons.length > 0 && <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-muted">{sd.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>}
            {sd.signals.length > 0 && <ul className="mt-2 space-y-1">{sd.signals.map((x, i) => <li key={i}><Badge tone={sevTone[x.severity]}>{x.severity}</Badge> <span className="font-medium">{x.title}</span> <span className="text-xs text-faint">{x.source}</span></li>)}</ul>}
            {sd.error && <p className="mt-1 text-xs text-red">{sd.error}</p>}
          </Card>
        );
      })()}
      {report.indicators.length > 0 && <Card title={`Indicators (defanged, ${report.indicators.length})`}><ul className="space-y-1 font-mono text-xs">{report.indicators.map((i, k) => <li key={k} className="break-all"><span className="text-muted">{i.type}</span> {i.value}</li>)}</ul></Card>}
      <Card title={`Findings (${report.findings.length})`}>
        <ul className="space-y-2">{report.findings.map((f, i) => (
          <li key={i} className="rounded-lg border border-line p-2">
            <div className="flex flex-wrap items-center gap-2"><Badge tone={sevTone[f.severity]}>{f.severity}</Badge><span className="font-medium">{f.title}</span></div>
            <p className="mt-1 text-xs text-muted">{f.detail}</p>
            {f.evidence.map((e, k) => <code key={k} className="mt-1 block break-all rounded border border-line px-2 py-1 font-mono text-[11px]">{e}</code>)}
            <p className="mt-1 text-[11px] text-faint">{f.dimension} · {f.source} · {trustLabel[f.trust]} · {f.exactness}</p>
          </li>
        ))}</ul>
      </Card>
      <Card title={`Checks (${report.checkSummary.total}: ${report.checkSummary.failed} failed, ${report.checkSummary.skipped} skipped)`} pad={false}>
        <DataTable head={['Stage', 'Check', 'Status', 'Result']} rows={report.checks.map((c) => [c.stage, c.label, <Badge key="s" tone={statusTone[c.status]}>{statusText(c.status)}</Badge>, <span key="r" className="text-xs">{c.result ?? c.detail ?? '—'}</span>])} />
      </Card>
      <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{report.disclaimers.map((d) => <li key={d}>{d}</li>)}</ul>
    </div>
  );
}
