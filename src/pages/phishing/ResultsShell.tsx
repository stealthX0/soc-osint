import { useEffect, useMemo, useRef, useState } from 'react';
import { Spinner } from '../../components/ui';
import { computeVerdict } from '../../../shared/phishing/verdict';
import { dedupeFindings, sortFindings } from '../../../shared/phishing/findings';
import { buildReport } from '../../../shared/phishing/report';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput } from '../../../shared/phishing/types';
import { newHistoryId, saveToHistory } from '../../lib/phishingHistory';
import { useAttachmentStage, type AttachmentStage } from './AttachmentPanel';
import { allCheckRows, buildPipeline } from './model';
import { useLinkStage, useSenderStage, type LinkStage, type SenderStage } from './hooks';
import { InvestigationDashboard } from './InvestigationDashboard';

export interface ResultsShellProps {
  r: ParseStageResult;
  input: PhishingInput;
  /** Files attached in the form: inspected in the browser and looked up by hash as part of the analysis. */
  files?: File[];
  /** When the analyst pressed Analyse (epoch ms), for the analysis time. */
  startedAt: number;
  historyEnabled?: boolean;
  onHistorySaved?: () => void;
  /** Callback to reset to input form for a new analysis. */
  onNewAnalysis?: () => void;
  /** Called once when all lookup stages settle and the dashboard is about to render. */
  onReady?: () => void;
}

/**
 * Owns the stage hooks (sender, links, attachments). They all start as soon as the parse result arrives, and NOTHING is
 * scored or shown until every one of them has finished: while lookups are outstanding only a progress list is rendered,
 * so no provisional verdict, score or confidence is ever displayed. The finished report is the six-tab view below.
 */
export function ResultsShell({ r, input, files = [], startedAt, historyEnabled = false, onHistorySaved, onNewAnalysis, onReady }: ResultsShellProps) {
  const sender = useSenderStage(r);
  const att = useAttachmentStage(r, files);
  const links = useLinkStage(r, input);
  const ready = sender.settled && links.settled && att.settled;
  const firedReady = useRef(false);
  useEffect(() => {
    if (ready && !firedReady.current) { firedReady.current = true; onReady?.(); }
  }, [ready, onReady]);
  return ready
    ? <FinishedReport r={r} input={input} sender={sender} links={links} att={att} startedAt={startedAt} historyEnabled={historyEnabled} onHistorySaved={onHistorySaved} onNewAnalysis={onNewAnalysis} />
    : <RunningChecks sender={sender} links={links} att={att} linkCount={r.links.length} fileCount={files.length} />;
}

/** What the analyst sees while the lookups run: one line per stage, and no result. */
function RunningChecks({ sender, links, att, linkCount, fileCount }: { sender: SenderStage; links: LinkStage; att: AttachmentStage; linkCount: number; fileCount: number }) {
  const total = sender.plan.requests.length;
  const done = total - sender.running;
  const rows: { id: string; label: string; state: 'done' | 'running' | 'none'; note: string }[] = [
    { id: 'parse', label: 'Message parsed', state: 'done', note: 'headers, links, attachments and wording' },
    { id: 'sender', label: 'Sender intelligence', state: total === 0 ? 'none' : sender.settled ? 'done' : 'running', note: total === 0 ? 'nothing to look up' : `${done} of ${total} lookups finished` },
    { id: 'links', label: 'Links', state: linkCount === 0 ? 'none' : links.settled ? 'done' : 'running', note: linkCount === 0 ? 'no links found' : `${linkCount} link${linkCount === 1 ? '' : 's'} being checked` },
    { id: 'attachments', label: 'Attachments', state: att.settled ? 'done' : 'running', note: fileCount > 0 ? `${fileCount} file${fileCount === 1 ? '' : 's'}: hash lookups and VirusTotal active scan (can take a few minutes)` : 'hash lookups' },
  ];
  return (
    <div className="ph-results space-y-3 rounded-xl border border-line bg-bg2/60 p-4" role="status" aria-live="polite">
      <Spinner label="Running all checks. The verdict appears when every lookup has finished." />
      <ul className="space-y-1.5 text-sm">
        {rows.map((x) => (
          <li key={x.id} className="flex flex-wrap items-center gap-2">
            <span aria-hidden className="w-4 text-center text-muted">{x.state === 'done' ? '✓' : x.state === 'running' ? '…' : '·'}</span>
            <span className="font-medium">{x.label}</span>
            <span className="text-xs text-muted">{x.state === 'running' ? 'running: ' : ''}{x.note}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The single-page investigation dashboard. Mounted only after every stage has settled, so the verdict is computed once from complete evidence. */
export function FinishedReport({ r, input, sender, links, att, startedAt, historyEnabled, onHistorySaved, onNewAnalysis }: { r: ParseStageResult; input: PhishingInput; sender: SenderStage; links: LinkStage; att: AttachmentStage; startedAt: number; historyEnabled: boolean; onHistorySaved?: () => void; onNewAnalysis?: () => void }) {
  const findings = useMemo(() => sortFindings(dedupeFindings([...r.findings, ...sender.findings, ...(links.stage?.findings ?? []), ...att.findings])), [r.findings, sender.findings, links.stage, att.findings]);
  const rows = useMemo(() => allCheckRows({ parse: r.checks, skipped: sender.plan.skipped, slots: sender.slots, links: links.stage?.checks ?? [], attachments: att.checks }), [r.checks, sender.plan.skipped, sender.slots, links.stage, att.checks]);
  const verdict = useMemo(() => computeVerdict({ parse: r, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, status: c.status, result: c.result ?? null, detail: c.detail })) }), [r, findings, rows]);
  const pipeline = useMemo(() => buildPipeline(rows, { provisional: verdict.provisional, unavailable: verdict.label === 'analysis_unavailable' }), [rows, verdict]);
  const report = useMemo(() => buildReport({ verdict, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, stage: c.stage, status: c.status, result: c.result, detail: c.detail })), parse: r, urlStage: links.stage, generatedAt: Date.now() }), [verdict, findings, rows, r, links.stage]);

  // History: one entry per investigation, updated as lookups complete. Only the exported report is stored.
  const runId = useRef<string>('');
  if (!runId.current) runId.current = newHistoryId();
  useEffect(() => {
    if (!historyEnabled) return;
    saveToHistory(report, { id: runId.current });
    onHistorySaved?.();
  }, [report, historyEnabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Printing shows every collapsed section, then puts them back.
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const opened: HTMLDetailsElement[] = [];
    const before = () => root.current?.querySelectorAll('details').forEach((d) => { if (!d.open) { d.open = true; opened.push(d); } });
    const after = () => { opened.splice(0).forEach((d) => { d.open = false; }); };
    window.addEventListener('beforeprint', before);
    window.addEventListener('afterprint', after);
    return () => { window.removeEventListener('beforeprint', before); window.removeEventListener('afterprint', after); };
  }, []);

  return (
    <div ref={root}>
      <InvestigationDashboard
        r={r} input={input} verdict={verdict} findings={findings} rows={rows}
        pipeline={pipeline} report={report}
        sender={sender} links={links} att={att} startedAt={startedAt}
        onNewAnalysis={onNewAnalysis}
      />
    </div>
  );
}
