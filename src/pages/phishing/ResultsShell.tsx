import { useEffect, useMemo, useRef, useState } from 'react';
import { Spinner } from '../../components/ui';
import { computeVerdict } from '../../../shared/phishing/verdict';
import { dedupeFindings, sortFindings } from '../../../shared/phishing/findings';
import { buildReport } from '../../../shared/phishing/report';
import { buildTimeline } from '../../../shared/phishing/timeline';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput } from '../../../shared/phishing/types';
import { newHistoryId, saveToHistory } from '../../lib/phishingHistory';
import { AttachmentTab, useAttachmentStage, type AttachmentStage } from './AttachmentPanel';
import { EvidenceTab } from './EvidenceTab';
import { HeadersTab } from './HeadersTab';
import { OverviewTab } from './OverviewTab';
import { SenderTab } from './SenderTab';
import { TabList, TabPanel, type TabDef } from './Tabs';
import { UrlTab } from './UrlTab';
import { allCheckRows, buildPipeline } from './model';
import { useLinkStage, useSenderStage, type LinkStage, type SenderStage } from './hooks';

export type TabId = 'overview' | 'headers' | 'sender' | 'urls' | 'attachments' | 'evidence';
export const TABS: TabDef<TabId>[] = [
  { id: 'overview', label: 'Overview', icon: 'eye' },
  { id: 'headers', label: 'Email Headers', icon: 'mail' },
  { id: 'sender', label: 'Sender Intelligence', icon: 'globe' },
  { id: 'urls', label: 'URL Analysis', icon: 'shield' },
  { id: 'attachments', label: 'Attachment Analysis', icon: 'file' },
  { id: 'evidence', label: 'Evidence & Timeline', icon: 'warn' },
];

export interface ResultsShellProps {
  r: ParseStageResult;
  input: PhishingInput;
  /** Files attached in the form: inspected in the browser and looked up by hash as part of the analysis. */
  files?: File[];
  /** When the analyst pressed Analyse (epoch ms), for the timeline. */
  startedAt: number;
  historyEnabled?: boolean;
  onHistorySaved?: () => void;
}

/**
 * Owns the stage hooks (sender, links, attachments). They all start as soon as the parse result arrives, and NOTHING is
 * scored or shown until every one of them has finished: while lookups are outstanding only a progress list is rendered,
 * so no provisional verdict, score or confidence is ever displayed. The finished report is the six-tab view below.
 */
export function ResultsShell({ r, input, files = [], startedAt, historyEnabled = false, onHistorySaved }: ResultsShellProps) {
  const sender = useSenderStage(r);
  const att = useAttachmentStage(r, files);
  const links = useLinkStage(r, input);
  const ready = sender.settled && links.settled && att.settled;
  return ready
    ? <FinishedReport r={r} input={input} sender={sender} links={links} att={att} startedAt={startedAt} historyEnabled={historyEnabled} onHistorySaved={onHistorySaved} />
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
    { id: 'attachments', label: 'Attachments', state: att.settled ? 'done' : 'running', note: fileCount > 0 ? `${fileCount} attached file${fileCount === 1 ? '' : 's'} and hash lookups` : 'hash lookups' },
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

/** The six-tab report. Mounted only after every stage has settled, so the verdict is computed once from complete evidence. */
export function FinishedReport({ r, input, sender, links, att, startedAt, historyEnabled, onHistorySaved }: { r: ParseStageResult; input: PhishingInput; sender: SenderStage; links: LinkStage; att: AttachmentStage; startedAt: number; historyEnabled: boolean; onHistorySaved?: () => void }) {
  const [tab, setTab] = useState<TabId>('overview');

  const findings = useMemo(() => sortFindings(dedupeFindings([...r.findings, ...sender.findings, ...(links.stage?.findings ?? []), ...att.findings])), [r.findings, sender.findings, links.stage, att.findings]);
  const rows = useMemo(() => allCheckRows({ parse: r.checks, skipped: sender.plan.skipped, slots: sender.slots, links: links.stage?.checks ?? [], attachments: att.checks }), [r.checks, sender.plan.skipped, sender.slots, links.stage, att.checks]);
  const verdict = useMemo(() => computeVerdict({ parse: r, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, status: c.status, result: c.result ?? null, detail: c.detail })) }), [r, findings, rows]);
  const pipeline = useMemo(() => buildPipeline(rows, { provisional: verdict.provisional, unavailable: verdict.label === 'analysis_unavailable' }), [rows, verdict]);
  const report = useMemo(() => buildReport({ verdict, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, stage: c.stage, status: c.status, result: c.result, detail: c.detail })), parse: r, generatedAt: Date.now() }), [verdict, findings, rows, r]);
  const timeline = useMemo(() => buildTimeline({
    parse: r, senderResults: sender.results, attachmentResults: att.results, findings,
    marks: { investigationStartedAt: startedAt, senderChecksFinishedAt: sender.finishedAt, linksInvestigatedAt: links.investigatedAt },
  }), [r, sender.results, sender.finishedAt, att.results, findings, startedAt, links.investigatedAt]);

  // Focus moves to the results heading after a run, so keyboard and screen-reader users land on the new report.
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);

  // History: one entry per investigation, updated as lookups complete. Only the exported report is stored.
  const runId = useRef<string>('');
  if (!runId.current) runId.current = newHistoryId();
  // This component only exists once every lookup has finished, so what is saved is always the complete result.
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
    <div ref={root} className="ph-results space-y-4">
      <h2 ref={heading} tabIndex={-1} id="ph-results-heading" className="text-lg font-semibold tracking-tight focus:outline-none">Investigation results</h2>
      <TabList tabs={TABS} value={tab} onChange={setTab} />
      <TabPanel id="overview" active={tab === 'overview'}><OverviewTab r={r} verdict={verdict} findings={findings} pipeline={pipeline} report={report} running={sender.running} onOpenEvidence={() => setTab('evidence')} /></TabPanel>
      <TabPanel id="headers" active={tab === 'headers'}><HeadersTab r={r} /></TabPanel>
      <TabPanel id="sender" active={tab === 'sender'}><SenderTab slots={sender.slots} skipped={sender.plan.skipped} running={sender.running} findings={findings} /></TabPanel>
      <TabPanel id="urls" active={tab === 'urls'}><UrlTab r={r} links={links} /></TabPanel>
      <TabPanel id="attachments" active={tab === 'attachments'}><AttachmentTab att={att} /></TabPanel>
      <TabPanel id="evidence" active={tab === 'evidence'}><EvidenceTab findings={findings} checks={rows} timeline={timeline} raw={{ sender: sender.results, urls: links.stage, attachments: att.results }} /></TabPanel>
    </div>
  );
}
