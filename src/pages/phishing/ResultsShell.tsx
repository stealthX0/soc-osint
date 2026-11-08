import { useEffect, useMemo, useRef, useState } from 'react';
import { computeVerdict } from '../../../shared/phishing/verdict';
import { dedupeFindings, sortFindings } from '../../../shared/phishing/findings';
import { buildReport } from '../../../shared/phishing/report';
import { buildTimeline } from '../../../shared/phishing/timeline';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput } from '../../../shared/phishing/types';
import { newHistoryId, saveToHistory } from '../../lib/phishingHistory';
import { AttachmentTab, useAttachmentStage } from './AttachmentPanel';
import { EvidenceTab } from './EvidenceTab';
import { HeadersTab } from './HeadersTab';
import { OverviewTab } from './OverviewTab';
import { SenderTab } from './SenderTab';
import { TabList, TabPanel, type TabDef } from './Tabs';
import { UrlTab } from './UrlTab';
import { allCheckRows, buildPipeline } from './model';
import { useLinkStage, useSenderStage } from './hooks';

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
  emailRep: boolean;
  autoLinks?: boolean;
  /** When the analyst pressed Analyse (epoch ms), for the timeline. */
  startedAt: number;
  historyEnabled?: boolean;
  onHistorySaved?: () => void;
}

/** The six-tab report. Owns the stage hooks (sender, links, attachments) and everything derived from them. */
export function ResultsShell({ r, input, emailRep, autoLinks = false, startedAt, historyEnabled = false, onHistorySaved }: ResultsShellProps) {
  const [tab, setTab] = useState<TabId>('overview');
  const sender = useSenderStage(r, emailRep);
  const att = useAttachmentStage(r);
  const links = useLinkStage(r, input, autoLinks);

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
  // Saved once the sender lookups have settled (or there were none), so a half-finished run is never stored as the result.
  const settled = sender.plan.requests.length === 0 || sender.finishedAt !== null;
  useEffect(() => {
    if (!historyEnabled || !settled || sender.running > 0) return;
    saveToHistory(report, { id: runId.current });
    onHistorySaved?.();
  }, [report, historyEnabled, settled, sender.running]); // eslint-disable-line react-hooks/exhaustive-deps

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
