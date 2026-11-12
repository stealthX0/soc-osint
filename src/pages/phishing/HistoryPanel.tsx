import { useEffect, useState } from 'react';
import { dmyTimeUtc } from '../../../shared/dates';
import { Badge, Empty, type Tone } from '../../components/ui';
import { clearHistory, deleteFromHistory, loadHistory, summarizeEntry, type HistoryEntry } from '../../lib/phishingHistory';
import { renderJson, renderMarkdown, renderTicketText, reportFilename } from '../../../shared/phishing/report';
import type { VerdictLabel } from '../../../shared/phishing/verdict';
import { copyText, downloadText } from './exportActions';
import { ReportView } from './ReportView';

const labelTone: Record<VerdictLabel, Tone> = { malicious: 'bad', suspicious: 'warn', likely_legitimate: 'good', inconclusive: 'info', analysis_unavailable: 'neutral' };
const small = 'rounded-md border border-line2 px-2 py-1 text-xs text-muted hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal';

/** Collapsible list of the investigations saved on this device. The toggle and its explanation live here too. */
export function HistoryPanel({ enabled, setEnabled, version, onChange }: { enabled: boolean; setEnabled: (v: boolean) => void; version: number; onChange?: () => void }) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  useEffect(() => setEntries(loadHistory()), [version]);
  const refresh = (next: HistoryEntry[]) => { setEntries(next); onChange?.(); };

  return (
    <details className="ph-noprint rounded-xl border border-line bg-panel/60">
      <summary className="cursor-pointer list-none px-4 py-2.5 text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">
        Investigation history <span className="text-xs font-normal text-muted">({entries.length} saved on this device)</span>
      </summary>
      <div className="space-y-3 border-t border-line p-4">
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="mt-1 accent-teal" />
          <span>Save investigations on this device
            <span className="block text-xs text-faint">Stores only the exported report (verdict, findings, defanged indicators) in this browser, for the last 20 investigations. The pasted headers, body and attachments are never stored, and nothing is sent anywhere.</span>
          </span>
        </label>
        {entries.length === 0 ? <Empty>No saved investigations yet.</Empty> : (
          <ul className="space-y-2">
            {entries.map((e) => {
              const row = summarizeEntry(e);
              return (
                <li key={e.id} className="rounded-lg border border-line bg-bg2/60 p-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-mono text-xs text-muted">{dmyTimeUtc(row.date)}</span>
                    <Badge tone={labelTone[row.label]}>{row.labelText}</Badge>
                    <Badge>risk {row.risk}/100</Badge>
                    <span className="min-w-0 flex-1 truncate" title={row.subject}>{row.subject}</span>
                    <span className="font-mono text-xs text-muted">{row.fromDomain}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <button type="button" className={small} aria-expanded={open === e.id} onClick={() => setOpen(open === e.id ? null : e.id)}>{open === e.id ? 'Hide report' : 'View report'}</button>
                    <button type="button" className={small} onClick={async () => setNote((await copyText(renderTicketText(e.report))) ? 'Ticket text copied.' : 'Could not copy.')}>Copy ticket text</button>
                    <button type="button" className={small} onClick={() => downloadText(reportFilename(e.report, 'md'), renderMarkdown(e.report), 'text/markdown')}>Download Markdown</button>
                    <button type="button" className={small} onClick={() => downloadText(reportFilename(e.report, 'json'), renderJson(e.report), 'application/json')}>Download JSON</button>
                    <button type="button" className={small} onClick={() => { refresh(deleteFromHistory(e.id)); if (open === e.id) setOpen(null); }}>Delete</button>
                  </div>
                  {open === e.id && <div className="mt-3"><ReportView report={e.report} /></div>}
                </li>
              );
            })}
          </ul>
        )}
        <div className="flex items-center gap-3">
          {entries.length > 0 && <button type="button" className={small} onClick={() => { refresh(clearHistory()); setOpen(null); }}>Clear all</button>}
          <span role="status" aria-live="polite" className="text-xs text-muted">{note}</span>
        </div>
      </div>
    </details>
  );
}
