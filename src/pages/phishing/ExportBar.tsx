import { useEffect, useRef, useState } from 'react';
import { Icon } from '../../components/icons';
import { renderJson, renderMarkdown, renderTicketText, reportFilename, type Report } from '../../../shared/phishing/report';
import { copyText, downloadText, printReport } from './exportActions';

const btn = 'inline-flex h-9 items-center gap-2 rounded-lg border border-line2 px-3 text-sm text-fg hover:border-teal/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal';

/** Ticket text, Markdown, JSON and print. Everything is rendered from one defanged report object. */
export function ExportBar({ report }: { report: Report }) {
  const [msg, setMsg] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const say = (m: string) => { setMsg(m); window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setMsg(null), 2500); };
  return (
    <div className="ph-noprint flex flex-wrap items-center gap-2" role="group" aria-label="Export report">
      <button type="button" className={btn} onClick={async () => say((await copyText(renderTicketText(report))) ? 'Ticket text copied.' : 'Could not copy: select and copy manually.')}><Icon name="copy" size={14} /> Copy ticket text</button>
      <button type="button" className={btn} onClick={() => downloadText(reportFilename(report, 'md'), renderMarkdown(report), 'text/markdown')}><Icon name="file" size={14} /> Download Markdown</button>
      <button type="button" className={btn} onClick={() => downloadText(reportFilename(report, 'json'), renderJson(report), 'application/json')}><Icon name="file" size={14} /> Download JSON</button>
      <button type="button" className={btn} onClick={printReport}><Icon name="file" size={14} /> Print / save as PDF</button>
      <span role="status" aria-live="polite" className="text-xs text-muted">{msg}</span>
    </div>
  );
}
