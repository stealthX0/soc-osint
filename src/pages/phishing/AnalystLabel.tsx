import { useMemo, useState } from 'react';
import { ANALYST_LABELS, toCalibrationRecord, type AnalystLabel as Label } from '../../../shared/phishing/calibrationRecord';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { CheckRow, Verdict } from '../../../shared/phishing/verdict';
import type { Finding } from '../../../shared/phishing/types';
import { clearLabels, labelsFile, loadLabels, removeLabel, saveLabel } from '../../lib/phishingLabels';
import { downloadText } from './exportActions';

const btn = 'inline-flex h-8 items-center rounded-lg border px-3 text-sm transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal';

/**
 * "Your verdict": the analyst's own call on this e-mail, saved in this browser to calibrate the engine later. Only finding
 * ids, severities and check statuses are kept (no content, addresses or URLs); the set downloads for
 * `npm run calibrate:labels`.
 */
export function AnalystLabel({ verdict, parse, findings, checks }: { verdict: Verdict; parse: ParseStageResult; findings: Finding[]; checks: CheckRow[] }) {
  const [chosen, setChosen] = useState<{ label: Label; id: string } | null>(null);
  const [count, setCount] = useState(() => loadLabels().length);
  const [confirmClear, setConfirmClear] = useState(false);
  const disabled = verdict.provisional || verdict.label === 'analysis_unavailable';
  const agrees = useMemo(() => {
    if (!chosen || chosen.label === 'unsure') return null;
    const ok = { phishing: ['malicious', 'suspicious'], bec: ['suspicious', 'malicious'], legitimate: ['likely_legitimate', 'inconclusive'] }[chosen.label];
    return ok.includes(verdict.label);
  }, [chosen, verdict.label]);

  const pick = (label: Label) => {
    if (chosen?.label === label) { setCount(removeLabel(chosen.id).length); setChosen(null); return; }
    const rec = toCalibrationRecord({ analyst: label, verdict, parse, findings, checks });
    if (chosen) removeLabel(chosen.id);
    const list = saveLabel(rec);
    setChosen({ label, id: rec.id });
    setCount(list.length);
  };
  const download = () => downloadText(`spectrix-labelled-set-${new Date().toISOString().slice(0, 10)}.json`, labelsFile(loadLabels()), 'application/json');

  return (
    <div className="ph-noprint flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-line bg-panel/60 px-4 py-2.5" role="group" aria-label="Your verdict">
      <span className="text-sm font-semibold text-fg" title="Your own call on this e-mail. Saved only in this browser, to calibrate the verdict engine.">Your verdict</span>
      {ANALYST_LABELS.map((l) => (
        <button key={l.id} type="button" disabled={disabled} title={l.hint} aria-pressed={chosen?.label === l.id} onClick={() => pick(l.id)}
          className={`${btn} ${chosen?.label === l.id ? 'border-teal bg-teal/15 text-teal' : 'border-line2 text-fg hover:border-teal/50'} disabled:cursor-not-allowed disabled:opacity-50`}>
          {l.text}
        </button>
      ))}
      <span role="status" aria-live="polite" className="text-xs text-muted">
        {disabled ? 'Available when all lookups have finished.'
          : chosen ? `Saved${agrees === false ? ' — differs from the engine, which helps calibration most' : ''}. Click again to undo.` : ''}
      </span>
      <span className="ml-auto flex items-center gap-2 text-xs text-muted">
        {count} labelled in this browser
        <button type="button" className={`${btn} h-7 border-line2 text-xs text-fg hover:border-teal/50 disabled:opacity-50`} disabled={!count} onClick={download}>Download labelled set</button>
        {count > 0 && (confirmClear
          ? <><button type="button" className={`${btn} h-7 border-rose/50 text-xs text-rose`} onClick={() => { clearLabels(); setCount(0); setChosen(null); setConfirmClear(false); }}>Delete all {count}</button>
              <button type="button" className={`${btn} h-7 border-line2 text-xs`} onClick={() => setConfirmClear(false)}>Keep</button></>
          : <button type="button" className={`${btn} h-7 border-line2 text-xs text-muted hover:text-fg`} onClick={() => setConfirmClear(true)}>Clear</button>)}
      </span>
    </div>
  );
}
