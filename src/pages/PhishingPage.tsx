import { useEffect, useState } from 'react';
import { PageHeader, Badge, Empty, Spinner, ErrorBox } from '../components/ui';
import { useAction } from '../lib/hooks';
import { api } from '../lib/api';
import { useStored } from '../lib/storage';
import { HISTORY_ENABLED_KEY } from '../lib/phishingHistory';
import type { ParseStageResult } from '../../shared/phishing/parse';
import type { PhishingInput } from '../../shared/phishing/types';
import { HistoryPanel } from './phishing/HistoryPanel';
import { InputForm } from './phishing/InputForm';
import { ResultsShell } from './phishing/ResultsShell';
import { EMPTY_FORM, buildInput, type FormFields } from './phishing/formHelpers';
import '../styles/phishing.css';

export default function PhishingPage() {
  const [f, setF] = useState<FormFields>(EMPTY_FORM);
  const [files, setFiles] = useState<File[]>([]);
  const [historyOn, setHistoryOn] = useStored<boolean>(HISTORY_ENABLED_KEY, true);
  const [historyVersion, setHistoryVersion] = useState(0);
  const [submitted, setSubmitted] = useState<{ id: number; input: PhishingInput; files: File[]; at: number; history: boolean } | null>(null);
  const act = useAction<ParseStageResult, PhishingInput>(async (input, signal) => (await api<ParseStageResult>('/api/phishing/parse', { method: 'POST', body: input, signal })).data);

  const submit = () => {
    const input = buildInput(f);
    setSubmitted((p) => ({ id: (p?.id ?? 0) + 1, input, files: [...files], at: Date.now(), history: historyOn }));
    return act.run(input);
  };

  /** Whether the analysis has been triggered (loading, error, or success). */
  const analysing = act.status !== 'idle';

  const resetToForm = () => {
    act.reset();
    setSubmitted(null);
  };

  /* Toggle full-page mode: hide the app's sidebar + header when showing investigation results */
  useEffect(() => {
    if (analysing) document.body.classList.add('ph-fullpage');
    else document.body.classList.remove('ph-fullpage');
    return () => document.body.classList.remove('ph-fullpage');
  }, [analysing]);

  return (
    <div className={`ph-page ${analysing ? 'ph-page--dashboard' : 'max-w-5xl'}`}>
      {/* ── Input form: visible only before Analyse is pressed ── */}
      {!analysing && (
        <>
          <PageHeader icon="eye" title="Phishing Investigation" blurb="Paste a suspicious email and collect the evidence: where it really came from, whether it authenticates, and where its links lead." badge={<Badge tone="warn">preview</Badge>} />
          <InputForm f={f} setF={setF} files={files} setFiles={setFiles} onSubmit={submit} busy={act.status === 'loading'} />
          <div className="mb-6"><HistoryPanel enabled={historyOn} setEnabled={setHistoryOn} version={historyVersion} onChange={() => setHistoryVersion((v) => v + 1)} /></div>
          <Empty>Paste at least the email headers, or a sender, link or attachment, then choose Analyse email. Or load the example to see how a report looks.</Empty>
        </>
      )}

      {/* ── Results: full-page dashboard replaces all content ── */}
      {analysing && (
        <>
          {act.status === 'loading' && <div className="flex min-h-[60vh] items-center justify-center"><Spinner label="Parsing the message" /></div>}
          {act.status === 'error' && act.error && <div className="mx-auto max-w-xl py-12"><ErrorBox error={act.error} onRetry={submit} /></div>}
          {act.status === 'success' && act.data && submitted && (
            <ResultsShell key={submitted.id} r={act.data} input={submitted.input} files={submitted.files} startedAt={submitted.at} historyEnabled={submitted.history} onHistorySaved={() => setHistoryVersion((v) => v + 1)} onNewAnalysis={resetToForm} />
          )}
        </>
      )}
    </div>
  );
}
