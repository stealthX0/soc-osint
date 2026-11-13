import { useEffect, useState } from 'react';
import { PageHeader, Empty, Spinner, ErrorBox } from '../components/ui';
import { useAction } from '../lib/hooks';
import { api } from '../lib/api';
import { useStored } from '../lib/storage';
import { HISTORY_ENABLED_KEY } from '../lib/phishingHistory';
import type { ParseStageResult } from '../../shared/phishing/parse';
import type { PretranslatedText } from '../../shared/phishing/language';
import { browserLabel, hasBrowserTranslator, translateInBrowser } from '../lib/browserTranslate';
import { TranslatePrompt } from './phishing/TranslatePrompt';
import type { PhishingInput } from '../../shared/phishing/types';
import { HistoryPanel } from './phishing/HistoryPanel';
import { InputForm } from './phishing/InputForm';
import { ResultsShell } from './phishing/ResultsShell';
import { EMPTY_FORM, buildInput, type FormFields } from './phishing/formHelpers';
import '../styles/phishing.css';

/** `active` is false while the page is kept alive but hidden behind another tool (see App). */
export default function PhishingPage({ active = true }: { active?: boolean } = {}) {
  const [f, setF] = useState<FormFields>(EMPTY_FORM);
  const [files, setFiles] = useState<File[]>([]);
  const [historyOn, setHistoryOn] = useStored<boolean>(HISTORY_ENABLED_KEY, true);
  const [historyVersion, setHistoryVersion] = useState(0);
  const [submitted, setSubmitted] = useState<{ id: number; input: PhishingInput; files: File[]; at: number; history: boolean } | null>(null);
  /** Progress label while the browser translates (the Cloudflare translation was unavailable). */
  const [translating, setTranslating] = useState<string | null>(null);
  /** The analyst chose to continue without the in-browser translation. */
  const [skipTranslate, setSkipTranslate] = useState(false);

  /*
   * Parse. When the wording is not English and Cloudflare could not translate it (free allowance used up, model error, or
   * a language it does not cover), the server returns `translationRequest`; this browser's built-in on-device translator
   * (Chrome 138+ / Edge 148+) then translates those pieces and the parse is repeated with them. A language pack that is
   * not on the device yet needs a click to download, so in that case the analyst is asked first (TranslatePrompt).
   */
  const act = useAction<ParseStageResult, { input: PhishingInput; pre?: PretranslatedText }>(async ({ input, pre }, signal) => {
    const parse = async (browserTranslation?: PretranslatedText) =>
      (await api<ParseStageResult>('/api/phishing/parse', { method: 'POST', body: browserTranslation ? { ...input, browserTranslation } : input, signal })).data;
    const translatedNote = (r: ParseStageResult): ParseStageResult => r.translationRequest
      ? { ...r, browserFallback: { status: 'failed', detail: 'The browser translation could not be matched to the message, so the wording was not translated.' } }
      : { ...r, browserFallback: { status: 'translated', detail: `Translated on this device by ${browserLabel()}'s built-in translator because the Cloudflare translation was unavailable.` } };
    if (pre) return translatedNote(await parse(pre));
    const first = await parse();
    const req = first.translationRequest;
    if (!req) return first;
    if (!hasBrowserTranslator()) return { ...first, browserFallback: { status: 'unsupported_browser', detail: 'The Cloudflare translation was unavailable, and this browser has no built-in translator (Chrome 138+ or Microsoft Edge 148+ on a desktop can translate on the device).' } };
    setTranslating(`Translating the ${req.languageName} wording in this browser`);
    try {
      const t = await translateInBrowser(req, { allowDownload: false, signal, onProgress: (x) => setTranslating(`Downloading the language pack (${Math.round(x * 100)}%)`) });
      if (t.ok) return translatedNote(await parse(t.value));
      return { ...first, browserFallback: { status: t.reason, detail: t.detail } };
    } finally { setTranslating(null); }
  });

  const submit = () => {
    const input = buildInput(f);
    setSkipTranslate(false);
    setSubmitted((p) => ({ id: (p?.id ?? 0) + 1, input, files: [...files], at: Date.now(), history: historyOn }));
    return act.run({ input });
  };

  /** After the analyst clicked "Download and translate": the pack is on the device, parse again with the translation. */
  const retryWithBrowser = async (onProgress: (x: number) => void) => {
    const req = act.data?.translationRequest;
    if (!req || !submitted) return 'Nothing to translate.';
    const t = await translateInBrowser(req, { allowDownload: true, onProgress });
    if (!t.ok) return t.detail;
    void act.run({ input: submitted.input, pre: t.value });
    return null;
  };
  const askToTranslate = act.status === 'success' && act.data?.browserFallback?.status === 'needs_download' && !skipTranslate;

  /** Whether the analysis has been triggered (loading, error, or success). */
  const analysing = act.status !== 'idle';

  const [dashboardReady, setDashboardReady] = useState(false);

  /** "New analysis": back to an empty form (pasted text, loaded email file and attachments are all cleared). */
  const resetToForm = () => {
    act.reset();
    setSubmitted(null);
    setDashboardReady(false);
    setF(EMPTY_FORM);
    setFiles([]);
    setSkipTranslate(false);
    window.scrollTo(0, 0);
  };

  /* Toggle full-page mode: hide the app's sidebar + header only when the dashboard is fully ready */
  useEffect(() => {
    if (dashboardReady && active) document.body.classList.add('ph-fullpage');
    else document.body.classList.remove('ph-fullpage');
    return () => document.body.classList.remove('ph-fullpage');
  }, [dashboardReady, active]);

  return (
    <div className={`ph-page ${dashboardReady ? 'ph-page--dashboard' : 'max-w-5xl'}`}>
      {/* ── Input form: visible only before Analyse is pressed ── */}
      {!analysing && (
        <>
          <PageHeader icon="eye" title="Phishing Investigation" blurb="Paste a suspicious email and collect the evidence: where it really came from, whether it authenticates, and where its links lead." />
          <InputForm f={f} setF={setF} files={files} setFiles={setFiles} onSubmit={submit} busy={act.status === 'loading'} />
          <div className="mb-6"><HistoryPanel enabled={historyOn} setEnabled={setHistoryOn} version={historyVersion} onChange={() => setHistoryVersion((v) => v + 1)} /></div>
          <Empty>Paste at least the email headers, or a sender, link or attachment, then choose Analyse email. Or load the example to see how a report looks.</Empty>
        </>
      )}

      {/* ── Results: full-page dashboard replaces all content ── */}
      {analysing && (
        <>
          {act.status === 'loading' && <div className="flex min-h-[60vh] items-center justify-center"><Spinner label={translating ?? 'Parsing the message'} /></div>}
          {askToTranslate && act.data?.translationRequest && (
            <TranslatePrompt request={act.data.translationRequest} detail={act.data.browserFallback!.detail} onTranslate={retryWithBrowser}
              onSkip={() => setSkipTranslate(true)} />
          )}
          {act.status === 'error' && act.error && <div className="mx-auto max-w-xl py-12"><ErrorBox error={act.error} onRetry={submit} /></div>}
          {act.status === 'success' && act.data && submitted && !askToTranslate && (
            <ResultsShell key={submitted.id} r={act.data} input={submitted.input} files={submitted.files} startedAt={submitted.at} historyEnabled={submitted.history} onHistorySaved={() => setHistoryVersion((v) => v + 1)} onNewAnalysis={resetToForm} onReady={() => setDashboardReady(true)} />
          )}
        </>
      )}
    </div>
  );
}
