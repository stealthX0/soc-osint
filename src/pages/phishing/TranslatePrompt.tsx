import { useState } from 'react';
import { Card } from '../../components/ui';
import type { TranslationRequest } from '../../../shared/phishing/language';
import { browserLabel } from '../../lib/browserTranslate';

/**
 * Shown before the dashboard when the wording is not English, the Cloudflare translation was unavailable, and this
 * browser can translate it on the device only after a one-time language-pack download (which needs a click). Asking here,
 * before the sender / link / attachment lookups start, means accepting does not spend those lookups twice.
 */
export function TranslatePrompt({ request, detail, onTranslate, onSkip }: {
  request: TranslationRequest;
  detail: string;
  /** Downloads + translates; resolves to an error message, or null once the analysis has been restarted. */
  onTranslate: (onProgress: (x: number) => void) => Promise<string | null>;
  onSkip: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const go = async () => {
    setBusy(true); setError(null); setProgress(null);
    const err = await onTranslate((x) => setProgress(x));
    if (err) { setError(err); setBusy(false); }
  };
  const btn = 'inline-flex h-9 items-center gap-2 rounded-lg px-4 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal disabled:opacity-50';
  return (
    <div className="mx-auto max-w-xl py-12">
      <Card title={`This message is in ${request.languageName}`}>
        <div className="space-y-3 text-sm">
          <p>The wording rules read English, and the free Cloudflare translation is not available for this message (its daily allowance may be used up, or it does not cover the language).</p>
          <p>{detail} The language pack is roughly 50–100 MB, downloaded once and reused afterwards. The translation runs on this computer, so the e-mail text does not leave it.</p>
          {progress !== null && <p className="text-xs text-muted">Downloading… {Math.round(progress * 100)}%</p>}
          {error && <p className="rounded-lg border border-amber/30 bg-amber/10 p-2 text-amber">{error}</p>}
          <div className="flex flex-wrap gap-2 pt-1">
            <button type="button" onClick={go} disabled={busy} className={`${btn} bg-teal font-semibold text-[#04202a] hover:brightness-110`}>
              {busy ? 'Translating…' : `Download and translate in ${browserLabel()}`}
            </button>
            <button type="button" onClick={onSkip} disabled={busy} className={`${btn} border border-line2 text-fg hover:border-teal/50`}>Continue without translation</button>
          </div>
          <p className="text-xs text-muted">Without a translation the wording is not analysed, so the message cannot be cleared on its wording.</p>
        </div>
      </Card>
    </div>
  );
}
