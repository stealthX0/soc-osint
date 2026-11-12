/**
 * In-browser translation fallback: Chrome 138+ / Edge 148+ (desktop) ship an on-device Translator API and Language
 * Detector API. Used only when the server could not translate the wording (Cloudflare Workers AI free allowance used up,
 * model error, or a language m2m100 does not cover). Free, no quota, and the text never leaves the analyst's machine.
 *
 * Downloading a language pack (roughly 50-100 MB per language pair, once) needs a click, so the automatic path only
 * translates when the pack is already on the device; otherwise the caller asks the analyst first.
 */
import type { PretranslatedText, TranslationRequest } from '../../shared/phishing/language';

type Availability = 'unavailable' | 'downloadable' | 'downloading' | 'available';
interface Monitor { addEventListener(type: 'downloadprogress', cb: (e: { loaded: number }) => void): void }
interface TranslatorInstance { translate(text: string, opts?: { signal?: AbortSignal }): Promise<string>; destroy?(): void }
interface TranslatorStatic {
  availability(o: { sourceLanguage: string; targetLanguage: string }): Promise<Availability>;
  create(o: { sourceLanguage: string; targetLanguage: string; monitor?: (m: Monitor) => void; signal?: AbortSignal }): Promise<TranslatorInstance>;
}
interface DetectorInstance { detect(text: string): Promise<{ detectedLanguage: string; confidence: number }[]>; destroy?(): void }
interface DetectorStatic {
  availability(): Promise<Availability>;
  create(o?: { monitor?: (m: Monitor) => void; signal?: AbortSignal }): Promise<DetectorInstance>;
}

const g = globalThis as unknown as { Translator?: TranslatorStatic; LanguageDetector?: DetectorStatic };

/** Does this browser have the built-in Translator API at all? */
export const hasBrowserTranslator = () => typeof g.Translator?.create === 'function';

/** Which browser, for messages. */
export function browserLabel(): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  return /Edg\//.test(ua) ? 'Microsoft Edge' : /Chrome\//.test(ua) ? 'Chrome' : 'this browser';
}

export type BrowserTranslateOutcome =
  | { ok: true; value: PretranslatedText }
  | { ok: false; reason: 'unsupported_browser' | 'unsupported_language' | 'needs_download' | 'failed'; detail: string; source?: string };

export interface BrowserTranslateOptions {
  /** false (automatic path): never start a download; report 'needs_download' instead. true: after a click. */
  allowDownload: boolean;
  onProgress?: (fraction: number) => void;
  signal?: AbortSignal;
}

const sampleOf = (req: TranslationRequest) => req.pieces.join('\n').slice(0, 2000);

/** Source language: the server's code when it knows the language, otherwise the browser's own detector. */
async function resolveSource(req: TranslationRequest, o: BrowserTranslateOptions): Promise<string | 'needs_download' | null> {
  if (req.source) return req.source;
  const D = g.LanguageDetector;
  if (!D) return null;
  const av = await D.availability();
  if (av === 'unavailable') return null;
  if (av !== 'available' && !o.allowDownload) return 'needs_download';
  const det = await D.create({ signal: o.signal });
  try {
    const top = (await det.detect(sampleOf(req)))[0];
    return top && top.detectedLanguage !== 'und' && top.confidence >= 0.5 ? top.detectedLanguage : null;
  } finally { det.destroy?.(); }
}

/** Translates the pieces the server asked for into English on this device. Never throws. */
export async function translateInBrowser(req: TranslationRequest, o: BrowserTranslateOptions): Promise<BrowserTranslateOutcome> {
  const T = g.Translator;
  const where = browserLabel();
  if (!T) return { ok: false, reason: 'unsupported_browser', detail: 'This browser has no built-in translator (it needs Chrome 138+ or Microsoft Edge 148+ on a desktop).' };
  try {
    const source = await resolveSource(req, o);
    if (source === 'needs_download') return { ok: false, reason: 'needs_download', detail: `${where} needs to download its language detector first.` };
    if (!source) return { ok: false, reason: 'unsupported_language', detail: `${where} could not identify the language (${req.languageName}).` };
    if (source === 'en' || source.startsWith('en-')) return { ok: false, reason: 'unsupported_language', detail: `${where} reads this text as English, so there is nothing to translate.`, source };
    const pair = { sourceLanguage: source, targetLanguage: 'en' };
    const av = await T.availability(pair);
    if (av === 'unavailable') return { ok: false, reason: 'unsupported_language', detail: `${where}'s built-in translator does not cover ${req.languageName} to English.`, source };
    if (av !== 'available' && !o.allowDownload) return { ok: false, reason: 'needs_download', detail: `${where} can translate ${req.languageName} on this device after a one-time language-pack download.`, source };
    const tr = await T.create({ ...pair, signal: o.signal, monitor: (m) => m.addEventListener('downloadprogress', (e) => o.onProgress?.(e.loaded)) });
    try {
      // One piece at a time: the on-device translator can fail under heavy concurrent use.
      const out: string[] = [];
      for (const p of req.pieces) out.push(await tr.translate(p, { signal: o.signal }));
      if (out.every((x) => !x.trim())) return { ok: false, reason: 'failed', detail: `${where}'s translator returned no text.`, source };
      return { ok: true, value: { engine: 'browser', source, pieces: req.pieces, out } };
    } finally { tr.destroy?.(); }
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    // Starting a download without a recent click is refused with NotAllowedError.
    if (name === 'NotAllowedError') return { ok: false, reason: 'needs_download', detail: `${where} needs a click before it downloads the language pack.` };
    if (name === 'AbortError') throw e;
    return { ok: false, reason: 'failed', detail: `${where}'s translator failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}
