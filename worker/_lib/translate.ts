import type { Env } from './env';
import type { Translator } from '../../shared/phishing/language';

/** Cloudflare Workers AI many-to-many translation model (hosted by Cloudflare, zero data retention). */
export const TRANSLATE_MODEL = '@cf/meta/m2m100-1.2b';
const PER_CALL_MS = 15_000;
/** Calls in flight at once (Workers AI allows roughly 720 translation requests a minute per account). */
const PARALLEL = 8;

/** Rejects after `ms`; the timer is always cleared, so a finished call leaves nothing running. */
const withTimeout = <T,>(p: Promise<T>, ms: number): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), ms); });
  return Promise.race([p, timeout]).finally(() => { if (timer !== undefined) clearTimeout(timer); });
};

/**
 * A Translator backed by Workers AI, or undefined when the AI binding is missing or TRANSLATE_CONTENT is "false".
 * No cap of our own: every non-English message is sent. On the Workers Free plan Cloudflare refuses calls past the free
 * 10,000 neurons/day instead of billing (on Workers Paid, usage past the allowance IS billed). Any failure (allowance
 * used up, model error, timeout) returns null; the browser's built-in translator then takes over where it can.
 */
export function workersAiTranslator(env: Env): Translator | undefined {
  const ai = env.AI;
  if (!ai || env.TRANSLATE_CONTENT === 'false') return undefined;
  return async (texts, source) => {
    const out: string[] = new Array(texts.length).fill('');
    const started = Date.now();
    const chars = texts.reduce((n, t) => n + t.length, 0);
    // Timing only (language, piece count, characters, milliseconds), never any of the e-mail text. Visible in the
    // Cloudflare dashboard: Workers & Pages > threatlens > Logs, search "[translate]".
    const log = (ok: boolean, extra = '') =>
      console.log(`[translate] ${source}->en ${ok ? 'ok' : 'failed'} pieces=${texts.length} chars=${chars} ms=${Date.now() - started} parallel=${PARALLEL}${extra}`);
    try {
      // A small pool: PARALLEL calls always in flight, the next piece starts as soon as one finishes.
      let next = 0;
      const worker = async () => {
        while (next < texts.length) {
          const i = next++;
          const r = await withTimeout(ai.run(TRANSLATE_MODEL, { text: texts[i], source_lang: source, target_lang: 'en' }), PER_CALL_MS) as { translated_text?: unknown; result?: { translated_text?: unknown } } | null;
          const t = r?.translated_text ?? r?.result?.translated_text;
          out[i] = typeof t === 'string' ? t : '';
        }
      };
      await Promise.all(Array.from({ length: Math.min(PARALLEL, texts.length) }, worker));
    } catch (e) {
      log(false, ` error=${JSON.stringify(e instanceof Error ? e.message : String(e)).slice(0, 200)}`);
      return null;
    }
    log(true);
    return out;
  };
}
