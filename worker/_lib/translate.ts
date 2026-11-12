import type { Env } from './env';
import type { Translator } from '../../shared/phishing/language';

/** Cloudflare Workers AI many-to-many translation model (hosted by Cloudflare, zero data retention). */
export const TRANSLATE_MODEL = '@cf/meta/m2m100-1.2b';
const PER_CALL_MS = 15_000;
const PARALLEL = 4;

const withTimeout = <T,>(p: Promise<T>, ms: number) => Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);

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
    try {
      for (let i = 0; i < texts.length; i += PARALLEL) {
        await Promise.all(texts.slice(i, i + PARALLEL).map(async (text, k) => {
          const r = await withTimeout(ai.run(TRANSLATE_MODEL, { text, source_lang: source, target_lang: 'en' }), PER_CALL_MS) as { translated_text?: unknown; result?: { translated_text?: unknown } } | null;
          const t = r?.translated_text ?? r?.result?.translated_text;
          out[i + k] = typeof t === 'string' ? t : '';
        }));
      }
    } catch (e) {
      console.warn(`[translate] ${source}->en failed: ${e instanceof Error ? e.message : String(e)}`);
      return null;
    }
    return out;
  };
}
