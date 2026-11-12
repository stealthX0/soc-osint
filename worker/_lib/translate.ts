import type { Env } from './env';
import { takeProviderBudget } from './ratelimit';
import type { Translator } from '../../shared/phishing/language';

/** Cloudflare Workers AI many-to-many translation model (hosted by Cloudflare, zero data retention). */
export const TRANSLATE_MODEL = '@cf/meta/m2m100-1.2b';
const PER_CALL_MS = 15_000;
const PARALLEL = 4;

const withTimeout = <T,>(p: Promise<T>, ms: number) => Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);

/**
 * A Translator backed by Workers AI, or undefined when the AI binding is missing or TRANSLATE_CONTENT is "false".
 * Free by design: one budget unit per message (`translate`, default 40/day, sized to the free 10,000 neurons/day), and
 * on the Workers Free plan Cloudflare refuses calls past the allowance instead of billing. Any failure returns null, so
 * the message is reported as "not translated" rather than failing the investigation.
 */
export function workersAiTranslator(env: Env): Translator | undefined {
  const ai = env.AI;
  if (!ai || env.TRANSLATE_CONTENT === 'false') return undefined;
  return async (texts, source) => {
    const budget = await takeProviderBudget(env, 'translate');
    if (!budget.ok) { console.warn(`[translate] skipped: ${budget.why}`); return null; }
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
