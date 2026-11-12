import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { LIMITS } from '../../../shared/phishing/types';
import { parseSubmission, validateInput } from '../../../shared/phishing/parse';
import { workersAiTranslator } from '../../_lib/translate';
import { validatePretranslated } from '../../../shared/phishing/language';
import type { Env } from '../../_lib/env';

/**
 * POST /api/phishing/parse   body: PhishingInput (JSON)
 * Stage 1 of the phishing investigation: header forensics, authentication, MIME body, links, attachments, indicators.
 * Nothing is stored or logged. When the wording is not English, the subject and body (all the text the wording rules read) are
 * machine-translated by Cloudflare Workers AI (same provider as this Worker; zero data retention; free daily allowance
 * only) so the English wording rules can read it. TRANSLATE_CONTENT=false switches that off.
 * When that is not possible the response carries `translationRequest`; the browser can translate those pieces on the
 * device (Chrome / Edge built-in Translator API) and repeat the request with `browserTranslation`, which is then used
 * instead of Workers AI (no second Workers AI call, so no budget is spent on a retry).
 */
export const onRequestPost = route(async (ctx) => {
  const text = await readTextLimited(ctx.request, LIMITS.requestBytes);
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw badInput('Request body must be JSON.');
  }
  const v = validateInput(json);
  if (!v.ok) throw badInput(v.error);
  const pretranslated = validatePretranslated((json as Record<string, unknown>).browserTranslation);
  return ok(await parseSubmission(v.value, pretranslated ? { pretranslated } : { translate: workersAiTranslator(ctx.env as Env) }));
});
