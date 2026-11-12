import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { LIMITS } from '../../../shared/phishing/types';
import { parseSubmission, validateInput } from '../../../shared/phishing/parse';
import { workersAiTranslator } from '../../_lib/translate';
import type { Env } from '../../_lib/env';

/**
 * POST /api/phishing/parse   body: PhishingInput (JSON)
 * Stage 1 of the phishing investigation: header forensics, authentication, MIME body, links, attachments, indicators.
 * Nothing is stored or logged. When the wording is not English, the subject and up to 5,000 characters of the body are
 * machine-translated by Cloudflare Workers AI (same provider as this Worker; zero data retention; free daily allowance
 * only) so the English wording rules can read it. TRANSLATE_CONTENT=false switches that off.
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
  return ok(await parseSubmission(v.value, { translate: workersAiTranslator(ctx.env as Env) }));
});
