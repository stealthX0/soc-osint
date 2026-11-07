import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { LIMITS } from '../../../shared/phishing/types';
import { parseSubmission, validateInput } from '../../../shared/phishing/parse';

/**
 * POST /api/phishing/parse   body: PhishingInput (JSON)
 * Stage 1 of the phishing investigation: header forensics, authentication, MIME body, links, attachments, indicators.
 * Pure parsing: nothing is stored, logged or sent to any third party. Later stages call the intelligence endpoints.
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
  return ok(await parseSubmission(v.value));
});
