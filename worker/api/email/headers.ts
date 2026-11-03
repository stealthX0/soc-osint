import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { MAX_HEADER_BYTES, analyzeHeaders } from '../../../shared/headers';

/**
 * POST /api/email/headers   body: { headers: "<raw header block>" }  (or text/plain)
 * Pure parsing: nothing is stored, logged or sent to any third party.
 */
export const onRequestPost = route(async (ctx) => {
  // JSON escaping can inflate the payload, so the wire cap is 2x; the decoded header block is capped separately below.
  const body = await readTextLimited(ctx.request, MAX_HEADER_BYTES * 2);

  const type = ctx.request.headers.get('content-type') ?? '';
  let raw = '';
  if (type.includes('application/json')) {
    let parsed: { headers?: unknown } | null = null;
    try {
      parsed = JSON.parse(body) as { headers?: unknown } | null;
    } catch {
      parsed = null;
    }
    if (typeof parsed?.headers !== 'string') throw badInput('JSON body must be { "headers": "<raw headers>" }.');
    raw = parsed.headers;
  } else {
    raw = body;
  }
  if (!raw.trim()) throw badInput('No headers supplied.');
  if (new TextEncoder().encode(raw).length > MAX_HEADER_BYTES) throw new ApiError(413, 'PAYLOAD_TOO_LARGE', `Headers must be under ${MAX_HEADER_BYTES / 1000} KB.`);

  return ok(analyzeHeaders(raw));
});
