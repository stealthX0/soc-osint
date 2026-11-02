import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { MAX_HEADER_BYTES, analyzeHeaders } from '../../../shared/headers';

/**
 * POST /api/email/headers   body: { headers: "<raw header block>" }  (or text/plain)
 * Pure parsing: nothing is stored, logged or sent to any third party.
 */
export const onRequestPost = route(async (ctx) => {
  const len = Number(ctx.request.headers.get('content-length') ?? 0);
  if (len > MAX_HEADER_BYTES * 2) throw new ApiError(413, 'PAYLOAD_TOO_LARGE', `Headers must be under ${MAX_HEADER_BYTES / 1000} KB.`);

  const type = ctx.request.headers.get('content-type') ?? '';
  let raw = '';
  if (type.includes('application/json')) {
    const body = (await ctx.request.json().catch(() => null)) as { headers?: unknown } | null;
    if (typeof body?.headers !== 'string') throw badInput('JSON body must be { "headers": "<raw headers>" }.');
    raw = body.headers;
  } else {
    raw = await ctx.request.text();
  }
  if (!raw.trim()) throw badInput('No headers supplied.');
  if (new TextEncoder().encode(raw).length > MAX_HEADER_BYTES) throw new ApiError(413, 'PAYLOAD_TOO_LARGE', `Headers must be under ${MAX_HEADER_BYTES / 1000} KB.`);

  return ok(analyzeHeaders(raw));
});
