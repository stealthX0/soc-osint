import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { callInternal } from '../../_lib/internal';
import { normalizeHash } from '../../../shared/fileHash';
import { convertFileReputation, failedReputationChecks, type AttachmentHashRequest, type AttachmentHashResponse } from '../../../shared/phishing/attachments';
import type { FileReputation } from '../../../shared/types';
import type { CheckResult, Finding } from '../../../shared/phishing/types';

/** More than the parse stage allows (20) so files dropped into the browser can be numbered after them. */
const MAX_INDEX = 99;

/**
 * POST /api/phishing/attachments   body: { hash, hashType, filename?, index }
 * Stage 4 of the phishing investigation: reputation of ONE attachment by hash. Only the hash leaves the app (no file bytes,
 * and the file name is used for labels only, never sent to a provider). The lookup is the existing /api/file/hash endpoint,
 * called in-process, so its caching and shared provider budgets apply and provider code is not duplicated.
 * A hash lookup fans out to up to four providers, so the page calls this once per hash, a few at a time.
 * Provider trouble is HTTP 200 with failed/skipped checks; 4xx is reserved for invalid input.
 */
export const onRequestPost = route(async (ctx) => {
  const text = await readTextLimited(ctx.request, 8_000);
  let body: Record<string, unknown>;
  try {
    const j = JSON.parse(text);
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error();
    body = j as Record<string, unknown>;
  } catch { throw badInput('Request body must be a JSON object.'); }

  if (typeof body.hash !== 'string' || !body.hash.trim()) throw badInput('"hash" is required.');
  const h = normalizeHash(body.hash);
  if (!h) throw badInput('Provide an MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal hash.');
  if (body.hashType !== 'md5' && body.hashType !== 'sha1' && body.hashType !== 'sha256') throw badInput('"hashType" must be "md5", "sha1" or "sha256".');
  if (body.hashType !== h.algo) throw badInput(`"hashType" is ${body.hashType} but the hash is ${h.algo}.`);
  if (typeof body.index !== 'number' || !Number.isInteger(body.index) || body.index < 0 || body.index > MAX_INDEX) throw badInput(`"index" must be an integer from 0 to ${MAX_INDEX}.`);
  if (body.filename !== undefined && typeof body.filename !== 'string') throw badInput('"filename" must be a string.');
  const filename = typeof body.filename === 'string' && body.filename.trim() ? body.filename.trim().slice(0, 255) : undefined;
  const request: AttachmentHashRequest = { hash: h.hash, hashType: h.algo, index: body.index, ...(filename ? { filename } : {}) };
  const rctx = { index: request.index, filename: filename ?? null };

  const r = await callInternal<FileReputation>(ctx, '/api/file/hash', { params: { hash: h.hash } });
  if (!r.ok) {
    const out: AttachmentHashResponse = { request, findings: [], checks: failedReputationChecks(rctx, r.message), data: null };
    return ok(out);
  }
  const { findings, checks } = convertFileReputation(r.data, rctx);
  const out: AttachmentHashResponse = { request, findings, checks, data: r.data };
  return ok(out, { cached: r.cached });
});
