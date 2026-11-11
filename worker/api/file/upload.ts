import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param, readBytesLimited } from '../../_lib/input';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import type { Env } from '../../_lib/env';
import type { FileUploadResult } from '../../../shared/types';

/** VirusTotal accepts direct uploads below 32 MB; stay safely under that. */
export const MAX_UPLOAD_BYTES = 32_000_000;

interface VtUpload { data?: { id?: string } }

const toHex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** Keep only characters that are safe in a multipart filename; the name is cosmetic for the scan report. */
export const cleanFileName = (raw: string): string => {
  const base = raw.split(/[\\/]/).pop() ?? '';
  const cleaned = base.replace(/[\u0000-\u001f\u007f"';<>|?*‪-‮⁦-⁩]/g, '_').trim().slice(0, 120);
  return cleaned || 'sample';
};

/**
 * POST /api/file/upload?confirm=1&name=<filename>      body: raw file bytes (max 32 MB)
 * Submits the file to VirusTotal for scanning. Uploaded files are shared with security vendors and may be visible to
 * other VirusTotal users, so the caller must pass confirm=1 to acknowledge that. Nothing is stored by this Worker.
 */
export const onRequestPost = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const env = ctx.env as Env;
  if (param(url, 'confirm', 8) !== '1') {
    throw badInput('Uploading shares the file with VirusTotal and its security partners. Pass confirm=1 to acknowledge this.');
  }
  if (!env.VIRUSTOTAL_API_KEY) throw new ApiError(503, 'NOT_CONFIGURED', 'File upload is not enabled on this site (no VirusTotal key configured).');
  if (!ctx.request.headers.has('content-length') && !ctx.request.body) throw badInput('Missing file body.');

  const bytes = await readBytesLimited(ctx.request, MAX_UPLOAD_BYTES);
  if (bytes.byteLength === 0) throw badInput('The file is empty.');
  const name = cleanFileName(param(url, 'name', 300));

  const budget = await takeProviderBudget(env, 'virustotal');
  if (!budget.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `VirusTotal quota reached: ${budget.why}.`, { 'retry-after': String(budget.retryAfter ?? 60) });

  const sha256 = toHex(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource));
  const form = new FormData();
  form.append('file', new Blob([bytes as unknown as ArrayBuffer], { type: 'application/octet-stream' }), name);
  const r = await fetchJson<VtUpload>('https://www.virustotal.com/api/v3/files', {
    method: 'POST', body: form, timeoutMs: 25_000, headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY },
  });
  const analysisId = r.data?.id;
  if (!analysisId) throw new ApiError(502, 'UPSTREAM_ERROR', 'VirusTotal did not return an analysis id.');
  const out: FileUploadResult = { analysisId, sha256, size: bytes.byteLength, link: `https://www.virustotal.com/gui/file/${sha256}` };
  return ok(out);
});
