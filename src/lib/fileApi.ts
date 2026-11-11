import { ApiClientError, retryAfterOf } from './api';
import type { ApiResponse, FileUploadResult } from '../../shared/types';

/** Largest file the site will forward to VirusTotal (its direct-upload limit is just under 32 MB). */
export const MAX_UPLOAD_BYTES = 32_000_000;
/** Largest file analysed in the browser (everything is held in memory). */
export const MAX_LOCAL_BYTES = 100 * 1024 * 1024;

export const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`);

/** Sends the raw file to /api/file/upload. Only call this after the user has explicitly confirmed. */
export async function uploadFile(file: File, signal?: AbortSignal): Promise<FileUploadResult> {
  const url = `/api/file/upload?confirm=1&name=${encodeURIComponent(file.name)}`;
  let res: Response;
  try {
    res = await fetch(url, { method: 'POST', body: file, headers: { 'content-type': 'application/octet-stream' }, signal });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiClientError('Could not reach the API. Check your connection.', 'NETWORK', 0);
  }
  let body: ApiResponse<FileUploadResult> | null = null;
  try { body = (await res.json()) as ApiResponse<FileUploadResult>; } catch { /* handled below */ }
  if (!body || typeof body !== 'object' || !('ok' in body)) throw new ApiClientError(`Unexpected response from the API (HTTP ${res.status}).`, 'BAD_RESPONSE', res.status);
  if (!body.ok) throw new ApiClientError(body.error.message, body.error.code, res.status, retryAfterOf(res));
  return body.data;
}
