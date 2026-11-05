/** Helpers for calling third-party intelligence APIs (fixed hosts, never user-controlled). */
import { ApiError } from './errors';
import { USER_AGENT } from './safeFetch';
import type { ProviderStatus } from '../../shared/types';

/** Runs a provider call, records its status, and returns null on failure (a failed source must never fail the lookup). */
export async function track<T>(providers: ProviderStatus[], name: string, fn: () => Promise<T>): Promise<T | null> {
  const t0 = Date.now();
  try {
    const v = await fn();
    providers.push({ name, ok: true, ms: Date.now() - t0 });
    return v;
  } catch (e) {
    providers.push({ name, ok: false, ms: Date.now() - t0, error: e instanceof Error ? e.message : 'failed' });
    return null;
  }
}

export const skipped = (providers: ProviderStatus[], name: string, why: string): null => {
  providers.push({ name, ok: false, ms: 0, skipped: true, error: why });
  return null;
};

async function send<T>(url: string, init: RequestInit, timeoutMs: number): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
    throw new ApiError(timeout ? 504 : 502, timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', timeout ? 'Upstream provider timed out.' : 'Upstream provider unreachable.');
  }
  if (res.status === 401 || res.status === 403) throw new ApiError(502, 'UPSTREAM_ERROR', `Upstream provider rejected the API key (HTTP ${res.status}).`);
  if (res.status === 429) throw new ApiError(502, 'UPSTREAM_ERROR', 'Upstream provider rate limit reached; try again later.');
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `Upstream provider returned HTTP ${res.status}.`);
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(502, 'UPSTREAM_ERROR', 'Upstream provider returned a malformed response.');
  }
}

export const postForm = <T>(url: string, form: Record<string, string>, headers: Record<string, string> = {}, timeoutMs = 6000): Promise<T> =>
  send<T>(url, { method: 'POST', headers: { accept: 'application/json', 'user-agent': USER_AGENT, 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(form).toString() }, timeoutMs);

export const postJson = <T>(url: string, body: unknown, headers: Record<string, string> = {}, timeoutMs = 6000): Promise<T> =>
  send<T>(url, { method: 'POST', headers: { accept: 'application/json', 'user-agent': USER_AGENT, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }, timeoutMs);

export async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** base64url without padding: VirusTotal's URL identifier. */
export function base64Url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
