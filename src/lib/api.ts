import type { ApiResponse } from '../../shared/types';

export class ApiClientError extends Error {
  /** Seconds the server asked us to wait (Retry-After), when it said. */
  constructor(message: string, public code: string, public status: number, public retryAfter: number | null = null) {
    super(message);
    this.name = 'ApiClientError';
  }
}

type Params = Record<string, string | number | boolean | undefined | null>;

/** Retry-After in seconds (only the delta-seconds form is used by this API). */
export const retryAfterOf = (res: Response): number | null => {
  const n = Number(res.headers.get('retry-after'));
  return Number.isFinite(n) && n > 0 ? n : null;
};

export async function api<T>(
  path: string,
  opts: { params?: Params; method?: 'GET' | 'POST'; body?: unknown; signal?: AbortSignal } = {},
): Promise<{ data: T; cached: boolean }> {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(opts.params ?? {})) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));

  let res: Response;
  try {
    res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers: opts.body !== undefined ? { 'content-type': 'application/json' } : undefined,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiClientError('Could not reach the API. Check your connection.', 'NETWORK', 0);
  }

  let body: ApiResponse<T> | null = null;
  try {
    body = (await res.json()) as ApiResponse<T>;
  } catch {
    /* non-JSON, handled below */
  }
  if (!body || typeof body !== 'object' || !('ok' in body)) {
    throw new ApiClientError(
      res.status === 404 || res.headers.get('content-type')?.includes('text/html')
        ? 'The API is not running. In development start it with `npm run build && npm run dev:api`.'
        : `Unexpected response from the API (HTTP ${res.status}).`,
      'BAD_RESPONSE',
      res.status,
    );
  }
  if (!body.ok) throw new ApiClientError(body.error.message, body.error.code, res.status, retryAfterOf(res));
  return { data: body.data, cached: !!body.meta.cached };
}
