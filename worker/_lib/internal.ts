/**
 * In-process calls to Spectrix's own lookup endpoints, so higher-level workflows (the phishing investigation) can reuse
 * the IP / domain / URL / e-mail / file intelligence without refactoring it or paying for an extra HTTP round trip.
 *
 * What this keeps: each endpoint's own validation, SSRF guard, Cache API caching and shared provider quota budgets.
 * What it skips: the middleware (CORS, per-client rate limit). The calling endpoint is rate limited once, at its own cost.
 *
 * Workers limit the number of outbound subrequests per invocation, and one URL lookup alone fans out to several
 * providers. Workflows therefore call this from small per-stage endpoints, never from one giant orchestrator.
 */
import type { Ctx } from './env';
import type { ApiResponse } from '../../shared/types';

export type InternalResult<T> = { ok: true; data: T; cached: boolean } | { ok: false; code: string; message: string };

type Params = Record<string, string | number | boolean | null | undefined>;

export async function callInternal<T>(
  ctx: Pick<Ctx, 'request' | 'env' | 'waitUntil'>,
  path: string,
  opts: { params?: Params; body?: unknown } = {},
): Promise<InternalResult<T>> {
  // Only the public lookup endpoints; never recurse into the workflow endpoints themselves.
  if (!path.startsWith('/api/') || path.startsWith('/api/phishing/') || path.includes('..')) {
    return { ok: false, code: 'BAD_REQUEST', message: `Internal call to ${path} is not allowed.` };
  }
  const url = new URL(path, ctx.request.url);
  for (const [k, v] of Object.entries(opts.params ?? {})) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));

  const method = opts.body !== undefined ? 'POST' : 'GET';
  const headers = new Headers();
  const ip = ctx.request.headers.get('cf-connecting-ip');
  if (ip) headers.set('cf-connecting-ip', ip);
  if (opts.body !== undefined) headers.set('content-type', 'application/json');
  const request = new Request(url, { method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });

  const { resolve } = await import('../routes'); // lazy: routes.ts imports the workflow endpoints that import this file
  const { handler } = resolve(method, url.pathname);
  if (!handler) return { ok: false, code: 'NOT_FOUND', message: `Unknown internal endpoint ${url.pathname}.` };

  let body: ApiResponse<T> | null = null;
  try {
    const res = await handler({ request, env: ctx.env, waitUntil: (p) => ctx.waitUntil(p), next: async () => new Response(null, { status: 404 }) });
    body = (await res.json()) as ApiResponse<T>;
  } catch (e) {
    return { ok: false, code: 'INTERNAL', message: e instanceof Error ? e.message : 'Internal call failed.' };
  }
  if (!body || typeof body !== 'object' || !('ok' in body)) return { ok: false, code: 'BAD_RESPONSE', message: 'Internal endpoint returned an unexpected response.' };
  return body.ok ? { ok: true, data: body.data, cached: !!body.meta.cached } : { ok: false, code: body.error.code, message: body.error.message };
}
