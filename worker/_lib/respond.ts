import { ApiError } from './errors';
import type { Ctx, Handler } from './env';

export interface Meta {
  ts: string;
  cached?: boolean;
  elapsedMs?: number;
}

export function json(body: unknown, init: ResponseInit & { cacheSeconds?: number } = {}): Response {
  const { cacheSeconds, ...rest } = init;
  const headers = new Headers(rest.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  if (!headers.has('cache-control')) {
    headers.set('cache-control', cacheSeconds ? `public, max-age=${cacheSeconds}` : 'no-store');
  }
  return new Response(JSON.stringify(body), { ...rest, headers });
}

export function ok<T>(data: T, meta: Partial<Meta> = {}, cacheSeconds?: number): Response {
  return json({ ok: true, data, meta: { ts: new Date().toISOString(), ...meta } }, { cacheSeconds });
}

export function fail(err: unknown): Response {
  if (err instanceof ApiError) {
    return json({ ok: false, error: { code: err.code, message: err.message } }, { status: err.status, headers: err.headers });
  }
  // eslint-disable-next-line no-console
  console.error('unhandled error', err);
  return json({ ok: false, error: { code: 'INTERNAL', message: 'Unexpected server error.' } }, { status: 500 });
}

/**
 * Wraps a handler so thrown ApiErrors become JSON error responses and timing is recorded.
 * Every endpoint should be exported through this helper.
 */
export function route(handler: (ctx: Ctx) => Promise<Response>): Handler {
  return async (ctx) => {
    try {
      return await handler(ctx);
    } catch (e) {
      return fail(e);
    }
  };
}
