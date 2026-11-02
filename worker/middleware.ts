import type { Ctx, Env } from './_lib/env';
import { ApiError } from './_lib/errors';
import { fail } from './_lib/respond';
import { costFor, rateLimit } from './_lib/ratelimit';

const SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cross-origin-resource-policy': 'same-site',
};

function corsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('origin');
  if (!origin) return {};
  const allowed = (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const sameOrigin = origin === new URL(request.url).origin;
  if (!sameOrigin && !allowed.includes(origin)) return {};
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
}

/** Wraps every API request; only /api/* is gated (anything else just calls next()). */
export const onRequest = async (ctx: Ctx): Promise<Response> => {
  const { request, env } = ctx;
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/api/')) return ctx.next();

  const cors = corsHeaders(request, env);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...SECURITY_HEADERS, ...cors } });

  let response: Response;
  let rl: Awaited<ReturnType<typeof rateLimit>> | null = null;
  try {
    if (!['GET', 'HEAD', 'POST'].includes(request.method)) {
      throw new ApiError(405, 'METHOD_NOT_ALLOWED', `${request.method} is not supported.`, { allow: 'GET, POST, OPTIONS' });
    }
    const cost = costFor(url.pathname);
    if (cost > 0) {
      const client = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
      rl = await rateLimit(env, client, cost);
      if (!rl.allowed) {
        throw new ApiError(429, 'RATE_LIMITED', `Rate limit exceeded. Try again in ${rl.resetSeconds}s.`, { 'retry-after': String(rl.resetSeconds) });
      }
    }
    response = await ctx.next();
  } catch (e) {
    response = fail(e);
  }

  const out = new Response(response.body, response);
  for (const [k, v] of Object.entries({ ...SECURITY_HEADERS, ...cors })) out.headers.set(k, v);
  if (rl) {
    out.headers.set('x-ratelimit-limit', String(rl.limit));
    out.headers.set('x-ratelimit-remaining', String(rl.remaining));
  }
  return out;
};
