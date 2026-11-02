import type { Ctx, Env } from './_lib/env';
import { ApiError } from './_lib/errors';
import { fail } from './_lib/respond';
import { onRequest as middleware } from './middleware';
import { resolve } from './routes';

export default {
  async fetch(request: Request, env: Env, execCtx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Everything that is not /api/* is the static React app (SPA fallback is handled by the assets config).
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);

    const { handler, known } = resolve(request.method, url.pathname);
    const ctx: Ctx = {
      request,
      env,
      waitUntil: (p) => execCtx.waitUntil(p),
      next: async () => {
        if (!handler) {
          return fail(
            known
              ? new ApiError(405, 'METHOD_NOT_ALLOWED', `${request.method} is not supported on this endpoint.`)
              : new ApiError(404, 'NOT_FOUND', 'Unknown API endpoint.'),
          );
        }
        return handler(ctx);
      },
    };
    return middleware(ctx);
  },
} satisfies ExportedHandler<Env>;
