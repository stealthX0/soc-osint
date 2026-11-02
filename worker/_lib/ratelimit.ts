import type { Env } from './env';

export interface RateResult { allowed: boolean; limit: number; remaining: number; resetSeconds: number }

const WINDOW_SECONDS = 60;
const memory = new Map<string, { count: number; expires: number }>();

/**
 * Fixed-window, cost-weighted limiter.
 *
 * - With a `RATE_LIMIT` KV binding the counter is shared across isolates (KV is eventually
 *   consistent, so treat the limit as approximate).
 * - Without KV it falls back to per-isolate memory, which still stops a single client hammering
 *   one isolate but is NOT a global limit. For hard guarantees add a Cloudflare WAF rate-limiting rule.
 */
export async function rateLimit(env: Env, clientId: string, cost: number, now = Date.now()): Promise<RateResult> {
  const limit = Math.max(1, Number(env.RATE_LIMIT_PER_MIN) || 60);
  const windowId = Math.floor(now / 1000 / WINDOW_SECONDS);
  const key = `rl:${clientId}:${windowId}`;
  const resetSeconds = (windowId + 1) * WINDOW_SECONDS - Math.floor(now / 1000);

  let used = 0;
  if (env.RATE_LIMIT) {
    try {
      used = Number((await env.RATE_LIMIT.get(key)) ?? 0);
      if (used + cost <= limit) {
        await env.RATE_LIMIT.put(key, String(used + cost), { expirationTtl: WINDOW_SECONDS * 2 });
      }
    } catch {
      used = 0; // fail open if KV is unavailable
    }
  } else {
    if (memory.size > 5000) for (const [k, v] of memory) if (v.expires < now) memory.delete(k);
    const entry = memory.get(key) ?? { count: 0, expires: now + WINDOW_SECONDS * 2000 };
    used = entry.count;
    if (used + cost <= limit) memory.set(key, { count: used + cost, expires: entry.expires });
  }

  const allowed = used + cost <= limit;
  return { allowed, limit, remaining: Math.max(0, limit - used - (allowed ? cost : 0)), resetSeconds };
}

/** Endpoint cost weights: probes that make outbound requests cost more. */
export function costFor(pathname: string): number {
  if (pathname.startsWith('/api/network/latency')) return 5;
  if (pathname.startsWith('/api/domain/http')) return 3;
  if (pathname.startsWith('/api/domain/ssl')) return 3;
  if (pathname.startsWith('/api/dns/propagation')) return 2;
  if (pathname.startsWith('/api/ip/lookup')) return 2;
  if (pathname.startsWith('/api/email/auth')) return 2;
  if (pathname.startsWith('/api/health')) return 0;
  return 1;
}
