import type { Env } from './env';

export interface RateResult { allowed: boolean; limit: number; remaining: number; resetSeconds: number }

const DEFAULT_WINDOW_SECONDS = 60;
const memory = new Map<string, { count: number; expires: number }>();

/**
 * Fixed-window, cost-weighted limiter.
 *
 * - With a `RATE_LIMIT` KV binding the counter is shared across isolates (KV is eventually
 *   consistent, so treat the limit as approximate).
 * - Without KV it falls back to per-isolate memory, which still stops a single client hammering
 *   one isolate but is NOT a global limit. For hard guarantees add a Cloudflare WAF rate-limiting rule.
 */
export async function rateLimit(
  env: Env,
  clientId: string,
  cost: number,
  now = Date.now(),
  opts: { limit?: number; windowSeconds?: number } = {},
): Promise<RateResult> {
  const WINDOW_SECONDS = opts.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
  const limit = opts.limit ?? Math.max(1, Number(env.RATE_LIMIT_PER_MIN) || 60);
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
  if (pathname.startsWith('/api/file/upload')) return 15;
  if (pathname.startsWith('/api/file/')) return 3;
  if (pathname.startsWith('/api/url/lookup')) return 3;
  if (pathname.startsWith('/api/email/auth')) return 2;
  if (pathname.startsWith('/api/email/usercheck')) return 2;
  if (pathname.startsWith('/api/email/ipqs')) return 2;
  if (pathname.startsWith('/api/phishing/sender')) return 2; // one upstream lookup per call
  if (pathname.startsWith('/api/phishing/parse')) return 2; // CPU-heavy parsing, no outbound requests
  if (pathname.startsWith('/api/phishing/urls')) return 8; // OpenPhish feed + up to 3 full URL lookups (each fans out to many providers)
  if (pathname.startsWith('/api/phishing/attachments')) return 2; // one hash per request (fans out to up to four providers)
  if (pathname.startsWith('/api/health')) return 0;
  return 1;
}

/** Test hook: clears the in-memory fallback counters. */
export function resetRateLimitMemory(): void {
  memory.clear();
}

/**
 * Upstream free-tier quotas. These are *global* budgets (not per client): once a provider's budget is
 * spent the lookup simply skips that provider instead of burning the key or getting it throttled.
 * Defaults match the free tiers; raise them for paid keys with <PROVIDER>_RPM / <PROVIDER>_DAILY vars.
 * Without a RATE_LIMIT KV binding the counters are per-isolate, so they are best-effort.
 */
const PROVIDER_BUDGETS: Record<string, { rpm?: number; daily?: number }> = {
  virustotal: { rpm: 4, daily: 450 }, // free tier: 4/min, 500/day
  abuseipdb: { daily: 900 }, // free tier: 1000/day
  pulsedive: {},
  apilayer: {}, // WHOIS fallback: no built-in cap (free plan is 3,000/month); set APILAYER_DAILY to add one
  hybridanalysis: { daily: 180 }, // conservative: Hybrid Analysis free keys are quota-limited and vary by account
  safebrowsing: { daily: 9000 }, // Lookup API: 10,000 requests/day
  urlscan: { rpm: 20 }, // anonymous search is limited to ~30/min per source address
  usercheck: {}, // plan quotas differ; set USERCHECK_DAILY to add a cap
  ipqs: { daily: 35 }, // when spent, the sender address check falls back to UserCheck; raise with IPQS_DAILY on a paid plan
  openphish: { daily: 300 }, // feed downloads only (the parsed feed is reused for ~30 minutes), never per-URL
};

export async function takeProviderBudget(env: Env, provider: string, now = Date.now()): Promise<{ ok: boolean; why?: string; retryAfter?: number }> {
  const base = PROVIDER_BUDGETS[provider] ?? {};
  const vars = env as unknown as Record<string, string | undefined>;
  const override = (suffix: string): number | undefined => {
    const n = Number(vars[`${provider.toUpperCase()}_${suffix}`]);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
  };
  const rpm = override('RPM') ?? base.rpm;
  const daily = override('DAILY') ?? base.daily;

  if (rpm) {
    const r = await rateLimit(env, `pb:${provider}:min`, 1, now, { limit: rpm, windowSeconds: 60 });
    if (!r.allowed) return { ok: false, why: `Request budget reached (${rpm}/min); retry in ${r.resetSeconds}s`, retryAfter: Math.max(1, r.resetSeconds) };
  }
  if (daily) {
    const r = await rateLimit(env, `pb:${provider}:day`, 1, now, { limit: daily, windowSeconds: 86_400 });
    if (!r.allowed) return { ok: false, why: `Daily request budget reached (${daily}/day); resets at 00:00 UTC` };
  }
  return { ok: true };
}
