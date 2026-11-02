/**
 * Thin wrapper over the Workers Cache API so repeated lookups do not burn
 * upstream free-tier quotas. Works without any binding; silently no-ops if
 * the Cache API is unavailable (e.g. under plain Node in tests).
 */
/**
 * Bump when the shape of any cached value changes. The Cache API outlives deployments, so without a
 * version an old Worker's entries (same key, old JSON shape) are served to the new code until their TTL ends.
 */
export const CACHE_VERSION = 'v2';

export interface CacheCtx { waitUntil(p: Promise<unknown>): void }

export interface Cacheable<T> { value: T; /** seconds; 0 disables caching of this result */ ttl: number }

export async function cached<T>(
  ctx: CacheCtx,
  key: string,
  compute: () => Promise<Cacheable<T>>,
): Promise<{ value: T; hit: boolean }> {
  const store: Cache | undefined = typeof caches !== 'undefined' ? (caches as unknown as { default?: Cache }).default : undefined;
  if (!store) return { value: (await compute()).value, hit: false };

  const req = new Request(`https://cache.internal.invalid/${CACHE_VERSION}/${encodeURIComponent(key)}`);
  try {
    const hit = await store.match(req);
    if (hit) return { value: (await hit.json()) as T, hit: true };
  } catch { /* cache failures must never break a lookup */ }

  const { value, ttl } = await compute();
  if (ttl > 0) {
    try {
      const res = new Response(JSON.stringify(value), {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttl}` },
      });
      ctx.waitUntil(store.put(req, res));
    } catch { /* ignore */ }
  }
  return { value, hit: false };
}
