/**
 * OpenPhish community feed: a plain-text list of recently verified phishing URLs (https://openphish.com/feed.txt, no key).
 *
 * The feed is downloaded once, indexed in memory and reused for every link, so checking 200 links costs one request, not 200.
 * It is cached per isolate and, where the Cache API stores entries (custom domains), across isolates. The download draws
 * on a small daily budget so a burst of cold starts cannot hammer the feed host. If a refresh fails or the budget is spent,
 * the previous copy is used and reported as stale instead of pretending the check ran against fresh data.
 *
 * Only the fixed feed host is contacted; no user-supplied URL is ever fetched here, and nothing about the email leaves the Worker.
 */
import { ApiError } from './errors';
import { USER_AGENT } from './safeFetch';
import { cached } from './cache';
import { takeProviderBudget } from './ratelimit';
import type { Env } from './env';

export const OPENPHISH_FEED = 'https://openphish.com/feed.txt';
const MAX_BYTES = 6_000_000;
const MAX_LINES = 100_000;
const MAX_LINE = 2048;
const FRESH_MS = 30 * 60_000;

export interface OpenPhishIndex { fetchedAt: number; size: number; urls: Set<string>; hosts: Map<string, number> }
export interface OpenPhishFeed { index: OpenPhishIndex; stale: boolean }

let memo: OpenPhishIndex | null = null;
let inflight: Promise<OpenPhishIndex> | null = null;

/** Case-insensitive on scheme and host, ignores the fragment and a trailing slash; the path and query stay exact. */
export function feedKey(raw: string): string | null {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  u.hash = '';
  u.username = '';
  u.password = '';
  return u.toString().replace(/\/$/, '');
}

export function buildIndex(lines: string[], now = Date.now()): OpenPhishIndex {
  const urls = new Set<string>();
  const hosts = new Map<string, number>();
  for (const line of lines.slice(0, MAX_LINES)) {
    if (line.length > MAX_LINE) continue;
    const key = feedKey(line);
    if (!key) continue;
    urls.add(key);
    const host = new URL(key).hostname.toLowerCase();
    hosts.set(host, (hosts.get(host) ?? 0) + 1);
  }
  return { fetchedAt: now, size: urls.size, urls, hosts };
}

/** Exact listing, plus how many OTHER listed URLs share the host. */
export function matchFeed(index: OpenPhishIndex, url: string): { exact: boolean; hostMatches: number } {
  const key = feedKey(url);
  if (!key) return { exact: false, hostMatches: 0 };
  const exact = index.urls.has(key);
  const host = new URL(key).hostname.toLowerCase();
  const onHost = index.hosts.get(host) ?? 0;
  return { exact, hostMatches: exact ? Math.max(0, onHost - 1) : onHost };
}

function feedUrl(env: Env): string {
  // An operator may point this at a mirror or the commercial feed; it must still be https and is never user-controlled.
  const v = env.OPENPHISH_FEED_URL;
  if (v) { try { const u = new URL(v); if (u.protocol === 'https:') return u.toString(); } catch { /* fall through */ } }
  return OPENPHISH_FEED;
}

async function download(env: Env): Promise<string[]> {
  let res: Response;
  try {
    res = await fetch(feedUrl(env), { headers: { 'user-agent': USER_AGENT, accept: 'text/plain' }, signal: AbortSignal.timeout(8000) });
  } catch (e) {
    const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
    throw new ApiError(timeout ? 504 : 502, timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', timeout ? 'OpenPhish feed timed out.' : 'OpenPhish feed unreachable.');
  }
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `OpenPhish feed returned HTTP ${res.status}.`);

  // Bounded read: a truncated feed would silently miss entries, so an oversized one is an error, not a partial answer.
  const reader = res.body?.getReader();
  if (!reader) throw new ApiError(502, 'UPSTREAM_ERROR', 'OpenPhish feed returned no body.');
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_BYTES) { await reader.cancel().catch(() => undefined); throw new ApiError(502, 'UPSTREAM_ERROR', 'OpenPhish feed is larger than expected.'); }
    chunks.push(value);
  }
  const all = new Uint8Array(bytes);
  let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  const lines = new TextDecoder().decode(all).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) throw new ApiError(502, 'UPSTREAM_ERROR', 'OpenPhish feed was empty.');
  return lines;
}

export async function loadFeed(ctx: { env: Env; waitUntil(p: Promise<unknown>): void }, now = Date.now()): Promise<OpenPhishFeed> {
  if (memo && now - memo.fetchedAt < FRESH_MS) return { index: memo, stale: false };
  try {
    if (!inflight) {
      inflight = (async () => {
        // Shared across isolates where the Cache API stores entries; the budget is only spent on a real download.
        const { value } = await cached<{ fetchedAt: number; lines: string[] }>(ctx, 'openphish:feed', async () => {
          const budget = await takeProviderBudget(ctx.env, 'openphish', now);
          if (!budget.ok) throw new ApiError(502, 'PROVIDER_BUDGET', budget.why ?? 'OpenPhish download budget reached.');
          return { value: { fetchedAt: now, lines: await download(ctx.env) }, ttl: FRESH_MS / 1000 };
        });
        return buildIndex(value.lines, value.fetchedAt);
      })().finally(() => { inflight = null; });
    }
    memo = await inflight;
    return { index: memo, stale: false };
  } catch (e) {
    if (memo) return { index: memo, stale: true };
    throw e;
  }
}

/** Test hook. */
export function resetOpenPhishMemory(): void {
  memo = null;
  inflight = null;
}
