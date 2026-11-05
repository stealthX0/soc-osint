/**
 * Redirect-chain tracer for URL intelligence. Every hop is SSRF-checked (assertPublicTarget) before it is requested.
 * Bodies are never read: the response is cancelled as soon as the headers arrive. Unlike safeFetch it keeps the hops
 * collected so far when a later hop fails, because a half-resolved chain is still evidence.
 */
import { ApiError } from './errors';
import { USER_AGENT, assertPublicTarget } from './safeFetch';
import type { UrlTraceHop } from '../../shared/types';

export interface TraceResult { hops: UrlTraceHop[]; finalUrl: string | null; error?: string }

export async function traceUrl(start: string, opts: { maxHops?: number; timeoutMs?: number } = {}): Promise<TraceResult> {
  const { maxHops = 8, timeoutMs = 10_000 } = opts;
  const deadline = Date.now() + timeoutMs;
  const hops: UrlTraceHop[] = [];
  const seen = new Set<string>();
  let current = start;

  for (let i = 0; i < maxHops; i++) {
    if (seen.has(current)) return { hops, finalUrl: current, error: 'Redirect loop detected.' };
    seen.add(current);

    let target: { url: URL; addresses: string[] };
    try {
      target = await assertPublicTarget(current);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : 'Target not allowed.';
      hops.push({ url: current, status: null, location: null, ip: null, ms: 0, contentType: null, download: false, error: msg });
      return { hops, finalUrl: null, error: msg };
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) return { hops, finalUrl: current, error: 'Trace exceeded the time budget.' };

    const t0 = Date.now();
    let res: Response;
    try {
      res = await fetch(target.url.toString(), {
        method: 'GET',
        redirect: 'manual',
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,*/*;q=0.8' },
        signal: AbortSignal.timeout(remaining),
      });
    } catch (e) {
      const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
      const msg = timeout ? 'The server did not respond in time.' : 'Could not connect to the server.';
      hops.push({ url: target.url.toString(), status: null, location: null, ip: target.addresses[0] ?? null, ms: Date.now() - t0, contentType: null, download: false, error: msg });
      return { hops, finalUrl: null, error: msg };
    }
    await res.body?.cancel().catch(() => undefined);

    const location = res.headers.get('location');
    const contentType = res.headers.get('content-type')?.split(';')[0].trim().toLowerCase() ?? null;
    const disposition = res.headers.get('content-disposition') ?? '';
    const download = /attachment/i.test(disposition) || (!!contentType && /^application\/(x-msdownload|x-dosexec|x-msdos-program|vnd\.microsoft\.portable-executable|x-msi|java-archive|vnd\.android\.package-archive)$/.test(contentType));
    hops.push({ url: target.url.toString(), status: res.status, location, ip: target.addresses[0] ?? null, ms: Date.now() - t0, contentType, download });

    if (res.status >= 300 && res.status < 400 && location) {
      let next: URL;
      try {
        next = new URL(location, target.url);
      } catch {
        return { hops, finalUrl: target.url.toString(), error: 'The server sent an invalid redirect location.' };
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return { hops, finalUrl: target.url.toString(), error: `Redirects to a non-web scheme (${next.protocol.replace(':', '')}).` };
      }
      next.hash = '';
      current = next.toString();
      continue;
    }
    return { hops, finalUrl: target.url.toString() };
  }
  return { hops, finalUrl: current, error: `Stopped after ${maxHops} redirects.` };
}
