/**
 * SSRF-hardened outbound fetch used by every endpoint that touches a user-supplied host.
 *
 * Defences:
 *  - http/https only, no credentials in the URL, a small allow-list of ports
 *  - IP-literal and DNS-resolved targets must all be globally routable (no RFC1918, loopback,
 *    link-local, CGNAT, multicast, documentation or reserved ranges, including IPv4-mapped IPv6)
 *  - redirects are followed manually and every hop is re-validated
 *  - hard timeout, redirect cap and response-size cap
 *
 * Residual risk: DNS can change between our check and the connection (rebinding). Workers cannot
 * reach private networks from Cloudflare's edge, which bounds the impact; keep this guard anyway.
 */
import { ApiError } from './errors';
import { resolve } from './doh';
import { classifyIP, parseIP } from '../../shared/ip';
import { isValidHostname } from '../../shared/domain';

const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
const BLOCKED_SUFFIX = /\.(local|localhost|internal|lan|home|corp|intranet|private|arpa|onion)$/i;

export const USER_AGENT = 'Spectrix/1.0 (passive-network-diagnostics)';

export async function resolveAddresses(host: string): Promise<string[]> {
  const [a, aaaa] = await Promise.allSettled([resolve(host, 'A'), resolve(host, 'AAAA')]);
  const out: string[] = [];
  for (const r of [a, aaaa]) {
    if (r.status === 'fulfilled') {
      for (const rec of r.value.answers) if ((rec.type === 'A' || rec.type === 'AAAA') && parseIP(rec.data)) out.push(rec.data);
    }
  }
  if (!out.length && a.status === 'rejected' && aaaa.status === 'rejected') {
    throw new ApiError(502, 'UPSTREAM_ERROR', 'DNS resolution failed for the target.');
  }
  return out;
}

export async function assertPublicTarget(rawUrl: string): Promise<{ url: URL; addresses: string[] }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ApiError(400, 'INVALID_URL', 'That is not a valid URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new ApiError(400, 'INVALID_URL', 'Only http and https targets are allowed.');
  if (url.username || url.password) throw new ApiError(400, 'INVALID_URL', 'Credentials in URLs are not allowed.');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) throw new ApiError(403, 'TARGET_NOT_ALLOWED', `Port ${port} is not allowed (use 80, 443, 8080 or 8443).`);

  const host = url.hostname.replace(/^\[|\]$/g, '');
  // The URL parser already canonicalises "2130706433", "0x7f.1" etc. to dotted form
  if (parseIP(host)) {
    if (!classifyIP(host)?.public) throw new ApiError(403, 'TARGET_NOT_ALLOWED', 'Target is a private, reserved or internal address.');
    return { url, addresses: [host] };
  }
  if (host === 'localhost' || BLOCKED_SUFFIX.test(host) || !host.includes('.') || !isValidHostname(host)) {
    throw new ApiError(403, 'TARGET_NOT_ALLOWED', 'Target hostname is not a public internet name.');
  }
  const addresses = await resolveAddresses(host);
  if (!addresses.length) throw new ApiError(422, 'DOES_NOT_RESOLVE', `${host} has no A/AAAA records.`);
  if (addresses.some((a) => !classifyIP(a)?.public)) {
    throw new ApiError(403, 'TARGET_NOT_ALLOWED', `${host} resolves to a private or reserved address.`);
  }
  return { url, addresses };
}

export interface Hop {
  url: string;
  status: number;
  statusText: string;
  location: string | null;
  ip: string | null;
  /** ms from request start to response headers */
  ttfbMs: number;
}

export interface SafeFetchResult {
  response: Response;
  hops: Hop[];
  finalUrl: string;
  /** ms from first request to last byte read (capped body) */
  totalMs: number;
  bytesRead: number;
  addresses: string[];
}

export interface SafeFetchOptions {
  method?: 'GET' | 'HEAD';
  /** 0 = never follow (return the 3xx response); N = follow up to N hops then fail. */
  maxRedirects?: number;
  timeoutMs?: number;
  maxBytes?: number;
}

export async function safeFetch(rawUrl: string, opts: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const { method = 'GET', maxRedirects = 5, timeoutMs = 8000, maxBytes = 65_536 } = opts;
  const started = Date.now();
  const deadline = started + timeoutMs;
  const hops: Hop[] = [];
  let current = rawUrl;

  for (let i = 0; i <= maxRedirects; i++) {
    const { url, addresses } = await assertPublicTarget(current);
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new ApiError(504, 'UPSTREAM_TIMEOUT', 'Request exceeded the time budget.');

    const t0 = Date.now();
    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method,
        redirect: 'manual',
        headers: { 'user-agent': USER_AGENT, accept: '*/*' },
        signal: AbortSignal.timeout(remaining),
      });
    } catch (e) {
      const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
      throw new ApiError(timeout ? 504 : 502, timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', timeout ? 'The target did not respond in time.' : 'Could not connect to the target.');
    }
    const location = response.headers.get('location');
    hops.push({ url: url.toString(), status: response.status, statusText: response.statusText, location, ip: addresses[0] ?? null, ttfbMs: Date.now() - t0 });

    // maxRedirects === 0 means "do not follow": the 3xx response itself is returned to the caller
    if (maxRedirects > 0 && response.status >= 300 && response.status < 400 && location) {
      await response.body?.cancel();
      if (i === maxRedirects) throw new ApiError(502, 'UPSTREAM_ERROR', `Too many redirects (more than ${maxRedirects}).`);
      try {
        current = new URL(location, url).toString();
      } catch {
        throw new ApiError(502, 'UPSTREAM_ERROR', 'Target sent an invalid redirect location.');
      }
      continue;
    }

    // read a bounded amount of the body so total time reflects a real transfer
    let bytesRead = 0;
    if (response.body && method === 'GET') {
      const reader = response.body.getReader();
      try {
        while (bytesRead < maxBytes) {
          const { done, value } = await reader.read();
          if (done) break;
          bytesRead += value.byteLength;
        }
      } catch { /* mid-body failure: keep what we have */ }
      await reader.cancel().catch(() => undefined);
    }
    return { response, hops, finalUrl: url.toString(), totalMs: Date.now() - started, bytesRead, addresses };
  }
  throw new ApiError(502, 'UPSTREAM_ERROR', 'Redirect handling failed.');
}

/** Fetches JSON from a trusted third-party API (fixed host, never user-controlled). */
export async function fetchJson<T>(url: string, init: { headers?: Record<string, string>; timeoutMs?: number } = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...init.headers }, signal: AbortSignal.timeout(init.timeoutMs ?? 6000) });
  } catch (e) {
    const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
    throw new ApiError(timeout ? 504 : 502, timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', timeout ? 'Upstream provider timed out.' : 'Upstream provider unreachable.');
  }
  if (res.status === 404) throw new ApiError(404, 'NOT_FOUND', 'Upstream provider has no data for this query.');
  if (res.status === 429) throw new ApiError(502, 'UPSTREAM_ERROR', 'Upstream provider rate limit reached; try again later.');
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `Upstream provider returned HTTP ${res.status}.`);
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(502, 'UPSTREAM_ERROR', 'Upstream provider returned a malformed response.');
  }
}
