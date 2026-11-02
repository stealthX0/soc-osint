import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { intParam, param } from '../../_lib/input';
import { safeFetch } from '../../_lib/safeFetch';
import { normalizeHostname } from '../../../shared/domain';
import { ipVersion } from '../../../shared/ip';
import type { LatencyResult, LatencySample } from '../../../shared/types';

/**
 * GET /api/network/latency?target=example.com[&samples=3][&scheme=https]
 *
 * HTTP-level latency measured from the Cloudflare data centre serving this request.
 * Workers cannot send ICMP pings or open raw TCP sockets, so this is time-to-first-byte,
 * not ICMP RTT. Samples run sequentially to avoid hammering the target. ACTIVE check.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const raw = param(url, 'target', 2048);
  if (!raw) throw badInput('Missing "target" parameter.');
  const host = normalizeHostname(raw) ?? (ipVersion(raw.replace(/^\[|\]$/g, '')) ? raw.replace(/^\[|\]$/g, '') : null);
  if (!host) throw badInput('Target must be a hostname, domain or public IP address.');
  const samples = intParam(url, 'samples', 3, 1, 5);
  const scheme = param(url, 'scheme', 5) === 'http' ? 'http' : 'https';
  const authority = ipVersion(host) === 6 ? `[${host}]` : host;

  const out: LatencySample[] = [];
  let address: string | null = null;
  for (let i = 0; i < samples; i++) {
    try {
      const r = await safeFetch(`${scheme}://${authority}/`, { maxRedirects: 0, timeoutMs: 6000, maxBytes: 16_384 });
      address ??= r.addresses[0] ?? null;
      out.push({ ok: true, status: r.response.status, ttfbMs: r.hops[0]?.ttfbMs ?? 0, totalMs: r.totalMs });
    } catch (e) {
      // policy errors (private target etc.) should surface immediately rather than as 5 failed samples
      if (e instanceof ApiError && ['TARGET_NOT_ALLOWED', 'DOES_NOT_RESOLVE', 'INVALID_URL'].includes(e.code)) throw e;
      out.push({ ok: false, error: e instanceof Error ? e.message : 'failed' });
    }
  }

  const times = out.filter((s) => s.ok).map((s) => s.ttfbMs!);
  let stats: LatencyResult['stats'] = null;
  if (times.length) {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const jitter = times.length > 1 ? times.slice(1).reduce((s, t, i) => s + Math.abs(t - times[i]), 0) / (times.length - 1) : 0;
    stats = { min: Math.min(...times), avg: Math.round(avg), max: Math.max(...times), jitter: Math.round(jitter), successRate: Math.round((times.length / out.length) * 100) };
  }
  const cf = (ctx.request as unknown as { cf?: { colo?: string; country?: string } }).cf;
  const data: LatencyResult = {
    target: host, address, samples: out, stats,
    vantage: { colo: cf?.colo ?? null, country: cf?.country ?? null, note: 'Measured from the Cloudflare data centre that handled your request, as HTTP time-to-first-byte (not ICMP ping).' },
  };
  return ok(data);
});
