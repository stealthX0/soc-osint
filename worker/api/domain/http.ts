import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { safeFetch } from '../../_lib/safeFetch';
import { normalizeHostname } from '../../../shared/domain';
import { auditSecurityHeaders, parseSetCookie } from '../../../shared/security';
import type { HttpCheck } from '../../../shared/types';
import type { Issue } from '../../../shared/emailAuth';

/**
 * GET /api/domain/http?target=example.com
 * Follows redirects (max 5, each hop re-validated against the SSRF guard), then audits security headers.
 * This sends real requests to the target from Cloudflare's network: it is an ACTIVE check.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const raw = param(url, 'target', 2048);
  if (!raw) throw badInput('Missing "target" parameter.');
  const host = normalizeHostname(raw);
  if (!host) throw badInput('Target must be a hostname or domain (IP addresses and internal names are not accepted here).');

  const { value, hit } = await cached(ctx, `http:${host}`, async () => {
    const issues: Issue[] = [];
    // Primary: HTTPS. Secondary: does plain HTTP upgrade to HTTPS?
    const [https, http] = await Promise.allSettled([
      safeFetch(`https://${host}/`, { maxRedirects: 5, timeoutMs: 9000 }),
      safeFetch(`http://${host}/`, { maxRedirects: 0, timeoutMs: 6000, method: 'HEAD' }),
    ]);

    let main = https.status === 'fulfilled' ? https.value : null;
    let httpsReachable = !!main;
    if (!main) {
      // fall back to plain HTTP so we can still report what the server does
      const fb = await safeFetch(`http://${host}/`, { maxRedirects: 5, timeoutMs: 8000 }).catch(() => null);
      if (!fb) {
        const reason = https.status === 'rejected' ? https.reason : null;
        if (reason instanceof ApiError && (reason.code === 'TARGET_NOT_ALLOWED' || reason.code === 'DOES_NOT_RESOLVE')) throw reason;
        throw new ApiError(502, 'UPSTREAM_ERROR', `Could not connect to ${host} over HTTPS or HTTP.`);
      }
      main = fb;
      httpsReachable = fb.finalUrl.startsWith('https:');
    }

    let httpUpgrades: boolean | null = null;
    if (http.status === 'fulfilled') {
      const r = http.value.response;
      httpUpgrades = r.status >= 300 && r.status < 400 && /^https:\/\//i.test(r.headers.get('location') ?? '');
      if (!httpUpgrades && r.status < 400) issues.push({ level: 'warn', message: 'Plain HTTP is served without redirecting to HTTPS.' });
    }

    const res = main.response;
    const finalIsHttps = main.finalUrl.startsWith('https:');
    const audit = auditSecurityHeaders((n) => res.headers.get(n), finalIsHttps);
    const setCookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
    const cookies = parseSetCookie(setCookies);
    for (const c of cookies) {
      if (finalIsHttps && !c.secure) issues.push({ level: 'warn', message: `Cookie "${c.name}" lacks the Secure flag.` });
      if (!c.httpOnly) issues.push({ level: 'info', message: `Cookie "${c.name}" lacks HttpOnly (fine if JavaScript needs it).` });
    }
    if (main.hops.length > 3) issues.push({ level: 'info', message: `Redirect chain has ${main.hops.length} hops.` });
    issues.push(...audit.issues);

    const out: HttpCheck = {
      target: host,
      finalUrl: main.finalUrl,
      status: res.status,
      httpsReachable,
      httpUpgradesToHttps: httpUpgrades,
      chain: main.hops.map((h) => ({ url: h.url, status: h.status, location: h.location, ttfbMs: h.ttfbMs, ip: h.ip })),
      totalMs: main.totalMs,
      server: audit.disclosure,
      contentType: res.headers.get('content-type'),
      audit,
      cookies,
      addresses: main.addresses,
      issues,
    };
    return { value: out, ttl: 120 };
  });
  return ok(value, { cached: hit });
});
