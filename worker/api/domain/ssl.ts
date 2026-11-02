import { ok, route } from '../../_lib/respond';
import { ApiError } from '../../_lib/errors';
import { param, requireDomain } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { USER_AGENT } from '../../_lib/safeFetch';
import type { CertEntry, CertResult } from '../../../shared/types';
import type { Issue } from '../../../shared/emailAuth';

interface CrtRow { id: number; issuer_name: string; common_name: string; name_value: string; not_before: string; not_after: string; serial_number: string; entry_timestamp?: string }

const parseUtc = (s: string) => Date.parse(/z$|[+-]\d\d:?\d\d$/i.test(s) ? s : `${s}Z`);
const issuerCN = (dn: string) => dn.match(/CN=([^,]+)/)?.[1]?.trim() ?? dn.match(/O=([^,]+)/)?.[1]?.trim() ?? dn;

async function crt(query: string): Promise<CrtRow[]> {
  let res: Response;
  try {
    res = await fetch(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(12_000) });
  } catch {
    throw new ApiError(504, 'UPSTREAM_TIMEOUT', 'crt.sh (Certificate Transparency search) did not respond in time. It is often slow; retry in a moment.');
  }
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `crt.sh returned HTTP ${res.status}.`);
  const text = await res.text();
  if (!text.trim()) return [];
  try {
    return JSON.parse(text) as CrtRow[];
  } catch {
    throw new ApiError(502, 'UPSTREAM_ERROR', 'crt.sh returned an unexpected response; retry shortly.');
  }
}

/**
 * GET /api/domain/ssl?domain=example.com[&subdomains=1]
 *
 * Workers cannot open raw TLS sockets, so this reads the public Certificate Transparency logs
 * (via crt.sh) rather than handshaking with the server. It shows what CAs have issued for the
 * domain, not necessarily what the server currently presents; /api/domain/http confirms HTTPS works.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const domain = requireDomain(url);
  const wantSubs = param(url, 'subdomains', 2) === '1';

  const { value, hit } = await cached(ctx, `ct:${domain}:${wantSubs ? 's' : 'c'}`, async () => {
    const rows = await crt(wantSubs ? `%.${domain}` : domain);
    const now = Date.now();

    const bySerial = new Map<string, CrtRow>();
    for (const r of rows) {
      const key = `${r.issuer_name}|${r.serial_number}`;
      const prev = bySerial.get(key);
      if (!prev || r.id > prev.id) bySerial.set(key, r);
    }
    const unique = [...bySerial.values()];
    const toEntry = (r: CrtRow): CertEntry => {
      const nb = parseUtc(r.not_before);
      const na = parseUtc(r.not_after);
      return {
        id: r.id,
        commonName: r.common_name,
        names: [...new Set(r.name_value.split('\n').map((n) => n.trim().toLowerCase()).filter(Boolean))],
        issuer: issuerCN(r.issuer_name),
        notBefore: new Date(nb).toISOString(),
        notAfter: new Date(na).toISOString(),
        serial: r.serial_number,
        loggedAt: r.entry_timestamp ? new Date(parseUtc(r.entry_timestamp)).toISOString() : null,
        validNow: nb <= now && na >= now,
        daysRemaining: Math.floor((na - now) / 86_400_000),
      };
    };

    const exactRows = wantSubs ? unique.filter((r) => r.name_value.toLowerCase().split('\n').some((n) => n === domain || n === `*.${domain}`)) : unique;
    const entries = exactRows.map(toEntry).sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore));
    const active = entries.filter((e) => e.validNow);

    const issuerCount = new Map<string, number>();
    for (const e of entries) issuerCount.set(e.issuer, (issuerCount.get(e.issuer) ?? 0) + 1);

    let subdomains: string[] | null = null;
    if (wantSubs) {
      const set = new Set<string>();
      for (const r of unique) for (const n of r.name_value.toLowerCase().split('\n')) if (n.endsWith(`.${domain}`) || n === domain) set.add(n.trim());
      subdomains = [...set].sort().slice(0, 1000);
    }

    const issues: Issue[] = [];
    if (!entries.length) issues.push({ level: 'info', message: 'No certificates found in Certificate Transparency logs for this exact name.' });
    else if (!active.length) issues.push({ level: 'warn', message: 'No currently valid certificate is logged for this name; the site may not use HTTPS, or issuance is not logged.' });
    else {
      const soonest = Math.min(...active.map((e) => e.daysRemaining));
      if (soonest < 14) issues.push({ level: 'warn', message: `Newest valid certificate expires in ${soonest} day(s).` });
    }
    const recent = entries.filter((e) => Date.now() - Date.parse(e.notBefore) < 7 * 86_400_000).length;
    if (recent >= 5) issues.push({ level: 'info', message: `${recent} certificates were issued in the last 7 days; check for unexpected issuance.` });

    const out: CertResult = {
      domain,
      total: entries.length,
      active: active.length,
      certificates: entries.slice(0, 30),
      issuers: [...issuerCount].map(([issuer, count]) => ({ issuer, count })).sort((a, b) => b.count - a.count).slice(0, 8),
      subdomains,
      wildcard: entries.some((e) => e.names.includes(`*.${domain}`)),
      note: 'Data comes from public Certificate Transparency logs (crt.sh), not a live TLS handshake.',
      issues,
    };
    return { value: out, ttl: 900 };
  });
  return ok(value, { cached: hit });
});
