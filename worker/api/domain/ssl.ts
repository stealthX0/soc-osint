import { ok, route } from '../../_lib/respond';
import { ApiError } from '../../_lib/errors';
import { param, requireDomain } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { USER_AGENT } from '../../_lib/safeFetch';
import type { Env } from '../../_lib/env';
import type { CertEntry, CertResult } from '../../../shared/types';
import type { Issue } from '../../../shared/emailAuth';

type Source = 'ctlogs.dev' | 'crt.sh';

/** What either provider is reduced to before the shared analysis below. */
interface Fetched {
  source: Source;
  entries: CertEntry[];
  subdomains: string[] | null;
  wildcard: boolean;
  /** Extra findings the provider wants to report (history window, partial results). */
  issues: Issue[];
  /** Provider-specific part of the explanatory note. */
  scope: string;
}

const DAY = 86_400_000;
const parseUtc = (s: string) => Date.parse(/z$|[+-]\d\d:?\d\d$/i.test(s) ? s : `${s}Z`);
const issuerCN = (dn: string) => dn.match(/CN=([^,]+)/)?.[1]?.trim() ?? dn.match(/O=([^,]+)/)?.[1]?.trim() ?? dn;
const entryFor = (e: Omit<CertEntry, 'validNow' | 'daysRemaining' | 'notBefore' | 'notAfter'> & { nb: number; na: number }): CertEntry => {
  const now = Date.now();
  const { nb, na, ...rest } = e;
  return { ...rest, notBefore: new Date(nb).toISOString(), notAfter: new Date(na).toISOString(), validNow: nb <= now && na >= now, daysRemaining: Math.floor((na - now) / DAY) };
};

/* ---------------------------------------------------------------- ctlogs.dev (primary) */

const CTLOGS = 'https://api.ctlogs.dev/v1';
const CTLOGS_TIMEOUT_MS = 5_000;
const CERT_PAGES = 2; // 100 certificates per page, newest first
const HOST_PAGES = 3; // 100 hostnames per page

interface CtRow { id: string; match?: string; not_before: string; not_after: string; serial_hex: string; issuer?: string }
interface CtPage { rows?: CtRow[] | null; hosts?: { host: string }[] | null; has_next?: boolean; next_cursor?: string; history_window_days?: number; history_truncated?: boolean }

async function ctGet(path: string, key: string | undefined): Promise<CtPage> {
  const headers: Record<string, string> = { 'user-agent': USER_AGENT, accept: 'application/json' };
  if (key) headers.authorization = `Bearer ${key}`;
  const res = await fetch(`${CTLOGS}${path}`, { headers, signal: AbortSignal.timeout(CTLOGS_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = (await res.json()) as CtPage;
  if (!json || typeof json !== 'object') throw new Error('unexpected response');
  return json;
}

/** Follows next_cursor for up to `max` pages. Any failure throws, so the caller can fall back to crt.sh. */
async function ctPaged(path: string, key: string | undefined, max: number) {
  const pages: CtPage[] = [];
  let cursor = '';
  for (let i = 0; i < max; i++) {
    const page = await ctGet(cursor ? `${path}${path.includes('?') ? '&' : '?'}after=${encodeURIComponent(cursor)}` : path, key);
    if (!('rows' in page) && !('hosts' in page)) throw new Error('unexpected response');
    pages.push(page);
    if (!page.has_next || !page.next_cursor) break;
    cursor = page.next_cursor;
  }
  const last = pages[pages.length - 1];
  return { pages, more: !!(last.has_next && last.next_cursor), first: pages[0] };
}

async function fromCtlogs(domain: string, wantSubs: boolean, key: string | undefined): Promise<Fetched> {
  const enc = encodeURIComponent(domain);
  const certs = await ctPaged(`/domain/${enc}`, key, CERT_PAGES);
  const seen = new Set<string>();
  const entries: CertEntry[] = [];
  for (const row of certs.pages.flatMap((p) => p.rows ?? [])) {
    if (seen.has(row.id)) continue;
    seen.add(row.id);
    const nb = Date.parse(row.not_before);
    const na = Date.parse(row.not_after);
    if (!Number.isFinite(nb) || !Number.isFinite(na)) continue;
    const name = (row.match ?? domain).toLowerCase();
    entries.push(entryFor({ id: row.id, commonName: name, names: [name], issuer: row.issuer || 'Unknown', serial: row.serial_hex, loggedAt: null, nb, na }));
  }

  let subdomains: string[] | null = null;
  let wildcard: boolean;
  let hostsMore = false;
  if (wantSubs) {
    const hosts = await ctPaged(`/hosts/${enc}`, key, HOST_PAGES);
    const names = new Set(hosts.pages.flatMap((p) => p.hosts ?? []).map((h) => h.host.toLowerCase()));
    wildcard = names.has(`*.${domain}`);
    subdomains = [...names].sort().slice(0, 1000);
    hostsMore = hosts.more;
  } else {
    wildcard = ((await ctGet(`/domain/${encodeURIComponent(`*.${domain}`)}`, key)).rows ?? []).length > 0;
  }

  const issues: Issue[] = [];
  const days = certs.first.history_window_days;
  if (certs.first.history_truncated) issues.push({ level: 'info', message: `Older certificates exist beyond ctlogs.dev's ${days ?? 90}-day expiry window. crt.sh has the full history.` });
  if (certs.more) issues.push({ level: 'info', message: `Showing the newest ${entries.length} certificates; more are logged for this name.` });
  if (hostsMore) issues.push({ level: 'info', message: 'The subdomain list is capped; more hostnames have certificates under this domain.' });
  return {
    source: 'ctlogs.dev', entries, subdomains, wildcard, issues,
    scope: days ? `ctlogs.dev; certificates valid now or expired within the last ${days} days` : 'ctlogs.dev',
  };
}

/* ---------------------------------------------------------------- crt.sh (fallback) */

interface CrtRow { id: number; issuer_name: string; common_name: string; name_value: string; not_before: string; not_after: string; serial_number: string; entry_timestamp?: string }

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

async function fromCrt(domain: string, wantSubs: boolean): Promise<Fetched> {
  const rows = await crt(wantSubs ? `%.${domain}` : domain);
  const bySerial = new Map<string, CrtRow>();
  for (const r of rows) {
    const key = `${r.issuer_name}|${r.serial_number}`;
    const prev = bySerial.get(key);
    if (!prev || r.id > prev.id) bySerial.set(key, r);
  }
  const unique = [...bySerial.values()];
  const toEntry = (r: CrtRow): CertEntry => entryFor({
    id: r.id,
    commonName: r.common_name,
    names: [...new Set(r.name_value.split('\n').map((n) => n.trim().toLowerCase()).filter(Boolean))],
    issuer: issuerCN(r.issuer_name),
    serial: r.serial_number,
    loggedAt: r.entry_timestamp ? new Date(parseUtc(r.entry_timestamp)).toISOString() : null,
    nb: parseUtc(r.not_before),
    na: parseUtc(r.not_after),
  });
  const exactRows = wantSubs ? unique.filter((r) => r.name_value.toLowerCase().split('\n').some((n) => n === domain || n === `*.${domain}`)) : unique;
  const entries = exactRows.map(toEntry);

  let subdomains: string[] | null = null;
  if (wantSubs) {
    const set = new Set<string>();
    for (const r of unique) for (const n of r.name_value.toLowerCase().split('\n')) if (n.endsWith(`.${domain}`) || n === domain) set.add(n.trim());
    subdomains = [...set].sort().slice(0, 1000);
  }
  return { source: 'crt.sh', entries, subdomains, wildcard: entries.some((e) => e.names.includes(`*.${domain}`)), issues: [], scope: 'crt.sh' };
}

/**
 * GET /api/domain/ssl?domain=example.com[&subdomains=1]
 *
 * Workers cannot open raw TLS sockets, so this reads the public Certificate Transparency logs rather
 * than handshaking with the server. ctlogs.dev is the primary source (fast, uses CTLOGS_API_KEY when set);
 * if it errors, times out or is rate limited, crt.sh answers instead. The result says which one was used.
 * It shows what CAs have issued for the domain, not necessarily what the server currently presents;
 * /api/domain/http confirms HTTPS works.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const domain = requireDomain(url);
  const wantSubs = param(url, 'subdomains', 2) === '1';
  const key = (ctx.env as Env).CTLOGS_API_KEY?.trim() || undefined;

  const { value, hit } = await cached(ctx, `ct2:${domain}:${wantSubs ? 's' : 'c'}`, async () => {
    let data: Fetched;
    let fellBack: string | null = null;
    try {
      data = await fromCtlogs(domain, wantSubs, key);
    } catch (e) {
      fellBack = e instanceof Error && e.name === 'TimeoutError' ? 'timed out' : e instanceof Error ? e.message : 'failed';
      console.warn(`ctlogs.dev unavailable for ${domain}: ${fellBack}`);
      try {
        data = await fromCrt(domain, wantSubs);
      } catch (e2) {
        if (e2 instanceof ApiError) throw new ApiError(e2.status, e2.code, `ctlogs.dev (${fellBack}) and ${e2.message}`);
        throw e2;
      }
    }

    const entries = data.entries.sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore));
    const active = entries.filter((e) => e.validNow);
    const issuerCount = new Map<string, number>();
    for (const e of entries) issuerCount.set(e.issuer, (issuerCount.get(e.issuer) ?? 0) + 1);

    const issues: Issue[] = [];
    if (fellBack) issues.push({ level: 'info', message: `ctlogs.dev was unavailable (${fellBack}), so this result comes from crt.sh.` });
    if (!entries.length) issues.push({ level: 'info', message: 'No certificates found in Certificate Transparency logs for this exact name.' });
    else if (!active.length) issues.push({ level: 'warn', message: 'No currently valid certificate is logged for this name; the site may not use HTTPS, or issuance is not logged.' });
    else {
      const soonest = Math.min(...active.map((e) => e.daysRemaining));
      if (soonest < 14) issues.push({ level: 'warn', message: `Newest valid certificate expires in ${soonest} day(s).` });
    }
    const recent = entries.filter((e) => Date.now() - Date.parse(e.notBefore) < 7 * DAY).length;
    if (recent >= 5) issues.push({ level: 'info', message: `${recent} certificates were issued in the last 7 days; check for unexpected issuance.` });
    issues.push(...data.issues);

    const out: CertResult = {
      domain,
      source: data.source,
      total: entries.length,
      active: active.length,
      certificates: entries.slice(0, 30),
      issuers: [...issuerCount].map(([issuer, count]) => ({ issuer, count })).sort((a, b) => b.count - a.count).slice(0, 8),
      subdomains: data.subdomains,
      wildcard: data.wildcard,
      note: `Data comes from public Certificate Transparency logs (${data.scope}), not a live TLS handshake.`,
      issues,
    };
    // A fallback answer is cached briefly so the primary source is retried soon.
    return { value: out, ttl: fellBack ? 300 : 900 };
  });
  return ok(value, { cached: hit });
});
