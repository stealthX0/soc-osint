import { ok, route } from '../../_lib/respond';
import { ApiError } from '../../_lib/errors';
import { requireDomain } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { USER_AGENT } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import type { Env } from '../../_lib/env';
import type { WhoisResult } from '../../../shared/types';
import type { Issue } from '../../../shared/emailAuth';

interface Rdap {
  ldhName?: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  nameservers?: { ldhName?: string }[];
  secureDNS?: { delegationSigned?: boolean };
  entities?: RdapEntity[];
  links?: { rel?: string; href?: string }[];
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, [string, unknown, string, unknown][]];
  publicIds?: { type: string; identifier: string }[];
  entities?: RdapEntity[];
}

const vcard = (e: RdapEntity | undefined, field: string): string | null => {
  const hit = e?.vcardArray?.[1]?.find((f) => f[0] === field);
  const v = hit?.[3];
  if (Array.isArray(v)) return v.filter(Boolean).join(', ') || null; // adr is an array
  return typeof v === 'string' && v.trim() ? v.trim() : null;
};

const NO_RDAP: Issue = { level: 'info', message: 'No RDAP record: the domain is unregistered, or its TLD does not publish RDAP data.' };

const days = (iso: string | null, sign: 1 | -1) => (iso && !Number.isNaN(Date.parse(iso)) ? Math.floor((sign * (Date.parse(iso) - Date.now())) / 86_400_000) : null);

/** Registration-age / expiry / status findings shared by both data sources. */
function findings(ageDays: number | null, daysToExpiry: number | null, status: string[], dnssec: boolean | null): Issue[] {
  const issues: Issue[] = [];
  if (ageDays !== null && ageDays < 30) issues.push({ level: 'warn', message: `Domain was registered only ${ageDays} day(s) ago. Newly registered domains are over-represented in phishing.` });
  else if (ageDays !== null && ageDays < 180) issues.push({ level: 'info', message: `Domain is relatively new (${ageDays} days old).` });
  if (daysToExpiry !== null && daysToExpiry < 0) issues.push({ level: 'error', message: 'Registration has expired.' });
  else if (daysToExpiry !== null && daysToExpiry < 30) issues.push({ level: 'warn', message: `Registration expires in ${daysToExpiry} day(s).` });
  if (status.some((s) => /transfer ?prohibited/i.test(s)) === false && status.length) issues.push({ level: 'info', message: 'No transfer lock (clientTransferProhibited) is set.' });
  if (status.some((s) => /hold/i.test(s))) issues.push({ level: 'warn', message: 'Domain is on hold, so it may not resolve.' });
  if (dnssec === false) issues.push({ level: 'info', message: 'DNSSEC is not enabled for this domain.' });
  return issues;
}

type Primary = { kind: 'found'; out: WhoisResult } | { kind: 'none' } | { kind: 'error'; error: ApiError };

/** Primary source: RDAP through rdap.org (registry data, free, no key). */
async function fromRdap(domain: string): Promise<Primary> {
  let res: Response;
  try {
    res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json, application/json', 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(8000),
      redirect: 'follow',
    });
  } catch {
    return { kind: 'error', error: new ApiError(504, 'UPSTREAM_TIMEOUT', 'The RDAP service did not respond in time.') };
  }
  if (res.status === 404) return { kind: 'none' };
  if (!res.ok) return { kind: 'error', error: new ApiError(502, 'UPSTREAM_ERROR', `RDAP service returned HTTP ${res.status}.`) };
  let r: Rdap;
  try { r = (await res.json()) as Rdap; } catch { return { kind: 'error', error: new ApiError(502, 'UPSTREAM_ERROR', 'RDAP service returned an unreadable response.') }; }

  const event = (a: string) => r.events?.find((e) => e.eventAction === a)?.eventDate ?? null;
  const registrarEnt = r.entities?.find((e) => e.roles?.includes('registrar'));
  const abuse = registrarEnt?.entities?.find((e) => e.roles?.includes('abuse'));
  const dates = { registered: event('registration'), updated: event('last changed'), expires: event('expiration') };
  const ageDays = days(dates.registered, -1);
  const daysToExpiry = days(dates.expires, 1);
  const status = r.status ?? [];
  const dnssecSigned = r.secureDNS?.delegationSigned ?? null;

  return {
    kind: 'found',
    out: {
      domain: r.ldhName?.toLowerCase() ?? domain,
      registered: true,
      source: 'rdap',
      registrar: registrarEnt
        ? {
            name: vcard(registrarEnt, 'fn'),
            ianaId: registrarEnt.publicIds?.find((p) => /iana/i.test(p.type))?.identifier ?? null,
            url: r.links?.find((l) => l.rel === 'related')?.href ?? null,
            abuseEmail: vcard(abuse, 'email'),
            abusePhone: vcard(abuse, 'tel')?.replace(/^tel:/, '') ?? null,
          }
        : null,
      dates, ageDays, daysToExpiry, status,
      nameservers: (r.nameservers ?? []).map((n) => (n.ldhName ?? '').toLowerCase()).filter(Boolean).sort(),
      dnssecSigned,
      rdapUrl: r.links?.find((l) => l.rel === 'self')?.href ?? null,
      issues: findings(ageDays, daysToExpiry, status, r.secureDNS?.delegationSigned === false ? false : null),
    },
  };
}

/* ------------------------------------------------ fallback: APILayer WHOIS */

/** First non-empty value among the candidate keys (the response is read defensively: field names vary by TLD/registry). */
const pick = (o: Record<string, unknown>, ...keys: string[]): unknown => {
  for (const k of keys) { const v = o[k]; if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length)) return v; }
  return undefined;
};
const asStr = (v: unknown): string | null => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === 'string' && x.trim() ? x.trim() : null;
};
const asList = (v: unknown): string[] => {
  const a = Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[\s,;\n]+/) : [];
  return a.filter((x): x is string => typeof x === 'string').map((x) => x.trim()).filter(Boolean);
};
/** WHOIS dates come as "1997-09-15 04:00:00" (UTC, no zone), ISO strings, or arrays of either. Returns ISO or null. */
export function whoisDate(v: unknown): string | null {
  const raw = asStr(Array.isArray(v) ? [...v].sort()[0] : v);
  if (!raw) return null;
  let t = raw.replace(/\s*\(.*?\)\s*$/, '');
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/.test(t)) t = t.replace(' ', 'T') + 'Z';
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

/** Fallback source: APILayer WHOIS (used only when RDAP has no record or fails). Returns null when it cannot answer. */
async function fromApiLayer(env: Env, domain: string): Promise<{ out: WhoisResult } | { error: string }> {
  const key = env.APILAYER_API_KEY;
  if (!key) return { error: 'not configured' };
  const budget = await takeProviderBudget(env, 'apilayer');
  if (!budget.ok) return { error: budget.why ?? 'budget reached' };

  let res: Response;
  try {
    res = await fetch(`https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domain)}`, {
      headers: { apikey: key, accept: 'application/json', 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(10_000),
    });
  } catch { return { error: 'timed out' }; }
  if (res.status === 401 || res.status === 403) return { error: 'the API key was rejected' };
  if (res.status === 429) return { error: 'the provider quota is exhausted' };
  if (!res.ok) return { error: `HTTP ${res.status}` };

  let body: Record<string, unknown>;
  try { body = (await res.json()) as Record<string, unknown>; } catch { return { error: 'unreadable response' }; }
  const inner = body.result;
  const r = (inner && typeof inner === 'object' && !Array.isArray(inner) ? inner : body) as Record<string, unknown>;

  const registered = asStr(pick(r, 'creation_date', 'created', 'created_date', 'registered', 'registration_date'));
  const dates = {
    registered: whoisDate(pick(r, 'creation_date', 'created', 'created_date', 'registered', 'registration_date')),
    updated: whoisDate(pick(r, 'updated_date', 'updated', 'last_updated', 'changed')),
    expires: whoisDate(pick(r, 'expiration_date', 'expires', 'expiry_date', 'registry_expiry_date')),
  };
  const registrarName = asStr(pick(r, 'registrar', 'registrar_name'));
  const nameservers = [...new Set(asList(pick(r, 'name_servers', 'nameservers', 'nserver', 'ns')).map((n) => n.toLowerCase().replace(/\.$/, '')))].sort();
  const status = asList(pick(r, 'status', 'domain_status', 'statuses')).map((s) => s.replace(/\s+https?:\/\/\S+$/i, ''));
  const available = /\b(available|not ?found|no match|free)\b/i.test(String(pick(r, 'availability', 'domain_availability') ?? '') + ' ' + String(pick(body, 'message', 'status_message') ?? ''));
  const hasData = Boolean(registered || dates.expires || registrarName || nameservers.length || (status.length && !available));
  const dnssecRaw = String(pick(r, 'dnssec') ?? '').toLowerCase();
  const dnssecSigned = !dnssecRaw ? null : /^(unsigned|false|no|inactive)/.test(dnssecRaw) ? false : /signed|true|yes|active/.test(dnssecRaw) ? true : null;

  if (!hasData) {
    return {
      out: {
        domain, registered: false, source: 'apilayer', registrar: null, dates, ageDays: null, daysToExpiry: null, status: [], nameservers: [], dnssecSigned: null, rdapUrl: null,
        issues: [{ level: 'info', message: 'The WHOIS fallback (APILayer) returned no registration data. The domain may be unregistered, or this TLD may not expose WHOIS data.' }],
      },
    };
  }
  const ageDays = days(dates.registered, -1);
  const daysToExpiry = days(dates.expires, 1);
  return {
    out: {
      domain, registered: true, source: 'apilayer',
      registrar: registrarName ? { name: registrarName, ianaId: asStr(pick(r, 'registrar_iana_id', 'iana_id')), url: asStr(pick(r, 'registrar_url')), abuseEmail: asStr(pick(r, 'registrar_abuse_contact_email', 'abuse_email')), abusePhone: asStr(pick(r, 'registrar_abuse_contact_phone', 'abuse_phone')) } : null,
      dates, ageDays, daysToExpiry, status, nameservers, dnssecSigned, rdapUrl: null,
      issues: [
        { level: 'info', message: 'This TLD has no RDAP record, so the data comes from a WHOIS provider (APILayer). Some fields can be missing because registries restrict what they publish.' },
        ...findings(ageDays, daysToExpiry, status, dnssecSigned === false ? false : null),
      ],
    },
  };
}

/** GET /api/domain/whois?domain=example.com  (RDAP first; APILayer WHOIS only as a fallback when RDAP has no record) */
export const onRequestGet = route(async (ctx) => {
  const domain = requireDomain(new URL(ctx.request.url));

  const { value, hit } = await cached(ctx, `rdap:${domain}`, async () => {
    const primary = await fromRdap(domain);
    if (primary.kind === 'found') return { value: primary.out, ttl: 21_600 }; // registration data rarely changes: 6 h

    const fb = await fromApiLayer(ctx.env, domain);
    if ('out' in fb) return { value: fb.out, ttl: 86_400 }; // one provider credit per domain per day

    if (primary.kind === 'error') throw primary.error;
    // RDAP has no record and the fallback could not answer: say so honestly rather than claiming "unregistered".
    const why = fb.error === 'not configured' ? '' : ` The WHOIS fallback could not be used (${fb.error}).`;
    const out: WhoisResult = {
      domain, registered: false, source: 'rdap', registrar: null, dates: { registered: null, updated: null, expires: null },
      ageDays: null, daysToExpiry: null, status: [], nameservers: [], dnssecSigned: null, rdapUrl: null,
      issues: [{ ...NO_RDAP, message: NO_RDAP.message + why }],
    };
    return { value: out, ttl: fb.error === 'not configured' ? 300 : 120 };
  });
  return ok(value, { cached: hit });
});
