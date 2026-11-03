import { ok, route } from '../../_lib/respond';
import { ApiError } from '../../_lib/errors';
import { requireDomain } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { USER_AGENT } from '../../_lib/safeFetch';
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

/** GET /api/domain/whois?domain=example.com  (RDAP: the structured successor to WHOIS port 43) */
export const onRequestGet = route(async (ctx) => {
  const domain = requireDomain(new URL(ctx.request.url));

  const { value, hit } = await cached(ctx, `rdap:${domain}`, async () => {
    let res: Response;
    try {
      res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        headers: { accept: 'application/rdap+json, application/json', 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(8000),
        redirect: 'follow',
      });
    } catch {
      throw new ApiError(504, 'UPSTREAM_TIMEOUT', 'The RDAP service did not respond in time.');
    }
    if (res.status === 404) {
      const out: WhoisResult = {
        domain, registered: false, registrar: null, dates: { registered: null, updated: null, expires: null },
        ageDays: null, daysToExpiry: null, status: [], nameservers: [], dnssecSigned: null, rdapUrl: null,
        issues: [{ level: 'info', message: 'No RDAP record: the domain is unregistered, or its TLD does not publish RDAP data.' }],
      };
      return { value: out, ttl: 300 };
    }
    if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `RDAP service returned HTTP ${res.status}.`);
    const r = (await res.json()) as Rdap;

    const event = (a: string) => r.events?.find((e) => e.eventAction === a)?.eventDate ?? null;
    const registrarEnt = r.entities?.find((e) => e.roles?.includes('registrar'));
    const abuse = registrarEnt?.entities?.find((e) => e.roles?.includes('abuse'));
    const dates = { registered: event('registration'), updated: event('last changed'), expires: event('expiration') };
    const now = Date.now();
    const days = (iso: string | null, sign: 1 | -1) => (iso && !Number.isNaN(Date.parse(iso)) ? Math.floor((sign * (Date.parse(iso) - now)) / 86_400_000) : null);
    const ageDays = days(dates.registered, -1);
    const daysToExpiry = days(dates.expires, 1);
    const status = r.status ?? [];

    const issues: Issue[] = [];
    if (ageDays !== null && ageDays < 30) issues.push({ level: 'warn', message: `Domain was registered only ${ageDays} day(s) ago. Newly registered domains are over-represented in phishing.` });
    else if (ageDays !== null && ageDays < 180) issues.push({ level: 'info', message: `Domain is relatively new (${ageDays} days old).` });
    if (daysToExpiry !== null && daysToExpiry < 0) issues.push({ level: 'error', message: 'Registration has expired.' });
    else if (daysToExpiry !== null && daysToExpiry < 30) issues.push({ level: 'warn', message: `Registration expires in ${daysToExpiry} day(s).` });
    if (status.some((s) => /transfer ?prohibited/i.test(s)) === false && status.length) issues.push({ level: 'info', message: 'No transfer lock (clientTransferProhibited) is set.' });
    if (status.some((s) => /hold/i.test(s))) issues.push({ level: 'warn', message: 'Domain is on hold, so it may not resolve.' });
    if (r.secureDNS?.delegationSigned === false) issues.push({ level: 'info', message: 'DNSSEC is not enabled for this domain.' });

    const out: WhoisResult = {
      domain: r.ldhName?.toLowerCase() ?? domain,
      registered: true,
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
      dnssecSigned: r.secureDNS?.delegationSigned ?? null,
      rdapUrl: r.links?.find((l) => l.rel === 'self')?.href ?? null,
      issues,
    };
    return { value: out, ttl: 900 };
  });
  return ok(value, { cached: hit });
});
