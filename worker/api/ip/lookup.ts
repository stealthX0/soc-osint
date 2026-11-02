import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { cached } from '../../_lib/cache';
import { param, requireIP } from '../../_lib/input';
import { fetchJson } from '../../_lib/safeFetch';
import { resolve } from '../../_lib/doh';
import type { Env } from '../../_lib/env';
import { classifyIP, normalizeIP, ptrName } from '../../../shared/ip';
import type { IpLookup, ProviderStatus } from '../../../shared/types';

/* Third-party response shapes (only the fields we use) */
interface IpWhoIs {
  success: boolean; message?: string; country?: string; country_code?: string; region?: string; city?: string; postal?: string;
  latitude?: number; longitude?: number; timezone?: { id?: string };
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
}
interface IpApiCo { error?: boolean; reason?: string; country_name?: string; country_code?: string; region?: string; city?: string; postal?: string; latitude?: number; longitude?: number; timezone?: string; asn?: string; org?: string }
interface RipeStat { data?: { resource?: string; asns?: { asn: number; holder: string }[]; announced?: boolean } }
interface IpInfoLite { asn?: string; as_name?: string; as_domain?: string; country_code?: string; country?: string }
interface GreyNoise { noise?: boolean; riot?: boolean; classification?: string; name?: string; link?: string; last_seen?: string }
interface InternetDb { ports?: number[]; hostnames?: string[]; vulns?: string[]; tags?: string[]; cpes?: string[] }
interface AbuseIpDb {
  data?: { abuseConfidenceScore: number; totalReports: number; numDistinctUsers: number; lastReportedAt: string | null; usageType: string | null; isTor?: boolean; isWhitelisted?: boolean | null };
}

/** Run a provider, recording latency/outcome without ever throwing. */
async function track<T>(providers: ProviderStatus[], name: string, fn: () => Promise<T>): Promise<T | null> {
  const t0 = Date.now();
  try {
    const v = await fn();
    providers.push({ name, ok: true, ms: Date.now() - t0 });
    return v;
  } catch (e) {
    providers.push({ name, ok: false, ms: Date.now() - t0, error: e instanceof Error ? e.message : 'failed' });
    return null;
  }
}

/**
 * GET /api/ip/lookup?q=1.2.3.4   (omit q to look up the caller's own address)
 * Aggregates geolocation, ASN/prefix, passive exposure data, reverse DNS and (optionally) reputation.
 * Private/reserved addresses are classified locally and never sent to third parties.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const env = ctx.env as Env;
  const self = param(url, 'q') === '';
  let ip: string;
  if (self) {
    const caller = normalizeIP(ctx.request.headers.get('cf-connecting-ip') ?? '');
    if (!caller) throw badInput('Could not determine your IP address; pass ?q=<ip> instead.');
    ip = caller;
  } else {
    ip = requireIP(url, 'q');
  }
  const cls = classifyIP(ip)!;

  const { value, hit } = await cached(ctx, `ip:${ip}:${[env.ABUSEIPDB_API_KEY, env.IPINFO_TOKEN, env.GREYNOISE_API_KEY].map((k) => (k ? 'k' : 'n')).join('')}`, async () => {
    const providers: ProviderStatus[] = [];
    const base: IpLookup = {
      ip, version: cls.version, scope: cls.scope, scopeLabel: cls.label, isPublic: cls.public, ptrName: ptrName(ip)!,
      geo: null, network: null, reverseDns: [], exposure: null, reputation: null, greynoise: null, flags: [], providers,
    };
    if (!cls.public) return { value: base, ttl: 3600 };

    const skip = (name: string, why: string) => {
      providers.push({ name, ok: false, ms: 0, skipped: true, error: why });
      return Promise.resolve(null);
    };

    const [whois, ripe, idb, abuse, ptr, ipinfo, grey] = await Promise.all([
      track(providers, 'ipwho.is (geo/ASN)', () => fetchJson<IpWhoIs>(`https://ipwho.is/${encodeURIComponent(ip)}`)),
      track(providers, 'RIPEstat (prefix/ASN)', () => fetchJson<RipeStat>(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`)),
      track(providers, 'Shodan InternetDB (exposure)', async () => {
        try {
          return await fetchJson<InternetDb>(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
        } catch (e) {
          if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as InternetDb; // 404 = never observed by Shodan
          throw e;
        }
      }),
      env.ABUSEIPDB_API_KEY
        ? track(providers, 'AbuseIPDB (reputation)', () =>
            fetchJson<AbuseIpDb>(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { Key: env.ABUSEIPDB_API_KEY! } }))
        : skip('AbuseIPDB (reputation)', 'No ABUSEIPDB_API_KEY configured'),
      track(providers, 'DNS PTR', async () => (await resolve(ptrName(ip)!, 'PTR')).answers.filter((a) => a.type === 'PTR').map((a) => a.data)),
      env.IPINFO_TOKEN
        ? track(providers, 'IPinfo Lite (ASN/country)', () =>
            fetchJson<IpInfoLite>(`https://api.ipinfo.io/lite/${encodeURIComponent(ip)}`, { headers: { Authorization: `Bearer ${env.IPINFO_TOKEN}` } }))
        : skip('IPinfo Lite (ASN/country)', 'No IPINFO_TOKEN configured'),
      env.GREYNOISE_API_KEY
        ? track(providers, 'GreyNoise Community (noise/RIOT)', async () => {
            try {
              return await fetchJson<GreyNoise>(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { headers: { key: env.GREYNOISE_API_KEY! } });
            } catch (e) {
              // 404 means "not observed scanning the internet and not in RIOT": a valid, useful answer
              if (e instanceof ApiError && e.code === 'NOT_FOUND') return { noise: false, riot: false, classification: 'unknown', observed: false } as GreyNoise & { observed: boolean };
              throw e;
            }
          })
        : skip('GreyNoise Community (noise/RIOT)', 'No GREYNOISE_API_KEY configured'),
    ]);

    // Geo: ipwho.is first, ipapi.co as fallback
    let geo: IpLookup['geo'] = null;
    let network: IpLookup['network'] = null;
    if (whois?.success) {
      geo = {
        country: whois.country ?? null, countryCode: whois.country_code ?? null, region: whois.region ?? null, city: whois.city ?? null,
        postal: whois.postal ?? null, latitude: whois.latitude ?? null, longitude: whois.longitude ?? null, timezone: whois.timezone?.id ?? null,
      };
      if (whois.connection) {
        network = { asn: whois.connection.asn ? `AS${whois.connection.asn}` : null, org: whois.connection.org ?? null, isp: whois.connection.isp ?? null, domain: whois.connection.domain ?? null, prefix: null };
      }
    } else {
      const fallback = await track(providers, 'ipapi.co (fallback geo)', () => fetchJson<IpApiCo>(`https://ipapi.co/${encodeURIComponent(ip)}/json/`));
      if (fallback && !fallback.error) {
        geo = {
          country: fallback.country_name ?? null, countryCode: fallback.country_code ?? null, region: fallback.region ?? null, city: fallback.city ?? null,
          postal: fallback.postal ?? null, latitude: fallback.latitude ?? null, longitude: fallback.longitude ?? null, timezone: fallback.timezone ?? null,
        };
        network = { asn: fallback.asn ?? null, org: fallback.org ?? null, isp: null, domain: null, prefix: null };
      }
    }
    // RIPEstat refines/cross-checks ASN + announced prefix
    if (ripe?.data) {
      const a = ripe.data.asns?.[0];
      network = {
        asn: a ? `AS${a.asn}` : network?.asn ?? null,
        org: network?.org ?? a?.holder ?? null,
        isp: network?.isp ?? null,
        domain: network?.domain ?? null,
        prefix: ripe.data.resource ?? null,
      };
    }

    // IPinfo Lite is the more reliable source for ASN and country, so it wins those fields.
    // City-level fields come from ipwho.is; if the two disagree on country the city is dropped rather than shown wrongly.
    let geoDisagrees = false;
    if (ipinfo && (ipinfo.asn || ipinfo.country_code)) {
      if (geo && geo.countryCode && ipinfo.country_code && geo.countryCode !== ipinfo.country_code) {
        geoDisagrees = true;
        geo = { country: ipinfo.country ?? null, countryCode: ipinfo.country_code, region: null, city: null, postal: null, latitude: null, longitude: null, timezone: null };
      } else if (geo) {
        geo = { ...geo, country: ipinfo.country ?? geo.country, countryCode: ipinfo.country_code ?? geo.countryCode };
      } else if (ipinfo.country_code) {
        geo = { country: ipinfo.country ?? null, countryCode: ipinfo.country_code, region: null, city: null, postal: null, latitude: null, longitude: null, timezone: null };
      }
      network = {
        asn: ipinfo.asn ?? network?.asn ?? null,
        org: ipinfo.as_name ?? network?.org ?? null,
        isp: network?.isp ?? null,
        domain: ipinfo.as_domain ?? network?.domain ?? null,
        prefix: network?.prefix ?? null,
      };
    }

    const greynoise: IpLookup['greynoise'] = grey
      ? {
          noise: !!grey.noise, riot: !!grey.riot, classification: grey.classification ?? 'unknown', name: grey.name ?? null,
          lastSeen: grey.last_seen ?? null, link: grey.link ?? null, observed: (grey as { observed?: boolean }).observed !== false,
        }
      : null;

    const exposure = idb ? { ports: idb.ports ?? [], hostnames: idb.hostnames ?? [], vulns: idb.vulns ?? [], tags: idb.tags ?? [], cpes: idb.cpes ?? [] } : null;
    const reputation = abuse?.data
      ? {
          abuseConfidence: abuse.data.abuseConfidenceScore, totalReports: abuse.data.totalReports, distinctReporters: abuse.data.numDistinctUsers,
          lastReportedAt: abuse.data.lastReportedAt, usageType: abuse.data.usageType, isTor: !!abuse.data.isTor, isWhitelisted: !!abuse.data.isWhitelisted,
        }
      : null;

    const flags: string[] = [];
    if (reputation && reputation.abuseConfidence >= 50) flags.push('Reported as abusive');
    if (greynoise?.classification === 'malicious') flags.push('GreyNoise: malicious scanner');
    else if (greynoise?.noise && greynoise.classification !== 'benign') flags.push('Internet scanner (GreyNoise)');
    if (greynoise?.riot) flags.push('Common business service (RIOT)');
    if (geoDisagrees) flags.push('Geo providers disagree on country');
    if (reputation?.isTor || exposure?.tags.includes('tor')) flags.push('Tor exit node');
    for (const t of exposure?.tags ?? []) if (['vpn', 'proxy', 'cloud', 'cdn', 'scanner', 'self-signed', 'honeypot', 'compromised', 'malware'].includes(t) && !flags.includes(t)) flags.push(t);
    if ((exposure?.vulns.length ?? 0) > 0) flags.push(`${exposure!.vulns.length} known CVE(s) on exposed services`);

    const out: IpLookup = { ...base, geo, network, reverseDns: ptr ?? [], exposure, reputation, greynoise, flags, providers };
    // never cache a result where the main providers failed
    const healthy = providers.filter((p) => !p.skipped).some((p) => p.ok);
    return { value: out, ttl: healthy && providers.filter((p) => !p.skipped && !p.ok).length <= 1 ? 600 : 0 };
  });
  return ok(value, { cached: hit });
});
