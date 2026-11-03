import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { cached } from '../../_lib/cache';
import { param, requireIP } from '../../_lib/input';
import { fetchJson } from '../../_lib/safeFetch';
import { resolve } from '../../_lib/doh';
import { takeProviderBudget } from '../../_lib/ratelimit';
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
/** ipapi.is: location + ASN + VPN/proxy/Tor/datacenter signals in one call. Every field is optional; we only read what exists. */
interface IpApiIs {
  error?: string; is_bogon?: boolean;
  is_mobile?: boolean; is_crawler?: boolean; is_datacenter?: boolean; is_tor?: boolean; is_proxy?: boolean; is_vpn?: boolean; is_abuser?: boolean;
  company?: { name?: string; abuser_score?: string; domain?: string; type?: string; network?: string };
  datacenter?: { datacenter?: string; network?: string; region?: string; service?: string };
  vpn?: { service?: string };
  asn?: { asn?: number | string; abuser_score?: string; route?: string; descr?: string; country?: string; org?: string; domain?: string; type?: string };
  location?: { country?: string; country_code?: string; state?: string; city?: string; zip?: string; latitude?: number; longitude?: number; timezone?: string };
}
interface Pulsedive {
  iid?: number; indicator?: string; risk?: string; risk_recommended?: string; stamp_seen?: string | null; stamp_updated?: string | null;
  riskfactors?: { description?: string; risk?: string }[];
  threats?: { name?: string; category?: string; risk?: string }[];
  feeds?: { name?: string; category?: string; organization?: string }[];
}
interface VirusTotalIp {
  data?: { attributes?: {
    last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
    reputation?: number; as_owner?: string; last_analysis_date?: number;
    total_votes?: { harmless?: number; malicious?: number };
  } };
}
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
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

  const { value, hit } = await cached(ctx, `ip:${ip}:${[env.ABUSEIPDB_API_KEY, env.IPAPI_IS_API_KEY, env.PULSEDIVE_API_KEY, env.VIRUSTOTAL_API_KEY].map((k) => (k ? 'k' : 'n')).join('')}`, async () => {
    const providers: ProviderStatus[] = [];
    const base: IpLookup = {
      ip, version: cls.version, scope: cls.scope, scopeLabel: cls.label, isPublic: cls.public, ptrName: ptrName(ip)!,
      geo: null, network: null, netType: null, geoSource: null, reverseDns: [], exposure: null, reputation: null, pulsedive: null, virustotal: null, flags: [], providers,
    };
    if (!cls.public) return { value: base, ttl: 3600 };

    const skip = (name: string, why: string) => {
      providers.push({ name, ok: false, ms: 0, skipped: true, error: why });
      return Promise.resolve(null);
    };

    // Quota-limited providers go through a global budget so a burst of lookups cannot exhaust a free-tier key.
    let budgetSkipped = false;
    const guarded = async <T>(provider: string, name: string, fn: () => Promise<T>): Promise<T | null> => {
      const b = await takeProviderBudget(env, provider);
      if (!b.ok) {
        budgetSkipped = true;
        providers.push({ name, ok: false, ms: 0, skipped: true, error: b.why });
        return null;
      }
      return track(providers, name, fn);
    };

    const [ipapiis, ripe, idb, abuse, ptr, pd, vt] = await Promise.all([
      // Primary geo/ASN/network-type provider. Works without a key; a key (if configured) is sent only to ipapi.is.
      track(providers, 'ipapi.is (geo/ASN/network type)', async () => {
        const qs = `q=${encodeURIComponent(ip)}${env.IPAPI_IS_API_KEY ? `&key=${encodeURIComponent(env.IPAPI_IS_API_KEY)}` : ''}`;
        const r = await fetchJson<IpApiIs>(`https://api.ipapi.is/?${qs}`);
        if (r.error) throw new ApiError(502, 'UPSTREAM_ERROR', `ipapi.is: ${String(r.error).slice(0, 120)}`);
        if (!r.location && !r.asn) throw new ApiError(502, 'UPSTREAM_ERROR', 'ipapi.is returned no location or ASN data.');
        return r;
      }),
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
        ? guarded('abuseipdb', 'AbuseIPDB (reputation)', () =>
            fetchJson<AbuseIpDb>(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { Key: env.ABUSEIPDB_API_KEY! } }))
        : skip('AbuseIPDB (reputation)', 'No ABUSEIPDB_API_KEY configured'),
      track(providers, 'DNS PTR', async () => (await resolve(ptrName(ip)!, 'PTR')).answers.filter((a) => a.type === 'PTR').map((a) => a.data)),
      env.PULSEDIVE_API_KEY
        ? guarded('pulsedive', 'Pulsedive (threat intel)', async () => {
            try {
              // Pulsedive takes the key as a query parameter; it is sent only to pulsedive.com.
              return await fetchJson<Pulsedive>(`https://pulsedive.com/api/indicator.php?indicator=${encodeURIComponent(ip)}&key=${encodeURIComponent(env.PULSEDIVE_API_KEY!)}`);
            } catch (e) {
              // 404 means Pulsedive has no record of this address: a valid answer, not a failure
              if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as Pulsedive;
              throw e;
            }
          })
        : skip('Pulsedive (threat intel)', 'No PULSEDIVE_API_KEY configured'),
      env.VIRUSTOTAL_API_KEY
        ? guarded('virustotal', 'VirusTotal (multi-engine verdicts)', async () => {
            try {
              return await fetchJson<VirusTotalIp>(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY! } });
            } catch (e) {
              // 404 means VirusTotal has no record of this address: a valid answer, not a failure
              if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as VirusTotalIp;
              throw e;
            }
          })
        : skip('VirusTotal (multi-engine verdicts)', 'No VIRUSTOTAL_API_KEY configured'),
    ]);

    // Geo/network: ipapi.is is primary. Fallbacks are tried in order, and only when needed, to spare their free quotas:
    // ipwho.is first, then ipapi.co.
    let geo: IpLookup['geo'] = null;
    let network: IpLookup['network'] = null;
    let netType: IpLookup['netType'] = null;
    let geoSource: IpLookup['geoSource'] = null;
    const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

    if (ipapiis) {
      const loc = ipapiis.location;
      geo = {
        country: loc?.country ?? null, countryCode: loc?.country_code ?? null, region: loc?.state ?? null, city: loc?.city ?? null,
        postal: loc?.zip ?? null, latitude: num(loc?.latitude), longitude: num(loc?.longitude), timezone: loc?.timezone ?? null,
      };
      const a = ipapiis.asn;
      network = {
        asn: a?.asn !== undefined && a?.asn !== null && String(a.asn) !== '' ? `AS${String(a.asn).replace(/^AS/i, '')}` : null,
        org: a?.org ?? a?.descr ?? ipapiis.company?.name ?? null,
        isp: ipapiis.company?.name ?? null,
        domain: a?.domain ?? ipapiis.company?.domain ?? null,
        prefix: a?.route ?? null,
      };
      netType = {
        isVpn: !!ipapiis.is_vpn, isProxy: !!ipapiis.is_proxy, isTor: !!ipapiis.is_tor, isDatacenter: !!ipapiis.is_datacenter,
        isMobile: !!ipapiis.is_mobile, isCrawler: !!ipapiis.is_crawler, isAbuser: !!ipapiis.is_abuser,
        companyName: ipapiis.company?.name ?? null, companyType: ipapiis.company?.type ?? a?.type ?? null,
        companyAbuserScore: ipapiis.company?.abuser_score ?? null, asnAbuserScore: a?.abuser_score ?? null,
        datacenter: ipapiis.datacenter?.datacenter ?? null, vpnService: ipapiis.vpn?.service ?? null,
      };
      geoSource = 'ipapi.is';
    }

    if (!geo) {
      const whois = await track(providers, 'ipwho.is (fallback geo/ASN)', async () => {
        const r = await fetchJson<IpWhoIs>(`https://ipwho.is/${encodeURIComponent(ip)}`);
        if (!r.success) throw new ApiError(502, 'UPSTREAM_ERROR', `ipwho.is: ${r.message ?? 'lookup failed'}`);
        return r;
      });
      if (whois) {
        geo = {
          country: whois.country ?? null, countryCode: whois.country_code ?? null, region: whois.region ?? null, city: whois.city ?? null,
          postal: whois.postal ?? null, latitude: whois.latitude ?? null, longitude: whois.longitude ?? null, timezone: whois.timezone?.id ?? null,
        };
        if (whois.connection) {
          network = { asn: whois.connection.asn ? `AS${whois.connection.asn}` : null, org: whois.connection.org ?? null, isp: whois.connection.isp ?? null, domain: whois.connection.domain ?? null, prefix: null };
        }
        geoSource = 'ipwho.is';
      }
    }

    if (!geo) {
      const fallback = await track(providers, 'ipapi.co (fallback geo)', async () => {
        const r = await fetchJson<IpApiCo>(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
        if (r.error) throw new ApiError(502, 'UPSTREAM_ERROR', `ipapi.co: ${r.reason ?? 'lookup failed'}`);
        return r;
      });
      if (fallback) {
        geo = {
          country: fallback.country_name ?? null, countryCode: fallback.country_code ?? null, region: fallback.region ?? null, city: fallback.city ?? null,
          postal: fallback.postal ?? null, latitude: fallback.latitude ?? null, longitude: fallback.longitude ?? null, timezone: fallback.timezone ?? null,
        };
        network = { asn: fallback.asn ?? null, org: fallback.org ?? null, isp: null, domain: null, prefix: null };
        geoSource = 'ipapi.co';
      }
    }

    // RIPEstat refines/cross-checks ASN + announced prefix
    if (ripe?.data) {
      const a = ripe.data.asns?.[0];
      network = {
        asn: network?.asn ?? (a ? `AS${a.asn}` : null), // the primary provider's ASN wins; RIPEstat fills the gap and supplies the announced prefix
        org: network?.org ?? a?.holder ?? null,
        isp: network?.isp ?? null,
        domain: network?.domain ?? null,
        prefix: ripe.data.resource ?? network?.prefix ?? null,
      };
    }

    const cap = <T,>(a: T[] | undefined, n: number) => (Array.isArray(a) ? a.slice(0, n) : []);
    const pulsedive: IpLookup['pulsedive'] = pd
      ? {
          risk: pd.risk ?? 'unknown', riskRecommended: pd.risk_recommended ?? null, observed: !!(pd.iid || pd.risk),
          lastSeen: pd.stamp_seen ?? null, lastUpdated: pd.stamp_updated ?? null,
          link: `https://pulsedive.com/indicator/?ioc=${btoa(ip)}`,
          threats: cap(pd.threats, 12).filter((t) => t.name).map((t) => ({ name: t.name!, category: t.category ?? null, risk: t.risk ?? null })),
          feeds: cap(pd.feeds, 12).filter((f) => f.name).map((f) => ({ name: f.name!, category: f.category ?? null, organization: f.organization ?? null })),
          riskFactors: cap(pd.riskfactors, 12).filter((r) => r.description).map((r) => ({ description: r.description!, risk: r.risk ?? null })),
        }
      : null;

    const vtAttr = vt?.data?.attributes;
    const virustotal: IpLookup['virustotal'] = vt
      ? {
          malicious: vtAttr?.last_analysis_stats?.malicious ?? 0, suspicious: vtAttr?.last_analysis_stats?.suspicious ?? 0,
          harmless: vtAttr?.last_analysis_stats?.harmless ?? 0, undetected: vtAttr?.last_analysis_stats?.undetected ?? 0,
          reputation: vtAttr?.reputation ?? null, votesMalicious: vtAttr?.total_votes?.malicious ?? 0, votesHarmless: vtAttr?.total_votes?.harmless ?? 0,
          asOwner: vtAttr?.as_owner ?? null,
          lastAnalysis: vtAttr?.last_analysis_date ? new Date(vtAttr.last_analysis_date * 1000).toISOString() : null,
          link: `https://www.virustotal.com/gui/ip-address/${ip}`,
          observed: !!vtAttr?.last_analysis_stats,
        }
      : null;

    const exposure = idb ? { ports: idb.ports ?? [], hostnames: idb.hostnames ?? [], vulns: (idb.vulns ?? []).filter((v) => CVE_RE.test(v)), tags: idb.tags ?? [], cpes: idb.cpes ?? [] } : null;
    const reputation = abuse?.data
      ? {
          abuseConfidence: abuse.data.abuseConfidenceScore, totalReports: abuse.data.totalReports, distinctReporters: abuse.data.numDistinctUsers,
          lastReportedAt: abuse.data.lastReportedAt, usageType: abuse.data.usageType, isTor: !!abuse.data.isTor, isWhitelisted: !!abuse.data.isWhitelisted,
        }
      : null;

    const flags: string[] = [];
    if (reputation && reputation.abuseConfidence >= 50) flags.push('Reported as abusive');
    if (pulsedive?.observed && ['medium', 'high', 'critical'].includes(pulsedive.risk)) flags.push(`Pulsedive: ${pulsedive.risk} risk`);
    if (virustotal && virustotal.malicious > 0) flags.push(`VirusTotal: ${virustotal.malicious} engine(s) flag as malicious`);
    else if (virustotal && virustotal.suspicious > 0) flags.push(`VirusTotal: ${virustotal.suspicious} engine(s) flag as suspicious`);
    if (netType?.isTor || reputation?.isTor || exposure?.tags.includes('tor')) flags.push('Tor exit node');
    if (netType?.isVpn) flags.push(netType.vpnService ? `VPN (${netType.vpnService})` : 'VPN');
    if (netType?.isProxy) flags.push('Proxy');
    if (netType?.isDatacenter) flags.push(netType.datacenter ? `Datacenter (${netType.datacenter})` : 'Datacenter / hosting');
    if (netType?.isAbuser) flags.push('Flagged as abuser (ipapi.is)');
    for (const t of exposure?.tags ?? []) if (['vpn', 'proxy', 'cloud', 'cdn', 'scanner', 'self-signed', 'honeypot', 'compromised', 'malware'].includes(t) && !flags.some((f) => f.toLowerCase().startsWith(t))) flags.push(t);
    if ((exposure?.vulns.length ?? 0) > 0) flags.push(`${exposure!.vulns.length} known CVE(s) on exposed services`);

    const out: IpLookup = { ...base, geo, network, netType, geoSource, reverseDns: ptr ?? [], exposure, reputation, pulsedive, virustotal, flags, providers };
    // Cache fully healthy results for an hour. If a provider that ran failed (bad key, quota, outage), or one was
    // skipped because its quota budget is spent, keep the result only briefly so recovery shows up quickly.
    const ran = providers.filter((p) => !p.skipped);
    const failed = ran.filter((p) => !p.ok).length;
    const ttl = ran.some((p) => p.ok) ? (failed === 0 && !budgetSkipped ? 3600 : 120) : 0;
    return { value: out, ttl };
  });
  return ok(value, { cached: hit });
});
