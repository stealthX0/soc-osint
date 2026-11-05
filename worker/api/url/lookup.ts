import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { USER_AGENT, fetchJson } from '../../_lib/safeFetch';
import { SECURITY_RESOLVER, dohQuery, queryEndpoint } from '../../_lib/doh';
import { base64Url, postForm, postJson, sha256Hex, skipped, track } from '../../_lib/providers';
import { takeProviderBudget } from '../../_lib/ratelimit';
import { traceUrl } from '../../_lib/trace';
import type { Env } from '../../_lib/env';
import type { ProviderStatus, UrlLookup, UrlSignal } from '../../../shared/types';
import { classifyIP } from '../../../shared/ip';
import { MAX_URL_LENGTH, analyzeUrlHeuristics, assessUrl, parseTargetUrl, sortSignals, type ParsedUrl } from '../../../shared/url';

/* Provider display names. The first six are threat-intelligence sources (they count towards coverage). */
const N = {
  urlhaus: 'URLhaus (malware URLs)',
  gsb: 'Google Safe Browsing',
  vt: 'VirusTotal (URL verdicts)',
  pd: 'Pulsedive (threat intel)',
  urlscan: 'urlscan.io (prior scans)',
  cfdns: 'Cloudflare Security DNS',
  rdap: 'RDAP (domain age)',
  trace: 'Redirect trace',
} as const;
const INTEL_NAMES: Set<string> = new Set([N.urlhaus, N.gsb, N.vt, N.pd, N.urlscan, N.cfdns]);
const FINAL = ' [final URL]';

type Intel = UrlLookup['intel'];
type Domain = NonNullable<UrlLookup['domain']>;
const sig = (source: string, id: string, severity: UrlSignal['severity'], title: string, detail?: string, extra: Partial<UrlSignal> = {}): UrlSignal => ({ id, severity, source, title, detail, ...extra });
const cap = <T>(a: T[] | undefined | null, n: number): T[] => (Array.isArray(a) ? a.slice(0, n) : []);
const day = 86_400_000;

/** Hosts that must never be sent to third parties or fetched: internal names and non-public addresses. */
function externalCandidate(p: ParsedUrl): { ok: boolean; why?: string } {
  if (p.isIp) return classifyIP(p.host)?.public ? { ok: true } : { ok: false, why: 'The URL points at a private or reserved address, so it was analysed locally only.' };
  const labels = p.host.split('.');
  const tld = labels[labels.length - 1];
  if (labels.length < 2 || ['local', 'localhost', 'internal', 'lan', 'home', 'corp', 'intranet', 'test', 'example', 'invalid', 'onion'].includes(tld)) {
    return { ok: false, why: 'The hostname looks internal or reserved, so it was analysed locally only.' };
  }
  return { ok: true };
}

/* ------------------------------------------------------------------ providers */

interface UhUrl { query_status?: string; urlhaus_reference?: string; url_status?: string; threat?: string; tags?: string[] | null; date_added?: string; blacklists?: Record<string, string> }
interface UhHost { query_status?: string; url_count?: string | number; blacklists?: Record<string, string>; urls?: { url_status?: string }[] }

async function urlhaus(env: Env, p: ParsedUrl): Promise<{ data: NonNullable<Intel['urlhaus']>; signals: UrlSignal[] }> {
  const headers = { 'Auth-Key': env.ABUSECH_AUTH_KEY! };
  const [u, h] = await Promise.allSettled([
    postForm<UhUrl>('https://urlhaus-api.abuse.ch/v1/url/', { url: p.lookupUrl }, headers),
    postForm<UhHost>('https://urlhaus-api.abuse.ch/v1/host/', { host: p.host }, headers),
  ]);
  if (u.status === 'rejected') throw u.reason;
  const url = u.value;
  if (!['ok', 'no_results', 'invalid_url'].includes(url.query_status ?? '')) throw new ApiError(502, 'UPSTREAM_ERROR', `URLhaus returned an unexpected status (${url.query_status ?? 'none'}).`);
  const host = h.status === 'fulfilled' && ['ok', 'no_results'].includes(h.value.query_status ?? '') ? h.value : null;

  const listed = url.query_status === 'ok';
  const status = listed ? (url.url_status ?? 'unknown') : null;
  const ref = typeof url.urlhaus_reference === 'string' && url.urlhaus_reference.startsWith('https://urlhaus.abuse.ch/') ? url.urlhaus_reference : null;
  const urlCount = Number(host?.url_count ?? 0) || 0;
  const online = (host?.urls ?? []).filter((x) => x.url_status === 'online').length;
  const blacklists = { ...(listed ? url.blacklists : {}), ...(host?.blacklists ?? {}) };
  const data: NonNullable<Intel['urlhaus']> = {
    listed, status, threat: listed ? (url.threat ?? null) : null, tags: cap(url.tags, 10), dateAdded: listed ? (url.date_added ?? null) : null, reference: ref,
    host: { listed: host?.query_status === 'ok', urlCount, online, blacklists },
  };

  const signals: UrlSignal[] = [];
  if (listed) {
    const bits = [data.threat && `Threat: ${data.threat}`, data.tags.length && `Tags: ${data.tags.join(', ')}`, data.dateAdded && `Added: ${data.dateAdded}`].filter(Boolean).join(' · ');
    signals.push(status === 'online'
      ? sig('urlhaus', 'urlhaus-online', 'critical', 'This exact URL is listed by URLhaus as actively distributing malware', bits, { confirmed: true, link: ref ?? undefined })
      : sig('urlhaus', 'urlhaus-listed', 'high', `This exact URL is listed by URLhaus as malware distribution (status: ${status})`, bits, { confirmed: true, link: ref ?? undefined }));
  } else if (data.host.listed && urlCount > 0) {
    signals.push(online > 0
      ? sig('urlhaus', 'urlhaus-host-online', 'high', `The host serves ${online} malware URL${online === 1 ? '' : 's'} listed by URLhaus`, `${urlCount} URLs on this host are listed in total. This exact URL is not, but it shares a host with confirmed malware.`)
      : sig('urlhaus', 'urlhaus-host-offline', 'medium', `The host previously served malware (${urlCount} URLhaus listing${urlCount === 1 ? '' : 's'}, none online now)`, 'This exact URL is not listed.'));
  }
  for (const [list, value] of Object.entries(blacklists)) {
    if (value && value !== 'not listed') {
      const label = list === 'spamhaus_dbl' ? 'Spamhaus DBL' : list === 'surbl' ? 'SURBL' : list;
      signals.push(sig('urlhaus', `urlhaus-bl-${list}`, 'high', `Host is on the ${label} blocklist`, `Reported via URLhaus: ${value}.`));
    }
  }
  return { data, signals };
}

interface GsbResponse { matches?: { threatType?: string; platformType?: string }[] }
const GSB_LABEL: Record<string, string> = {
  SOCIAL_ENGINEERING: 'phishing / social engineering',
  MALWARE: 'malware',
  UNWANTED_SOFTWARE: 'unwanted software',
  POTENTIALLY_HARMFUL_APPLICATION: 'potentially harmful application',
};

async function safeBrowsing(env: Env, p: ParsedUrl): Promise<{ data: NonNullable<Intel['safeBrowsing']>; signals: UrlSignal[] }> {
  const body = {
    client: { clientId: 'spectrix', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: Object.keys(GSB_LABEL),
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: p.lookupUrl }],
    },
  };
  const r = await postJson<GsbResponse>(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.GOOGLE_SAFE_BROWSING_API_KEY!)}`, body);
  const matches = cap(r.matches, 8).filter((m) => m.threatType && GSB_LABEL[m.threatType]).map((m) => ({ threatType: m.threatType!, platformType: m.platformType ?? 'ANY_PLATFORM' }));
  const signals = [...new Set(matches.map((m) => m.threatType))].map((t) =>
    sig('safebrowsing', `gsb-${t.toLowerCase()}`, 'critical', `Google Safe Browsing lists this URL for ${GSB_LABEL[t]}`, 'Safe Browsing is the list used by Chrome, Firefox and Safari to show full-page warnings.', { confirmed: true }));
  return { data: { matches }, signals };
}

interface VtUrl {
  data?: { id?: string; attributes?: {
    last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
    last_analysis_results?: Record<string, { category?: string; result?: string }>;
    last_analysis_date?: number; categories?: Record<string, string>;
  } };
}

async function virusTotal(env: Env, p: ParsedUrl): Promise<{ data: NonNullable<Intel['virustotal']>; signals: UrlSignal[] }> {
  let r: VtUrl;
  try {
    r = await fetchJson<VtUrl>(`https://www.virustotal.com/api/v3/urls/${base64Url(p.lookupUrl)}`, { headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY! } });
  } catch (e) {
    // 404: VirusTotal has never analysed this URL. A valid answer, not a failure (and it is not "clean" either).
    if (e instanceof ApiError && e.code === 'NOT_FOUND') {
      return { data: { found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, engines: [], lastAnalysis: null, categories: [], link: null }, signals: [] };
    }
    throw e;
  }
  const a = r.data?.attributes;
  const st = a?.last_analysis_stats ?? {};
  const malicious = st.malicious ?? 0, suspicious = st.suspicious ?? 0;
  const engines = Object.entries(a?.last_analysis_results ?? {})
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .slice(0, 10).map(([k, v]) => `${k}: ${v.result ?? v.category}`);
  const id = r.data?.id && /^[0-9a-f]{64}$/.test(r.data.id) ? r.data.id : null;
  const last = a?.last_analysis_date ? new Date(a.last_analysis_date * 1000) : null;
  const data: NonNullable<Intel['virustotal']> = {
    found: true, malicious, suspicious, harmless: st.harmless ?? 0, undetected: st.undetected ?? 0, engines,
    lastAnalysis: last ? last.toISOString() : null, categories: [...new Set(Object.values(a?.categories ?? {}))].slice(0, 6),
    link: id ? `https://www.virustotal.com/gui/url/${id}` : null,
  };

  const signals: UrlSignal[] = [];
  const detail = [engines.length && `Engines: ${engines.slice(0, 5).join(', ')}`, last && `Last analysed ${last.toISOString().slice(0, 10)}`].filter(Boolean).join(' · ');
  const link = data.link ?? undefined;
  if (malicious >= 5) signals.push(sig('virustotal', 'vt-malicious', 'critical', `${malicious} security engines flag this URL as malicious`, detail, { link }));
  else if (malicious >= 2) signals.push(sig('virustotal', 'vt-malicious', 'high', `${malicious} security engines flag this URL as malicious`, detail, { link }));
  else if (malicious === 1) signals.push(sig('virustotal', 'vt-malicious-1', 'medium', '1 security engine flags this URL as malicious', `${detail}${detail ? ' · ' : ''}A single detection is often a false positive; look for corroboration.`, { link }));
  if (suspicious >= 3) signals.push(sig('virustotal', 'vt-suspicious', 'medium', `${suspicious} security engines rate this URL as suspicious`, detail, { link }));
  else if (suspicious > 0 && malicious === 0) signals.push(sig('virustotal', 'vt-suspicious-low', 'low', `${suspicious} security engine${suspicious === 1 ? '' : 's'} rate this URL as suspicious`, detail, { link }));
  if (last && Date.now() - last.getTime() > 90 * day) {
    signals.push(sig('virustotal', 'vt-stale', 'info', 'VirusTotal\u2019s last analysis of this URL is old', `Last analysed ${Math.floor((Date.now() - last.getTime()) / day)} days ago, so the verdict may be out of date.`, { link }));
  }
  return { data, signals };
}

interface Pulsedive {
  risk?: string; stamp_seen?: string | null;
  threats?: { name?: string }[]; feeds?: { name?: string }[];
}

async function pulsedive(env: Env, p: ParsedUrl): Promise<{ data: NonNullable<Intel['pulsedive']>; signals: UrlSignal[] }> {
  let r: Pulsedive;
  try {
    // The key is a query parameter by Pulsedive's design and is only ever sent to pulsedive.com.
    r = await fetchJson<Pulsedive>(`https://pulsedive.com/api/indicator.php?indicator=${encodeURIComponent(p.lookupUrl)}&key=${encodeURIComponent(env.PULSEDIVE_API_KEY!)}`);
  } catch (e) {
    if (e instanceof ApiError && e.code === 'NOT_FOUND') r = {};
    else throw e;
  }
  const risk = r.risk ?? null;
  const threats = cap(r.threats, 8).map((t) => t.name).filter((x): x is string => !!x);
  const feeds = cap(r.feeds, 8).map((f) => f.name).filter((x): x is string => !!x);
  const observed = !!(risk && risk !== 'unknown');
  const data: NonNullable<Intel['pulsedive']> = { observed, risk, threats, feeds, link: observed ? `https://pulsedive.com/indicator/?ioc=${btoa(p.lookupUrl)}` : null };
  const signals: UrlSignal[] = [];
  const detail = [threats.length && `Threats: ${threats.join(', ')}`, feeds.length && `Feeds: ${feeds.slice(0, 4).join(', ')}`].filter(Boolean).join(' · ');
  if (risk === 'critical' || risk === 'high') signals.push(sig('pulsedive', 'pd-risk', 'high', `Pulsedive rates this URL ${risk} risk`, detail, { link: data.link ?? undefined }));
  else if (risk === 'medium') signals.push(sig('pulsedive', 'pd-risk', 'medium', 'Pulsedive rates this URL medium risk', detail, { link: data.link ?? undefined }));
  return { data, signals };
}

interface UrlscanSearch { results?: {
  _id?: string; task?: { url?: string; time?: string; uuid?: string }; page?: { url?: string; domain?: string; country?: string };
  verdicts?: { overall?: { malicious?: boolean; score?: number; categories?: string[]; brands?: string[] } };
}[] }
interface UrlscanResult { verdicts?: { overall?: { malicious?: boolean; score?: number; categories?: string[]; brands?: string[] } } }

const sameUrl = (a: string | undefined, b: string): boolean => {
  if (!a) return false;
  try {
    const x = new URL(a), y = new URL(b);
    x.hash = ''; y.hash = '';
    x.username = ''; x.password = ''; y.username = ''; y.password = '';
    return x.toString().replace(/\/$/, '') === y.toString().replace(/\/$/, '');
  } catch {
    return false;
  }
};

async function urlscan(env: Env, p: ParsedUrl): Promise<{ data: NonNullable<Intel['urlscan']>; signals: UrlSignal[] }> {
  const headers: Record<string, string> = env.URLSCAN_API_KEY ? { 'API-Key': env.URLSCAN_API_KEY } : {};
  const q = `page.domain:"${p.host}"`;
  const r = await fetchJson<UrlscanSearch>(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`, { headers });
  const results = cap(r.results, 10).filter((x) => x.task?.uuid && /^[0-9a-f-]{36}$/i.test(x.task.uuid));
  const exact = results.filter((x) => sameUrl(x.task?.url, p.lookupUrl) || sameUrl(x.page?.url, p.lookupUrl));
  const pick = exact[0] ?? results[0];
  if (!pick) return { data: { scans: 0, exactMatches: 0, latest: null }, signals: [] };

  let overall = pick.verdicts?.overall;
  if (!overall) {
    // search results often omit verdicts; the result document has them. Best effort only.
    try {
      overall = (await fetchJson<UrlscanResult>(`https://urlscan.io/api/v1/result/${pick.task!.uuid}/`, { headers, timeoutMs: 5000 })).verdicts?.overall;
    } catch { /* verdicts unavailable for this plan or scan */ }
  }
  const resultUrl = `https://urlscan.io/result/${pick.task!.uuid}/`;
  const latest = {
    date: pick.task?.time ?? null, url: pick.task?.url ?? null, country: pick.page?.country ?? null,
    malicious: typeof overall?.malicious === 'boolean' ? overall.malicious : null,
    score: typeof overall?.score === 'number' ? overall.score : null,
    categories: cap(overall?.categories, 6), brands: cap(overall?.brands, 6), resultUrl,
  };
  const data = { scans: results.length, exactMatches: exact.length, latest };

  const signals: UrlSignal[] = [];
  if (latest.malicious) {
    const when = latest.date ? latest.date.slice(0, 10) : 'an earlier date';
    const detail = [latest.categories.length && `Categories: ${latest.categories.join(', ')}`, latest.brands.length && `Targets: ${latest.brands.join(', ')}`, `Scanned ${when}`].filter(Boolean).join(' · ');
    signals.push(exact.length
      ? sig('urlscan', 'urlscan-malicious', 'high', 'urlscan.io scanned this URL and judged it malicious', detail, { link: resultUrl })
      : sig('urlscan', 'urlscan-host-malicious', 'medium', 'urlscan.io judged a scan of this host malicious', `${detail}. The scanned page was ${latest.url ?? 'a different path'}, not this exact URL.`, { link: resultUrl }));
  }
  return { data, signals };
}

async function cloudflareDns(p: ParsedUrl): Promise<{ data: NonNullable<Intel['cloudflareDns']>; domain: { resolves: boolean | null; addresses: string[] }; signals: UrlSignal[] }> {
  const [nA, sA, nAAAA, sAAAA] = await Promise.allSettled([
    dohQuery(p.host, 'A', 'cloudflare'),
    queryEndpoint(SECURITY_RESOLVER, p.host, 'A'),
    dohQuery(p.host, 'AAAA', 'cloudflare'),
    queryEndpoint(SECURITY_RESOLVER, p.host, 'AAAA'),
  ]);
  if (nA.status === 'rejected' && sA.status === 'rejected') throw nA.reason;

  const real = (r: PromiseSettledResult<Awaited<ReturnType<typeof dohQuery>>>, type: 'A' | 'AAAA', zero: string): string[] =>
    r.status === 'fulfilled' ? r.value.answers.filter((a) => a.type === type && a.data !== zero).map((a) => a.data) : [];
  const zeroed = (r: PromiseSettledResult<Awaited<ReturnType<typeof dohQuery>>>, type: 'A' | 'AAAA', zero: string): boolean =>
    r.status === 'fulfilled' && r.value.answers.some((a) => a.type === type && a.data === zero);

  const addresses = [...real(nA, 'A', '0.0.0.0'), ...real(nAAAA, 'AAAA', '::')];
  const filteredZero = zeroed(sA, 'A', '0.0.0.0') || zeroed(sAAAA, 'AAAA', '::');
  const unfilteredZero = zeroed(nA, 'A', '0.0.0.0') || zeroed(nAAAA, 'AAAA', '::');
  const resolves = nA.status === 'fulfilled' ? (nA.value.status === 'NXDOMAIN' ? false : addresses.length > 0) : null;

  let blocked: boolean | null;
  let note: string;
  if (filteredZero && addresses.length > 0) { blocked = true; note = 'The filtered resolver returned 0.0.0.0 while the unfiltered resolver returned real addresses: Cloudflare has classified this domain as a security threat.'; }
  else if (filteredZero && unfilteredZero) { blocked = false; note = 'Both resolvers return 0.0.0.0 (the domain is sinkholed by its owner or another party), so this does not indicate a Cloudflare block.'; }
  else if (filteredZero) { blocked = null; note = 'The filtered resolver returned 0.0.0.0 but the unfiltered resolver gave no addresses to compare, so a block could not be confirmed.'; }
  else if (sA.status === 'rejected') { blocked = null; note = 'The filtered resolver did not answer.'; }
  else { blocked = false; note = 'Not blocked by Cloudflare\u2019s malware/phishing filter.'; }

  const signals: UrlSignal[] = [];
  if (blocked) signals.push(sig('cloudflare-dns', 'cfdns-blocked', 'high', 'Blocked by Cloudflare Security DNS (malware / phishing category)', note));
  if (resolves === false) signals.push(sig('dns', 'nxdomain', 'low', 'The domain does not resolve (NXDOMAIN)', 'It may have been taken down, has expired, or the URL is mistyped. A dead host can still have been malicious.'));
  return { data: { blocked, note }, domain: { resolves, addresses: addresses.slice(0, 8) }, signals };
}

interface Rdap { events?: { eventAction: string; eventDate: string }[]; entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, unknown][]] }[] }

async function rdapAge(domain: string): Promise<{ ageDays: number | null; registered: string | null; registrar: string | null }> {
  let res: Response;
  try {
    res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { accept: 'application/rdap+json, application/json', 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(6000), redirect: 'follow' });
  } catch {
    throw new ApiError(504, 'UPSTREAM_TIMEOUT', 'The RDAP service did not respond in time.');
  }
  if (res.status === 404) return { ageDays: null, registered: null, registrar: null };
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `RDAP service returned HTTP ${res.status}.`);
  const r = (await res.json()) as Rdap;
  const regIso = r.events?.find((e) => e.eventAction === 'registration')?.eventDate ?? null;
  const t = regIso ? Date.parse(regIso) : NaN;
  const reg = r.entities?.find((e) => e.roles?.includes('registrar'));
  const fn = reg?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3];
  return {
    ageDays: Number.isFinite(t) ? Math.max(0, Math.floor((Date.now() - t) / day)) : null,
    registered: Number.isFinite(t) ? new Date(t).toISOString() : null,
    registrar: typeof fn === 'string' ? fn : null,
  };
}

/* ------------------------------------------------------------------ gathering */

interface Gathered { signals: UrlSignal[]; intel: Intel; domain: Domain | null; providers: ProviderStatus[] }

/** Runs every available source for one URL. `suffix` tags provider names for the final-destination pass. */
async function gather(env: Env, p: ParsedUrl, suffix = ''): Promise<Gathered> {
  const providers: ProviderStatus[] = [];
  const intel: Intel = { urlhaus: null, safeBrowsing: null, cloudflareDns: null, virustotal: null, pulsedive: null, urlscan: null };
  const signals: UrlSignal[] = [];
  const ext = externalCandidate(p);
  let domain: Domain | null = null;
  if (!ext.ok) return { signals: [sig('scope', 'internal', 'info', 'Not sent to external services', ext.why)], intel, domain, providers };

  const name = (n: string) => `${n}${suffix}`;
  const budgeted = async <T>(provider: string, label: string, fn: () => Promise<T>): Promise<T | null> => {
    const b = await takeProviderBudget(env, provider);
    if (!b.ok) return skipped(providers, label, b.why ?? 'Request budget reached');
    return track(providers, label, fn);
  };

  const [uh, gsb, vt, pd, us, dns, age] = await Promise.all([
    env.ABUSECH_AUTH_KEY ? track(providers, name(N.urlhaus), () => urlhaus(env, p)) : skipped(providers, name(N.urlhaus), 'No ABUSECH_AUTH_KEY configured'),
    env.GOOGLE_SAFE_BROWSING_API_KEY ? budgeted('safebrowsing', name(N.gsb), () => safeBrowsing(env, p)) : skipped(providers, name(N.gsb), 'No GOOGLE_SAFE_BROWSING_API_KEY configured'),
    env.VIRUSTOTAL_API_KEY ? budgeted('virustotal', name(N.vt), () => virusTotal(env, p)) : skipped(providers, name(N.vt), 'No VIRUSTOTAL_API_KEY configured'),
    env.PULSEDIVE_API_KEY ? budgeted('pulsedive', name(N.pd), () => pulsedive(env, p)) : skipped(providers, name(N.pd), 'No PULSEDIVE_API_KEY configured'),
    p.isIp ? null : budgeted('urlscan', name(N.urlscan), () => urlscan(env, p)),
    p.isIp ? null : track(providers, name(N.cfdns), () => cloudflareDns(p)),
    p.isIp || p.platform || !p.registrableDomain ? null : track(providers, name(N.rdap), () => rdapAge(p.registrableDomain!)),
  ]);

  if (uh) { intel.urlhaus = uh.data; signals.push(...uh.signals); }
  if (gsb) { intel.safeBrowsing = gsb.data; signals.push(...gsb.signals); }
  if (vt) { intel.virustotal = vt.data; signals.push(...vt.signals); }
  if (pd) { intel.pulsedive = pd.data; signals.push(...pd.signals); }
  if (us) { intel.urlscan = us.data; signals.push(...us.signals); }
  if (dns) { intel.cloudflareDns = dns.data; signals.push(...dns.signals); }

  if (!p.isIp) {
    domain = { name: p.registrableDomain ?? p.host, ageDays: age?.ageDays ?? null, registered: age?.registered ?? null, registrar: age?.registrar ?? null, resolves: dns?.domain.resolves ?? null, addresses: dns?.domain.addresses ?? [] };
    const d = age?.ageDays;
    if (typeof d === 'number') {
      if (d <= 7) signals.push(sig('rdap', 'age-new', 'high', `Domain registered only ${d} day${d === 1 ? '' : 's'} ago`, 'Brand-new domains are heavily over-represented in phishing and malware campaigns. New does not mean malicious, but it removes any track record.'));
      else if (d <= 30) signals.push(sig('rdap', 'age-young', 'medium', `Domain registered ${d} days ago`, 'Young domains have little reputation history.'));
      else if (d <= 90) signals.push(sig('rdap', 'age-recent', 'low', `Domain registered ${d} days ago`));
    }
  }
  return { signals, intel, domain, providers };
}

/* ------------------------------------------------------------------ endpoint */

/**
 * GET /api/url/lookup?q=<url>
 * Always an active scan: besides the intelligence sources, the URL is requested (headers only, redirects followed,
 * private addresses refused at every hop) so the real destination can be checked too.
 */
export const onRequestGet = route(async (ctx) => {
  const reqUrl = new URL(ctx.request.url);
  const parsed = parseTargetUrl(param(reqUrl, 'q', MAX_URL_LENGTH + 64));
  if (!parsed.ok) throw badInput(parsed.error);
  const p = parsed.value;
  const env = ctx.env;

  // The cache key records which keyed providers are configured, so enabling one is not hidden behind stale entries.
  const cfg = [env.ABUSECH_AUTH_KEY, env.GOOGLE_SAFE_BROWSING_API_KEY, env.VIRUSTOTAL_API_KEY, env.PULSEDIVE_API_KEY, env.URLSCAN_API_KEY].map((k) => (k ? 1 : 0)).join('');
  const { value, hit } = await cached(ctx, `url:${await sha256Hex(p.lookupUrl)}:active:${cfg}`, async () => {
    const heur = analyzeUrlHeuristics(p);
    const main = await gather(env, p);
    const signals: UrlSignal[] = [...heur, ...main.signals];
    const providers: ProviderStatus[] = [...main.providers];
    let traceOut: UrlLookup['trace'] = null;

    const ext = externalCandidate(p);
    if (!ext.ok) {
      traceOut = { performed: false, hops: [], finalUrl: null, error: ext.why };
    } else {
      const t0 = Date.now();
      const tr = await traceUrl(p.lookupUrl);
      providers.push({ name: N.trace, ok: !tr.error || tr.hops.length > 0, ms: Date.now() - t0, ...(tr.error ? { error: tr.error } : {}) });
      traceOut = { performed: true, hops: tr.hops, finalUrl: tr.finalUrl, ...(tr.error ? { error: tr.error } : {}) };

      const redirects = tr.hops.filter((h) => h.status !== null && h.status >= 300 && h.status < 400 && h.location).length;
      const finalParsed = tr.finalUrl ? parseTargetUrl(tr.finalUrl) : null;
      const fp = finalParsed?.ok ? finalParsed.value : null;
      if (redirects > 0 && fp) {
        signals.push(sig('trace', 'redirects', 'info', `Redirects ${redirects} time${redirects === 1 ? '' : 's'} before the final page`, `Final destination: ${fp.lookupUrl}`));
        if (fp.registrableDomain && p.registrableDomain && fp.registrableDomain !== p.registrableDomain) {
          signals.push(sig('trace', 'cross-domain', 'low', `Redirects to a different domain (${fp.registrableDomain})`, 'The link you were given is not where it ends up.'));
        } else if (fp.isIp && !p.isIp) {
          signals.push(sig('trace', 'redirect-ip', 'medium', 'Redirects to a raw IP address'));
        }
        if (redirects >= 4) signals.push(sig('trace', 'long-chain', 'low', `Long redirect chain (${redirects} hops)`));
      }
      const last = tr.hops[tr.hops.length - 1];
      if (last?.download) signals.push(sig('trace', 'download', 'medium', 'The final response is a file download', `Content type: ${last.contentType ?? 'unknown'}. Do not open files from links you do not trust.`));

      // The destination is what the victim actually reaches, so check it as well (one level only, never recursive).
      if (fp && fp.lookupUrl !== p.lookupUrl) {
        const fin = await gather(env, fp, FINAL);
        const prefix = (s: UrlSignal): UrlSignal => ({ ...s, id: `final-${s.id}`, title: `Final destination: ${s.title}` });
        signals.push(...analyzeUrlHeuristics(fp).filter((s) => s.severity !== 'info').map(prefix), ...fin.signals.filter((s) => s.severity !== 'info').map(prefix));
        // keep the final-URL results, but not the "no key configured" noise a second time
        providers.push(...fin.providers.filter((x) => !(x.skipped && /No \w+ configured/.test(x.error ?? ''))));
      }
    }

    // "checked" counts only sources that produced a verdict for THIS url. VirusTotal's "never scanned", Pulsedive's
    // "unknown" and urlscan's "no prior scans" are responses, but they say nothing about the URL, so they do not count.
    const counted = providers.filter((x) => INTEL_NAMES.has(x.name));
    const attempted = counted.filter((x) => !x.skipped || /budget/i.test(x.error ?? '')).length;
    const okOf = (n: string) => providers.some((x) => x.name === n && x.ok && !x.skipped);
    const checkedBy = {
      urlhaus: okOf(N.urlhaus),
      safebrowsing: okOf(N.gsb),
      cloudflare: okOf(N.cfdns) && main.intel.cloudflareDns?.blocked !== null && main.intel.cloudflareDns !== null,
      virustotal: okOf(N.vt) && !!main.intel.virustotal?.found,
      pulsedive: okOf(N.pd) && !!main.intel.pulsedive?.observed,
      urlscan: okOf(N.urlscan) && (main.intel.urlscan?.scans ?? 0) > 0,
    };
    const checked = Object.values(checkedBy).filter(Boolean).length;
    const a = assessUrl(signals, checked, attempted, Number(checkedBy.urlhaus) + Number(checkedBy.safebrowsing));

    const out: UrlLookup = {
      input: p.input, url: p.url, lookupUrl: p.lookupUrl,
      parts: { scheme: p.scheme, host: p.host, hostUnicode: p.hostUnicode, isIp: p.isIp, ipObfuscated: p.ipObfuscated, port: p.port, path: p.path, query: p.query.slice(0, 300), hasUserinfo: p.hasUserinfo, registrableDomain: p.registrableDomain, tld: p.tld, platform: p.platform },
      verdict: a.verdict, score: a.score, confidence: a.confidence, summary: a.summary, checked, attempted,
      signals: sortSignals(signals), intel: main.intel, domain: main.domain, trace: traceOut, providers,
    };
    const degraded = providers.some((x) => (!x.ok && !x.skipped) || (x.skipped && /budget/i.test(x.error ?? '')));
    return { value: out, ttl: degraded ? 120 : a.verdict === 'malicious' ? 600 : 900 };
  });
  return ok(value, { cached: hit });
});
