/**
 * Step 3 of the phishing investigation: URL triage. Pure and runtime-agnostic (shared by the Worker and the React app).
 *
 *  1. Normalise and de-duplicate the links (tracking parameters, fragments and trailing slashes do not make a new link).
 *  2. Rank them by how much they deserve attention, using only offline evidence: look-alike domains, text that shows one
 *     domain while the link goes to another, form actions, raw IPs, shorteners, brand mismatches ...
 *  3. Pick the few that get a full lookup (the existing URL Intelligence endpoint: URLhaus, Safe Browsing, VirusTotal,
 *     Pulsedive, urlscan, redirect trace ...). Everything else gets local heuristics and an OpenPhish feed check only.
 *  4. Turn every observation into a Finding / CheckResult in the shared format, so a failed or skipped check is never
 *     presented as a clean one.
 *
 * Nothing here decides a verdict. The verdict engine (Step 6) weighs the findings.
 */
import { analyzeUrlHeuristics, brandDomains, brandNames, isOfficialBrandHost, parseTargetUrl, type ParsedUrl } from '../url';
import { registrableOf } from './domains';
import { check, dedupeFindings, makeFinding, sortFindings } from './findings';
import type { UrlSeverity, UrlSignal } from '../types';
import type { CheckResult, Exactness, Finding, Reliability, Severity } from './types';
import type { LinkSource } from './links';

/* ------------------------------------------------------------------ types */

export const LINK_SOURCES: readonly LinkSource[] = ['text', 'anchor', 'image', 'form', 'area', 'manual'];
/** Full lookups per request. Each one fans out into ~10-40 outbound subrequests, so the cap is deliberately small. */
export const DEEP_HARD_CAP = 3;
export const DEEP_DEFAULT = 2;
/** A link scoring at least this much is worth a full lookup (the single top-ranked link always is). */
export const DEEP_MIN_SCORE = 10;
const MAX_LINKS = 200;

export interface LinkInput {
  url: string;
  /** Visible anchor text, if known. */
  text?: string | null;
  sources?: LinkSource[];
  count?: number;
  /** The link was unwrapped from a security-gateway rewrite. */
  wrapped?: boolean;
}

export interface TriageContext {
  /** Registrable domains the message was sent from (From / Return-Path / DKIM). */
  senderDomains: string[];
  /** Organisation names or domains the message claims to be from (the Step 2 brand engine can feed this). */
  claimedBrands: string[];
  claimedDomains: string[];
  displayName?: string;
  subject?: string;
  /** Plain-text body (first part is enough). */
  text?: string;
}

export interface UrlStageRequest { links: LinkInput[]; context: TriageContext; deep: string[]; maxDeep: number }

export interface ClaimedBrand { brand: string; basis: string; confidence: 'high' | 'medium' }

export interface OpenPhishMatch { exact: boolean; hostMatches: number }

export interface RankedLink {
  rank: number;
  /** Credential-free URL: the identifier used everywhere (lookups, findings, the UI). */
  url: string;
  host: string;
  registrableDomain: string | null;
  /** Shared-hosting platform suffix (pages.dev, github.io ...), when the host lives on one. */
  platform: string | null;
  score: number;
  tier: 'deep' | 'heuristic';
  /** Plain-language reasons the link was ranked where it was. */
  reasons: string[];
  text: string | null;
  displayedHost: string | null;
  displayMismatch: boolean;
  sources: LinkSource[];
  wrapped: boolean;
  /** Occurrences in the message, after merging duplicates. */
  count: number;
  /** How many differently-tracked variants were merged into this one. */
  variants: number;
  /** Set when the link's domain is not one of the claimed brand's own domains. */
  brandMismatch: string | null;
  signals: UrlSignal[];
  openphish: OpenPhishMatch | null;
}

export interface TriagedLink extends RankedLink { parsed: ParsedUrl }

export interface LookupSummary {
  url: string;
  verdict: string;
  score: number;
  confidence: string;
  summary: string;
  checked: number;
  attempted: number;
  finalUrl: string | null;
  redirects: number;
  domainAgeDays: number | null;
  providers: { name: string; ok: boolean; skipped?: boolean; error?: string }[];
  signals: { id: string; severity: UrlSeverity; source: string; title: string; detail?: string; confirmed?: boolean; link?: string }[];
  cached: boolean;
  ms: number;
  finalOpenphish: OpenPhishMatch | null;
  finalBrandMismatch: string | null;
}

export interface OpenPhishStatus {
  status: 'ok' | 'failed' | 'skipped';
  feedSize: number | null;
  fetchedAt: string | null;
  stale?: boolean;
  error?: string;
}

export interface UrlStageResult {
  ranked: RankedLink[];
  lookups: Record<string, LookupSummary>;
  lookupErrors: Record<string, string>;
  openphish: OpenPhishStatus;
  claimedBrands: ClaimedBrand[];
  /** Links that deserve a full lookup, best first. The caller sends the ones not yet checked as `deep` in later requests. */
  deepCandidates: string[];
  /** Links that got a full lookup in THIS request. */
  deepChecked: string[];
  skipped: { value: string; reason: string }[];
  merged: number;
  truncated: boolean;
  limits: string[];
  findings: Finding[];
  checks: CheckResult[];
}

/* ------------------------------------------------------------- validation */

const str = (v: unknown, max: number): string | undefined => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : undefined);
const strList = (v: unknown, max: number, each: number): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && !!x.trim()).slice(0, max).map((x) => x.trim().slice(0, each)) : []);

export function validateUrlRequest(raw: unknown): { ok: true; value: UrlStageRequest } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, error: 'Request body must be a JSON object.' };
  const r = raw as Record<string, unknown>;
  if (!Array.isArray(r.links) || !r.links.length) return { ok: false, error: '"links" must be a non-empty array.' };
  if (r.links.length > MAX_LINKS) return { ok: false, error: `At most ${MAX_LINKS} links can be investigated at once.` };

  const links: LinkInput[] = [];
  for (const item of r.links) {
    if (!item || typeof item !== 'object') return { ok: false, error: 'Every link must be an object with a "url".' };
    const l = item as Record<string, unknown>;
    const url = str(l.url, 2048);
    if (!url) return { ok: false, error: 'Every link needs a non-empty "url".' };
    const sources = Array.isArray(l.sources) ? l.sources.filter((s): s is LinkSource => LINK_SOURCES.includes(s as LinkSource)) : [];
    const count = typeof l.count === 'number' && Number.isFinite(l.count) ? Math.min(1000, Math.max(1, Math.floor(l.count))) : 1;
    links.push({ url, text: str(l.text, 200) ?? null, sources, count, wrapped: l.wrapped === true });
  }

  const c = (r.context && typeof r.context === 'object' && !Array.isArray(r.context) ? r.context : {}) as Record<string, unknown>;
  const context: TriageContext = {
    senderDomains: strList(c.senderDomains, 10, 255),
    claimedBrands: strList(c.claimedBrands, 10, 80),
    claimedDomains: strList(c.claimedDomains, 10, 255),
    displayName: str(c.displayName, 200),
    subject: str(c.subject, 300),
    text: typeof c.text === 'string' ? c.text.slice(0, 20_000) : undefined,
  };

  const maxDeepRaw = r.maxDeep === undefined ? DEEP_DEFAULT : Number(r.maxDeep);
  if (!Number.isFinite(maxDeepRaw) || maxDeepRaw < 0) return { ok: false, error: '"maxDeep" must be a number from 0 to ' + DEEP_HARD_CAP + '.' };
  const maxDeep = Math.min(DEEP_HARD_CAP, Math.floor(maxDeepRaw));
  const deep = strList(r.deep, DEEP_HARD_CAP, 2048);
  return { ok: true, value: { links, context, deep, maxDeep } };
}

/* ------------------------------------------------------ normalise / dedupe */

/** Query parameters that identify a recipient or campaign, not a page: they must not make two links "different". */
const TRACKING_PARAM = /^(utm_[a-z0-9_]+|fbclid|gclid|dclid|msclkid|yclid|igshid|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|vero_id|ref_src)$/i;

export function canonicalKey(p: ParsedUrl): string {
  let u: URL;
  try { u = new URL(p.lookupUrl); } catch { return p.lookupUrl; }
  const params = [...u.searchParams.entries()].filter(([k]) => !TRACKING_PARAM.test(k)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const q = params.length ? `?${new URLSearchParams(params).toString()}` : '';
  const path = u.pathname.replace(/\/+$/, '') || '/';
  return `${u.protocol}//${u.host.toLowerCase()}${path}${q}`;
}

/* ----------------------------------------------------- visible-text checks */

const DISPLAY_RE = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i;
const ACTION_RE = /\b(verify|confirm|log\s?in|sign\s?in|secure|unlock|restore|reactivate|re-?activate|update|review|validate|authenticate|view (?:the )?(?:document|invoice|message|file)|download|open (?:the )?(?:document|file)|pay(?:ment)?|claim|click here|get started|access)\b/i;

export function analyzeDisplayText(text: string | null | undefined, actualRegistrable: string | null): { displayedHost: string | null; mismatch: boolean } {
  if (!text) return { displayedHost: null, mismatch: false };
  const m = text.trim().match(DISPLAY_RE);
  if (!m) return { displayedHost: null, mismatch: false };
  const displayedHost = m[1].toLowerCase();
  const shown = registrableOf(displayedHost);
  return { displayedHost, mismatch: !!shown && !!actualRegistrable && shown !== actualRegistrable };
}

/* ------------------------------------------------------------ claimed brands */

const AMBIGUOUS_BRANDS = new Set(['apple', 'chase', 'zoom', 'steam', 'outlook']);
const BRAND_PHRASE: Record<string, string> = {
  bankofamerica: 'bank\\s+of\\s+america', wellsfargo: 'wells\\s*fargo', office365: '(?:office|microsoft)\\s*365', onedrive: 'one\\s*drive',
  citibank: 'citi\\s*bank', docusign: 'docu\\s*sign', whatsapp: 'whats\\s*app',
};
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const phraseRe = (brand: string) => new RegExp(`\\b(?:${BRAND_PHRASE[brand] ?? escapeRe(brand)})\\b`, 'gi');
const mentions = (text: string | undefined, brand: string): number => (text ? (text.match(phraseRe(brand)) ?? []).length : 0);
const brandsOfDomain = (domain: string): string[] => {
  const reg = registrableOf(domain);
  return reg ? brandNames().filter((b) => brandDomains(b).includes(reg)) : [];
};

/**
 * Which organisations does this message claim to be from? Evidence, strongest first: the analyst's own claim (or the
 * Step 2 brand engine), a sender domain that IS the brand's, the display name / subject, and repeated body mentions.
 * Common English words (apple, chase, zoom ...) need more evidence than distinctive names.
 */
export function detectClaimedBrands(ctx: TriageContext): ClaimedBrand[] {
  const out = new Map<string, ClaimedBrand>();
  const add = (brand: string, basis: string, confidence: 'high' | 'medium') => {
    const cur = out.get(brand);
    if (!cur || (cur.confidence === 'medium' && confidence === 'high')) out.set(brand, { brand, basis, confidence });
  };
  const known = new Set(brandNames());

  for (const raw of ctx.claimedBrands) {
    const key = raw.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (known.has(key)) add(key, `named as the claimed organisation (${raw})`, 'high');
    else for (const b of brandsOfDomain(raw)) add(b, `claimed organisation ${raw}`, 'high');
  }
  for (const d of ctx.claimedDomains) for (const b of brandsOfDomain(d)) add(b, `claimed website ${d}`, 'high');
  for (const d of ctx.senderDomains) for (const b of brandsOfDomain(d)) add(b, `sent from ${d}`, 'high');

  const head = `${ctx.displayName ?? ''}\n${ctx.subject ?? ''}`;
  for (const b of brandNames()) {
    if (mentions(head, b) > 0) add(b, 'named in the sender name or subject', AMBIGUOUS_BRANDS.has(b) ? 'medium' : 'high');
    else {
      const n = mentions(ctx.text, b);
      if (n >= (AMBIGUOUS_BRANDS.has(b) ? 3 : 2)) add(b, `mentioned ${n} times in the message`, 'medium');
    }
  }
  return [...out.values()].sort((a, b) => (a.confidence === b.confidence ? 0 : a.confidence === 'high' ? -1 : 1)).slice(0, 6);
}

/** The claimed brand name when this host belongs to none of the claimed organisations, else null. */
export function brandMismatchOf(parsed: ParsedUrl | { host: string; registrableDomain: string | null }, claimed: ClaimedBrand[]): string | null {
  if (!claimed.length) return null;
  const { host, registrableDomain } = parsed;
  if (claimed.some((c) => isOfficialBrandHost(c.brand, host, registrableDomain))) return null;
  return claimed[0].brand;
}

/* ------------------------------------------------------------------ ranking */

const POINTS: Record<UrlSeverity, number> = { critical: 70, high: 40, medium: 20, low: 8, info: 0 };
const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

interface Merged { parsed: ParsedUrl; text: string | null; sources: Set<LinkSource>; wrapped: boolean; count: number; variants: number; order: number }

export function triageLinks(inputs: LinkInput[], ctx: TriageContext): { items: TriagedLink[]; skipped: { value: string; reason: string }[]; claimed: ClaimedBrand[]; merged: number } {
  const skipped: { value: string; reason: string }[] = [];
  const map = new Map<string, Merged>();
  let merged = 0;
  inputs.forEach((l, order) => {
    const parsed = parseTargetUrl(l.url);
    if (!parsed.ok) { skipped.push({ value: l.url.slice(0, 200), reason: parsed.error }); return; }
    const key = canonicalKey(parsed.value);
    const cur = map.get(key);
    const text = l.text?.trim() || null;
    if (cur) {
      merged++;
      cur.count += l.count ?? 1;
      cur.variants += parsed.value.lookupUrl === cur.parsed.lookupUrl ? 0 : 1;
      for (const s of l.sources ?? []) cur.sources.add(s);
      cur.wrapped ||= !!l.wrapped;
      if (!cur.text && text) cur.text = text;
      return;
    }
    map.set(key, { parsed: parsed.value, text, sources: new Set(l.sources ?? []), wrapped: !!l.wrapped, count: l.count ?? 1, variants: 1, order });
  });

  const senderRegs = new Set(ctx.senderDomains.map((d) => registrableOf(d)).filter((x): x is string => !!x));
  const claimed = detectClaimedBrands(ctx);

  const items: TriagedLink[] = [...map.values()].map((m) => {
    const p = m.parsed;
    const signals = analyzeUrlHeuristics(p);
    const reasons: string[] = [];
    let score = signals.reduce((n, s) => n + POINTS[s.severity], 0);
    for (const s of signals) if (s.severity !== 'info' && reasons.length < 4) reasons.push(s.title);

    const disp = analyzeDisplayText(m.text, p.registrableDomain);
    if (disp.mismatch) { score += 45; reasons.unshift(`Link text shows ${disp.displayedHost} but the link goes to ${p.host}`); }
    if (m.sources.has('form')) { score += 25; reasons.push('A form posts to this address'); }
    if (signals.some((s) => s.id === 'shortener')) score += 12;
    if (m.text && ACTION_RE.test(m.text)) { score += 10; reasons.push(`Call-to-action text (“${m.text.slice(0, 40)}”)`); }

    const mismatch = brandMismatchOf(p, claimed);
    if (mismatch) { score += 35; reasons.push(`Not a ${mismatch} domain, but the message is about ${mismatch}`); }

    // Links back to the sender's own organisation are the least interesting, unless something else is wrong with them.
    if (p.registrableDomain && senderRegs.has(p.registrableDomain) && score < 40) score -= 15;

    return {
      rank: 0, url: p.lookupUrl, host: p.host, registrableDomain: p.registrableDomain, platform: p.platform, score: clamp(score), tier: 'heuristic' as const,
      reasons: reasons.slice(0, 5), text: m.text, displayedHost: disp.displayedHost, displayMismatch: disp.mismatch,
      sources: [...m.sources], wrapped: m.wrapped, count: m.count, variants: m.variants, brandMismatch: mismatch, signals, openphish: null, parsed: p,
    };
  });

  items.sort((a, b) => b.score - a.score || b.count - a.count || (map.get(canonicalKey(a.parsed))!.order - map.get(canonicalKey(b.parsed))!.order));
  items.forEach((it, i) => { it.rank = i + 1; });
  return { items, skipped, claimed, merged };
}

/** Links worth a full lookup, best first: the top-ranked link always, then anything scoring at least DEEP_MIN_SCORE. */
export function deepCandidatesOf(items: { url: string; score: number }[]): string[] {
  return items.filter((it, i) => i === 0 || it.score >= DEEP_MIN_SCORE).map((it) => it.url);
}

/** Chooses what to look up in this request: the caller's explicit picks, else the best candidates up to `max`. */
export function selectDeep(items: { url: string; score: number }[], forced: string[], max: number): string[] {
  const known = new Set(items.map((i) => i.url));
  const picked = forced.filter((u, i) => known.has(u) && forced.indexOf(u) === i).slice(0, DEEP_HARD_CAP);
  if (picked.length) return picked;
  return deepCandidatesOf(items).slice(0, Math.min(max, DEEP_HARD_CAP));
}

/**
 * Findings that need no lookup at all (look-alike domains, text that shows one domain while linking to another, brand
 * mismatches, raw IPs ...). Passive and instant, so they are produced when the message is parsed; the same pure
 * functions run again in the link investigation, and identical findings are de-duplicated.
 */
export function offlineLinkFindings(links: LinkInput[], ctx: TriageContext): { findings: Finding[]; claimed: ClaimedBrand[]; linkCount: number } {
  const { items, claimed } = triageLinks(links, ctx);
  if (!items.length) return { findings: [], claimed, linkCount: 0 };
  const ranked = items.map(({ parsed: _parsed, ...rest }) => rest);
  const stage = assembleUrlStage({ ranked, lookups: {}, lookupErrors: {}, openphish: { status: 'skipped', feedSize: null, fetchedAt: null }, claimedBrands: claimed, deepCandidates: [], deepChecked: [], skipped: [], merged: 0, truncated: false, maxDeep: 0 });
  return { findings: stage.findings, claimed, linkCount: items.length };
}

/* -------------------------------------------------------- signal -> finding */

const SOURCE_LABEL: Record<string, string> = {
  heuristic: 'url-heuristics', urlhaus: 'URLhaus', safebrowsing: 'Google Safe Browsing', virustotal: 'VirusTotal', pulsedive: 'Pulsedive',
  urlscan: 'urlscan.io', 'cloudflare-dns': 'Cloudflare Security DNS', rdap: 'RDAP', dns: 'DNS', trace: 'Redirect trace', scope: 'url-heuristics',
};

interface Mapped { id: string; exactness: Exactness; reliability: Reliability }

/** Stable finding ids: the verdict engine (Step 6) assigns points to these, not to provider-specific signal ids. */
function mapSignal(rawId: string, severity: UrlSeverity): Mapped | null {
  const id = rawId.replace(/^final-/, '');
  const m = (fid: string, exactness: Exactness, reliability: Reliability): Mapped => ({ id: fid, exactness, reliability });
  if (id === 'urlhaus-online' || id === 'urlhaus-listed') return m('url_listed_malware', 'exact', 'high');
  if (id === 'urlhaus-host-online') return m('url_host_listed', 'related', 'medium');
  if (id === 'urlhaus-host-offline') return m('url_host_listed', 'related', 'low');
  if (id.startsWith('urlhaus-bl-')) return m('url_blocklisted_host', 'related', 'medium');
  if (id === 'gsb-social_engineering') return m('url_listed_phishing', 'exact', 'high');
  if (id.startsWith('gsb-')) return m('url_listed_malware', 'exact', 'high');
  if (id === 'vt-malicious' || id === 'vt-malicious-1') return m('url_engine_detections', 'exact', severity === 'critical' ? 'high' : severity === 'high' ? 'medium' : 'low');
  if (id === 'vt-suspicious' || id === 'vt-suspicious-low') return m('url_engine_suspicious', 'exact', 'low');
  if (id === 'pd-risk') return m('url_threat_intel_rating', 'related', 'medium');
  if (id === 'urlscan-malicious') return m('url_scan_malicious', 'exact', 'medium');
  if (id === 'urlscan-host-malicious') return m('url_host_scan_malicious', 'related', 'low');
  if (id === 'cfdns-blocked') return m('url_dns_blocked', 'exact', 'medium');
  if (id === 'nxdomain') return m('url_domain_dead', 'contextual', 'low');
  if (id.startsWith('age-')) return m('url_domain_young', 'contextual', 'medium');
  if (id === 'cross-domain') return m('url_redirect_cross_domain', 'contextual', 'low');
  if (id === 'redirect-ip') return m('url_redirect_to_ip', 'related', 'medium');
  if (id === 'long-chain') return m('url_redirect_chain', 'contextual', 'low');
  if (id === 'download') return m('url_download_on_open', 'related', 'medium');
  if (id === 'ip-obfuscated') return m('url_obfuscated_ip', 'exact', 'medium');
  if (id === 'ip-host') return m('url_ip_host', 'exact', 'low');
  if (id === 'userinfo-deception') return m('url_deceptive_userinfo', 'exact', 'medium');
  if (id === 'userinfo') return m('url_userinfo', 'exact', 'low');
  if (id.startsWith('homograph-')) return m('url_homograph_domain', 'exact', 'medium');
  if (id.startsWith('brand-') || id.startsWith('squat-')) return m('url_lookalike_domain', 'exact', 'medium');
  if (id.startsWith('typo-')) return m('url_lookalike_domain', 'exact', 'low');
  if (id === 'cred-host' || id === 'cred-path') return m('url_credential_wording', 'exact', 'low');
  if (id === 'login-no-tls') return m('url_login_without_tls', 'exact', 'low');
  if (id === 'double-ext') return m('url_double_extension', 'exact', 'medium');
  if (id === 'risky-file') return m('url_risky_file_type', 'exact', 'medium');
  if (id === 'shortener') return m('url_shortener', 'exact', 'low');
  if (id === 'tld') return m('url_unusual_tld', 'exact', 'low');
  if (id === 'open-redirect') return m('url_open_redirect_param', 'exact', 'low');
  if (['port', 'deep-subdomain', 'long-host', 'hyphens', 'long-url', 'encoding'].includes(id)) return m('url_obfuscation_pattern', 'exact', 'low');
  // redirects (info), shared-hosting, idn, archive-file, vt-stale, scope: context for the analyst, not evidence.
  return null;
}

export function signalFinding(s: { id: string; severity: UrlSeverity; source: string; title: string; detail?: string; link?: string }, link: string): Finding | null {
  if (s.severity === 'info') return null;
  const mapped = mapSignal(s.id, s.severity);
  if (!mapped) return null;
  const isFinal = s.id.startsWith('final-');
  const external = s.source !== 'heuristic';
  return makeFinding({
    id: isFinal ? mapped.id.replace(/^url_/, 'url_final_') : mapped.id,
    dimension: 'url',
    severity: s.severity as Severity,
    title: s.title,
    detail: s.detail ?? s.title,
    source: SOURCE_LABEL[s.source] ?? s.source,
    // A listing for the page the victim actually lands on is as direct as one for the link itself.
    exactness: isFinal && mapped.exactness === 'related' ? 'related' : mapped.exactness,
    reliability: mapped.reliability,
    trust: external ? 'independently_verified' : 'derived',
    evidence: [s.detail && s.detail.length > 160 ? `${s.detail.slice(0, 159)}…` : '', s.link ?? ''].filter(Boolean) as string[],
    indicator: { type: 'url', value: link },
  });
}

const FINDING_LINK_CAP = 25;

function textMismatchFinding(l: RankedLink): Finding {
  const shownOrg = l.displayedHost ? registrableOf(l.displayedHost) : null;
  const brand = shownOrg ? brandNames().find((b) => brandDomains(b).includes(shownOrg)) : undefined;
  return makeFinding({
    id: 'link_text_mismatch',
    dimension: 'url',
    severity: brand ? 'high' : 'medium',
    title: `Link text shows ${l.displayedHost} but the link goes to ${l.host}`,
    detail: brand
      ? `The visible text names a ${brand} address, yet clicking it leads somewhere else. Showing a trusted address while linking to another is the classic phishing disguise.`
      : 'The visible text looks like one website address while the real destination is a different organisation. Legitimate senders rarely do this.',
    source: 'link-analysis', exactness: 'exact', reliability: brand ? 'high' : 'medium', trust: 'derived',
    evidence: [`shown: ${l.text ?? l.displayedHost}`, `goes to: ${l.url}`],
    indicator: { type: 'url', value: l.url },
  });
}

function brandMismatchFinding(l: RankedLink, claimed: ClaimedBrand[], where: 'link' | 'final'): Finding {
  const brand = l.brandMismatch ?? claimed[0]?.brand ?? 'the claimed brand';
  const basis = claimed.find((c) => c.brand === brand)?.basis ?? 'the message content';
  const lookalike = l.signals.some((s) => /^(brand-|squat-|typo-|homograph-)/.test(s.id));
  const actionish = l.sources.includes('form') || (!!l.text && ACTION_RE.test(l.text)) || l.signals.some((s) => s.id.startsWith('cred-'));
  const severity: Severity = lookalike || l.sources.includes('form') ? 'high' : actionish ? 'medium' : 'low';
  return makeFinding({
    id: where === 'final' ? 'url_final_brand_mismatch' : 'url_brand_mismatch',
    dimension: 'url',
    severity,
    title: where === 'final' ? `Redirect ends on ${l.host}, which is not a ${brand} domain` : `Link goes to ${l.host}, which is not a ${brand} domain`,
    detail: `The message claims to concern ${brand} (${basis}), but this ${where === 'final' ? 'final destination' : 'link'} is registered to ${l.registrableDomain ?? l.host}. ${severity === 'low' ? 'It is not a call-to-action link, so this is only weak evidence (mailing and tracking services are common).' : 'A genuine message from the brand would send you to its own domain.'}`,
    source: 'link-analysis', exactness: where === 'final' ? 'exact' : 'related', reliability: lookalike ? 'high' : 'medium', trust: 'derived',
    evidence: [l.url],
    indicator: { type: 'url', value: l.url },
  });
}

function openphishFindings(url: string, host: string, platform: string | null, m: OpenPhishMatch, final: boolean): Finding[] {
  const out: Finding[] = [];
  const pre = final ? 'url_final_' : 'url_';
  const where = final ? 'The final destination' : 'This exact URL';
  if (m.exact) {
    out.push(makeFinding({
      id: `${pre}listed_phishing`, dimension: 'url', severity: 'critical',
      title: `${where} is listed by OpenPhish as an active phishing page`,
      detail: 'OpenPhish\u2019s community feed lists verified phishing URLs and removes them once the page goes offline, so a match means a phishing page seen recently.',
      source: 'OpenPhish', exactness: 'exact', reliability: 'high', trust: 'independently_verified',
      evidence: [url], indicator: { type: 'url', value: url },
    }));
  } else if (m.hostMatches > 0) {
    // Host-level matches are related evidence, never exact: cap at medium regardless of platform status.
    out.push(makeFinding({
      id: `${pre}host_listed`, dimension: 'url', severity: 'medium',
      title: `OpenPhish lists ${m.hostMatches} phishing URL${m.hostMatches === 1 ? '' : 's'} on ${host}`,
      detail: `This exact URL is not in the feed, but the same host is.${platform ? ` It is a shared platform (${platform}), so other tenants\u2019 listings say little about this page.` : ' A host serving phishing pages is likely to serve more.'}`,
      source: 'OpenPhish', exactness: 'related', reliability: platform ? 'low' : 'medium', trust: 'independently_verified',
      evidence: [host], indicator: { type: 'url', value: url },
    }));
  }
  return out;
}

/* ----------------------------------------------------------- assembling */

const providerKey = (n: string) => n.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');

/** Every finding and check row for the current state. Pure, so the browser can re-run it after merging several requests. */
export function assembleUrlStage(input: Omit<UrlStageResult, 'findings' | 'checks' | 'limits'> & { maxDeep: number }): UrlStageResult {
  const { maxDeep, ...base } = input;
  const { ranked, lookups, lookupErrors, openphish } = base;
  const claimed = base.claimedBrands;
  const findings: Finding[] = [];
  const byUrl = new Map(ranked.map((r) => [r.url, r]));

  // Offline evidence for the links that matter; the long tail is summarised in the check rows instead.
  for (const l of ranked.filter((r) => r.score >= DEEP_MIN_SCORE || r.rank === 1).slice(0, FINDING_LINK_CAP)) {
    for (const s of l.signals) { const f = signalFinding(s, l.url); if (f) findings.push(f); }
    if (l.displayMismatch) findings.push(textMismatchFinding(l));
    if (l.brandMismatch) findings.push(brandMismatchFinding(l, claimed, 'link'));
  }
  // OpenPhish is checked for every link, ranked or not.
  for (const l of ranked) if (l.openphish) findings.push(...openphishFindings(l.url, l.host, l.platform, l.openphish, false));

  for (const [url, lk] of Object.entries(lookups)) {
    for (const s of lk.signals) {
      if (s.source === 'heuristic' && !s.id.startsWith('final-')) continue; // already produced from the offline pass
      const f = signalFinding(s, url);
      if (f) findings.push(f);
    }
    const link = byUrl.get(url);
    if (lk.finalOpenphish && lk.finalUrl) findings.push(...openphishFindings(lk.finalUrl, safeHost(lk.finalUrl), null, lk.finalOpenphish, true));
    if (lk.finalBrandMismatch && link) findings.push(brandMismatchFinding({ ...link, url: lk.finalUrl ?? link.url, host: safeHost(lk.finalUrl ?? link.url), registrableDomain: registrableOf(safeHost(lk.finalUrl ?? link.url)), brandMismatch: lk.finalBrandMismatch, sources: [], text: null, signals: [] }, claimed, 'final'));
  }

  const limits: string[] = [];
  const pending = ranked.filter((r) => base.deepCandidates.includes(r.url) && !lookups[r.url] && !lookupErrors[r.url]);
  if (pending.length) limits.push(`${pending.length} ranked link${pending.length === 1 ? '' : 's'} still ${pending.length === 1 ? 'has' : 'have'} no full lookup (only local heuristics and the OpenPhish feed). Each full lookup makes many outbound requests and VirusTotal\u2019s free tier allows about 4 per minute, so they are run in small batches.`);
  if (base.truncated) limits.push('The message has more links than can be investigated at once; the extra ones were ignored.');
  if (base.skipped.length) limits.push(`${base.skipped.length} link${base.skipped.length === 1 ? ' was' : 's were'} not valid web URLs and could not be investigated.`);
  if (!claimed.length) limits.push('No claimed organisation could be identified, so destination-versus-brand checks were not applied.');

  return { ...base, findings: sortFindings(dedupeFindings(findings)), checks: buildUrlChecks({ ranked, lookups, lookupErrors, openphish, deepCandidates: base.deepCandidates, skipped: base.skipped.length, merged: base.merged, maxDeep }), limits };
}

const safeHost = (u: string): string => { try { return new URL(u).hostname; } catch { return u; } };

export function buildUrlChecks(i: { ranked: RankedLink[]; lookups: Record<string, LookupSummary>; lookupErrors: Record<string, string>; openphish: OpenPhishStatus; deepCandidates: string[]; skipped: number; merged: number; maxDeep: number }): CheckResult[] {
  const rows: CheckResult[] = [];
  const total = i.ranked.length;
  rows.push(check('urls.triage', 'urls', 'Link triage', 'complete', `${total} unique link${total === 1 ? '' : 's'} ranked`, [i.merged ? `${i.merged} duplicate or tracking-only variant${i.merged === 1 ? '' : 's'} merged` : '', i.skipped ? `${i.skipped} invalid link${i.skipped === 1 ? '' : 's'} skipped` : ''].filter(Boolean).join('; ') || undefined));

  const op = i.openphish;
  if (op.status === 'ok') {
    const hits = i.ranked.filter((r) => r.openphish?.exact).length;
    rows.push(check('urls.openphish', 'urls', 'OpenPhish feed', 'complete', hits ? `${hits} exact match${hits === 1 ? '' : 'es'}` : 'no listing', `${op.feedSize?.toLocaleString('en-US') ?? '?'} URLs in the feed${op.stale ? ' (cached copy; the live feed could not be refreshed)' : ''}. A missing listing is not an all-clear: the feed only covers recently verified phishing pages.`));
  } else rows.push(check('urls.openphish', 'urls', 'OpenPhish feed', op.status === 'skipped' ? 'skipped' : 'failed', null, op.error));

  const done = Object.keys(i.lookups).length;
  const errs = Object.keys(i.lookupErrors).length;
  if (i.maxDeep === 0 && !done && !errs) rows.push(check('urls.deep', 'urls', 'Full URL intelligence', 'skipped', null, 'Full lookups were switched off for this request.'));
  else if (!done && errs) rows.push(check('urls.deep', 'urls', 'Full URL intelligence', 'failed', `0 of ${errs} lookups completed`, Object.values(i.lookupErrors)[0]));
  else if (!done) rows.push(check('urls.deep', 'urls', 'Full URL intelligence', 'skipped', null, 'No link has had a full lookup yet.'));
  else rows.push(check('urls.deep', 'urls', 'Full URL intelligence', 'complete', `${done} of ${total} link${total === 1 ? '' : 's'} fully checked`, errs ? `${errs} lookup${errs === 1 ? '' : 's'} failed: ${Object.values(i.lookupErrors)[0]}` : undefined));

  // One row per provider across every full lookup, so a provider that failed or was paused is visible, never absent.
  const agg = new Map<string, { ok: number; failed: number; skipped: number; why: Set<string> }>();
  for (const lk of Object.values(i.lookups)) {
    for (const p of lk.providers) {
      const a = agg.get(p.name) ?? { ok: 0, failed: 0, skipped: 0, why: new Set<string>() };
      if (p.skipped) a.skipped++; else if (p.ok) a.ok++; else a.failed++;
      if (p.error) a.why.add(p.error);
      agg.set(p.name, a);
    }
  }
  for (const [name, a] of agg) {
    const status: CheckResult['status'] = a.failed ? 'failed' : a.ok ? 'complete' : 'skipped';
    const result = a.failed ? `${a.failed} failed${a.ok ? `, ${a.ok} ok` : ''}` : a.ok ? `${a.ok} URL${a.ok === 1 ? '' : 's'} checked` : null;
    rows.push(check(`urls.provider.${providerKey(name)}`, 'urls', name, status, result, [...a.why].slice(0, 2).join(' · ') || undefined));
  }

  const heuristicOnly = i.ranked.filter((r) => !i.lookups[r.url]).length;
  if (done && heuristicOnly) rows.push(check('urls.heuristic_only', 'urls', 'Links without a full lookup', 'skipped', `${heuristicOnly} link${heuristicOnly === 1 ? '' : 's'}: local heuristics + OpenPhish only`, 'Lower-ranked links are not sent to VirusTotal, urlscan and the other sources unless you select them.'));
  return rows;
}
