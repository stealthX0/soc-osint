/**
 * URL extraction from an e-mail: plain text, HTML anchors, image links, forms, image maps and analyst-supplied URLs.
 * Keeps what the reader SEES (anchor text) next to where the link GOES, because that gap is the classic phishing trick,
 * and unwraps security-gateway rewrites (Safe Links, Proofpoint, ...) so the real destination is what gets investigated.
 */
import { refang } from '../domain';
import { parseTargetUrl } from '../url';
import { decodeEntities, htmlToText, parseAttrs } from './html';
import { registrableOf } from './domains';
import { LIMITS } from './types';

export type LinkSource = 'text' | 'anchor' | 'image' | 'form' | 'area' | 'manual';

export interface LinkWrapper { service: string; wrapperUrl: string; /** true when the original could only be recovered approximately */ approximate?: boolean }

export interface ExtractedLink {
  /** The URL as found in the message (after unwrapping a gateway rewrite). May contain credentials: display only. */
  url: string;
  /** Credential-free URL used for lookups and fetching. */
  normalized: string;
  host: string;
  registrableDomain: string | null;
  isIp: boolean;
  ipObfuscated: boolean;
  hasUserinfo: boolean;
  scheme: 'http' | 'https';
  /** First non-empty visible text of the anchor(s) pointing here. */
  text: string | null;
  /** The anchor text, when it itself looks like a URL / domain ("www.paypal.com"). */
  displayedUrl: string | null;
  displayedHost: string | null;
  /** True when the displayed domain belongs to a different organisation than the real destination. */
  displayMismatch: boolean;
  sources: LinkSource[];
  wrapper: LinkWrapper | null;
  count: number;
}

export interface SkippedLink { value: string; reason: string; source: LinkSource }

export interface LinkExtraction { links: ExtractedLink[]; skipped: SkippedLink[]; truncated: boolean }

/* ------------------------------------------------------------ unwrapping */

function unwrap(raw: string): { url: string; wrapper: LinkWrapper | null } {
  let u: URL;
  try { u = new URL(raw); } catch { return { url: raw, wrapper: null }; }
  const h = u.hostname.toLowerCase();
  const http = (v: string | null) => (v && /^https?:\/\//i.test(v) ? v : null);

  if (h === 'safelinks.protection.outlook.com' || h.endsWith('.safelinks.protection.outlook.com')) {
    const o = http(u.searchParams.get('url'));
    if (o) return { url: o, wrapper: { service: 'Microsoft Defender Safe Links', wrapperUrl: raw } };
  }
  if ((h === 'www.google.com' || h === 'google.com') && u.pathname === '/url') {
    const o = http(u.searchParams.get('q') ?? u.searchParams.get('url'));
    if (o) return { url: o, wrapper: { service: 'Google redirector', wrapperUrl: raw } };
  }
  if (h === 'urldefense.proofpoint.com' && u.pathname.startsWith('/v2/url')) {
    const p = u.searchParams.get('u');
    if (p) {
      try {
        const o = http(decodeURIComponent(p.replace(/-/g, '%').replace(/_/g, '/')));
        if (o) return { url: o, wrapper: { service: 'Proofpoint URL Defense v2', wrapperUrl: raw } };
      } catch { /* fall through */ }
    }
  }
  if (h === 'urldefense.com') {
    const m = u.pathname.match(/^\/v3\/__(.+?)__;/);
    const o = m ? http(m[1]) : null;
    if (o) return { url: o, wrapper: { service: 'Proofpoint URL Defense v3', wrapperUrl: raw, approximate: o.includes('*') } };
  }
  if (h === 'linkprotect.cudasvc.com' && u.pathname === '/url') {
    const o = http(u.searchParams.get('a'));
    if (o) return { url: o, wrapper: { service: 'Barracuda Link Protection', wrapperUrl: raw } };
  }
  return { url: raw, wrapper: null };
}

/* -------------------------------------------------------------- scanning */

const URL_RE = /\b(?:(?:https?|hxxps?|ftp):\/\/|www\.)[^\s<>"'`\u00a0]+/gi;

function trimTrailing(u: string): string {
  let s = u;
  for (;;) {
    const last = s[s.length - 1];
    if (!last) return s;
    if ('.,;:!?'.includes(last)) { s = s.slice(0, -1); continue; }
    const pair: Record<string, string> = { ')': '(', ']': '[', '}': '{' };
    if (pair[last] && s.split(last).length > s.split(pair[last]).length) { s = s.slice(0, -1); continue; }
    return s;
  }
}

const DISPLAY_RE = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i;

export function extractLinks(input: { text?: string; html?: string | null; manual?: string[] }): LinkExtraction {
  const map = new Map<string, ExtractedLink>();
  const skipped: SkippedLink[] = [];
  let truncated = false;

  const add = (rawIn: string, source: LinkSource, visibleText: string | null) => {
    const cleaned = decodeEntities(rawIn).replace(/[\t\n\r]/g, '').trim();
    if (!cleaned || cleaned.startsWith('#')) return;
    const scheme = cleaned.match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase();
    if (scheme && !['http', 'https', 'hxxp', 'hxxps'].includes(scheme) && !/^[a-z0-9.-]+:\d/i.test(cleaned)) {
      if (scheme !== 'cid') skipped.push({ value: cleaned.slice(0, 200), reason: scheme === 'javascript' || scheme === 'data' ? `${scheme}: link` : `${scheme}: link (not a web URL)`, source });
      return;
    }
    const candidate = cleaned.startsWith('//') ? `https:${cleaned}` : cleaned;
    if (!scheme && !candidate.startsWith('https:') && !/^(?:www\.|[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/:?#]|$))/i.test(candidate)) {
      skipped.push({ value: cleaned.slice(0, 200), reason: 'relative link (no destination host)', source });
      return;
    }
    const first = parseTargetUrl(candidate);
    if (!first.ok) { skipped.push({ value: cleaned.slice(0, 200), reason: first.error, source }); return; }
    const { url: target, wrapper } = unwrap(first.value.url);
    const parsed = wrapper ? parseTargetUrl(target) : first;
    if (!parsed.ok) { skipped.push({ value: cleaned.slice(0, 200), reason: parsed.error, source }); return; }
    const p = parsed.value;

    const key = p.lookupUrl;
    const existing = map.get(key);
    const text = visibleText && visibleText.trim() ? visibleText.trim().slice(0, 200) : null;
    if (existing) {
      existing.count++;
      if (!existing.sources.includes(source)) existing.sources.push(source);
      if (!existing.text && text) setText(existing, text);
      return;
    }
    if (map.size >= LIMITS.links) { truncated = true; return; }
    const link: ExtractedLink = {
      url: p.url,
      normalized: p.lookupUrl,
      host: p.host,
      registrableDomain: p.registrableDomain,
      isIp: p.isIp,
      ipObfuscated: p.ipObfuscated,
      hasUserinfo: p.hasUserinfo,
      scheme: p.scheme,
      text: null,
      displayedUrl: null,
      displayedHost: null,
      displayMismatch: false,
      sources: [source],
      wrapper,
      count: 1,
    };
    if (text) setText(link, text);
    map.set(key, link);
  };

  const setText = (link: ExtractedLink, text: string) => {
    link.text = text;
    const m = text.match(DISPLAY_RE);
    if (!m) return;
    link.displayedUrl = text;
    link.displayedHost = m[1].toLowerCase();
    const shown = registrableOf(link.displayedHost);
    link.displayMismatch = !!shown && !!link.registrableDomain && shown !== link.registrableDomain;
  };

  const html = input.html ?? '';
  // Text that merely repeats an anchor's visible label ("www.paypal.com") is what the link CLAIMS, not another destination.
  const shownInAnchors = new Set<string>();
  const norm = (v: string) => v.toLowerCase().replace(/^(?:https?|hxxps?):\/\//, '').replace(/\/+$/, '');
  if (html) {
    for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
      const a = parseAttrs(m[1]);
      if (!a.href) continue;
      const inner = m[2];
      const img = inner.match(/<img\b([^>]*)>/i);
      const label = htmlToText(inner).replace(/\s+/g, ' ') || (img ? parseAttrs(img[1]).alt ?? '' : '');
      if (label) shownInAnchors.add(norm(label));
      add(a.href, img && !htmlToText(inner) ? 'image' : 'anchor', label);
    }
    for (const m of html.matchAll(/<area\b([^>]*)>/gi)) { const a = parseAttrs(m[1]); if (a.href) add(a.href, 'area', a.alt ?? null); }
    for (const m of html.matchAll(/<form\b([^>]*)>/gi)) { const a = parseAttrs(m[1]); if (a.action) add(a.action, 'form', null); }
  }

  const text = input.text ?? '';
  if (text) for (const m of text.matchAll(URL_RE)) {
    const u = trimTrailing(m[0]);
    if (!shownInAnchors.has(norm(u))) add(u, 'text', null);
  }
  // Defanged URLs in text ("hxxp://evil[.]com") are matched above; also catch "evil[.]com/path" written without a scheme only when manual.
  for (const raw of input.manual ?? []) {
    const v = refang(raw.trim());
    if (v) add(v, 'manual', null);
  }

  return { links: [...map.values()], skipped, truncated };
}
