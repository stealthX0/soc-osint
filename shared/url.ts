/**
 * URL intelligence: parsing, local (offline) heuristics and the verdict logic. Pure and runtime-agnostic.
 *
 * Accuracy principles:
 *  - Only external, reputable sources can make a URL "malicious". Local heuristics alone cap at "suspicious".
 *  - A clean result is reported as "no detections", never "safe", together with how many sources actually answered.
 *  - Every finding carries its source so an analyst can see exactly who said what.
 */
import { isValidHostname, refang } from './domain';
import { parseIP } from './ip';
import type { UrlSignal, UrlSeverity, UrlVerdict } from './types';

/* ------------------------------------------------------------------ parsing */

export interface ParsedUrl {
  /** What the user typed (refanged, trimmed). */
  input: string;
  /** Normalised URL, fragment removed (kept for display; may contain credentials). */
  url: string;
  /** Same URL with username/password removed: this is what is sent to third parties and fetched when tracing. */
  lookupUrl: string;
  scheme: 'http' | 'https';
  /** Lowercase ASCII (punycode) host, no brackets. */
  host: string;
  /** Host decoded from punycode for display / homograph analysis. */
  hostUnicode: string;
  isIp: boolean;
  /** IPv4 written as decimal/hex/octal/short form (e.g. 2130706433, 0x7f.1) that the URL parser normalised. */
  ipObfuscated: boolean;
  port: number | null;
  path: string;
  query: string;
  hasUserinfo: boolean;
  userinfo: string | null;
  /** Public-suffix-aware registrable domain (null for IPs). Shared hosting suffixes (github.io ...) count as suffixes. */
  registrableDomain: string | null;
  tld: string | null;
  /** The shared-hosting platform suffix (e.g. "pages.dev") when the host lives on one. */
  platform: string | null;
}

export type ParseResult = { ok: true; value: ParsedUrl } | { ok: false; error: string };

export const MAX_URL_LENGTH = 2048;

export function parseTargetUrl(raw: string): ParseResult {
  let s = refang(String(raw ?? '').trim());
  if (!s) return { ok: false, error: 'Enter a URL to check.' };
  if (s.length > MAX_URL_LENGTH) return { ok: false, error: `URL is too long (max ${MAX_URL_LENGTH} characters).` };
  if (/[\u0000-\u001f\u007f]/.test(s)) return { ok: false, error: 'URL contains control characters.' };

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // "javascript:...", "mailto:...", "data:..." are not web URLs; "example.com:8080/x" (colon + digit) is a scheme-less host:port
    if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s)) return { ok: false, error: 'Only http:// and https:// URLs are supported.' };
    s = `http://${s}`;
  }

  const hostText = s.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?(\[[^\]]*\]|[^/?#:]*)/i)?.[1] ?? '';

  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return { ok: false, error: 'That does not look like a valid URL.' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: 'Only http:// and https:// URLs are supported.' };

  const bare = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!bare) return { ok: false, error: 'The URL has no host.' };
  const ip = parseIP(bare);
  const isIp = !!ip;
  if (!isIp && !isValidHostname(bare)) return { ok: false, error: 'The URL host is not a valid hostname.' };

  const numericForm = /^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$/i.test(hostText);
  const ipObfuscated = isIp && ip!.version === 4 && numericForm && hostText.toLowerCase() !== bare;

  const userinfo = u.username || u.password ? decodeURIComponentSafe(`${u.username}${u.password ? `:${u.password}` : ''}`) : null;
  u.hash = '';
  const url = u.toString();
  const clean = new URL(url);
  clean.username = '';
  clean.password = '';
  const lookupUrl = clean.toString();

  const { registrable, tld, platform } = isIp ? { registrable: null, tld: null, platform: null } : splitHost(bare);

  return {
    ok: true,
    value: {
      input: s,
      url,
      lookupUrl,
      scheme: u.protocol === 'https:' ? 'https' : 'http',
      host: bare,
      hostUnicode: isIp ? bare : toUnicodeHost(bare),
      isIp,
      ipObfuscated,
      port: u.port ? Number(u.port) : null,
      path: u.pathname,
      query: u.search.replace(/^\?/, ''),
      hasUserinfo: userinfo !== null,
      userinfo,
      registrableDomain: registrable,
      tld,
      platform,
    },
  };
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* --------------------------------------------------------- public suffix (lite) */

/** Multi-label public suffixes (not exhaustive: enough to get the registrable domain right for common cases). */
const MULTI_SUFFIX = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'ac.in', 'gov.in', 'firm.in', 'gen.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'org.hk', 'com.tw', 'org.tw', 'com.sg', 'edu.sg', 'com.my', 'com.ph', 'com.vn', 'co.id', 'co.th', 'in.th',
  'com.br', 'net.br', 'org.br', 'gov.br', 'com.ar', 'com.mx', 'com.co', 'com.pe', 'com.ve', 'com.uy', 'com.ec', 'com.bo', 'com.py',
  'com.tr', 'org.tr', 'net.tr', 'gen.tr', 'com.ua', 'com.pl', 'com.ru', 'com.es', 'com.pt', 'com.gr', 'com.cy', 'com.eg', 'com.sa', 'com.pk', 'com.bd', 'com.ng', 'com.gh', 'co.za', 'co.ke', 'co.tz', 'co.ug', 'co.zw', 'co.il', 'org.il', 'co.ae',
]);

/** Shared / user-content hosting suffixes: the registrable unit is the customer subdomain, not the platform. */
export const PLATFORM_SUFFIXES = [
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'r2.dev', 'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com',
  'blogspot.com', 'wixsite.com', 'weebly.com', 'herokuapp.com', 'glitch.me', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com',
  'duckdns.org', 'no-ip.org', 'ddns.net', 'hopto.org', 'azurewebsites.net', 'cloudfront.net', 'webflow.io', 'framer.app',
  'godaddysites.com', 'square.site', 'carrd.co', 'notion.site', 'gitbook.io', 'repl.co', 'replit.app', 'onrender.com', 'fly.dev',
  'surge.sh', '000webhostapp.com', 'infinityfreeapp.com', 'epizy.com', 'rf.gd', 'wordpress.com', 'myshopify.com', 'typedream.app', 'webcindario.com',
];

function splitHost(host: string): { registrable: string | null; tld: string | null; platform: string | null } {
  const labels = host.split('.');
  if (labels.length < 2) return { registrable: null, tld: labels[0] ?? null, platform: null };
  const tld = labels[labels.length - 1];
  const platform = PLATFORM_SUFFIXES.find((p) => host === p || host.endsWith(`.${p}`)) ?? null;
  if (platform) {
    const take = platform.split('.').length + 1;
    return { registrable: labels.length >= take ? labels.slice(-take).join('.') : host, tld, platform };
  }
  const last2 = labels.slice(-2).join('.');
  if (MULTI_SUFFIX.has(last2) && labels.length >= 3) return { registrable: labels.slice(-3).join('.'), tld, platform: null };
  return { registrable: last2, tld, platform: null };
}

/* ------------------------------------------------------------------ punycode */

const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta: number, numPoints: number, first: boolean): number {
  let k = 0;
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - T_MIN) * T_MAX) >> 1; k += BASE) delta = Math.floor(delta / (BASE - T_MIN));
  return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

const digitOf = (cp: number): number => (cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : BASE);

/** RFC 3492 decoder. Throws on malformed input. */
export function punycodeDecode(input: string): string {
  const out: number[] = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) throw new Error('bad punycode');
    out.push(input.charCodeAt(j));
  }
  let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error('bad punycode');
      const digit = digitOf(input.charCodeAt(idx++));
      if (digit >= BASE) throw new Error('bad punycode');
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function toUnicodeHost(host: string): string {
  return host
    .split('.')
    .map((l) => {
      if (!l.toLowerCase().startsWith('xn--')) return l;
      try {
        return punycodeDecode(l.slice(4).toLowerCase());
      } catch {
        return l;
      }
    })
    .join('.');
}

/* ------------------------------------------------------- brands & word lists */

/** Brand token -> registrable domains that legitimately belong to that brand. */
export const BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal.de', 'paypal.co.uk'],
  apple: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com', 'cdn-apple.com'],
  icloud: ['icloud.com', 'apple.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com', 'outlook.com', 'windows.com', 'azure.com', 'sharepoint.com', 'onedrive.com', 'bing.com', 'msn.com', 'skype.com', 'xbox.com', 'microsoft365.com'],
  office365: ['office.com', 'office365.com', 'microsoft.com', 'microsoftonline.com'],
  onedrive: ['onedrive.com', 'live.com', 'microsoft.com', 'sharepoint.com'],
  outlook: ['outlook.com', 'live.com', 'office.com', 'microsoft.com'],
  google: ['google.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com', 'youtube.com', 'goo.gl', 'g.co', 'withgoogle.com', 'gstatic.com', 'googlemail.com'],
  gmail: ['gmail.com', 'google.com', 'googlemail.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.ca', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazonaws.com', 'amzn.to', 'amzn.com', 'a.co', 'amazon.nl', 'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.se', 'amazon.pl'],
  netflix: ['netflix.com', 'nflxso.net', 'nflximg.net'],
  facebook: ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fbcdn.net'],
  instagram: ['instagram.com', 'facebook.com', 'meta.com', 'cdninstagram.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me', 'facebook.com', 'meta.com'],
  linkedin: ['linkedin.com', 'licdn.com', 'lnkd.in'],
  dropbox: ['dropbox.com', 'dropboxusercontent.com', 'dropboxstatic.com'],
  docusign: ['docusign.com', 'docusign.net'],
  adobe: ['adobe.com', 'adobelogin.com', 'adobe.io', 'acrobat.com'],
  dhl: ['dhl.com', 'dhl.de', 'dhl.co.uk'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com', 'binance.us'],
  metamask: ['metamask.io'],
  chase: ['chase.com', 'jpmorganchase.com', 'jpmorgan.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  citibank: ['citibank.com', 'citi.com'],
  steam: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'],
  roblox: ['roblox.com'],
  telegram: ['telegram.org', 't.me', 'telegram.me'],
  zoom: ['zoom.us', 'zoom.com'],
  github: ['github.com', 'githubusercontent.com', 'github.io', 'githubassets.com'],
};

export const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'icu', 'cyou', 'click', 'buzz', 'rest', 'gq', 'cf', 'tk', 'ml', 'ga', 'zip', 'mov', 'cfd', 'sbs', 'quest', 'bond',
  'monster', 'cam', 'kim', 'loan', 'men', 'party', 'review', 'stream', 'trade', 'win', 'download', 'racing', 'accountant', 'science', 'date', 'faith', 'work',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy',
  't.ly', 'v.gd', 'lnkd.in', 's.id', 'bl.ink', 'qrco.de', 'ift.tt', 'dlvr.it', 'soo.gd', 'clck.ru', 'x.co', 'adf.ly', 'bit.do',
  'mcaf.ee', 'su.pr', 'trib.al', 'wp.me', 'youtu.be', 'amzn.to', 'fb.me', 'j.mp', 'ouo.io', 'shorte.st', 'chilp.it', 'urlz.fr', 'l.ead.me', 'tr.ee', 'cli.re',
]);

const CRED_WORDS = ['login', 'logon', 'signin', 'sign-in', 'secure', 'verify', 'verification', 'account', 'update', 'confirm', 'billing', 'payment', 'wallet', 'password', 'suspend', 'suspended', 'unlock', 'recover', 'recovery', 'security', 'authenticate', 'validate', 'webmail', 'helpdesk', 'invoice'];

const RISKY_EXT = new Set(['exe', 'scr', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'hta', 'lnk', 'iso', 'img', 'dll', 'jar', 'apk', 'docm', 'xlsm', 'pptm', 'wsf', 'cpl', 'msp', 'pif']);
const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tar', 'cab', 'z']);

/* ------------------------------------------------------- homograph helpers */

const CONFUSABLE: Record<string, string> = {
  // Cyrillic
  а: 'a', с: 'c', е: 'e', о: 'o', р: 'p', х: 'x', у: 'y', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ӏ: 'l', һ: 'h', ԛ: 'q', ԝ: 'w', к: 'k', ѵ: 'v',
  // Greek
  ο: 'o', ν: 'v', ι: 'i', ρ: 'p', α: 'a', τ: 't', κ: 'k', υ: 'u',
  // Latin look-alikes
  ɡ: 'g', ɑ: 'a', ǝ: 'e', ı: 'i', ɩ: 'i', ƅ: 'b', ɓ: 'b', ʋ: 'v', ꞵ: 'b',
};

const skeleton = (s: string): string => [...s].map((c) => CONFUSABLE[c] ?? c).join('');

const scriptOf = (ch: string): 'latin' | 'cyrillic' | 'greek' | 'other' | 'neutral' => {
  if (/[0-9\-_.]/.test(ch)) return 'neutral';
  if (/\p{Script=Latin}/u.test(ch)) return 'latin';
  if (/\p{Script=Cyrillic}/u.test(ch)) return 'cyrillic';
  if (/\p{Script=Greek}/u.test(ch)) return 'greek';
  return 'other';
};

/** Digit/letter swaps used for look-alike domains (paypa1, micr0soft, rnicrosoft, vvhatsapp). */
export const deLeet = (s: string): string => s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/5/g, 's').replace(/3/g, 'e').replace(/\$/g, 's');

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m || !n) return Math.max(m, n);
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

export const tokens = (s: string): string[] => s.split(/[.\-_]+/).filter(Boolean);

export function isOfficial(brand: string, host: string, registrable: string | null): boolean {
  const official = BRANDS[brand] ?? [];
  if (official.some((d) => host === d || host.endsWith(`.${d}`) || registrable === d)) return true;
  // the brand's own name as the registrable label under an ordinary TLD (google.co.uk, amazon.nl) is assumed to be theirs;
  // the same name under an abused TLD (paypal.xyz) is not
  if (registrable && !PLATFORM_SUFFIXES.some((pl) => registrable.endsWith(`.${pl}`))) {
    const [label, ...rest] = registrable.split('.');
    if (label === brand && !SUSPICIOUS_TLDS.has(rest[rest.length - 1])) return true;
  }
  return false;
}

/* -------------------------------------------------------------- heuristics */

const sig = (id: string, severity: UrlSeverity, title: string, detail?: string, extra: Partial<UrlSignal> = {}): UrlSignal => ({ id, severity, source: 'heuristic', title, detail, ...extra });

/** Offline, deterministic checks. Never "confirmed": heuristics can make a URL suspicious, not malicious. */
export function analyzeUrlHeuristics(p: ParsedUrl): UrlSignal[] {
  const out: UrlSignal[] = [];
  const host = p.host;
  const labelsAll = host.split('.');

  // --- host type
  if (p.isIp) {
    if (p.ipObfuscated) out.push(sig('ip-obfuscated', 'high', 'Obfuscated IP address in the URL', `The host was written in a non-standard numeric form and resolves to ${host}. Legitimate sites do not do this; it is used to evade filters.`));
    else out.push(sig('ip-host', 'medium', 'URL uses a raw IP address instead of a domain name', 'Legitimate public services almost always use domain names. Raw-IP URLs are common for malware delivery and phishing kits.'));
  }

  // --- credentials / @ trick
  if (p.hasUserinfo) {
    const looksLikeHost = /[a-z0-9-]+\.[a-z]{2,}/i.test(p.userinfo ?? '');
    out.push(looksLikeHost
      ? sig('userinfo-deception', 'high', 'Deceptive "@" in the URL', `Everything before the "@" ("${truncate(p.userinfo ?? '', 60)}") is a username, not the destination. The real host is ${host}.`)
      : sig('userinfo', 'medium', 'URL embeds a username/password', `The URL carries credentials ("${truncate(p.userinfo ?? '', 40)}"). Legitimate links rarely do; the real host is ${host}.`));
  }

  // --- IDN / homograph
  if (!p.isIp) {
    const uni = p.hostUnicode;
    const hasPuny = labelsAll.some((l) => l.startsWith('xn--'));
    if (hasPuny) {
      let mixed = false;
      let skeletonHit: string | null = null;
      for (const label of uni.split('.')) {
        const scripts = new Set([...label].map(scriptOf).filter((s) => s !== 'neutral'));
        if (scripts.size > 1 && scripts.has('latin')) mixed = true;
        const sk = skeleton(label);
        if (sk !== label && /^[a-z0-9-]+$/.test(sk)) {
          const hit = Object.keys(BRANDS).find((b) => tokens(sk).includes(b) || sk === b);
          if (hit) skeletonHit = hit;
          else if (scripts.size === 1 && !scripts.has('latin')) skeletonHit = skeletonHit ?? `"${sk}"`;
        }
      }
      if (mixed) out.push(sig('homograph-mixed', 'high', 'Mixed-script (homograph) domain', `The host ${uni} mixes Latin letters with look-alike letters from another alphabet (shown as ${host}). This is the classic IDN spoofing technique.`));
      else if (skeletonHit) out.push(sig('homograph-skeleton', 'high', 'Look-alike (homograph) domain', `The host ${uni} (${host}) is built from non-Latin characters that render like Latin letters, resembling ${skeletonHit}.`));
      else out.push(sig('idn', 'info', 'Internationalised (non-ASCII) domain', `Displayed as ${uni}; the real DNS name is ${host}.`));
    }
  }

  // --- brand impersonation
  if (!p.isIp && p.registrableDomain) {
    const reg = p.registrableDomain;
    const regLabel = reg.split('.')[0];
    const subLabels = labelsAll.slice(0, Math.max(0, labelsAll.length - reg.split('.').length));
    const hostTokens = new Set<string>([...tokens(subLabels.join('.')), ...tokens(regLabel)]);
    let flagged = false;

    for (const brand of Object.keys(BRANDS)) {
      if (isOfficial(brand, host, reg)) continue;
      // exact brand word used inside a hostname that the brand does not own
      if (hostTokens.has(brand)) {
        const platformNote = p.platform ? ` It is hosted on ${p.platform}, where anyone can create a subdomain.` : '';
        out.push(sig(`brand-${brand}`, 'medium', `Hostname uses the "${brand}" brand name but is not a ${brand} domain`, `${host} is registered under ${reg}, which is not one of ${brand}'s domains.${platformNote}`));
        flagged = true;
        break;
      }
    }
    if (!flagged && !p.platform) {
      // digit/letter swaps (paypa1.com, micr0soft.com, rnicrosoft.com) and one-character typos of long brand names
      const norm = deLeet(regLabel.replace(/-/g, ''));
      // also each hyphen-separated part on its own: "secure-paypa1-login.xyz" hides "paypa1" inside a longer label
      const parts = regLabel.split('-').filter((t) => t.length >= 5);
      for (const brand of Object.keys(BRANDS)) {
        if (brand.length < 5 || isOfficial(brand, host, reg)) continue;
        if (regLabel !== brand && (norm === brand || parts.some((t) => t !== brand && deLeet(t) === brand))) {
          out.push(sig(`squat-${brand}`, 'medium', `Look-alike of "${brand}" using character swaps`, `${regLabel} reads as "${brand}" once digits/letter pairs are normalised (1→l, 0→o, rn→m).`));
          flagged = true;
          break;
        }
      }
      if (!flagged) {
        for (const brand of Object.keys(BRANDS)) {
          if (brand.length < 7 || isOfficial(brand, host, reg)) continue;
          if (levenshtein(regLabel, brand) === 1) {
            out.push(sig(`typo-${brand}`, 'low', `Possible typosquat of "${brand}"`, `${regLabel} differs from "${brand}" by a single character. This is only an indicator: many unrelated sites have similar names.`));
            break;
          }
        }
      }
    }
    // the brand's own label under a TLD the brand does not use (paypal.xyz)
    if (!flagged && p.tld && SUSPICIOUS_TLDS.has(p.tld) && BRANDS[regLabel] && !isOfficial(regLabel, host, reg)) {
      out.push(sig(`brand-tld-${regLabel}`, 'medium', `"${regLabel}" brand name on an unusual TLD (.${p.tld})`, `${reg} is not one of ${regLabel}'s domains.`));
    }
  }

  // --- credential-themed words
  const hostWords = tokens(host);
  const hostCred = CRED_WORDS.filter((w) => hostWords.includes(w));
  if (hostCred.length >= 2) out.push(sig('cred-host', 'medium', 'Credential-themed hostname', `The hostname contains ${hostCred.map((w) => `"${w}"`).join(', ')}. Phishing hosts often pack account/verification words into the name.`));
  const pathWords = decodeURIComponentSafe(p.path).toLowerCase().split(/[./\-_]+/).filter(Boolean);
  const pathCred = CRED_WORDS.filter((w) => pathWords.includes(w));
  if (pathCred.length && !hostCred.length) out.push(sig('cred-path', 'low', 'Credential-themed path', `The path mentions ${pathCred.slice(0, 4).map((w) => `"${w}"`).join(', ')}. Normal on real login pages, so only meaningful together with other findings.`));
  if (p.scheme === 'http' && (hostCred.length || pathCred.length)) out.push(sig('login-no-tls', 'medium', 'Login/credential page served over plain HTTP', 'Credentials entered here would travel unencrypted, and legitimate providers do not host sign-in pages without HTTPS.'));

  // --- file type
  const file = p.path.split('/').pop() ?? '';
  const ext = file.includes('.') ? file.split('.').pop()!.toLowerCase() : '';
  const doubleExt = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs|lnk|com|pif)$/i.test(file);
  if (doubleExt) out.push(sig('double-ext', 'high', 'Double file extension', `"${truncate(file, 80)}" pretends to be a document but is an executable type.`));
  else if (RISKY_EXT.has(ext)) out.push(sig('risky-file', 'medium', `Direct link to a .${ext} file`, 'The URL points straight at an executable/script/installer or macro-enabled document. Do not open it unless you expected it.'));
  else if (ARCHIVE_EXT.has(ext)) out.push(sig('archive-file', 'info', `Direct link to a .${ext} archive`, 'Archives are a common wrapper for malware, but also for ordinary downloads.'));

  // --- infrastructure hints
  if (p.platform) out.push(sig('shared-hosting', 'info', `Hosted on a shared platform (${p.platform})`, 'Anyone can publish a page here, so the platform\u2019s own reputation and domain age say nothing about this specific site.'));
  if (SHORTENERS.has(host) || (p.registrableDomain && SHORTENERS.has(p.registrableDomain))) out.push(sig('shortener', 'low', 'Link shortener: the real destination is hidden', 'Run the redirect trace to see where it leads.'));
  if (p.tld && SUSPICIOUS_TLDS.has(p.tld) && !p.isIp) out.push(sig('tld', 'low', `Frequently abused TLD (.${p.tld})`, 'Cheap or free TLDs are over-represented in abuse reports. Many legitimate sites use them too.'));
  if (p.port && ![80, 443].includes(p.port)) out.push(sig('port', 'low', `Non-standard port (${p.port})`, 'Public web services normally use 80/443.'));
  if (!p.isIp && labelsAll.length - (p.registrableDomain?.split('.').length ?? 2) >= 4) out.push(sig('deep-subdomain', 'low', 'Unusually deep subdomain chain', `${host} has ${labelsAll.length} labels. Long chains are used to push the real domain out of view on small screens.`));
  if (!p.isIp && host.length > 60) out.push(sig('long-host', 'low', 'Very long hostname', `${host.length} characters.`));
  if ((host.match(/-/g) ?? []).length >= 4) out.push(sig('hyphens', 'low', 'Many hyphens in the hostname'));
  if (p.url.length > 300) out.push(sig('long-url', 'low', `Very long URL (${p.url.length} characters)`));
  if ((p.url.match(/%[0-9a-f]{2}/gi) ?? []).length >= 12 || /%25[0-9a-f]{2}/i.test(p.url)) out.push(sig('encoding', 'low', 'Heavy or double percent-encoding', 'Encoding is sometimes used to hide the real path or parameters from filters.'));
  if (/(^|&)(url|redirect|redir|next|return|returnurl|goto|dest|destination|continue|target)=https?(%3a|:)/i.test(p.query)) out.push(sig('open-redirect', 'low', 'URL carries another URL in a redirect parameter', 'This pattern is used for open-redirect abuse: the trusted site bounces the visitor to a second address.'));

  return out;
}

const truncate = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/* ----------------------------------------------------------------- verdict */

const POINTS: Record<UrlSeverity, number> = { critical: 70, high: 40, medium: 20, low: 8, info: 0 };
const ORDER: Record<UrlSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const sortSignals = (signals: UrlSignal[]): UrlSignal[] => [...signals].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

export interface Assessment { verdict: UrlVerdict; score: number; confidence: 'high' | 'medium' | 'low'; summary: string }

/**
 * @param signals       all findings (heuristic + provider)
 * @param checked       external intelligence sources that returned a usable verdict for THIS url
 *                      ("never scanned" / "no prior scans" answers say nothing about the url and are not counted)
 * @param attempted     external sources that were configured and attempted
 * @param authoritative how many of the checked sources are authoritative blocklists (URLhaus, Safe Browsing)
 */
export function assessUrl(signals: UrlSignal[], checked: number, attempted: number, authoritative = checked): Assessment {
  const sorted = sortSignals(signals);
  const score = Math.min(100, sorted.reduce((n, s) => n + POINTS[s.severity], 0));
  const external = sorted.filter((s) => s.source !== 'heuristic');
  const critical = sorted.filter((s) => s.severity === 'critical');
  const confirmed = sorted.filter((s) => s.confirmed);
  const highSources = new Set(external.filter((s) => s.severity === 'high' || s.severity === 'critical').map((s) => s.source));
  const medium = sorted.filter((s) => s.severity === 'medium').length;
  const anyHigh = sorted.some((s) => s.severity === 'high' || s.severity === 'critical');
  const coverage = attempted ? `checked by ${checked} of ${attempted} intelligence sources` : 'no external intelligence source was available';

  const top = (n: number) => sorted.filter((s) => s.severity !== 'info').slice(0, n).map((s) => s.title).join('; ');

  // Malicious: only on external evidence
  if (critical.some((s) => s.source !== 'heuristic') || confirmed.length || highSources.size >= 2) {
    const sources = [...new Set(external.filter((s) => s.severity === 'critical' || s.severity === 'high' || s.confirmed).map((s) => s.source))];
    return {
      verdict: 'malicious',
      score: Math.max(score, 80),
      confidence: confirmed.length || critical.length ? 'high' : 'medium',
      summary: `Flagged as malicious by ${sources.length} source${sources.length === 1 ? '' : 's'}: ${top(2)}.`,
    };
  }
  if (anyHigh || medium >= 2 || score >= 35) {
    return {
      verdict: 'suspicious',
      score: Math.max(score, 35),
      confidence: checked >= 2 ? 'medium' : 'low',
      summary: `Suspicious indicators found: ${top(3)}. No source has confirmed it as malicious (${coverage}).`,
    };
  }
  if (checked === 0) {
    return {
      verdict: 'unknown',
      score,
      confidence: 'low',
      summary: `Only local checks ran (${coverage}), so this URL has not been checked against any threat feed. This is not an all-clear.`,
    };
  }
  return {
    verdict: 'no_detections',
    score,
    confidence: checked >= 3 && authoritative >= 1 ? 'high' : checked >= 2 ? 'medium' : 'low',
    summary: `No source flagged this URL (${coverage}). That is not a guarantee of safety: new or targeted threats are often not listed yet.`,
  };
}

/* ------------------------------------------------- brand table (read-only views) */

/** Brand names the offline heuristics know (lowercase keys such as "paypal", "microsoft"). */
export const brandNames = (): string[] => Object.keys(BRANDS);
/** Registrable domains that legitimately belong to a brand (empty for unknown brands). */
export const brandDomains = (brand: string): readonly string[] => BRANDS[brand] ?? [];
/** True when `host` (registrable domain `registrable`) is one of the brand's own domains. */
export const isOfficialBrandHost = (brand: string, host: string, registrable: string | null): boolean => isOfficial(brand, host, registrable);
