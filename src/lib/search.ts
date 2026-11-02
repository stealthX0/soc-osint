import type { Flag, ResourceData, Tool } from '../types/resources';

/**
 * Weighted, synonym-aware search ported from the original single-file dashboard.
 * Fields are weighted (name > best-for > path > description ...) and every query token
 * may match through a synonym at reduced weight.
 */

const W = { n: 10, p: 5, b: 6, d: 3, io: 2, u: 2, k: 1 } as const;
type Field = keyof typeof W;

const SYN: Record<string, string[]> = {
  phishing: ['phish', 'typosquat', 'homograph'], phish: ['phishing'], reputation: ['blacklist', 'blocklist', 'threat intel'],
  blacklist: ['blocklist', 'reputation'], blocklist: ['blacklist', 'reputation'], whois: ['registrant', 'rdap', 'domain ownership'],
  malware: ['sandbox', 'ransomware', 'virus', 'c2'], breach: ['leak', 'pwned', 'credential', 'infostealer'], leak: ['breach', 'leaked'],
  subdomain: ['dns', 'certificate'], dns: ['subdomain', 'resolver'], ioc: ['indicator'], indicator: ['ioc'],
  sandbox: ['dynamic analysis', 'detonat'], vulnerability: ['cve', 'exploit', 'scanner'], cve: ['vulnerab', 'advisor'],
  decode: ['deobfuscat', 'encoding', 'base64'], deobfuscate: ['deobfuscat', 'decode', 'xor'], obfuscation: ['deobfuscat', 'xor'],
  port: ['nmap', 'scanner', 'masscan'], ransomware: ['ransom'], c2: ['command and control', 'botnet'], botnet: ['c2'],
  screenshot: ['capture'], tor: ['onion', 'dark web'], onion: ['tor'], geolocation: ['geoip', 'location'], geoip: ['geolocation'],
  cert: ['certificate', 'ssl', 'tls'], ssl: ['certificate', 'tls'], tls: ['certificate', 'ssl'], archive: ['wayback', 'snapshot', 'cache'],
  evidence: ['capture', 'screenshot', 'archiv'], anonymity: ['tor', 'vpn', 'privacy'], vpn: ['leak', 'anonym'],
  hash: ['md5', 'sha256', 'virustotal'], url: ['link', 'redirect'], ip: ['ipv4', 'asn'], asn: ['bgp'], bgp: ['asn'],
  email: ['mail'], mail: ['email'], pdf: ['document'], office: ['document', 'macro'], apk: ['android'], android: ['apk'],
  threat: ['intelligence', 'ioc'], intel: ['intelligence'], typosquatting: ['typosquat', 'permutation', 'homograph'],
  username: ['account', 'social'], phone: ['number'], cloud: ['aws', 'azure', 'gcp', 's3'], s3: ['bucket'], bucket: ['s3', 'blob'],
};

export interface IndexedTool { tool: Tool; path: string[]; h: Record<Field, string> }

export function buildIndex(data: ResourceData): IndexedTool[] {
  return data.tools.map((tool) => {
    const c = data.categories[tool.category];
    const path = [c.name, c.subs[tool.sub].name, ...(tool.group ? [tool.group] : [])];
    return {
      tool,
      path,
      h: {
        n: tool.name.toLowerCase(),
        p: path.join(' ').toLowerCase(),
        b: (tool.bestFor ?? '').toLowerCase(),
        d: (tool.description ?? '').toLowerCase(),
        io: `${tool.input ?? ''} ${tool.output ?? ''}`.toLowerCase(),
        u: tool.url.toLowerCase(),
        k: `${tool.opsecNote ?? ''} ${tool.flags.join(' ')}`.toLowerCase(),
      },
    };
  });
}

const stem = (t: string) => (t.length > 4 && t.endsWith('s') && !t.endsWith('ss') ? t.slice(0, -1) : t);
const escRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const reCache = new Map<string, RegExp>();

/** Short tokens (<= 3 chars) must start a word, otherwise "ip" would match "zip", "tip"... */
function has(field: string, tok: string): boolean {
  if (tok.length <= 3) {
    let r = reCache.get(tok);
    if (!r) reCache.set(tok, (r = new RegExp(`(^|[^a-z0-9])${escRe(tok)}`)));
    return r.test(field);
  }
  return field.includes(tok);
}

interface QToken { raw: string; alts: { t: string; m: number }[] }
export function parseQuery(q: string): QToken[] {
  return q
    .toLowerCase()
    .split(/\s+/)
    .map((x) => x.replace(/^["']|["']$/g, ''))
    .filter(Boolean)
    .map((raw) => {
      const s = stem(raw);
      const alts = [{ t: s, m: 1 }];
      for (const a of SYN[s] ?? SYN[raw] ?? []) alts.push({ t: a, m: 0.55 });
      return { raw, alts };
    });
}

function score(it: IndexedTool, qs: QToken[], q: string): number {
  let total = 0;
  for (const tk of qs) {
    let best = 0;
    for (const a of tk.alts) {
      let sc = 0;
      for (const f of Object.keys(W) as Field[]) if (has(it.h[f], a.t)) sc += W[f];
      best = Math.max(best, sc * a.m);
    }
    if (best === 0) return 0; // AND semantics: every token must match somewhere
    total += best;
  }
  const ql = q.toLowerCase().trim();
  if (qs.length > 1) {
    if (it.h.n.includes(ql)) total += 12;
    else if (it.h.b.includes(ql) || it.h.p.includes(ql)) total += 7;
    else if (it.h.d.includes(ql)) total += 4;
  }
  if (it.h.n === ql) total += 20;
  else if (it.h.n.startsWith(ql)) total += 6;
  if (it.tool.status === 'live') total += 0.5;
  if (it.tool.flags.includes('depr')) total -= 2;
  return Math.max(total, 0.1);
}

export interface Filters {
  category: number | null;
  sub: number | null;
  opsec: 'passive' | 'active' | null;
  pricing: 'free' | 'freemium' | 'paid' | null;
  flags: Flag[];
}
export const NO_FILTERS: Filters = { category: null, sub: null, opsec: null, pricing: null, flags: [] };

export function filterTools(index: IndexedTool[], f: Filters): IndexedTool[] {
  return index.filter(({ tool: t }) =>
    (f.category === null || t.category === f.category) &&
    (f.sub === null || t.sub === f.sub) &&
    (f.opsec === null || t.opsec === f.opsec) &&
    (f.pricing === null || t.pricing === f.pricing) &&
    f.flags.every((fl) => t.flags.includes(fl)),
  );
}

export function searchIndex(index: IndexedTool[], q: string): IndexedTool[] {
  const qs = parseQuery(q);
  if (!qs.length) return index;
  return index
    .map((it) => ({ it, s: score(it, qs, q) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.it.tool.name.localeCompare(b.it.tool.name))
    .map((x) => x.it);
}
