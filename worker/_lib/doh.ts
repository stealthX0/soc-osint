/**
 * DNS-over-HTTPS client (JSON API). Several public resolvers are supported so that
 * propagation checks can compare answers and lookups can fail over.
 */
import { ApiError } from './errors';

export type RecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'SOA' | 'CAA' | 'SRV' | 'PTR' | 'DNSKEY' | 'DS';
export const RECORD_TYPES: RecordType[] = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR', 'DNSKEY', 'DS'];

const TYPE_NUM: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 43: 'DS', 48: 'DNSKEY', 257: 'CAA' };

export interface Resolver { id: 'cloudflare' | 'google' | 'quad9'; name: string; url: string }
export const RESOLVERS: Record<Resolver['id'], Resolver> = {
  cloudflare: { id: 'cloudflare', name: 'Cloudflare 1.1.1.1', url: 'https://cloudflare-dns.com/dns-query' },
  google: { id: 'google', name: 'Google 8.8.8.8', url: 'https://dns.google/resolve' },
  quad9: { id: 'quad9', name: 'Quad9 9.9.9.9', url: 'https://dns.quad9.net:5053/dns-query' },
};

export interface DnsRecord { name: string; type: string; ttl: number; data: string }
export interface DnsAnswer {
  resolver: string;
  rcode: number;
  status: 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'REFUSED' | 'OTHER';
  /** true if the resolver validated DNSSEC (AD flag) */
  authenticated: boolean;
  answers: DnsRecord[];
  ms: number;
}

const RCODE: Record<number, DnsAnswer['status']> = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

/** TXT data arrives as `"part1" "part2"`; join the parts the way resolvers do. */
export function cleanTxt(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : data;
}

interface RawAnswer { name: string; type: number; TTL: number; data: string }

export async function dohQuery(name: string, type: RecordType, resolver: Resolver['id'] = 'cloudflare', timeoutMs = 4000): Promise<DnsAnswer> {
  const r = RESOLVERS[resolver];
  const u = new URL(r.url);
  u.searchParams.set('name', name);
  u.searchParams.set('type', type);
  const t0 = Date.now();
  let res: Response;
  try {
    res = await fetch(u, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    const timeout = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
    throw new ApiError(timeout ? 504 : 502, timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', `${r.name} did not respond${timeout ? ' in time' : ''}.`);
  }
  if (!res.ok) throw new ApiError(502, 'UPSTREAM_ERROR', `${r.name} returned HTTP ${res.status}.`);
  const body = (await res.json()) as { Status: number; AD?: boolean; Answer?: RawAnswer[] };
  const answers = (body.Answer ?? [])
    .filter((a) => TYPE_NUM[a.type] !== undefined)
    .map<DnsRecord>((a) => {
      const t = TYPE_NUM[a.type];
      return { name: a.name.replace(/\.$/, ''), type: t, ttl: a.TTL, data: t === 'TXT' ? cleanTxt(a.data) : a.data.replace(/^(.*[^.])\.$/, '$1') };
    });
  return { resolver: r.name, rcode: body.Status, status: RCODE[body.Status] ?? 'OTHER', authenticated: !!body.AD, answers, ms: Date.now() - t0 };
}

/** Query with automatic failover across resolvers (first healthy answer wins). */
export async function resolve(name: string, type: RecordType, order: Resolver['id'][] = ['cloudflare', 'google']): Promise<DnsAnswer> {
  let last: unknown;
  for (const id of order) {
    try {
      return await dohQuery(name, type, id);
    } catch (e) {
      last = e;
    }
  }
  throw last instanceof ApiError ? last : new ApiError(502, 'UPSTREAM_ERROR', 'All DNS resolvers failed.');
}

/** Convenience: resolve to a list of data strings; NXDOMAIN/NOERROR-empty give []. */
export async function resolveData(name: string, type: RecordType): Promise<string[]> {
  const r = await resolve(name, type);
  return r.answers.filter((a) => a.type === type).map((a) => a.data);
}
