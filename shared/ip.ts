/**
 * IP / CIDR primitives shared by the Worker API and the React app.
 * Pure TypeScript, no runtime dependencies. IPv4 and IPv6 are both handled as BigInt.
 */

export type IPVersion = 4 | 6;
export type IPScope =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link-local'
  | 'cgnat'
  | 'multicast'
  | 'documentation'
  | 'reserved'
  | 'unspecified';

export interface IPClass {
  version: IPVersion;
  scope: IPScope;
  /** true only for globally routable unicast addresses */
  public: boolean;
  /** human-readable explanation of the range the address falls in */
  label: string;
}

const BITS: Record<IPVersion, number> = { 4: 32, 6: 128 };

/* ------------------------------------------------------------------ parsing */

export function parseIPv4(input: string): bigint | null {
  const parts = input.trim().split('.');
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

export function parseIPv6(input: string): bigint | null {
  let s = input.trim();
  if (!s || !/^[0-9a-fA-F:.]+$/.test(s)) return null; // also rejects zone ids (%eth0)
  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':');
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (lastColon < 0 || v4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${((v4 >> 16n) & 0xffffn).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const split = (p: string) => (p === '' ? [] : p.split(':'));
  const head = split(dbl[0]);
  const tail = dbl.length === 2 ? split(dbl[1]) : [];
  let groups: string[];
  if (dbl.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    if (head.length + tail.length > 7) return null;
    groups = [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail];
  }
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return v;
}

export const isIPv4 = (s: string) => parseIPv4(s) !== null;
export const isIPv6 = (s: string) => parseIPv6(s) !== null;

export function ipVersion(s: string): IPVersion | null {
  if (isIPv4(s)) return 4;
  if (isIPv6(s)) return 6;
  return null;
}

export function parseIP(s: string): { version: IPVersion; value: bigint } | null {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { version: 4, value: v4 };
  const v6 = parseIPv6(s);
  if (v6 !== null) return { version: 6, value: v6 };
  return null;
}

/* --------------------------------------------------------------- formatting */

export function formatIPv4(v: bigint): string {
  return [24n, 16n, 8n, 0n].map((sh) => Number((v >> sh) & 0xffn)).join('.');
}

export function groupsOf(v: bigint): number[] {
  const out: number[] = [];
  for (let i = 7; i >= 0; i--) out.push(Number((v >> BigInt(i * 16)) & 0xffffn));
  return out;
}

export function formatIPv6Expanded(v: bigint): string {
  return groupsOf(v).map((g) => g.toString(16).padStart(4, '0')).join(':');
}

/** RFC 5952 compression (longest run of zero groups, length >= 2, first wins). */
export function formatIPv6(v: bigint): string {
  const g = groupsOf(v);
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

export function formatIP(version: IPVersion, v: bigint): string {
  return version === 4 ? formatIPv4(v) : formatIPv6(v);
}

/** Canonical text form of an address, or null if it is not an IP. */
export function normalizeIP(s: string): string | null {
  const p = parseIP(s);
  return p ? formatIP(p.version, p.value) : null;
}

/* ----------------------------------------------------------- classification */

type RangeDef = [cidr: string, scope: IPScope, label: string];

const V4_RANGES: RangeDef[] = [
  ['0.0.0.0/8', 'unspecified', '"This network" (RFC 1122)'],
  ['10.0.0.0/8', 'private', 'Private-use (RFC 1918)'],
  ['100.64.0.0/10', 'cgnat', 'Carrier-grade NAT shared space (RFC 6598)'],
  ['127.0.0.0/8', 'loopback', 'Loopback (RFC 1122)'],
  ['169.254.0.0/16', 'link-local', 'Link-local (RFC 3927)'],
  ['172.16.0.0/12', 'private', 'Private-use (RFC 1918)'],
  ['192.0.0.0/24', 'reserved', 'IETF protocol assignments (RFC 6890)'],
  ['192.0.2.0/24', 'documentation', 'Documentation TEST-NET-1 (RFC 5737)'],
  ['192.88.99.0/24', 'reserved', 'Deprecated 6to4 relay anycast (RFC 7526)'],
  ['192.168.0.0/16', 'private', 'Private-use (RFC 1918)'],
  ['198.18.0.0/15', 'reserved', 'Network benchmarking (RFC 2544)'],
  ['198.51.100.0/24', 'documentation', 'Documentation TEST-NET-2 (RFC 5737)'],
  ['203.0.113.0/24', 'documentation', 'Documentation TEST-NET-3 (RFC 5737)'],
  ['224.0.0.0/4', 'multicast', 'Multicast (RFC 5771)'],
  ['240.0.0.0/4', 'reserved', 'Reserved / limited broadcast (RFC 1112)'],
];

const V6_RANGES: RangeDef[] = [
  ['::/128', 'unspecified', 'Unspecified address'],
  ['::1/128', 'loopback', 'Loopback'],
  ['64:ff9b::/96', 'reserved', 'NAT64 translation (RFC 6052)'],
  ['100::/64', 'reserved', 'Discard-only (RFC 6666)'],
  ['2001::/32', 'reserved', 'Teredo tunnelling (RFC 4380)'],
  ['2001:db8::/32', 'documentation', 'Documentation (RFC 3849)'],
  ['2002::/16', 'reserved', '6to4 tunnelling (RFC 3056)'],
  ['fc00::/7', 'private', 'Unique local address (RFC 4193)'],
  ['fe80::/10', 'link-local', 'Link-local (RFC 4291)'],
  ['fec0::/10', 'reserved', 'Deprecated site-local (RFC 3879)'],
  ['ff00::/8', 'multicast', 'Multicast (RFC 4291)'],
];

interface Compiled { base: bigint; prefix: number; scope: IPScope; label: string }
const compile = (defs: RangeDef[], v: IPVersion): Compiled[] =>
  defs.map(([c, scope, label]) => {
    const p = parseCIDR(c);
    if (!p || p.version !== v) throw new Error(`bad range table entry ${c}`);
    return { base: p.base, prefix: p.prefix, scope, label };
  });

let V4C: Compiled[] | undefined;
let V6C: Compiled[] | undefined;

const inPrefix = (value: bigint, base: bigint, prefix: number, bits: number) =>
  prefix === 0 ? true : value >> BigInt(bits - prefix) === base >> BigInt(bits - prefix);

export function classifyIP(input: string): IPClass | null {
  const p = parseIP(input);
  if (!p) return null;
  let { version, value } = p;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged by the embedded IPv4 address.
  if (version === 6 && value >> 32n === 0xffffn) {
    version = 4;
    value = value & 0xffffffffn;
  }
  const table = version === 4 ? (V4C ??= compile(V4_RANGES, 4)) : (V6C ??= compile(V6_RANGES, 6));
  for (const r of table) {
    if (inPrefix(value, r.base, r.prefix, BITS[version])) {
      return { version: p.version, scope: r.scope, public: false, label: r.label };
    }
  }
  // IPv6: only 2000::/3 is currently allocated as global unicast
  if (version === 6 && value >> 125n !== 1n) {
    return { version: 6, scope: 'reserved', public: false, label: 'Outside global unicast space (2000::/3)' };
  }
  return { version: p.version, scope: 'public', public: true, label: 'Globally routable unicast' };
}

export const isPublicIP = (s: string) => classifyIP(s)?.public === true;

/* --------------------------------------------------------------------- CIDR */

export interface ParsedCIDR { version: IPVersion; base: bigint; prefix: number }

export function parseCIDR(input: string): ParsedCIDR | null {
  const m = input.trim().match(/^([^/\s]+)\/(\d{1,3})$/);
  if (!m) return null;
  const ip = parseIP(m[1]);
  if (!ip) return null;
  const prefix = Number(m[2]);
  if (prefix > BITS[ip.version]) return null;
  const bits = BITS[ip.version];
  const hostBits = BigInt(bits - prefix);
  const base = (ip.value >> hostBits) << hostBits;
  return { version: ip.version, base, prefix };
}

export interface CidrInfo {
  input: string;
  version: IPVersion;
  cidr: string;
  prefix: number;
  network: string;
  firstAddress: string;
  lastAddress: string;
  /** IPv4 only */
  netmask?: string;
  wildcard?: string;
  broadcast?: string;
  firstHost: string;
  lastHost: string;
  totalAddresses: string;
  usableHosts: string;
  /** bit size of the host portion */
  hostBits: number;
  scope: IPScope;
  hostBitsSet: boolean;
}

export function cidrInfo(input: string): CidrInfo | null {
  const parsed = parseCIDR(input);
  if (!parsed) return null;
  const { version, base, prefix } = parsed;
  const bits = BITS[version];
  const hostBits = bits - prefix;
  const size = 1n << BigInt(hostBits);
  const last = base + size - 1n;
  const fmt = (v: bigint) => formatIP(version, v);

  let firstHost = base;
  let lastHost = last;
  let usable = size;
  if (version === 4) {
    if (prefix <= 30) { firstHost = base + 1n; lastHost = last - 1n; usable = size - 2n; }
    // /31 (RFC 3021) and /32 use every address
  } else if (prefix <= 127) {
    // IPv6 has no broadcast; the subnet-router anycast (all-zeros) is conventionally skipped
    firstHost = base + 1n;
  }
  const mask = ((1n << BigInt(bits)) - 1n) ^ (size - 1n);
  const original = parseIP(input.trim().split('/')[0])!;

  return {
    input: input.trim(),
    version,
    cidr: `${fmt(base)}/${prefix}`,
    prefix,
    network: fmt(base),
    firstAddress: fmt(base),
    lastAddress: fmt(last),
    ...(version === 4
      ? { netmask: formatIPv4(mask), wildcard: formatIPv4(size - 1n), broadcast: prefix <= 30 ? fmt(last) : undefined }
      : {}),
    firstHost: fmt(firstHost),
    lastHost: fmt(lastHost),
    totalAddresses: size.toString(),
    usableHosts: usable.toString(),
    hostBits,
    scope: classifyIP(fmt(base))?.scope ?? 'public',
    hostBitsSet: original.value !== base,
  };
}

export function cidrContains(cidr: string, ip: string): boolean | null {
  const c = parseCIDR(cidr);
  const p = parseIP(ip);
  if (!c || !p || c.version !== p.version) return c && p ? false : null;
  return inPrefix(p.value, c.base, c.prefix, BITS[c.version]);
}

/** Smallest list of CIDR blocks that exactly covers [start, end]. */
export function rangeToCidrs(startIp: string, endIp: string): string[] | null {
  const a = parseIP(startIp);
  const b = parseIP(endIp);
  if (!a || !b || a.version !== b.version || a.value > b.value) return null;
  const bits = BITS[a.version];
  const out: string[] = [];
  let cur = a.value;
  const end = b.value;
  while (cur <= end) {
    // largest block aligned at `cur`
    let size = cur === 0n ? 1n << BigInt(bits) : cur & -cur;
    while (cur + size - 1n > end) size >>= 1n;
    const hostBits = size.toString(2).length - 1;
    out.push(`${formatIP(a.version, cur)}/${bits - hostBits}`);
    cur += size;
    if (out.length > 4096) return null; // pathological IPv6 range guard
  }
  return out;
}

/* --------------------------------------------------------------- conversion */

export interface IPConversion {
  version: IPVersion;
  canonical: string;
  /** IPv4 */
  decimal: string;
  hex: string;
  binary: string;
  /** IPv4 only */
  octal?: string;
  /** IPv4 only: ::ffff:a.b.c.d */
  ipv4MappedIPv6?: string;
  /** IPv6 only */
  expanded?: string;
  /** IPv6 only */
  compressed?: string;
  /** IPv6 only: embedded IPv4 if mapped */
  embeddedIPv4?: string;
  reverseDns: string;
  scope: IPScope;
  scopeLabel: string;
}

/** Accepts dotted-quad, IPv6, plain decimal ("3232235777") or hex ("0xC0A80101"). */
export function convertIP(input: string): IPConversion | null {
  const raw = input.trim();
  let p = parseIP(raw);
  if (!p && /^\d{1,10}$/.test(raw)) {
    const n = BigInt(raw);
    if (n <= 0xffffffffn) p = { version: 4, value: n };
  }
  if (!p && /^0x[0-9a-f]{1,8}$/i.test(raw)) p = { version: 4, value: BigInt(raw) };
  if (!p) return null;

  const { version, value } = p;
  const cls = classifyIP(formatIP(version, value))!;
  const base = {
    version,
    canonical: formatIP(version, value),
    decimal: value.toString(10),
    hex: `0x${value.toString(16).padStart(version === 4 ? 8 : 32, '0')}`,
    binary:
      version === 4
        ? [24n, 16n, 8n, 0n].map((s) => Number((value >> s) & 0xffn).toString(2).padStart(8, '0')).join('.')
        : groupsOf(value).map((g) => g.toString(2).padStart(16, '0')).join(':'),
    reverseDns: reverseName(version, value),
    scope: cls.scope,
    scopeLabel: cls.label,
  };
  if (version === 4) {
    return {
      ...base,
      octal: [24n, 16n, 8n, 0n].map((s) => '0' + Number((value >> s) & 0xffn).toString(8)).join('.'),
      ipv4MappedIPv6: `::ffff:${formatIPv4(value)}`,
    };
  }
  return {
    ...base,
    expanded: formatIPv6Expanded(value),
    compressed: formatIPv6(value),
    ...(value >> 32n === 0xffffn ? { embeddedIPv4: formatIPv4(value & 0xffffffffn) } : {}),
  };
}

function reverseName(version: IPVersion, value: bigint): string {
  if (version === 4) return formatIPv4(value).split('.').reverse().join('.') + '.in-addr.arpa';
  const nibbles = value.toString(16).padStart(32, '0').split('').reverse().join('.');
  return `${nibbles}.ip6.arpa`;
}

/** PTR query name for an address (`8.8.8.8` -> `8.8.8.8.in-addr.arpa`). */
export function ptrName(ip: string): string | null {
  const p = parseIP(ip);
  return p ? reverseName(p.version, p.value) : null;
}
