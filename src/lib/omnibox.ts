import { detectInput, normalizeHostname, parseEmail, type InputKind } from '../../shared/domain';

export interface Route { to: string; kind: InputKind; label: string }

/** Decides which tool page a pasted value belongs to. Pure so it can be unit-tested. */
export function routeFor(raw: string): Route | null {
  const { kind, value } = detectInput(raw);
  if (!value) return null;
  const enc = encodeURIComponent;
  switch (kind) {
    case 'ipv4':
    case 'ipv6':
      return { to: `/ip?q=${enc(value)}`, kind, label: 'IP lookup' };
    case 'domain':
      return { to: `/domain?q=${enc(value)}`, kind, label: 'Domain intelligence' };
    case 'url': {
      const host = normalizeHostname(value);
      return host ? { to: `/domain?tab=http&q=${enc(host)}`, kind, label: 'HTTP & security headers' } : null;
    }
    case 'email': {
      const e = parseEmail(value);
      return e ? { to: `/email?q=${enc(e.domain)}`, kind, label: `Email auth for ${e.domain}` } : null;
    }
    case 'hash':
      return { to: `/resources?q=${enc('hash')}`, kind, label: 'Hash analysis resources' };
    case 'cve':
      return { to: `/resources?q=${enc('cve')}`, kind, label: 'CVE resources' };
    case 'asn':
      return { to: `/resources?q=${enc('asn bgp')}`, kind, label: 'ASN / BGP resources' };
    default:
      return { to: `/resources?q=${enc(value)}`, kind: 'text', label: 'Search resource directory' };
  }
}
