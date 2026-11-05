import { detectInput, parseEmail, type InputKind } from '../../shared/domain';

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
    case 'url':
      // a full link is checked as a link (threat feeds, heuristics); the domain/HTTP tools stay reachable from the sidebar
      return { to: `/url?q=${enc(value)}`, kind, label: 'URL intelligence' };
    case 'email': {
      const e = parseEmail(value);
      return e ? { to: `/email?q=${enc(e.domain)}`, kind, label: `Email auth for ${e.domain}` } : null;
    }
    case 'hash':
      return { to: `/file?hash=${enc(value.toLowerCase())}`, kind, label: 'File hash reputation' };
    case 'cve':
      return { to: `/resources?q=${enc('cve')}`, kind, label: 'CVE resources' };
    case 'asn':
      return { to: `/resources?q=${enc('asn bgp')}`, kind, label: 'ASN / BGP resources' };
    default:
      return { to: `/resources?q=${enc(value)}`, kind: 'text', label: 'Search resource directory' };
  }
}
