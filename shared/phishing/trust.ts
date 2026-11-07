/**
 * Trusted receiver boundary.
 *
 * Anyone can forge Received headers BELOW the point where the message entered the recipient's own mail system, so only the
 * hops added by the receiving organisation are evidence. This finds that boundary and, from it, the IP that actually
 * connected to the receiver ("connecting IP"): the one address in the headers that was observed rather than claimed.
 */
import { type Hop } from '../headers';
import { classifyIP, parseIP } from '../ip';
import { GATEWAY_ORGS, registrableOf } from './domains';

export interface TrustedHop extends Hop {
  trust: 'trusted' | 'untrusted';
  /** Public IPs in the "from" clause only (the client that connected), excluding the receiving server's own address. */
  clientIps: string[];
  fromOrg: string | null;
  byOrg: string | null;
}

export interface TrustBoundary {
  receiverHost: string | null;
  receiverOrg: string | null;
  /** How the receiving system was identified. */
  basis: 'authserv_id' | 'newest_hop' | 'none';
  trustedHops: number;
  untrustedHops: number;
  /** Chronological index of the oldest trusted hop (the one that accepted the message from outside). */
  boundaryHop: number | null;
  connectingIp: string | null;
  connectingIpSource: 'trusted_received' | 'x_originating_ip' | 'untrusted_received' | 'none';
  /** Oldest public IP in the untrusted part of the chain: a claim by whoever wrote those headers. */
  claimedOriginIp: string | null;
  gateways: string[];
  confidence: 'high' | 'medium' | 'low';
  notes: string[];
}

const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;
const IPV6 = /\[(?:IPv6:)?([0-9a-f:]{3,39})\]/gi;

function ipsIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(IPV4)) if (parseIP(m[0])) out.add(m[0]);
  for (const m of text.matchAll(IPV6)) if (parseIP(m[1])) out.add(m[1]);
  return [...out];
}

export function clientIpsOf(hop: Hop): string[] {
  const from = hop.raw.match(/\bfrom\s+([\s\S]*?)\s+by\s/i)?.[1];
  const ips = from ? ipsIn(from) : hop.publicIps;
  return ips.filter((ip) => classifyIP(ip)?.public);
}

export function determineTrust(hops: Hop[], topAuthservId: string | null, xOriginatingIp: string | null): { boundary: TrustBoundary; hops: TrustedHop[] } {
  const notes: string[] = [];
  const view: TrustedHop[] = hops.map((h) => ({
    ...h,
    trust: 'untrusted',
    clientIps: clientIpsOf(h),
    fromOrg: registrableOf(h.from),
    byOrg: registrableOf(h.by),
  }));
  const xo = xOriginatingIp && classifyIP(xOriginatingIp)?.public ? xOriginatingIp : null;

  const empty: TrustBoundary = {
    receiverHost: null, receiverOrg: null, basis: 'none', trustedHops: 0, untrustedHops: view.length, boundaryHop: null,
    connectingIp: xo, connectingIpSource: xo ? 'x_originating_ip' : 'none', claimedOriginIp: null, gateways: [], confidence: 'low', notes,
  };
  if (!view.length) {
    notes.push('No Received headers: the delivery path cannot be traced from these headers.');
    return { boundary: empty, hops: view };
  }

  const newest = view[view.length - 1];
  const authOrg = registrableOf(topAuthservId);
  // The very newest hop is often an internal one ("by 2002:a05:..." at Gmail) with no host name: anchor on the newest named receiver.
  const anchor = [...view].reverse().find((h) => h.byOrg) ?? null;
  const receiverOrg = anchor?.byOrg ?? null;
  const trustedOrgs = new Set<string>();
  if (receiverOrg) trustedOrgs.add(receiverOrg);
  let basis: TrustBoundary['basis'] = 'newest_hop';
  if (authOrg) {
    if (view.some((h) => h.byOrg === authOrg)) { trustedOrgs.add(authOrg); basis = 'authserv_id'; }
    else notes.push(`The Authentication-Results authserv-id (${topAuthservId}) does not match any Received hop; the newest hop was assumed to be the receiver.`);
  } else if (topAuthservId === null) {
    notes.push('No authserv-id in Authentication-Results: the newest Received hop was assumed to be the receiver.');
  }

  const gateways: string[] = [];
  for (let i = view.length - 1; i >= 0; i--) {
    const h = view[i];
    const org = h.byOrg;
    if (!org && anchor && h.index > anchor.index) { h.trust = 'trusted'; continue; } // unnamed internal hop inside the receiver
    if (org && trustedOrgs.has(org)) { h.trust = 'trusted'; continue; }
    // A mail gateway directly in front of the trusted receiver is part of the recipient's delivery path.
    if (org && GATEWAY_ORGS.has(org) && i < view.length - 1 && view[i + 1].trust === 'trusted') { h.trust = 'trusted'; gateways.push(org); continue; }
    break;
  }
  const trusted = view.filter((h) => h.trust === 'trusted');
  const untrusted = view.filter((h) => h.trust === 'untrusted');
  const boundaryHop = trusted.length ? trusted[0].index : null;
  const boundary = trusted[0];

  let connectingIp: string | null = null;
  let source: TrustBoundary['connectingIpSource'] = 'none';
  if (boundary?.clientIps.length) {
    connectingIp = boundary.clientIps[0];
    source = 'trusted_received';
    if (gateways.length) notes.push(`The message passed through ${[...new Set(gateways)].join(', ')} before reaching the receiver; the connecting IP shown is the one that reached the gateway.`);
  } else if (xo) {
    connectingIp = xo;
    source = 'x_originating_ip';
    notes.push('The trusted hop recorded no public client IP; X-Originating-IP (added by some webmail systems) is used as an unverified clue.');
  } else {
    const older = [...untrusted].reverse().find((h) => h.clientIps.length);
    if (older) {
      connectingIp = older.clientIps[0];
      source = 'untrusted_received';
      notes.push('Only an older, untrusted Received header names a public IP; treat it as a claim.');
    }
  }

  const claimedOrigin = untrusted.find((h) => h.clientIps.length)?.clientIps[0] ?? null;
  if (untrusted.length) notes.push(`${untrusted.length} Received header(s) precede the trusted boundary and could have been written by the sender.`);

  const confidence: TrustBoundary['confidence'] = basis === 'authserv_id' && source === 'trusted_received' ? 'high' : source === 'none' ? 'low' : 'medium';
  return {
    boundary: {
      receiverHost: anchor?.by ?? newest.by, receiverOrg: authOrg && basis === 'authserv_id' ? authOrg : receiverOrg, basis, trustedHops: trusted.length, untrustedHops: untrusted.length,
      boundaryHop, connectingIp, connectingIpSource: source, claimedOriginIp: claimedOrigin, gateways: [...new Set(gateways)], confidence, notes,
    },
    hops: view,
  };
}

