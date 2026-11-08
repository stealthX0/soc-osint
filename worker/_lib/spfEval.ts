/**
 * Independent SPF evaluation (RFC 7208, simplified): does the published SPF policy of a domain authorise a given IP?
 *
 * Why: pasted headers only tell us what the receiving server SAID. Re-running the check against current DNS gives
 * Spectrix evidence of its own ("independently verified"). It can legitimately disagree with the header (DNS changes
 * after delivery, receiver-side allow-lists), so callers treat a disagreement as a signal, not proof.
 *
 * Supported: ip4, ip6, a, mx, include, redirect, all. Not evaluated (reported as unsupported): exists, ptr, macros.
 */
import { resolve as dohResolve } from './doh';
import { isSpfRecord, parseSpf } from '../../shared/emailAuth';
import { cidrContains, normalizeIP, parseIP } from '../../shared/ip';
import { normalizeDomain } from '../../shared/domain';

export type SpfResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'permerror' | 'temperror';

export interface SpfEvaluation {
  domain: string;
  ip: string;
  result: SpfResult;
  /** The term that decided the result, e.g. "ip4:203.0.113.0/24" or "include:_spf.google.com -> ip4:...". */
  matched: string | null;
  /** DNS-querying terms evaluated (RFC limit: 10). */
  lookups: number;
  record: string | null;
  notes: string[];
}

export interface DnsReader {
  txt(name: string): Promise<string[]>;
  a(name: string): Promise<string[]>;
  aaaa(name: string): Promise<string[]>;
  mx(name: string): Promise<string[]>;
}

export const dohReader: DnsReader = {
  txt: async (n) => (await dohResolve(n, 'TXT')).answers.filter((a) => a.type === 'TXT').map((a) => a.data),
  a: async (n) => (await dohResolve(n, 'A')).answers.filter((a) => a.type === 'A').map((a) => a.data),
  aaaa: async (n) => (await dohResolve(n, 'AAAA')).answers.filter((a) => a.type === 'AAAA').map((a) => a.data),
  mx: async (n) => (await dohResolve(n, 'MX')).answers.filter((a) => a.type === 'MX').map((a) => a.data.trim().split(/\s+/).pop() ?? '').filter(Boolean),
};

const QUAL: Record<string, SpfResult> = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

class Abort extends Error { constructor(public result: SpfResult, msg: string) { super(msg); } }

export async function evaluateSpf(domainIn: string, ipIn: string, dns: DnsReader = dohReader, maxLookups = 10): Promise<SpfEvaluation> {
  const domain = normalizeDomain(domainIn) ?? domainIn;
  const ip = normalizeIP(ipIn) ?? ipIn;
  const notes: string[] = [];
  const ev: SpfEvaluation = { domain, ip, result: 'none', matched: null, lookups: 0, record: null, notes };
  if (!parseIP(ip)) { ev.result = 'permerror'; notes.push('Invalid IP address.'); return ev; }
  const isV6 = ip.includes(':');
  let skippedMechanism = false;

  const count = () => { if (++ev.lookups > maxLookups) throw new Abort('permerror', `More than ${maxLookups} DNS-querying terms: the SPF record is invalid (RFC 7208 limit).`); };
  const dnsErr = (e: unknown) => new Abort('temperror', `DNS error: ${e instanceof Error ? e.message : 'lookup failed'}`);

  /**
   * Look up A or AAAA records for `name` and check whether `ip` falls in any of them.
   * When `counted` is true the caller already counted this toward the lookup limit (used for `mx` host lookups,
   * which RFC 7208 does not count individually — only the `mx` term itself counts).
   */
  async function addrsMatch(name: string, prefix4: number, prefix6: number, counted = false): Promise<boolean> {
    if (!counted) count();
    let addrs: string[];
    try { addrs = isV6 ? await dns.aaaa(name) : await dns.a(name); } catch (e) { throw dnsErr(e); }
    return addrs.some((a) => cidrContains(`${a}/${isV6 ? prefix6 : prefix4}`, ip) === true);
  }

  /** Returns a result if a term decided it, or 'nomatch'. */
  async function check(name: string, depth: number, path: Set<string>): Promise<SpfResult | 'nomatch'> {
    if (depth > 8 || path.has(name)) throw new Abort('permerror', 'SPF include/redirect loop or nesting too deep.');
    const branch = new Set(path);
    branch.add(name);
    let txts: string[];
    try { txts = await dns.txt(name); } catch (e) { throw dnsErr(e); }
    const records = txts.filter(isSpfRecord);
    if (!records.length) return depth === 0 ? 'none' : 'permerror';
    if (records.length > 1) throw new Abort('permerror', 'More than one SPF record is published.');
    if (depth === 0) ev.record = records[0];
    const spf = parseSpf(records[0]);

    for (const m of spf.mechanisms) {
      const q = QUAL[m.qualifier];
      const v = m.value?.trim();
      let hit = false;
      let via: string | null = null;
      switch (m.type) {
        case 'ip4':
        case 'ip6':
          hit = !!v && (m.type === 'ip6') === isV6 && cidrContains(v.includes('/') ? v : `${v}/${isV6 ? 128 : 32}`, ip) === true;
          break;
        case 'a':
        case 'mx': {
          const [target] = (v ?? '').split('/');
          const dual = (v ?? '').match(/\/(\d+)?(?:\/(\d+))?$/);
          const p4 = dual?.[1] ? Number(dual[1]) : 32;
          const p6 = dual?.[2] ? Number(dual[2]) : 128;
          const host = (target && !target.startsWith('/') ? target : name).toLowerCase();
          if (m.type === 'a') hit = await addrsMatch(host, p4, p6);
          else {
            count(); // count the mx term itself
            let hosts: string[];
            try { hosts = await dns.mx(host); } catch (e) { throw dnsErr(e); }
            // RFC 7208 §5.4: the per-MX-host A/AAAA lookups are NOT counted toward the 10-lookup limit.
            for (const h of hosts.slice(0, 10)) if (await addrsMatch(h.toLowerCase(), p4, p6, true)) { hit = true; break; }
          }
          break;
        }
        case 'include': {
          if (!v) throw new Abort('permerror', 'include: without a domain.');
          count();
          const r = await check(v.toLowerCase(), depth + 1, branch);
          if (r === 'pass') { via = `include:${v} → ${ev.matched ?? 'match'}`; hit = true; }
          else if (r === 'permerror' || r === 'temperror') throw new Abort(r, `include:${v} returned ${r}.`);
          else if (r === 'none') throw new Abort('permerror', `include:${v} has no SPF record.`);
          break;
        }
        case 'exists': case 'ptr':
          skippedMechanism = true;
          notes.push(`The "${m.type}" mechanism is not evaluated here; the result may differ from a full SPF check.`);
          break;
        default:
          notes.push(`Unknown mechanism "${m.type}" ignored.`);
      }
      if (hit) {
        ev.matched = via ?? `${m.type}${v ? `:${v}` : ''}`;
        return q;
      }
    }
    if (spf.all !== null) { ev.matched = `${spf.all}all`; return QUAL[spf.all]; }
    if (spf.redirect) { count(); const r = await check(spf.redirect.toLowerCase(), depth + 1, branch); return r === 'nomatch' ? 'neutral' : r === 'none' ? 'permerror' : r; }
    return 'neutral';
  }

  try {
    const r = await check(domain, 0, new Set<string>());
    ev.result = r === 'nomatch' ? 'neutral' : r;
  } catch (e) {
    if (e instanceof Abort) { ev.result = e.result; notes.push(e.message); } else throw e;
  }

  // If a mechanism was skipped (exists/ptr), a fail/softfail/neutral result is unreliable:
  // the skipped mechanism could have matched and produced pass.  Mark the evaluation
  // inconclusive so convertSpf does not raise spf_independent_fail / spf_independent_disagrees.
  if (skippedMechanism && (ev.result === 'fail' || ev.result === 'softfail' || ev.result === 'neutral')) {
    notes.push(`Result downgraded from "${ev.result}" to inconclusive because an unevaluated mechanism (exists/ptr) could have matched.`);
    ev.result = 'none';
  }

  return ev;
}
