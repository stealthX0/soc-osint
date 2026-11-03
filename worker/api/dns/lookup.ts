import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { param, requireHostname } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { RECORD_TYPES, RESOLVERS, dohQuery, type RecordType, type Resolver } from '../../_lib/doh';
import type { DnsLookup, ProviderStatus } from '../../../shared/types';
import { ptrName, parseIP } from '../../../shared/ip';

const ALL: RecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

/** GET /api/dns/lookup?name=example.com&type=ALL|A|MX|...&resolver=cloudflare|google */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const rawName = param(url, 'name');
  if (!rawName) throw badInput('Missing "name" parameter.');
  // PTR convenience: allow an IP address and convert it to its reverse name
  const ptr = parseIP(rawName) ? ptrName(rawName) : null;
  const name = ptr ?? requireHostname(url, 'name');

  const typeParam = (param(url, 'type', 10) || 'ALL').toUpperCase();
  const resolverId = (param(url, 'resolver', 12) || 'cloudflare').toLowerCase() as Resolver['id'];
  if (!(resolverId in RESOLVERS)) throw badInput('resolver must be cloudflare or google.');
  let types: RecordType[];
  if (ptr) types = ['PTR'];
  else if (typeParam === 'ALL') types = ALL;
  else if ((RECORD_TYPES as string[]).includes(typeParam)) types = [typeParam as RecordType];
  else throw badInput(`type must be ALL or one of ${RECORD_TYPES.join(', ')}.`);

  const { value, hit } = await cached(ctx, `dns:${resolverId}:${name}:${types.join(',')}`, async () => {
    const providers: ProviderStatus[] = [];
    const settled = await Promise.allSettled(types.map((t) => dohQuery(name, t, resolverId)));
    const results = settled.map((r, i) => {
      if (r.status === 'fulfilled') {
        providers.push({ name: `${r.value.resolver} ${types[i]}`, ok: true, ms: r.value.ms });
        return { type: types[i], status: r.value.status, authenticated: r.value.authenticated, records: r.value.answers.filter((a) => a.type === types[i] || a.type === 'CNAME') };
      }
      providers.push({ name: `${RESOLVERS[resolverId].name} ${types[i]}`, ok: false, ms: 0, error: r.reason instanceof Error ? r.reason.message : 'failed' });
      return { type: types[i], status: 'ERROR', authenticated: false, records: [] };
    });
    if (results.every((r) => r.status === 'ERROR')) throw (settled[0] as PromiseRejectedResult).reason;
    const out: DnsLookup = { name, resolver: RESOLVERS[resolverId].name, results, providers };
    return { value: out, ttl: providers.every((p) => p.ok) ? 60 : 0 };
  });
  return ok(value, { cached: hit });
});
