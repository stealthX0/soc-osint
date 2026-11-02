import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param, requireHostname } from '../../_lib/input';
import { RECORD_TYPES, RESOLVERS, dohQuery, type RecordType } from '../../_lib/doh';
import type { DnsPropagation } from '../../../shared/types';

/** GET /api/dns/propagation?name=example.com&type=A  - compares answers across independent public resolvers */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const name = requireHostname(url, 'name');
  const type = (param(url, 'type', 10) || 'A').toUpperCase();
  if (!(RECORD_TYPES as string[]).includes(type)) throw badInput(`type must be one of ${RECORD_TYPES.join(', ')}.`);

  const ids = Object.keys(RESOLVERS) as (keyof typeof RESOLVERS)[];
  const settled = await Promise.allSettled(ids.map((id) => dohQuery(name, type as RecordType, id)));
  const resolvers = settled.map((r, i) =>
    r.status === 'fulfilled'
      ? { resolver: r.value.resolver, status: r.value.status, ms: r.value.ms, authenticated: r.value.authenticated, records: r.value.answers.filter((a) => a.type === type) }
      : { resolver: RESOLVERS[ids[i]].name, status: 'ERROR', ms: 0, authenticated: false, records: [], error: r.reason instanceof Error ? r.reason.message : 'failed' },
  );
  const healthy = resolvers.filter((r) => r.status !== 'ERROR');
  if (!healthy.length) throw new ApiError(502, 'UPSTREAM_ERROR', 'No resolver responded.');

  // Compare data sets ignoring order and TTL (TTLs legitimately differ between caches)
  const sig = (r: (typeof resolvers)[number]) => `${r.status}|${r.records.map((x) => x.data).sort().join(',')}`;
  const consistent = new Set(healthy.map(sig)).size === 1;

  const data: DnsPropagation = {
    name,
    type,
    consistent,
    resolvers,
    note: 'These are independent anycast public resolvers, not geographically distributed probes. Differences usually mean a recent change is still expiring from caches (check the TTL).',
  };
  return ok(data);
});
