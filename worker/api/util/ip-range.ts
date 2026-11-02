import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cidrInfo, parseIP, rangeToCidrs } from '../../../shared/ip';

/** GET /api/util/ip-range?start=10.0.0.5&end=10.0.1.20  -> minimal CIDR cover */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const start = param(url, 'start', 64);
  const end = param(url, 'end', 64);
  if (!start || !end) throw badInput('Both "start" and "end" are required.');
  if (!parseIP(start) || !parseIP(end)) throw badInput('start and end must be IP addresses.');
  const cidrs = rangeToCidrs(start, end);
  if (!cidrs) throw badInput('Range is invalid: start and end must be the same IP version with start <= end (and the range must be reasonably sized).');
  return ok({
    start, end, count: cidrs.length,
    blocks: cidrs.map((c) => { const i = cidrInfo(c)!; return { cidr: i.cidr, firstAddress: i.firstAddress, lastAddress: i.lastAddress, totalAddresses: i.totalAddresses }; }),
  });
});
