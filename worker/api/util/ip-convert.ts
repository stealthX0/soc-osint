import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { convertIP } from '../../../shared/ip';

/** GET /api/util/ip-convert?value=192.168.1.1 | 3232235777 | 0xC0A80101 | 2001:db8::1 */
export const onRequestGet = route(async (ctx) => {
  const value = param(new URL(ctx.request.url), 'value', 64);
  if (!value) throw badInput('Missing "value" parameter.');
  const r = convertIP(value);
  if (!r) throw badInput('Not an IPv4/IPv6 address, decimal integer (IPv4) or 0x-hex value.');
  return ok(r);
});
