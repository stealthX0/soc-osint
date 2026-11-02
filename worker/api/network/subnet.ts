import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cidrContains, cidrInfo, parseIP } from '../../../shared/ip';

/** GET /api/network/subnet?cidr=192.168.1.0/24[&contains=192.168.1.77]  (also accepts a bare IP and a /prefix) */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  let input = param(url, 'cidr', 80);
  if (!input) throw badInput('Missing "cidr" parameter, e.g. 192.168.1.0/24.');
  if (!input.includes('/') && parseIP(input)) input += parseIP(input)!.version === 4 ? '/32' : '/128';
  const info = cidrInfo(input);
  if (!info) throw badInput('Not a valid CIDR block (e.g. 10.0.0.0/8 or 2001:db8::/32).');

  const probe = param(url, 'contains', 64);
  let contains: boolean | null = null;
  if (probe) {
    if (!parseIP(probe)) throw badInput('"contains" must be an IP address.');
    contains = cidrContains(info.cidr, probe);
  }
  return ok({ ...info, contains: probe ? { ip: probe, inside: contains } : null });
});
