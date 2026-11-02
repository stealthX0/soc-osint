import { ApiError, badInput } from './errors';
import { normalizeDomain, normalizeHostname } from '../../shared/domain';
import { normalizeIP } from '../../shared/ip';

export const param = (url: URL, name: string, max = 512): string => {
  const v = url.searchParams.get(name)?.trim() ?? '';
  if (v.length > max) throw new ApiError(400, 'INVALID_INPUT', `"${name}" is too long (max ${max} characters).`);
  return v;
};

export function requireDomain(url: URL, name = 'domain'): string {
  const raw = param(url, name);
  if (!raw) throw badInput(`Missing "${name}" parameter.`);
  const d = normalizeDomain(raw);
  if (!d) throw badInput(`"${raw.slice(0, 80)}" is not a valid domain name.`);
  return d;
}

export function requireHostname(url: URL, name: string): string {
  const raw = param(url, name);
  if (!raw) throw badInput(`Missing "${name}" parameter.`);
  const h = normalizeHostname(raw);
  if (!h) throw badInput(`"${raw.slice(0, 80)}" is not a valid hostname.`);
  return h;
}

export function requireIP(url: URL, name = 'q'): string {
  const raw = param(url, name);
  const ip = normalizeIP(raw.replace(/^\[|\]$/g, ''));
  if (!ip) throw badInput(`"${raw.slice(0, 80)}" is not a valid IPv4 or IPv6 address.`);
  return ip;
}

export function intParam(url: URL, name: string, def: number, min: number, max: number): number {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw badInput(`"${name}" must be an integer between ${min} and ${max}.`);
  return n;
}
