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

/**
 * Reads a request body as text but never buffers more than `maxBytes`. Unlike request.text() this also holds for
 * chunked uploads that send no Content-Length: the stream is cancelled as soon as the cap is exceeded.
 */
export async function readTextLimited(request: Request, maxBytes: number): Promise<string> {
  const tooLarge = () => new ApiError(413, 'PAYLOAD_TOO_LARGE', `Request body must be under ${Math.round(maxBytes / 1000)} KB.`);
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > maxBytes) throw tooLarge();
  if (!request.body) return '';

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

/**
 * Reads a request body as raw bytes, never buffering more than `maxBytes` (stream is cancelled at the cap, so this
 * also holds for chunked uploads without a Content-Length).
 */
export async function readBytesLimited(request: Request, maxBytes: number): Promise<Uint8Array> {
  const tooLarge = () => new ApiError(413, 'PAYLOAD_TOO_LARGE', `File must be under ${Math.round(maxBytes / 1_000_000)} MB.`);
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > maxBytes) throw tooLarge();
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  return all;
}
