import type { Handler } from './_lib/env';
import * as health from './api/health';
import * as ipLookup from './api/ip/lookup';
import * as dnsLookup from './api/dns/lookup';
import * as dnsPropagation from './api/dns/propagation';
import * as whois from './api/domain/whois';
import * as ssl from './api/domain/ssl';
import * as http from './api/domain/http';
import * as emailAuth from './api/email/auth';
import * as emailHeaders from './api/email/headers';
import * as latency from './api/network/latency';
import * as subnet from './api/network/subnet';
import * as ipConvert from './api/util/ip-convert';
import * as ipRange from './api/util/ip-range';

type Methods = { onRequestGet?: Handler; onRequestPost?: Handler };

/** Explicit route table (Workers has no file-based routing). Keys are exact pathnames. */
export const ROUTES: Record<string, Methods> = {
  '/api/health': health,
  '/api/ip/lookup': ipLookup,
  '/api/dns/lookup': dnsLookup,
  '/api/dns/propagation': dnsPropagation,
  '/api/domain/whois': whois,
  '/api/domain/ssl': ssl,
  '/api/domain/http': http,
  '/api/email/auth': emailAuth,
  '/api/email/headers': emailHeaders,
  '/api/network/latency': latency,
  '/api/network/subnet': subnet,
  '/api/util/ip-convert': ipConvert,
  '/api/util/ip-range': ipRange,
};

/** Resolve a handler for method + path, or null. HEAD is served by the GET handler. */
export function resolve(method: string, pathname: string): { handler: Handler | null; known: boolean } {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  const entry = ROUTES[path];
  if (!entry) return { handler: null, known: false };
  const handler = method === 'POST' ? entry.onRequestPost : entry.onRequestGet;
  return { handler: handler ?? null, known: true };
}
