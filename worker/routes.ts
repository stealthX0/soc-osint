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
import * as emailReputation from './api/email/reputation';
import * as urlLookup from './api/url/lookup';
import * as latency from './api/network/latency';
import * as subnet from './api/network/subnet';
import * as ipConvert from './api/util/ip-convert';
import * as ipRange from './api/util/ip-range';
import * as fileHash from './api/file/hash';
import * as fileUpload from './api/file/upload';
import * as fileAnalysis from './api/file/analysis';
import * as phishingParse from './api/phishing/parse';
import * as phishingSender from './api/phishing/sender';
import * as phishingUrls from './api/phishing/urls';
import * as phishingAttachments from './api/phishing/attachments';

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
  '/api/email/reputation': emailReputation,
  '/api/url/lookup': urlLookup,
  '/api/network/latency': latency,
  '/api/network/subnet': subnet,
  '/api/util/ip-convert': ipConvert,
  '/api/util/ip-range': ipRange,
  '/api/file/hash': fileHash,
  '/api/file/upload': fileUpload,
  '/api/file/analysis': fileAnalysis,
  '/api/phishing/parse': phishingParse,
  '/api/phishing/sender': phishingSender,
  '/api/phishing/urls': phishingUrls,
  '/api/phishing/attachments': phishingAttachments,
};

/** Resolve a handler for method + path, or null. HEAD is served by the GET handler. */
export function resolve(method: string, pathname: string): { handler: Handler | null; known: boolean } {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  const entry = ROUTES[path];
  if (!entry) return { handler: null, known: false };
  const handler = method === 'POST' ? entry.onRequestPost : entry.onRequestGet;
  return { handler: handler ?? null, known: true };
}
