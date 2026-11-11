import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import { parseEmail } from '../../../shared/domain';
import type { Env } from '../../_lib/env';
import type { EmailReputation } from '../../../shared/types';

/**
 * The fields of the IPQualityScore Email Validation response that Spectrix uses
 * (https://www.ipqualityscore.com/documentation/email-validation-api/response-parameters).
 */
interface IpqsDate { human?: string | null; timestamp?: number | null; iso?: string | null }
interface IpqsRaw {
  success?: boolean;
  message?: string;
  request_id?: string;
  valid?: boolean;
  timed_out?: boolean;
  suspect?: boolean;
  fraud_score?: number;
  recent_abuse?: boolean;
  leaked?: boolean;
  disposable?: boolean;
  honeypot?: boolean;
  spam_trap_score?: string;
  frequent_complainer?: boolean;
  catch_all?: boolean;
  generic?: boolean;
  common?: boolean;
  dns_valid?: boolean;
  deliverability?: string;
  smtp_score?: number;
  overall_score?: number;
  risky_tld?: boolean;
  suggested_domain?: string;
  first_seen?: IpqsDate;
  domain_age?: IpqsDate;
}

const bool = (v: unknown) => v === true;
const tri = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() && !/^n\/?a$/i.test(v.trim()) ? v.trim() : null);
const oneOf = (v: unknown, allowed: string[]): string | null => { const s = str(v)?.toLowerCase() ?? null; return s && allowed.includes(s) ? s : null; };
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
/** IPQS uses timestamp 0 / the Unix epoch for "unknown". */
const iso = (d: IpqsDate | undefined): string | null => (d && typeof d.timestamp === 'number' && d.timestamp > 0 ? str(d.iso) : null);
const human = (d: IpqsDate | undefined): string | null => (d && typeof d.timestamp === 'number' && d.timestamp > 0 ? str(d.human) : null);

/** Strips whitespace, line breaks and wrapping quotes that often come along when a key is pasted into a secret. Exported for tests. */
export const cleanKey = (k: string | undefined): string => (k ?? '').trim().replace(/^["'`]+|["'`]+$/g, '').trim();

/** A safe fingerprint of a key for error messages: its length, plus the last 4 characters only for keys of 16+ characters. Exported for tests. */
export const keyHint = (k: string): string => (k.length >= 16 ? `${k.length} characters, ending "…${k.slice(-4)}"` : `${k.length} characters`);

/** First 12 hex characters of the key's SHA-256: proves which exact key is stored without revealing it. Exported for tests. */
export async function keySha(k: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(k));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
}

/** IPQS says this when it does not accept the key as sent. */
export const isKeyRejection = (m: unknown): boolean => typeof m === 'string' && /invalid|unauthori[sz]ed/i.test(m) && /key/i.test(m);

/**
 * The documented ways of sending the key, in the order tried. The address keeps a plain "@" in the path, exactly as a
 * browser sends it. Exported for tests.
 */
export interface IpqsAttempt { name: string; url: string; headers?: Record<string, string>; method?: 'GET' | 'POST'; body?: string; noUserAgent?: boolean }
export function ipqsAttempts(key: string, email: string): IpqsAttempt[] {
  const addr = encodeURIComponent(email).replace(/%40/g, '@');
  const k = encodeURIComponent(key);
  const opts = 'timeout=7&abuse_strictness=0';
  const path = (host: string) => `https://${host}/api/json/email/${k}/${addr}`;
  return [
    { name: 'URL path', url: `${path('www.ipqualityscore.com')}?${opts}` },
    { name: 'IPQS-KEY header', url: `https://www.ipqualityscore.com/api/json/email?email=${encodeURIComponent(email)}&${opts}`, headers: { 'IPQS-KEY': key } },
    { name: 'plain URL path', url: path('www.ipqualityscore.com') },
    // Diagnostics for the Cloudflare Workers rejection: all documented forms, none disguised as a browser.
    { name: 'plain URL path without the Spectrix user agent', url: path('www.ipqualityscore.com'), noUserAgent: true },
    { name: 'ipqualityscore.com (no www)', url: path('ipqualityscore.com') },
    { name: 'ipqs.com', url: path('ipqs.com') },
    { name: 'POST form', url: 'https://www.ipqualityscore.com/api/json/email', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `key=${k}&email=${encodeURIComponent(email)}&${opts}` },
  ];
}

/** Maps the IPQS response to Spectrix's shape. Exported for tests. */
export function mapIpqs(email: string, domain: string, r: IpqsRaw, ms: number): EmailReputation {
  const timedOut = bool(r.timed_out);
  const suspect = bool(r.suspect);
  return {
    email, domain,
    // An "invalid" result after a timeout or a temporary mail-server error is not trustworthy (IPQS docs): report unknown.
    valid: timedOut || suspect ? (r.valid === true ? true : null) : tri(r.valid),
    timedOut, suspect,
    fraudScore: num(r.fraud_score),
    recentAbuse: bool(r.recent_abuse), leaked: bool(r.leaked), disposable: bool(r.disposable),
    honeypot: bool(r.honeypot), spamTrapScore: oneOf(r.spam_trap_score, ['high', 'medium', 'low', 'none']), frequentComplainer: bool(r.frequent_complainer),
    catchAll: bool(r.catch_all), generic: bool(r.generic), freeProvider: bool(r.common),
    dnsValid: tri(r.dns_valid),
    // Plan-restricted fields can come back as text such as "Upgraded plan required.": keep only documented values.
    deliverability: oneOf(r.deliverability, ['high', 'medium', 'low']),
    smtpScore: num(r.smtp_score), overallScore: num(r.overall_score),
    riskyTld: bool(r.risky_tld),
    suggestedDomain: str(r.suggested_domain),
    firstSeen: iso(r.first_seen), firstSeenHuman: human(r.first_seen),
    domainRegistered: iso(r.domain_age), domainAgeHuman: human(r.domain_age),
    providers: [{ name: 'IPQualityScore', ok: true, ms }],
  };
}

/**
 * GET /api/email/ipqs?email=user@example.com
 * Mailbox reputation from IPQualityScore's Email Validation API: whether the mailbox exists, fraud score, recent abuse,
 * spam-trap and breach flags, domain age. Needs IPQS_API_KEY (no keyless mode).
 * The address is sent to ipqualityscore.com, which also probes the address's mail server. IPQS takes the key in the URL
 * path, so the URL is never logged or put in an error message.
 */
export const onRequestGet = route(async (ctx) => {
  const env = ctx.env as Env;
  const raw = param(new URL(ctx.request.url), 'email', 320);
  const parsed = raw ? parseEmail(raw) : null;
  if (!parsed) throw badInput(raw ? `"${raw.slice(0, 80)}" is not a valid e-mail address.` : 'Missing "email" parameter.');
  const email = `${parsed.local}@${parsed.domain}`.toLowerCase();
  const domain = parsed.domain.toLowerCase();
  // Secrets pasted with a trailing newline / spaces or wrapping quotes are rejected by IPQS as "invalid key": clean them.
  const key = cleanKey(env.IPQS_API_KEY);
  if (!key) throw new ApiError(503, 'NOT_CONFIGURED', 'IPQualityScore is not configured (IPQS_API_KEY is not set).');

  const { value, hit } = await cached(ctx, `ipqs:${email}`, async () => {
    const b = await takeProviderBudget(env, 'ipqs');
    if (!b.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `IPQualityScore budget reached: ${b.why}.`);
    const t0 = Date.now();
    // IPQS accepts the key in the URL path, in an IPQS-KEY header, or as a parameter. Some accounts reject one form with
    // "Invalid or unauthorized key" while another works, so on that answer (and only that one) the next form is tried.
    // A rejected key costs no IPQS credit. timeout=7 is IPQS's default wait for the mail server.
    let r: IpqsRaw = {};
    const tried: string[] = [];
    const ids: string[] = [];
    const attempts = ipqsAttempts(key, email);
    for (let i = 0; i < attempts.length; i++) {
      const at = attempts[i];
      try {
        r = await fetchJson<IpqsRaw>(at.url, { timeoutMs: 10_000, headers: at.headers, method: at.method, body: at.body, noUserAgent: at.noUserAgent });
      } catch (e) {
        if (i === 0) throw e; // the normal form failed outright (timeout, HTTP error): no point trying variants
        tried.push(`${at.name} (${e instanceof Error ? e.message.replace(/\.$/, '') : 'failed'})`);
        continue; // a later variant failing outright leaves the earlier key rejection standing
      }
      tried.push(at.name);
      // IPQS support looks requests up by request_id; keep the ids of rejected attempts (short alphanumeric only).
      if (r.success === false && typeof r.request_id === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(r.request_id)) ids.push(r.request_id);
      if (r.success !== false || !isKeyRejection(r.message)) break;
    }
    if (r.success !== false && tried.length > 1) console.warn(`[ipqs] key accepted when sent as: ${tried[tried.length - 1]}`);
    if (r.success === false) {
      // e.g. invalid key or quota exhausted. Never echo anything that could contain the key.
      const msg = (typeof r.message === 'string' ? r.message : 'request was not successful').split(key).join('[key]').slice(0, 200);
      const quota = /credit|quota|exceeded|limit/i.test(msg);
      // For a rejected key, say which key the Worker holds without revealing it, and which ways of sending it were tried.
      const reqIds = ids.length ? ` request_id: ${ids.join(', ')}` : '';
      const hint = isKeyRejection(msg) ? ` [IPQS_API_KEY on this Worker: ${keyHint(key)}, SHA-256 ${await keySha(key)}…; rejected when sent as: ${tried.join(', ')};${reqIds || ' no request_id returned'}]` : reqIds ? ` [${reqIds.trim()}]` : '';
      throw new ApiError(502, quota ? 'PROVIDER_BUDGET' : 'UPSTREAM_ERROR', `IPQualityScore: ${msg}${hint}`);
    }
    return { value: mapIpqs(email, domain, r, Date.now() - t0), ttl: 6 * 3600 };
  });
  return ok(value, { cached: hit });
});
