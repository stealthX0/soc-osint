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
  domain_trust?: string;
  risky_tld?: boolean;
  suggested_domain?: string;
  first_seen?: IpqsDate;
  domain_age?: IpqsDate;
}

const bool = (v: unknown) => v === true;
const tri = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() && !/^n\/?a$/i.test(v.trim()) ? v.trim() : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
/** IPQS uses timestamp 0 / the Unix epoch for "unknown". */
const iso = (d: IpqsDate | undefined): string | null => (d && typeof d.timestamp === 'number' && d.timestamp > 0 ? str(d.iso) : null);
const human = (d: IpqsDate | undefined): string | null => (d && typeof d.timestamp === 'number' && d.timestamp > 0 ? str(d.human) : null);

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
    honeypot: bool(r.honeypot), spamTrapScore: str(r.spam_trap_score)?.toLowerCase() ?? null, frequentComplainer: bool(r.frequent_complainer),
    catchAll: bool(r.catch_all), generic: bool(r.generic), freeProvider: bool(r.common),
    dnsValid: tri(r.dns_valid),
    deliverability: str(r.deliverability)?.toLowerCase() ?? null,
    smtpScore: num(r.smtp_score), overallScore: num(r.overall_score),
    domainTrust: str(r.domain_trust)?.toLowerCase() ?? null,
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
 * spam-trap and breach flags, domain trust and age. Needs IPQS_API_KEY (no keyless mode).
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
  const key = env.IPQS_API_KEY;
  if (!key) throw new ApiError(503, 'NOT_CONFIGURED', 'IPQualityScore is not configured (IPQS_API_KEY is not set).');

  const { value, hit } = await cached(ctx, `ipqs:${email}`, async () => {
    const b = await takeProviderBudget(env, 'ipqs');
    if (!b.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `IPQualityScore budget reached: ${b.why}.`);
    const t0 = Date.now();
    // timeout=7 is IPQS's default wait for the mail server; the fetch itself gets a little longer than that.
    const url = `https://www.ipqualityscore.com/api/json/email/${encodeURIComponent(key)}/${encodeURIComponent(email)}?timeout=7&abuse_strictness=0`;
    const r = await fetchJson<IpqsRaw>(url, { timeoutMs: 10_000 });
    if (r.success === false) {
      // e.g. invalid key or quota exhausted. Never echo anything that could contain the key.
      const msg = (typeof r.message === 'string' ? r.message : 'request was not successful').split(key).join('[key]').slice(0, 200);
      const quota = /credit|quota|exceeded|limit/i.test(msg);
      throw new ApiError(502, quota ? 'PROVIDER_BUDGET' : 'UPSTREAM_ERROR', `IPQualityScore: ${msg}`);
    }
    return { value: mapIpqs(email, domain, r, Date.now() - t0), ttl: 6 * 3600 };
  });
  return ok(value, { cached: hit });
});
