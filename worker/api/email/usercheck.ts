import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import { parseEmail } from '../../../shared/domain';
import type { Env } from '../../_lib/env';
import type { EmailCheck } from '../../../shared/types';

/** The fields of the UserCheck.com email response that Spectrix uses (https://www.usercheck.com/docs/api/email-endpoint). */
interface UserCheckRaw {
  email?: string;
  domain?: string;
  domain_age_in_days?: number | null;
  mx?: boolean | null;
  spf?: string | null;
  dmarc?: string | null;
  disposable?: boolean;
  public_domain?: boolean;
  relay_domain?: boolean;
  free_subdomain?: boolean;
  role_account?: boolean;
  spam?: boolean;
  did_you_mean?: string | null;
}

const bool = (v: unknown) => v === true;
const tri = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);

/**
 * GET /api/email/usercheck?email=user@example.com
 * Address and domain checks from UserCheck.com: disposable and spam domains, whether the domain can receive mail (MX),
 * domain age, public / relay / free-subdomain flags, role accounts and "did you mean" typo detection.
 * Needs USERCHECK_API_KEY (UserCheck has no keyless mode). The address is sent to api.usercheck.com (only this endpoint does that).
 */
export const onRequestGet = route(async (ctx) => {
  const env = ctx.env as Env;
  const raw = param(new URL(ctx.request.url), 'email', 320);
  const parsed = raw ? parseEmail(raw) : null;
  if (!parsed) throw badInput(raw ? `"${raw.slice(0, 80)}" is not a valid e-mail address.` : 'Missing "email" parameter.');
  const email = `${parsed.local}@${parsed.domain}`.toLowerCase();
  const key = env.USERCHECK_API_KEY;
  if (!key) throw new ApiError(503, 'NOT_CONFIGURED', 'UserCheck is not configured (USERCHECK_API_KEY is not set).');

  const { value, hit } = await cached(ctx, `usercheck:${email}`, async () => {
    const b = await takeProviderBudget(env, 'usercheck');
    if (!b.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `UserCheck budget reached: ${b.why}.`);
    const t0 = Date.now();
    const r = await fetchJson<UserCheckRaw>(`https://api.usercheck.com/email/${encodeURIComponent(email).replace(/%40/g, '@')}`, { headers: { Authorization: `Bearer ${key}` } });
    const out: EmailCheck = {
      email,
      domain: str(r.domain) ?? parsed.domain.toLowerCase(),
      domainAgeDays: typeof r.domain_age_in_days === 'number' && r.domain_age_in_days >= 0 ? r.domain_age_in_days : null,
      mx: tri(r.mx),
      disposable: bool(r.disposable), spam: bool(r.spam),
      publicDomain: bool(r.public_domain), relayDomain: bool(r.relay_domain), freeSubdomain: bool(r.free_subdomain), roleAccount: bool(r.role_account),
      didYouMean: str(r.did_you_mean),
      spf: str(r.spf), dmarc: str(r.dmarc),
      providers: [{ name: 'UserCheck.com', ok: true, ms: Date.now() - t0 }],
    };
    return { value: out, ttl: 6 * 3600 };
  });
  return ok(value, { cached: hit });
});
