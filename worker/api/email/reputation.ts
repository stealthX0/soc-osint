import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import { parseEmail } from '../../../shared/domain';
import type { Env } from '../../_lib/env';
import type { EmailReputation } from '../../../shared/types';

interface EmailRepRaw {
  email?: string;
  reputation?: string;
  suspicious?: boolean;
  references?: number;
  details?: Record<string, unknown>;
}

const bool = (v: unknown) => v === true;
const tri = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);

/**
 * GET /api/email/reputation?email=user@example.com
 * Address-level reputation from EmailRep.io: blacklist / malicious-activity history, how established the address is,
 * disposable and free-provider flags, spoofability of its domain. Works without a key at a small shared quota;
 * EMAILREP_API_KEY raises it. The address is sent to emailrep.io (only this endpoint does that).
 */
export const onRequestGet = route(async (ctx) => {
  const env = ctx.env as Env;
  const raw = param(new URL(ctx.request.url), 'email', 320);
  const parsed = raw ? parseEmail(raw) : null;
  if (!parsed) throw badInput(raw ? `"${raw.slice(0, 80)}" is not a valid e-mail address.` : 'Missing "email" parameter.');
  const email = `${parsed.local}@${parsed.domain}`.toLowerCase();

  const { value, hit } = await cached(ctx, `emailrep:${email}:${env.EMAILREP_API_KEY ? 'k' : 'n'}`, async () => {
    const b = await takeProviderBudget(env, 'emailrep');
    if (!b.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `EmailRep budget reached: ${b.why}.`);
    const t0 = Date.now();
    const r = await fetchJson<EmailRepRaw>(`https://emailrep.io/${encodeURIComponent(email)}`, { headers: env.EMAILREP_API_KEY ? { Key: env.EMAILREP_API_KEY } : {} });
    const d = r.details ?? {};
    const rep = r.reputation === 'none' || r.reputation === 'low' || r.reputation === 'medium' || r.reputation === 'high' ? r.reputation : null;
    const out: EmailReputation = {
      email,
      reputation: rep,
      suspicious: bool(r.suspicious),
      references: typeof r.references === 'number' ? r.references : 0,
      details: {
        blacklisted: bool(d.blacklisted), maliciousActivity: bool(d.malicious_activity), maliciousActivityRecent: bool(d.malicious_activity_recent),
        credentialsLeaked: bool(d.credentials_leaked), dataBreach: bool(d.data_breach), spam: bool(d.spam),
        freeProvider: bool(d.free_provider), disposable: bool(d.disposable), deliverable: tri(d.deliverable), validMx: tri(d.valid_mx),
        spoofable: tri(d.spoofable), dmarcEnforced: tri(d.dmarc_enforced), suspiciousTld: bool(d.suspicious_tld), newDomain: bool(d.new_domain),
        daysSinceDomainCreation: typeof d.days_since_domain_creation === 'number' && d.days_since_domain_creation >= 0 ? d.days_since_domain_creation : null,
        firstSeen: str(d.first_seen), lastSeen: str(d.last_seen), profiles: Array.isArray(d.profiles) ? d.profiles.filter((p): p is string => typeof p === 'string').slice(0, 20) : [],
      },
      providers: [{ name: 'EmailRep.io', ok: true, ms: Date.now() - t0 }],
    };
    return { value: out, ttl: 6 * 3600 };
  });
  return ok(value, { cached: hit });
});
