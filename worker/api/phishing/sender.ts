import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import type { Env } from '../../_lib/env';
import { readTextLimited } from '../../_lib/input';
import { callInternal } from '../../_lib/internal';
import { evaluateSpf } from '../../_lib/spfEval';
import { check } from '../../../shared/phishing/findings';
import { convertAuth, convertDomain, convertUserCheck, convertIpqs, convertIp, convertSpf, idOf, labelOf } from '../../../shared/phishing/sender';
import type { SenderCheckRequest, SenderCheckResponse, SenderCheckData } from '../../../shared/phishing/sender';
import { normalizeDomain, parseEmail } from '../../../shared/domain';
import { classifyIP, normalizeIP } from '../../../shared/ip';
import type { IpLookup, WhoisResult, EmailAuth, EmailCheck, EmailReputation } from '../../../shared/types';
import type { DomainRole, EmailRole, IpRole, TrustLevel } from '../../../shared/phishing/types';

const IP_ROLES: IpRole[] = ['connecting', 'claimed_origin', 'x_originating', 'supplied'];
const DOMAIN_ROLES: DomainRole[] = ['from', 'return_path', 'reply_to', 'sender_header', 'dkim', 'spf', 'message_id', 'claimed_org', 'supplied'];
const EMAIL_ROLES: EmailRole[] = ['from', 'return_path', 'reply_to', 'sender_header', 'supplied'];
const TRUST: TrustLevel[] = ['receiver_reported', 'unverified', 'independently_verified', 'derived'];

function validate(raw: unknown): SenderCheckRequest {
  if (!raw || typeof raw !== 'object') throw badInput('Request body must be a JSON object.');
  const r = raw as Record<string, unknown>;
  const s = (k: string) => (typeof r[k] === 'string' ? (r[k] as string).trim() : '');
  const trust = (TRUST as string[]).includes(s('trust')) ? (s('trust') as TrustLevel) : 'unverified';
  const domain = () => { const d = normalizeDomain(s('domain')); if (!d) throw badInput('A valid "domain" is required.'); return d; };
  const ip = () => { const v = normalizeIP(s('ip').replace(/^\[|\]$/g, '')); if (!v) throw badInput('A valid "ip" is required.'); return v; };
  switch (r.check) {
    case 'ip': return { check: 'ip', ip: ip(), role: (IP_ROLES as string[]).includes(s('role')) ? (s('role') as IpRole) : 'supplied', trust };
    case 'domain': return { check: 'domain', domain: domain(), roles: Array.isArray(r.roles) ? (r.roles as unknown[]).filter((x): x is DomainRole => (DOMAIN_ROLES as unknown[]).includes(x)) : [] };
    case 'auth': return { check: 'auth', domain: domain(), role: s('role') === 'return_path' ? 'return_path' : 'from', reportedDmarc: s('reportedDmarc') || null };
    case 'spf': return { check: 'spf', domain: domain(), ip: ip(), reported: s('reported') || null, trust };
    case 'usercheck':
    case 'ipqs': {
      const e = parseEmail(s('email'));
      if (!e) throw badInput('A valid "email" is required.');
      return { check: r.check, email: `${e.local}@${e.domain}`.toLowerCase(), roles: Array.isArray(r.roles) ? (r.roles as unknown[]).filter((x): x is EmailRole => (EMAIL_ROLES as unknown[]).includes(x)) : [] };
    }
    default: throw badInput('"check" must be one of: ip, domain, auth, spf, usercheck, ipqs.');
  }
}

/**
 * POST /api/phishing/sender   body: one SenderCheckRequest
 * Stage 2 of the phishing investigation. Runs ONE sender / infrastructure lookup through Spectrix's own IP, domain,
 * e-mail-auth and reputation endpoints and converts the result to findings. One lookup per request keeps each call inside
 * the Worker's per-invocation subrequest budget; the page runs several in parallel. A failed lookup is reported as failed
 * (HTTP 200, status "failed"): it must never be mistaken for a clean result.
 */
export const onRequestPost = route(async (ctx) => {
  let json: unknown;
  try { json = JSON.parse(await readTextLimited(ctx.request, 8_000)); } catch (e) {
    if (e instanceof Error && e.name === 'ApiError') throw e;
    throw badInput('Request body must be JSON.');
  }
  const req = validate(json);
  const fail = (code: string, message: string): SenderCheckResponse => ({ request: req, findings: [], data: null, checks: [check(idOf(req), 'sender', labelOf(req), 'failed', null, `${message} (${code})`)] });
  const done = (data: SenderCheckData, c: { findings: SenderCheckResponse['findings']; check: SenderCheckResponse['checks'][number] }): SenderCheckResponse => ({ request: req, findings: c.findings, checks: [c.check], data });

  switch (req.check) {
    case 'ip': {
      if (!classifyIP(req.ip)?.public) return ok({ request: req, findings: [], data: null, checks: [check(idOf(req), 'sender', labelOf(req), 'skipped', null, 'Private or reserved address: not sent to any third party.')] } satisfies SenderCheckResponse);
      const r = await callInternal<IpLookup>(ctx, '/api/ip/lookup', { params: { q: req.ip } });
      return ok(r.ok ? done({ check: 'ip', value: r.data }, convertIp(req, r.data)) : fail(r.code, r.message));
    }
    case 'domain': {
      const r = await callInternal<WhoisResult>(ctx, '/api/domain/whois', { params: { domain: req.domain } });
      return ok(r.ok ? done({ check: 'domain', value: r.data }, convertDomain(req, r.data)) : fail(r.code, r.message));
    }
    case 'auth': {
      const r = await callInternal<EmailAuth>(ctx, '/api/email/auth', { params: { domain: req.domain } });
      return ok(r.ok ? done({ check: 'auth', value: r.data }, convertAuth(req, r.data)) : fail(r.code, r.message));
    }
    case 'spf': {
      try {
        const ev = await evaluateSpf(req.domain, req.ip);
        return ok(done({ check: 'spf', value: ev }, convertSpf(req, ev)));
      } catch (e) {
        return ok(fail('UPSTREAM_ERROR', e instanceof Error ? e.message : 'SPF evaluation failed.'));
      }
    }
    case 'usercheck': {
      if (!(ctx.env as Env).USERCHECK_API_KEY) return ok({ request: req, findings: [], data: null, checks: [check(idOf(req), 'sender', labelOf(req), 'skipped', null, 'UserCheck is not configured on this deployment (USERCHECK_API_KEY is not set).')] } satisfies SenderCheckResponse);
      const r = await callInternal<EmailCheck>(ctx, '/api/email/usercheck', { params: { email: req.email } });
      return ok(r.ok ? done({ check: 'usercheck', value: r.data }, convertUserCheck(req, r.data)) : fail(r.code, r.message));
    }
    case 'ipqs': {
      // IPQualityScore first. UserCheck is used ONLY when IPQS cannot answer: daily cap spent, quota / API error, upstream
      // failure, or no IPQS key. Otherwise UserCheck is never called for the address.
      const env = ctx.env as Env;
      let why: string;
      if (env.IPQS_API_KEY) {
        const r = await callInternal<EmailReputation>(ctx, '/api/email/ipqs', { params: { email: req.email } });
        if (r.ok) return ok(done({ check: 'ipqs', value: r.data }, convertIpqs(req, r.data)));
        why = r.code === 'PROVIDER_BUDGET' ? `IPQualityScore limit reached: ${r.message.replace(/^IPQualityScore( budget reached)?:?\s*/i, '')}` : `IPQualityScore failed: ${r.message} (${r.code})`;
      } else {
        why = 'IPQualityScore is not configured (IPQS_API_KEY is not set)';
      }
      if (!env.USERCHECK_API_KEY) {
        const neither = !env.IPQS_API_KEY;
        return ok({ request: req, findings: [], data: null, checks: [check(idOf(req), 'sender', labelOf(req), neither ? 'skipped' : 'failed', null, neither ? 'IPQualityScore and UserCheck are not configured on this deployment (IPQS_API_KEY and USERCHECK_API_KEY are not set).' : `${why}. No UserCheck fallback is configured (USERCHECK_API_KEY is not set).`)] } satisfies SenderCheckResponse);
      }
      const uc = await callInternal<EmailCheck>(ctx, '/api/email/usercheck', { params: { email: req.email } });
      if (!uc.ok) return ok(fail(uc.code, `${why}. The UserCheck fallback also failed: ${uc.message}`));
      const c = convertUserCheck({ check: 'usercheck', email: req.email, roles: req.roles }, uc.data);
      const fallbackCheck = { ...c.check, id: idOf(req), label: `Address check (UserCheck fallback): ${req.email}`, detail: `${why}. Results come from UserCheck instead.` };
      return ok({ request: req, findings: c.findings, checks: [fallbackCheck], data: { check: 'usercheck', value: uc.data } } satisfies SenderCheckResponse);
    }
  }
});
