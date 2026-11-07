/**
 * Sender identity analysis (no network): is the sender dressed up as someone it is not?
 * Reuses the brand table and look-alike detection of the URL heuristics so a domain is judged the same way everywhere.
 */
import { BRANDS, analyzeUrlHeuristics, deLeet, isOfficial, levenshtein, parseTargetUrl } from '../url';
import { isFreeMail, registrableOf, sameOrg } from './domains';
import { makeFinding } from './findings';
import type { Finding, Severity } from './types';

export interface IdentityInput {
  fromDomain: string | null;
  display: string | null;
  /** The organisation the analyst says the message claims to be from (domain / website). */
  claimedDomain: string | null;
}

const ROLE = /\b(ceo|cfo|coo|cto|chief|director|president|vice president|managing partner|human resources|hr (?:team|department|dept)|payroll|accounts (?:payable|receivable)|finance (?:team|department)|it (?:support|help ?desk|service ?desk|admin(?:istrator)?)|help ?desk|service ?desk|security team|system administrator|mail ?(?:admin|administrator|team))\b/i;

const sevMap = (s: string): Severity => (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' ? (s as Severity) : 'info');

export function analyzeIdentity(i: IdentityInput): Finding[] {
  const out: Finding[] = [];
  type Init = Omit<Parameters<typeof makeFinding>[0], 'dimension'>;
  const F = (f: Init) => out.push(makeFinding({ source: 'identity-analysis', exactness: 'exact', trust: 'derived', reliability: 'medium', ...f, dimension: 'content' }));
  const domain = i.fromDomain;
  if (!domain) return out;
  const reg = registrableOf(domain);
  const free = isFreeMail(domain);
  const ind = { type: 'domain' as const, value: domain };

  /* 1. the sender domain itself: brand misuse, look-alikes, homographs, credential words */
  if (!free) {
    const p = parseTargetUrl(`https://${domain}/`);
    if (p.ok) {
      for (const s of analyzeUrlHeuristics(p.value)) {
        if (s.id.startsWith('brand-') || s.id.startsWith('squat-') || s.id.startsWith('typo-')) {
          const look = s.id.startsWith('squat-') || s.id.startsWith('typo-');
          F({ id: look ? 'sender_domain_lookalike' : 'sender_domain_brand_misuse', severity: sevMap(s.severity), title: `Sender domain: ${s.title}`, detail: s.detail ?? s.title, indicator: ind });
        } else if (s.id === 'homograph-mixed' || s.id === 'homograph-skeleton') {
          F({ id: 'sender_domain_homograph', severity: 'high', title: `Sender domain: ${s.title}`, detail: s.detail ?? s.title, indicator: ind, reliability: 'high' });
        } else if (s.id === 'cred-host') {
          F({ id: 'sender_domain_credential_words', severity: 'medium', title: 'Sender domain is packed with account / security words', detail: s.detail ?? s.title, indicator: ind });
        } else if (s.id === 'tld') {
          F({ id: 'sender_domain_risky_tld', severity: 'low', title: s.title, detail: s.detail ?? s.title, indicator: ind });
        }
      }
    }
  }

  /* 2. display name pretends to be a known brand */
  const words = new Set((i.display ?? '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  const compact = (i.display ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (i.display && reg) {
    const brand = Object.keys(BRANDS).find((b) => (words.has(b) || (b.length >= 6 && compact.includes(b))) && !isOfficial(b, domain, reg));
    if (brand) {
      F({
        id: 'display_name_brand_spoof', severity: free ? 'high' : 'medium',
        title: `Display name uses the "${brand}" brand but the sender is not ${brand}`,
        detail: `The visible sender name suggests ${brand}, yet the address is at ${domain}, which is not one of that brand's domains.${free ? ' It is a consumer mailbox provider, which a real company would not use.' : ''}`,
        evidence: [`Display name: ${i.display}`, `Sender domain: ${domain}`], indicator: ind, reliability: 'high',
      });
    }
    if (free && ROLE.test(i.display)) {
      F({ id: 'role_impersonation_freemail', severity: 'medium', title: 'Display name suggests an executive or internal team, sent from a consumer mailbox', detail: 'Business-email-compromise messages often use a manager, finance or IT title in the display name with a free mailbox. Verify through another channel before acting.', evidence: [`Display name: ${i.display}`, `Sender domain: ${domain}`], indicator: ind });
    }
  }

  /* 3. the sender domain resembles the organisation the message claims to be */
  if (i.claimedDomain && reg && !sameOrg(i.claimedDomain, domain)) {
    const cReg = registrableOf(i.claimedDomain);
    const cl = cReg?.split('.')[0] ?? '';
    const fl = reg.split('.')[0];
    const flc = fl.replace(/-/g, '');
    const near = cl.length >= 4 && (flc.includes(cl) || deLeet(flc) === cl || levenshtein(flc, cl) <= (cl.length >= 10 ? 2 : 1));
    if (near) {
      F({ id: 'sender_domain_lookalikes_claimed_org', severity: 'high', title: 'Sender domain imitates the organisation it claims to be', detail: `${domain} is built from, or one edit away from, "${cl}" (${cReg}), the organisation this message claims to come from, but it is a different domain.`, evidence: [`Claimed: ${i.claimedDomain}`, `Sender domain: ${domain}`], indicator: ind, reliability: 'high' });
    }
  }
  return out;
}
