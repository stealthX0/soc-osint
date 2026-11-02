/** HTTP response-header audit used by /api/domain/http. */
import type { Issue } from './emailAuth';

export interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  status: 'good' | 'weak' | 'missing';
  points: number;
  max: number;
  note: string;
}

export interface HeaderAudit {
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  checks: HeaderCheck[];
  disclosure: { header: string; value: string }[];
  issues: Issue[];
}

type Get = (name: string) => string | null;

export function auditSecurityHeaders(get: Get, isHttps: boolean): HeaderAudit {
  const checks: HeaderCheck[] = [];
  const add = (header: string, max: number, evaluate: (v: string | null) => { status: HeaderCheck['status']; points: number; note: string }) => {
    const value = get(header);
    const r = evaluate(value);
    checks.push({ header, present: value !== null, value, max, ...r });
  };

  add('strict-transport-security', 25, (v) => {
    if (!isHttps) return { status: 'missing', points: 0, note: 'Site was not reached over HTTPS.' };
    if (!v) return { status: 'missing', points: 0, note: 'HSTS forces browsers to use HTTPS.' };
    const age = Number(v.match(/max-age=(\d+)/i)?.[1] ?? 0);
    if (age < 15552000) return { status: 'weak', points: 10, note: `max-age ${age}s is short; use at least 6 months (15552000).` };
    return { status: 'good', points: 25, note: /includesubdomains/i.test(v) ? 'Long max-age with includeSubDomains.' : 'Long max-age (consider includeSubDomains).' };
  });
  add('content-security-policy', 25, (v) => {
    if (!v) return { status: 'missing', points: 0, note: 'CSP mitigates XSS and data injection.' };
    if (/unsafe-inline|unsafe-eval|\*\s*(;|$)/.test(v) && !/nonce-|strict-dynamic/.test(v)) return { status: 'weak', points: 12, note: 'Policy allows unsafe-inline/unsafe-eval or wildcards.' };
    return { status: 'good', points: 25, note: 'Policy present.' };
  });
  add('x-content-type-options', 10, (v) =>
    v?.toLowerCase().includes('nosniff') ? { status: 'good', points: 10, note: 'MIME sniffing disabled.' } : { status: 'missing', points: 0, note: 'Set to "nosniff".' });
  add('x-frame-options', 10, (v) => {
    const csp = get('content-security-policy') ?? '';
    if (/frame-ancestors/i.test(csp)) return { status: 'good', points: 10, note: 'Covered by CSP frame-ancestors.' };
    if (v && /deny|sameorigin/i.test(v)) return { status: 'good', points: 10, note: 'Clickjacking protection set.' };
    return { status: 'missing', points: 0, note: 'Use X-Frame-Options or CSP frame-ancestors.' };
  });
  add('referrer-policy', 10, (v) => (v ? { status: 'good', points: 10, note: 'Referrer policy set.' } : { status: 'missing', points: 0, note: 'Limits URL leakage in the Referer header.' }));
  add('permissions-policy', 10, (v) => (v ? { status: 'good', points: 10, note: 'Browser features restricted.' } : { status: 'missing', points: 0, note: 'Restricts camera, microphone, geolocation, etc.' }));
  add('cross-origin-opener-policy', 5, (v) => (v ? { status: 'good', points: 5, note: 'Process isolation hint set.' } : { status: 'missing', points: 0, note: 'Optional hardening against cross-window attacks.' }));
  add('cross-origin-resource-policy', 5, (v) => (v ? { status: 'good', points: 5, note: 'Resource sharing restricted.' } : { status: 'missing', points: 0, note: 'Optional hardening against cross-origin reads.' }));

  const score = checks.reduce((s, c) => s + c.points, 0);
  const disclosure = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']
    .map((h) => ({ header: h, value: get(h) }))
    .filter((x): x is { header: string; value: string } => !!x.value);

  const issues: Issue[] = [];
  if (!isHttps) issues.push({ level: 'error', message: 'HTTPS is not available (or not reachable) for this host.' });
  for (const d of disclosure.filter((x) => /\d/.test(x.value))) {
    issues.push({ level: 'info', message: `${d.header}: ${d.value} reveals software/version information.` });
  }

  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return { grade, score, checks, disclosure, issues };
}

export interface CookieInfo { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }

export function parseSetCookie(values: string[]): CookieInfo[] {
  return values.map((v) => {
    const parts = v.split(';').map((p) => p.trim());
    const [name] = parts[0].split('=');
    const attr = (a: string) => parts.slice(1).find((p) => p.toLowerCase().startsWith(a));
    return {
      name,
      secure: parts.some((p) => p.toLowerCase() === 'secure'),
      httpOnly: parts.some((p) => p.toLowerCase() === 'httponly'),
      sameSite: attr('samesite=')?.split('=')[1] ?? null,
    };
  });
}
