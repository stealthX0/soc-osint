/** Parsers and linters for SPF, DKIM and DMARC DNS records (pure functions). */

export type Level = 'error' | 'warn' | 'info';
export interface Issue { level: Level; message: string }

/* ---------------------------------------------------------------------- SPF */

export interface SpfMechanism { qualifier: '+' | '-' | '~' | '?'; type: string; value?: string }
export interface SpfAnalysis {
  raw: string;
  mechanisms: SpfMechanism[];
  all: '+' | '-' | '~' | '?' | null;
  /** terms that cost a DNS lookup: include, a, mx, ptr, exists, redirect */
  directLookups: number;
  includes: string[];
  redirect: string | null;
  issues: Issue[];
}

const LOOKUP_TYPES = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);

export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseSpf(txt: string): SpfAnalysis {
  const raw = txt.trim();
  const issues: Issue[] = [];
  const mechanisms: SpfMechanism[] = [];
  let all: SpfAnalysis['all'] = null;
  let redirect: string | null = null;
  const includes: string[] = [];
  let directLookups = 0;

  for (const term of raw.split(/\s+/).slice(1)) {
    const m = term.match(/^([+\-~?])?([a-z0-9]+)(?:[:=](.*))?$/i);
    if (!m) { issues.push({ level: 'warn', message: `Unrecognised term "${term}"` }); continue; }
    const type = m[2].toLowerCase();
    const value = m[3];
    if (type === 'redirect') { redirect = value ?? null; directLookups++; continue; }
    if (type === 'exp') continue;
    const qualifier = (m[1] as SpfMechanism['qualifier']) ?? '+';
    if (type === 'all') { all = qualifier; continue; }
    mechanisms.push({ qualifier, type, value });
    if (LOOKUP_TYPES.has(type)) directLookups++;
    if (type === 'include' && value) includes.push(value.toLowerCase());
    if (type === 'ptr') issues.push({ level: 'warn', message: 'The "ptr" mechanism is deprecated (RFC 7208) and slow; remove it.' });
  }

  if (all === '+') issues.push({ level: 'error', message: '"+all" authorises every sender on the internet.' });
  else if (all === '?') issues.push({ level: 'warn', message: '"?all" is neutral and gives no protection.' });
  else if (all === '~') issues.push({ level: 'info', message: '"~all" (softfail) is common; "-all" is stricter once all senders are listed.' });
  else if (all === null && !redirect) issues.push({ level: 'warn', message: 'No "all" mechanism or redirect: unlisted senders get a neutral result.' });
  if (all !== null && redirect) issues.push({ level: 'info', message: 'redirect= is ignored when an "all" mechanism is present.' });
  if (raw.length > 255) issues.push({ level: 'info', message: 'Record exceeds 255 characters and must be split into multiple TXT strings.' });

  return { raw, mechanisms, all, directLookups, includes, redirect, issues };
}

/* -------------------------------------------------------------------- DMARC */

export interface DmarcAnalysis {
  raw: string;
  tags: Record<string, string>;
  policy: 'none' | 'quarantine' | 'reject' | string;
  subdomainPolicy: string | null;
  pct: number;
  rua: string[];
  ruf: string[];
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  issues: Issue[];
}

export const isDmarcRecord = (txt: string) => /^v=DMARC1\s*;?/i.test(txt.trim());

export function parseDmarc(txt: string): DmarcAnalysis {
  const raw = txt.trim();
  const tags: Record<string, string> = {};
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  const list = (v?: string) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : []);
  const pct = tags.pct !== undefined ? Math.max(0, Math.min(100, parseInt(tags.pct, 10) || 0)) : 100;
  const policy = (tags.p ?? '').toLowerCase();
  const issues: Issue[] = [];

  if (!policy) issues.push({ level: 'error', message: 'Missing required "p=" policy tag.' });
  else if (policy === 'none') issues.push({ level: 'warn', message: 'p=none is monitor-only: spoofed mail is still delivered.' });
  else if (!['quarantine', 'reject'].includes(policy)) issues.push({ level: 'error', message: `Invalid policy "${policy}".` });
  if (pct < 100 && policy !== 'none') issues.push({ level: 'warn', message: `Policy only applies to ${pct}% of failing mail (pct=${pct}).` });
  if (!tags.rua) issues.push({ level: 'info', message: 'No aggregate report address (rua=); you will not receive DMARC reports.' });
  if (tags.sp && ['none'].includes(tags.sp.toLowerCase()) && policy !== 'none') {
    issues.push({ level: 'warn', message: 'Subdomain policy sp=none leaves subdomains unprotected.' });
  }

  return {
    raw,
    tags,
    policy,
    subdomainPolicy: tags.sp ? tags.sp.toLowerCase() : null,
    pct,
    rua: list(tags.rua),
    ruf: list(tags.ruf),
    adkim: tags.adkim?.toLowerCase() === 's' ? 's' : 'r',
    aspf: tags.aspf?.toLowerCase() === 's' ? 's' : 'r',
    issues,
  };
}

/* --------------------------------------------------------------------- DKIM */

export interface DkimAnalysis {
  raw: string;
  version: string | null;
  keyType: string;
  revoked: boolean;
  testing: boolean;
  /** approximate RSA modulus size inferred from the encoded key length */
  approxKeyBits: number | null;
  issues: Issue[];
}

export const isDkimRecord = (txt: string) => /(^|;)\s*p=/i.test(txt) && !isSpfRecord(txt);

export function parseDkim(txt: string): DkimAnalysis {
  const tags: Record<string, string> = {};
  for (const part of txt.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, '').trim();
  }
  const keyType = (tags.k ?? 'rsa').toLowerCase();
  const p = tags.p ?? '';
  const revoked = p === '';
  const testing = (tags.t ?? '').split(':').includes('y');
  const issues: Issue[] = [];
  let approxKeyBits: number | null = null;

  if (revoked) issues.push({ level: 'error', message: 'Empty p= tag: this key has been revoked.' });
  else if (keyType === 'rsa') {
    try {
      const bytes = atob(p).length;
      // SubjectPublicKeyInfo overhead is ~38 bytes for RSA
      const est = Math.max(0, bytes - 38) * 8;
      approxKeyBits = [512, 768, 1024, 1536, 2048, 3072, 4096, 8192].find((b) => est <= b + 64) ?? 8192;
      if (approxKeyBits < 1024) issues.push({ level: 'error', message: `RSA key is about ${approxKeyBits} bits and can be factored; use at least 2048.` });
      else if (approxKeyBits < 2048) issues.push({ level: 'warn', message: 'RSA key is about 1024 bits; 2048 is recommended.' });
    } catch {
      issues.push({ level: 'warn', message: 'p= is not valid base64.' });
    }
  }
  if (testing) issues.push({ level: 'info', message: 'Domain is in testing mode (t=y); receivers may ignore failures.' });
  if (tags.v && tags.v.toUpperCase() !== 'DKIM1') issues.push({ level: 'warn', message: `Unexpected version "${tags.v}".` });

  return { raw: txt.trim(), version: tags.v ?? null, keyType, revoked, testing, approxKeyBits, issues };
}

/* ------------------------------------------------------------------ grading */

export interface AuthSummary {
  /** 0-100 */
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  spoofable: boolean;
  notes: string[];
}

export function summarizeAuth(input: {
  spf: SpfAnalysis | null;
  spfLookups?: number;
  dmarc: DmarcAnalysis | null;
  dkimFound: number;
  hasMx: boolean;
}): AuthSummary {
  const { spf, dmarc } = input;
  let score = 0;
  const notes: string[] = [];

  if (spf) {
    score += spf.all === '-' ? 30 : spf.all === '~' ? 24 : spf.all === '?' || spf.all === null ? 8 : 0;
    if (spf.all === '+') notes.push('SPF allows any sender.');
  } else notes.push('No SPF record.');
  if ((input.spfLookups ?? 0) > 10) { score -= 10; notes.push(`SPF needs ${input.spfLookups} DNS lookups (limit 10): receivers return permerror.`); }

  if (dmarc) {
    score += dmarc.policy === 'reject' ? 45 : dmarc.policy === 'quarantine' ? 38 : dmarc.policy === 'none' ? 15 : 0;
    if (dmarc.rua.length) score += 5;
    if (dmarc.pct < 100 && dmarc.policy !== 'none') score -= 8;
  } else notes.push('No DMARC record.');

  if (input.dkimFound > 0) score += 20;
  else notes.push('No DKIM key found at the common selectors tried (this does not prove DKIM is absent).');

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  const enforcing = dmarc && (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') && dmarc.pct === 100;
  const spoofable = input.hasMx ? !enforcing : !enforcing && !(spf && spf.all === '-');
  return { score, grade, spoofable: !!spoofable, notes };
}
