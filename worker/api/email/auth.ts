import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param, requireDomain } from '../../_lib/input';
import { cached } from '../../_lib/cache';
import { resolve } from '../../_lib/doh';
import { countSpfLookups } from '../../_lib/spf';
import { isDkimRecord, isDmarcRecord, isSpfRecord, parseDkim, parseDmarc, parseSpf, summarizeAuth, type Issue } from '../../../shared/emailAuth';
import { normalizeHostname, parseEmail } from '../../../shared/domain';
import type { EmailAuth, ProviderStatus } from '../../../shared/types';

const COMMON_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'smtp', 'mandrill', 'mxvault', 'zoho', 'cm', 'everlytickey1'];

const txt = async (name: string) => (await resolve(name, 'TXT')).answers.filter((a) => a.type === 'TXT').map((a) => a.data);

/** GET /api/email/auth?domain=example.com[&selectors=a,b]  (an e-mail address is also accepted) */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const input = param(url, 'domain');
  if (!input) throw badInput('Missing "domain" parameter.');
  const domain = parseEmail(input)?.domain ?? requireDomain(url, 'domain');

  const custom = param(url, 'selectors', 200)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[a-z0-9_-]{1,63}$/.test(s))
    .slice(0, 10);
  const selectors = [...new Set([...custom, ...COMMON_SELECTORS])];

  const { value, hit } = await cached(ctx, `mail:${domain}:${selectors.join(',')}`, async () => {
    const providers: ProviderStatus[] = [];
    const t = <T,>(name: string, p: Promise<T>) => {
      const t0 = Date.now();
      return p.then(
        (v) => (providers.push({ name, ok: true, ms: Date.now() - t0 }), v),
        (e) => (providers.push({ name, ok: false, ms: Date.now() - t0, error: e instanceof Error ? e.message : 'failed' }), null),
      );
    };

    // organisational-domain fallback for DMARC (_dmarc.sub.example.com -> _dmarc.example.com)
    const labels = domain.split('.');
    const dmarcCandidates: string[] = [];
    for (let i = 0; i <= labels.length - 2; i++) dmarcCandidates.push(`_dmarc.${labels.slice(i).join('.')}`);

    const [apexTxt, mxAns, mtaSts, ...rest] = await Promise.all([
      t('TXT (SPF)', txt(domain)),
      t('MX', resolve(domain, 'MX')),
      t('TXT (MTA-STS)', txt(`_mta-sts.${domain}`)),
      t('TXT (DMARC)', (async () => {
        for (const c of dmarcCandidates) {
          const rec = (await txt(c)).find(isDmarcRecord);
          if (rec) return { at: c, rec };
        }
        return null;
      })()),
      ...selectors.map((s) => t(`DKIM ${s}`, txt(`${s}._domainkey.${domain}`))),
    ]);
    const dmarcFound = rest[0] as { at: string; rec: string } | null;
    const dkimTxts = rest.slice(1) as (string[] | null)[];

    if (apexTxt === null && mxAns === null) {
      // nothing resolved at all: surface as upstream failure rather than a misleading "no records"
      return { value: null as unknown as EmailAuth, ttl: 0 };
    }

    const spfRecords = (apexTxt ?? []).filter(isSpfRecord);
    const spfParsed = spfRecords.length ? parseSpf(spfRecords[0]) : null;
    const spfIssues: Issue[] = [];
    let totalLookups: number | null = null;
    if (spfRecords.length > 1) spfIssues.push({ level: 'error', message: `${spfRecords.length} SPF records found: receivers return permerror. Merge them into one.` });
    if (spfParsed) {
      spfIssues.push(...spfParsed.issues);
      const c = await countSpfLookups(domain, spfRecords[0]);
      totalLookups = c.total;
      if (c.total > 10) spfIssues.push({ level: 'error', message: `SPF requires ${c.total} DNS lookups (limit 10): evaluation fails with permerror.` });
      else if (c.total >= 8) spfIssues.push({ level: 'warn', message: `SPF uses ${c.total} of 10 allowed DNS lookups.` });
      if (c.truncated) spfIssues.push({ level: 'info', message: 'Lookup count is a lower bound (recursion limit reached).' });
    } else spfIssues.push({ level: 'error', message: 'No SPF record: anyone can send mail claiming to be this domain without an SPF check failing.' });

    const dmarcParsed = dmarcFound ? parseDmarc(dmarcFound.rec) : null;
    const dmarcIssues: Issue[] = dmarcParsed ? [...dmarcParsed.issues] : [{ level: 'error', message: 'No DMARC record found.' }];
    if (dmarcFound && dmarcFound.at !== `_dmarc.${domain}`) dmarcIssues.push({ level: 'info', message: `Inherited from ${dmarcFound.at}.` });

    const dkim = selectors.map((selector, i) => {
      const rec = (dkimTxts[i] ?? []).find(isDkimRecord);
      return { selector, found: !!rec, parsed: rec ? parseDkim(rec) : null };
    });
    const dkimFound = dkim.filter((d) => d.found).length;

    const mx = (mxAns?.answers ?? [])
      .filter((a) => a.type === 'MX')
      .map((a) => { const [p, h] = a.data.split(/\s+/); return { priority: Number(p), host: (h ?? '').toLowerCase() }; })
      .filter((m) => m.host && m.host !== '.')
      .sort((a, b) => a.priority - b.priority);
    const hasMx = mx.length > 0;

    const mtaRec = (mtaSts ?? []).find((r) => /^v=STSv1/i.test(r)) ?? null;
    const summary = summarizeAuth({ spf: spfParsed, spfLookups: totalLookups ?? 0, dmarc: dmarcParsed, dkimFound, hasMx });
    if (!hasMx) summary.notes.push('Domain has no MX records: it cannot receive mail (spoofing protection still matters for sending).');

    const out: EmailAuth = {
      domain, hasMx, mx,
      spf: { found: !!spfParsed, records: spfRecords.length, parsed: spfParsed, totalLookups, issues: spfIssues },
      dmarc: { found: !!dmarcParsed, foundAt: dmarcFound?.at ?? null, parsed: dmarcParsed, issues: dmarcIssues },
      dkim,
      mtaSts: { found: !!mtaRec, record: mtaRec },
      summary,
      providers: providers.filter((p) => !p.ok || !p.name.startsWith('DKIM ')), // keep the strip short
    };
    return { value: out, ttl: providers.some((p) => !p.ok && !p.name.startsWith('DKIM ')) ? 0 : 300 };
  });

  if (value === null) throw new ApiError(502, 'UPSTREAM_ERROR', 'DNS resolvers did not respond.');
  return ok(value, { cached: hit });
});
