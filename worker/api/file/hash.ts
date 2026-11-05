import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { cached } from '../../_lib/cache';
import { param } from '../../_lib/input';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import type { Env } from '../../_lib/env';
import { normalizeHash } from '../../../shared/fileHash';
import type { FileReputation, ProviderStatus } from '../../../shared/types';

/* Third-party response shapes (only the fields we read; everything is optional on purpose) */
interface VtFile {
  data?: { attributes?: {
    last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
    last_analysis_date?: number; first_submission_date?: number; times_submitted?: number;
    type_description?: string; meaningful_name?: string; names?: string[]; size?: number;
    md5?: string; sha1?: string; sha256?: string; reputation?: number; tags?: string[];
    popular_threat_classification?: {
      suggested_threat_label?: string;
      popular_threat_name?: { value?: string }[];
      popular_threat_category?: { value?: string }[];
    };
  } };
}
interface MalwareBazaar {
  query_status?: string;
  data?: {
    sha256_hash?: string; file_name?: string; file_type?: string; signature?: string | null; tags?: string[] | null; first_seen?: string;
    reporter?: string; delivery_method?: string | null; origin_country?: string | null;
    intelligence?: { clamav?: string[] | null };
  }[];
}
interface Circl {
  FileName?: string; FileSize?: number | string; 'hashlookup:trust'?: number | string; source?: string; KnownMalicious?: string;
  SHA256?: string; 'SHA-256'?: string;
}
interface HybridOverview {
  verdict?: string; threat_score?: number | null; multiscan_result?: number | null; vx_family?: string | null; type_short?: string[] | string | null; type?: string | null;
}

const iso = (unix?: number) => (unix ? new Date(unix * 1000).toISOString() : null);
const strs = (a: unknown, n = 20): string[] => (Array.isArray(a) ? a.filter((x): x is string => typeof x === 'string' && x.length > 0).slice(0, n) : []);

async function track<T>(providers: ProviderStatus[], name: string, fn: () => Promise<T>): Promise<T | null> {
  const t0 = Date.now();
  try {
    const v = await fn();
    providers.push({ name, ok: true, ms: Date.now() - t0 });
    return v;
  } catch (e) {
    providers.push({ name, ok: false, ms: Date.now() - t0, error: e instanceof Error ? e.message : 'failed' });
    return null;
  }
}

/**
 * GET /api/file/hash?hash=<md5|sha1|sha256>
 * Reputation of a file by hash only. No file content is involved: this is safe for sensitive files.
 * Sources: VirusTotal, MalwareBazaar (abuse.ch), CIRCL hashlookup (known files, no key), Hybrid Analysis (sha256 only).
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const env = ctx.env as Env;
  const raw = param(url, 'hash', 200);
  if (!raw) throw badInput('Missing "hash" parameter.');
  const h = normalizeHash(raw);
  if (!h) throw badInput('Provide an MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal hash.');
  const { hash, algo } = h;

  const keys = [env.VIRUSTOTAL_API_KEY, env.ABUSECH_AUTH_KEY, env.HYBRID_ANALYSIS_API_KEY].map((k) => (k ? 'k' : 'n')).join('');
  const { value, hit } = await cached(ctx, `file:${hash}:${keys}`, async () => {
    const providers: ProviderStatus[] = [];
    const skip = (name: string, why: string) => {
      providers.push({ name, ok: false, ms: 0, skipped: true, error: why });
      return Promise.resolve(null);
    };
    const guarded = async <T>(provider: string, name: string, fn: () => Promise<T>): Promise<T | null> => {
      const b = await takeProviderBudget(env, provider);
      if (!b.ok) {
        providers.push({ name, ok: false, ms: 0, skipped: true, error: b.why });
        return null;
      }
      return track(providers, name, fn);
    };

    const [vt, mb, circl] = await Promise.all([
      env.VIRUSTOTAL_API_KEY
        ? guarded('virustotal', 'VirusTotal (multi-engine verdicts)', async () => {
            try {
              return await fetchJson<VtFile>(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY! } });
            } catch (e) {
              if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as VtFile; // never seen: a valid answer
              throw e;
            }
          })
        : skip('VirusTotal (multi-engine verdicts)', 'No VIRUSTOTAL_API_KEY configured'),
      env.ABUSECH_AUTH_KEY
        ? track(providers, 'MalwareBazaar (abuse.ch)', async () => {
            const r = await fetchJson<MalwareBazaar>('https://mb-api.abuse.ch/api/v1/', {
              method: 'POST',
              headers: { 'Auth-Key': env.ABUSECH_AUTH_KEY!, 'content-type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ query: 'get_info', hash }).toString(),
            });
            // hash_not_found is a valid "never reported" answer; any other non-ok status is a real failure
            if (r.query_status === 'hash_not_found') return {} as MalwareBazaar;
            if (r.query_status && r.query_status !== 'ok') throw new ApiError(502, 'UPSTREAM_ERROR', `MalwareBazaar: ${r.query_status}`);
            return r;
          })
        : skip('MalwareBazaar (abuse.ch)', 'No ABUSECH_AUTH_KEY configured'),
      track(providers, 'CIRCL hashlookup (known files)', async () => {
        try {
          return await fetchJson<Circl>(`https://hashlookup.circl.lu/lookup/${algo}/${hash}`);
        } catch (e) {
          if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as Circl; // unknown to the known-file lists
          throw e;
        }
      }),
    ]);

    const a = vt?.data?.attributes;
    const sha256 = algo === 'sha256' ? hash : a?.sha256 ?? null;
    const virustotal: FileReputation['virustotal'] = vt
      ? {
          observed: !!a?.last_analysis_stats,
          malicious: a?.last_analysis_stats?.malicious ?? 0, suspicious: a?.last_analysis_stats?.suspicious ?? 0,
          harmless: a?.last_analysis_stats?.harmless ?? 0, undetected: a?.last_analysis_stats?.undetected ?? 0,
          typeDescription: a?.type_description ?? null, meaningfulName: a?.meaningful_name ?? null, names: strs(a?.names, 8), size: a?.size ?? null,
          md5: a?.md5 ?? null, sha1: a?.sha1 ?? null, sha256: a?.sha256 ?? null, reputation: a?.reputation ?? null, tags: strs(a?.tags, 15),
          threatLabel: a?.popular_threat_classification?.suggested_threat_label ?? null,
          threatNames: strs(a?.popular_threat_classification?.popular_threat_name?.map((x) => x.value), 6),
          threatCategories: strs(a?.popular_threat_classification?.popular_threat_category?.map((x) => x.value), 6),
          firstSeen: iso(a?.first_submission_date), lastAnalysis: iso(a?.last_analysis_date), timesSubmitted: a?.times_submitted ?? null,
          link: `https://www.virustotal.com/gui/file/${sha256 ?? hash}`,
        }
      : null;

    const mbRow = mb?.data?.[0];
    const malwarebazaar: FileReputation['malwarebazaar'] = mb
      ? {
          observed: !!mbRow,
          fileName: mbRow?.file_name ?? null, fileType: mbRow?.file_type ?? null, signature: mbRow?.signature ?? null, tags: strs(mbRow?.tags, 15),
          firstSeen: mbRow?.first_seen ?? null, reporter: mbRow?.reporter ?? null, deliveryMethod: mbRow?.delivery_method ?? null,
          originCountry: mbRow?.origin_country ?? null, clamav: strs(mbRow?.intelligence?.clamav, 6),
          link: `https://bazaar.abuse.ch/sample/${mbRow?.sha256_hash ?? sha256 ?? hash}/`,
        }
      : null;

    const known = !!(circl && (circl.FileName || circl.SHA256 || circl['SHA-256'] || circl.source));
    const num = (v: unknown) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
    const circlOut: FileReputation['circl'] = circl
      ? {
          known, fileName: circl.FileName ?? null, fileSize: num(circl.FileSize), trust: num(circl['hashlookup:trust']),
          sources: circl.source ? [circl.source] : [], knownMalicious: circl.KnownMalicious ?? null,
        }
      : null;

    // Hybrid Analysis overview takes a SHA-256, so it runs once we have one (VirusTotal may supply it for MD5/SHA-1 input).
    let hybrid: FileReputation['hybrid'] = null;
    if (env.HYBRID_ANALYSIS_API_KEY) {
      if (sha256) {
        const ho = await guarded('hybridanalysis', 'Hybrid Analysis (sandbox)', async () => {
          try {
            return await fetchJson<HybridOverview>(`https://www.hybrid-analysis.com/api/v2/overview/${sha256}`, {
              headers: { 'api-key': env.HYBRID_ANALYSIS_API_KEY!, 'user-agent': 'Falcon Sandbox' },
            });
          } catch (e) {
            if (e instanceof ApiError && e.code === 'NOT_FOUND') return {} as HybridOverview;
            throw e;
          }
        });
        if (ho) {
          const type = Array.isArray(ho.type_short) ? ho.type_short[0] : ho.type_short;
          hybrid = {
            observed: !!(ho.verdict || ho.threat_score !== undefined),
            verdict: ho.verdict ?? null, threatScore: ho.threat_score ?? null, avDetect: ho.multiscan_result ?? null,
            family: ho.vx_family ?? null, fileType: type ?? ho.type ?? null,
            link: `https://www.hybrid-analysis.com/sample/${sha256}`,
          };
        }
      } else {
        providers.push({ name: 'Hybrid Analysis (sandbox)', ok: false, ms: 0, skipped: true, error: 'Needs a SHA-256 (not available from this hash)' });
      }
    } else {
      providers.push({ name: 'Hybrid Analysis (sandbox)', ok: false, ms: 0, skipped: true, error: 'No HYBRID_ANALYSIS_API_KEY configured' });
    }

    const flags: string[] = [];
    if (virustotal?.observed && virustotal.malicious > 0) flags.push(`VirusTotal: ${virustotal.malicious} engine(s) flag as malicious`);
    else if (virustotal?.observed && virustotal.suspicious > 0) flags.push(`VirusTotal: ${virustotal.suspicious} engine(s) flag as suspicious`);
    if (malwarebazaar?.observed) flags.push(malwarebazaar.signature ? `Known sample in MalwareBazaar (${malwarebazaar.signature})` : 'Known sample in MalwareBazaar');
    if (hybrid?.verdict && /malicious/i.test(hybrid.verdict) && !/no specific/i.test(hybrid.verdict)) flags.push(`Hybrid Analysis: ${hybrid.verdict}`);
    if (circlOut?.known) flags.push('Known file in CIRCL hashlookup');
    if (circlOut?.knownMalicious) flags.push('CIRCL hashlookup: listed as known malicious');

    const out: FileReputation = { hash, algo, sha256, virustotal, malwarebazaar, circl: circlOut, hybrid, flags, providers };
    const healthy = providers.some((p) => p.ok);
    const anyObserved = !!(virustotal?.observed || malwarebazaar?.observed || circlOut?.known || hybrid?.observed);
    return { value: out, ttl: !healthy ? 0 : anyObserved ? 21_600 : 300 };
  });
  return ok(value, { cached: hit });
});
