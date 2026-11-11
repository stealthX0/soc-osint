import { ok, route } from '../../_lib/respond';
import { ApiError, badInput } from '../../_lib/errors';
import { param } from '../../_lib/input';
import { fetchJson } from '../../_lib/safeFetch';
import { takeProviderBudget } from '../../_lib/ratelimit';
import type { Env } from '../../_lib/env';
import type { FileAnalysisReport } from '../../../shared/types';

interface VtAnalysis {
  data?: { attributes?: {
    status?: string;
    stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number; timeout?: number };
    results?: Record<string, { category?: string; result?: string | null; engine_name?: string }>;
  } };
  meta?: { file_info?: { sha256?: string } };
}

/**
 * GET /api/file/analysis?id=<analysis id from /api/file/upload>
 * Polls a VirusTotal scan. Each poll costs one request from the shared VirusTotal quota, so the UI backs off.
 */
export const onRequestGet = route(async (ctx) => {
  const url = new URL(ctx.request.url);
  const env = ctx.env as Env;
  const id = param(url, 'id', 300);
  if (!/^[A-Za-z0-9=_-]{16,300}$/.test(id)) throw badInput('Missing or malformed analysis id.');
  if (!env.VIRUSTOTAL_API_KEY) throw new ApiError(503, 'NOT_CONFIGURED', 'File scanning is not enabled on this site (no VirusTotal key configured).');

  const budget = await takeProviderBudget(env, 'virustotal');
  if (!budget.ok) throw new ApiError(429, 'PROVIDER_BUDGET', `VirusTotal quota reached: ${budget.why}.`, { 'retry-after': String(budget.retryAfter ?? 60) });

  const r = await fetchJson<VtAnalysis>(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, { headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY } });
  const a = r.data?.attributes;
  const status = a?.status === 'completed' ? 'completed' : a?.status === 'in-progress' ? 'in-progress' : 'queued';
  const s = a?.stats;
  const stats = s
    ? {
        malicious: s.malicious ?? 0, suspicious: s.suspicious ?? 0, harmless: s.harmless ?? 0, undetected: s.undetected ?? 0, timeout: s.timeout ?? 0,
        total: (s.malicious ?? 0) + (s.suspicious ?? 0) + (s.harmless ?? 0) + (s.undetected ?? 0),
      }
    : null;
  const detections = Object.values(a?.results ?? {})
    .filter((x) => x.category === 'malicious' || x.category === 'suspicious')
    .slice(0, 60)
    .map((x) => ({ engine: x.engine_name ?? 'unknown', category: x.category!, result: x.result ?? null }));
  const sha256 = r.meta?.file_info?.sha256 ?? null;
  const out: FileAnalysisReport = { id, status, sha256, stats: status === 'completed' ? stats : null, detections: status === 'completed' ? detections : [], link: sha256 ? `https://www.virustotal.com/gui/file/${sha256}` : null };
  return ok(out);
});
