import { ok, route } from '../../_lib/respond';
import { badInput } from '../../_lib/errors';
import { readTextLimited } from '../../_lib/input';
import { callInternal } from '../../_lib/internal';
import { loadFeed, matchFeed, type OpenPhishIndex } from '../../_lib/openphish';
import { parseTargetUrl } from '../../../shared/url';
import { registrableOf } from '../../../shared/phishing/domains';
import {
  assembleUrlStage, brandMismatchOf, deepCandidatesOf, selectDeep, triageLinks, validateUrlRequest,
  type LookupSummary, type OpenPhishStatus, type UrlStageResult,
} from '../../../shared/phishing/urlTriage';
import type { UrlLookup } from '../../../shared/types';

/** Stop starting new full lookups after this long; the rest stay "pending" and are reported as such. */
const DEEP_TIME_BUDGET_MS = 25_000;

function summarise(l: UrlLookup, cached: boolean, ms: number, finalOp: LookupSummary['finalOpenphish'], finalBrand: string | null): LookupSummary {
  const hops = l.trace?.hops ?? [];
  return {
    url: l.lookupUrl,
    verdict: l.verdict,
    score: l.score,
    confidence: l.confidence,
    summary: l.summary,
    checked: l.checked,
    attempted: l.attempted,
    finalUrl: l.trace?.finalUrl && l.trace.finalUrl !== l.lookupUrl ? l.trace.finalUrl : null,
    redirects: hops.filter((h) => h.status !== null && h.status >= 300 && h.status < 400 && h.location).length,
    domainAgeDays: l.domain?.ageDays ?? null,
    providers: l.providers.map((p) => ({ name: p.name, ok: p.ok, ...(p.skipped ? { skipped: true } : {}), ...(p.error ? { error: p.error.slice(0, 200) } : {}) })),
    signals: l.signals.slice(0, 30).map((s) => ({ id: s.id, severity: s.severity, source: s.source, title: s.title, ...(s.detail ? { detail: s.detail.slice(0, 400) } : {}), ...(s.confirmed ? { confirmed: true } : {}), ...(s.link ? { link: s.link } : {}) })),
    cached,
    ms,
    finalOpenphish: finalOp,
    finalBrandMismatch: finalBrand,
  };
}

/**
 * POST /api/phishing/urls   body: { links: [{ url, text?, sources?, count?, wrapped? }], context?, deep?, maxDeep? }
 * Stage 3 of the phishing investigation. Links come from /api/phishing/parse (or are typed in).
 *
 *  - Every link is normalised, de-duplicated, ranked and checked offline and against the OpenPhish feed.
 *  - Only the best few (maxDeep, hard cap 4; or the ones named in `deep`; a link with source 'sender' is always first) get a full lookup through the existing
 *    /api/url/lookup endpoint, called in-process so its caching, SSRF guard and provider quota budgets all apply.
 *    Callers fetch the next batch with another request naming them in `deep`: each request is its own Worker invocation
 *    with its own subrequest allowance, which is why this is not one giant fan-out.
 * Active scan: full lookups request the link (headers only) from Cloudflare's network, exactly like the URL Intelligence page.
 */
export const onRequestPost = route(async (ctx) => {
  const text = await readTextLimited(ctx.request, 600_000);
  let json: unknown;
  try { json = JSON.parse(text); } catch { throw badInput('Request body must be JSON.'); }
  const v = validateUrlRequest(json);
  if (!v.ok) throw badInput(v.error);
  const { links, context, deep, maxDeep } = v.value;

  const { items, skipped, claimed, merged } = triageLinks(links, context);
  if (!items.length) throw badInput('None of the links is a valid http(s) URL.');

  // OpenPhish: one feed download serves every link (and, later, every redirect destination).
  let openphish: OpenPhishStatus;
  let index: OpenPhishIndex | null = null;
  try {
    const feed = await loadFeed(ctx);
    index = feed.index;
    openphish = { status: 'ok', feedSize: feed.index.size, fetchedAt: new Date(feed.index.fetchedAt).toISOString(), ...(feed.stale ? { stale: true } : {}) };
  } catch (e) {
    openphish = { status: 'failed', feedSize: null, fetchedAt: null, error: e instanceof Error ? e.message : 'OpenPhish feed unavailable.' };
  }
  if (index) for (const it of items) it.openphish = matchFeed(index, it.url);

  // Full lookups, one after another: they share the Worker's subrequest allowance and VirusTotal's per-minute budget.
  const picked = selectDeep(items, deep, maxDeep);
  const lookups: Record<string, LookupSummary> = {};
  const lookupErrors: Record<string, string> = {};
  const deepChecked: string[] = [];
  const started = Date.now();
  for (const url of picked) {
    if (Date.now() - started > DEEP_TIME_BUDGET_MS) break;
    const t0 = Date.now();
    const r = await callInternal<UrlLookup>(ctx, '/api/url/lookup', { params: { q: url } });
    if (!r.ok) { lookupErrors[url] = r.message; deepChecked.push(url); continue; }
    const finalUrl = r.data.trace?.finalUrl && r.data.trace.finalUrl !== r.data.lookupUrl ? r.data.trace.finalUrl : null;
    const fp = finalUrl ? parseTargetUrl(finalUrl) : null;
    const finalParsed = fp?.ok ? fp.value : null;
    lookups[url] = summarise(
      r.data, r.cached, Date.now() - t0,
      index && finalParsed ? matchFeed(index, finalParsed.lookupUrl) : null,
      finalParsed ? brandMismatchOf({ host: finalParsed.host, registrableDomain: finalParsed.registrableDomain ?? registrableOf(finalParsed.host) }, claimed) : null,
    );
    deepChecked.push(url);
  }
  for (const it of items) if (lookups[it.url] || lookupErrors[it.url]) it.tier = 'deep';

  const ranked = items.map(({ parsed: _parsed, ...rest }) => rest);
  const result: UrlStageResult = assembleUrlStage({
    ranked, lookups, lookupErrors, openphish, claimedBrands: claimed,
    deepCandidates: deepCandidatesOf(items), deepChecked, skipped, merged, truncated: false, maxDeep,
  });
  return ok(result);
});
