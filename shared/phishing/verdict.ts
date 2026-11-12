/**
 * Step 6: the phishing verdict engine.
 *
 * Pure function from everything the earlier stages found to one of five outcomes, with the reasons, the evidence gaps and a
 * full audit trail of how each finding was counted. No network, no model, no randomness: the same findings always give the
 * same verdict, which makes it testable and auditable.
 *
 * How it decides
 *  1. Each finding gets base points from its id (verdictRules.ts) scaled by context multipliers: is it about the actual
 *     sender / URL / file (exactness), how reliable is the source, how far can it be trusted, how fresh is it, and is it
 *     only about shared mail infrastructure.
 *  2. Findings that describe the same underlying fact are grouped so they cannot add up as if they were independent.
 *  3. Points are summed per dimension (authentication, infrastructure, URLs, attachments, content), turned into a 0-100
 *     score and combined into a risk score, each area counting by its weight. Areas are combined so that one with nothing
 *     found never dilutes the others: more evidence can only raise risk. Passing authentication never lowers risk.
 *  4. VERDICT RULES decide the outcome, not the score: a confirmed-malicious exact URL or file is Malicious whatever else
 *     is missing; an authentication failure alone, or a bad IP alone, can never be more than Suspicious; and a clean
 *     result needs real coverage. The score only drives the grey zone.
 *  5. Coverage and confidence are reported separately: a lookup that failed or never ran lowers confidence and can force
 *     Inconclusive. It is never counted as a clean result.
 *
 * "Likely legitimate" is deliberately not "safe": no automated system can promise that.
 */
import type { ParseStageResult } from './parse';
import type { CheckResult, Dimension, Finding, IndicatorType, Severity } from './types';
import {
  DIMENSION_WEIGHTS, EXACTNESS_FACTOR, GROUP_CAP, GROUP_REST_FACTOR, RELIABILITY_FACTOR, SHARED_INFRA_AFFECTED, SHARED_INFRA_FACTOR, THRESHOLDS, TRUST_FACTOR,
  freshnessFactor, groupOf, pointsFor, type Thresholds,
} from './verdictRules';

export type VerdictLabel = 'malicious' | 'suspicious' | 'likely_legitimate' | 'inconclusive' | 'analysis_unavailable';

export const VERDICT_TEXT: Record<VerdictLabel, { label: string; short: string }> = {
  malicious: { label: 'MALICIOUS', short: 'Strong direct evidence of phishing or malware.' },
  suspicious: { label: 'SUSPICIOUS', short: 'Meaningful warning signs, but not enough proof to call it malicious.' },
  likely_legitimate: { label: 'LIKELY LEGITIMATE', short: 'No meaningful threat indicators found, with sufficient coverage. This is not a safety guarantee.' },
  inconclusive: { label: 'INCONCLUSIVE', short: 'Not enough evidence, conflicting evidence, or important checks did not complete.' },
  analysis_unavailable: { label: 'ANALYSIS UNAVAILABLE', short: 'The investigation could not be completed.' },
};

/** Label text for exports and badges, including the high-risk Suspicious variant. */
export const HIGH_RISK_LABEL = 'SUSPICIOUS (HIGH RISK)';
export const labelTextOf = (v: Pick<Verdict, 'label' | 'highRisk'>) => (v.label === 'suspicious' && v.highRisk ? HIGH_RISK_LABEL : VERDICT_TEXT[v.label].label);

/** A check row as shown in the status table; "running" means a lookup has not finished yet. */
export type CheckRow = { id: string; label: string; status: CheckResult['status'] | 'running'; result?: string | null; detail?: string };

export interface VerdictInput {
  parse: ParseStageResult | null;
  /** Findings from every stage, de-duplicated. */
  findings: Finding[];
  /** Check rows from every stage. */
  checks: CheckRow[];
  /** Override for tests. */
  now?: number;
  /** Calibration only: try other thresholds or per-finding points without editing the rule tables. */
  tuning?: { thresholds?: Partial<Thresholds>; points?: Record<string, number> };
}

export interface Contribution {
  findingId: string;
  title: string;
  dimension: Dimension;
  severity: Severity;
  group: string | null;
  base: number;
  mapped: boolean;
  multipliers: { exactness: number; reliability: number; trust: number; freshness: number; context: number };
  value: number;
  /** What actually counted after grouping. */
  counted: number;
  source: string;
}

export interface DimensionScore { dimension: Dimension; weight: number; effectiveWeight: number; active: boolean; points: number; score: number; coverage: number; findings: number }
export interface Gap { critical: boolean; text: string }
export interface Reason { title: string; detail: string; severity: Severity; dimension: Dimension; points: number; findingIds: string[] }
export interface RuleHit { id: string; text: string; findingIds: string[] }
export interface Indicator { type: IndicatorType | string; value: string; reason: string; severity: Severity }

export interface Verdict {
  label: VerdictLabel;
  headline: string;
  /** 0-100 headline risk. A guide for the grey zone and for ranking, not a probability. */
  risk: number;
  confidence: { level: 'low' | 'medium' | 'high'; score: number; notes: string[] };
  /** The rule that decided the outcome. */
  rule: RuleHit | null;
  /**
   * Set when a Suspicious verdict matches a high-risk pattern (business email compromise with a corroborating sender signal,
   * or strong evidence from several independent areas). The label stays Suspicious: nothing is confirmed by threat
   * intelligence, but the message should be handled as a likely attack.
   */
  highRisk: { id: 'bec_pattern' | 'convergent_evidence'; title: string; detail: string } | null;
  reasons: Reason[];
  mitigating: string[];
  conflicts: string[];
  gaps: Gap[];
  coverage: number;
  /** True while lookups are still running: the verdict may change. */
  provisional: boolean;
  dimensions: DimensionScore[];
  contributions: Contribution[];
  unmapped: string[];
  indicators: Indicator[];
  actions: string[];
  notes: string[];
}

const SEV: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const atLeast = (s: Severity, min: Severity) => SEV[s] >= SEV[min];
const norm = (id: string) => id.replace(/^url_final_/, 'url_');
const clamp = (n: number, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, n));

/* ------------------------------------------------------------------ coverage */

const DIMS: Dimension[] = ['authentication', 'infrastructure', 'url', 'attachment', 'content'];

interface Coverage { byDimension: Record<Dimension, { active: boolean; coverage: number }>; gaps: Gap[]; pending: boolean }

function assessCoverage(parse: ParseStageResult, checks: CheckRow[]): Coverage {
  const gaps: Gap[] = [];
  const byId = new Map<string, CheckRow>();
  for (const c of checks) byId.set(c.id, c);
  const pending = checks.some((c) => c.status === 'running');
  const done = (id: string) => byId.get(id)?.status === 'complete';
  const cov: Coverage['byDimension'] = { authentication: { active: true, coverage: 0 }, infrastructure: { active: true, coverage: 0 }, url: { active: false, coverage: 0 }, attachment: { active: false, coverage: 0 }, content: { active: true, coverage: 0 } };

  /* authentication: the headers and what the receiving server reported */
  const hasHeaders = byId.get('headers.parse')?.status === 'complete';
  if (!hasHeaders) gaps.push({ critical: true, text: 'No usable headers were supplied, so the sending infrastructure and the SPF / DKIM / DMARC results could not be assessed. Paste the complete raw headers.' });
  const authIds = ['headers.parse', 'headers.trust', 'auth.spf', 'auth.dkim', 'auth.dmarc'];
  cov.authentication.coverage = hasHeaders ? authIds.filter(done).length / authIds.length : 0;
  if (hasHeaders) for (const id of ['auth.spf', 'auth.dkim', 'auth.dmarc']) if (!done(id)) gaps.push({ critical: false, text: `${byId.get(id)?.label ?? id}: no result in the supplied headers.` });

  /* infrastructure: sender lookups (IP, domain, DNS, SPF re-check, address reputation) */
  const sender = checks.filter((c) => c.id.startsWith('sender.') && c.id !== 'sender.identity' && c.status !== 'not_applicable' && !((c.id.startsWith('sender.usercheck') || c.id.startsWith('sender.ipqs')) && c.status === 'skipped' && /not configured/i.test(c.detail ?? '')));
  const senderDone = sender.filter((c) => c.status === 'complete').length;
  cov.infrastructure.coverage = sender.length ? senderDone / sender.length : 0;
  for (const c of sender.filter((x) => x.status === 'failed')) gaps.push({ critical: false, text: `${c.label} failed${c.detail ? `: ${c.detail}` : ''}.` });
  for (const c of sender.filter((x) => x.status === 'skipped')) gaps.push({ critical: false, text: `${c.label} was skipped${c.detail ? `: ${c.detail}` : ''}.` });
  if (!sender.length && hasHeaders) gaps.push({ critical: true, text: 'The sender and infrastructure lookups have not run.' });
  else if (senderDone === 0 && !pending) gaps.push({ critical: true, text: 'None of the sender and infrastructure lookups completed.' });

  /* truncation: what was cut off cannot be assessed, and an attacker can pad a message to push the bad part past the limits */
  if (parse.truncation?.links) gaps.push({ critical: true, text: 'The message has more links than the analysis keeps; the remaining links were not examined. Review them manually: one bad link can hide among many harmless ones.' });
  if (parse.truncation?.mime) gaps.push({ critical: true, text: 'The message structure exceeded the parsing limits, so some parts (possibly attachments) were not examined.' });
  if (parse.truncation?.text) gaps.push({ critical: false, text: 'Only the first part of a very long message was read for wording.' });

  /* URLs */
  if (parse.links.length) {
    cov.url.active = true;
    const offline = done('urls.offline');
    const feed = done('urls.openphish');
    const deep = checks.some((c) => (c.id.startsWith('urls.provider.') || c.id === 'urls.deep') && c.status === 'complete');
    cov.url.coverage = ((offline ? 1 : 0) + (feed ? 1 : 0) + (deep ? 1 : 0)) / 3;
    if (!feed && !deep) gaps.push({ critical: true, text: `${parse.links.length} link${parse.links.length === 1 ? '' : 's'} not checked for reputation. Use "Investigate links" on the Links tab: the verdict is based on local checks only.` });
    else if (!deep) gaps.push({ critical: false, text: 'No link received a full reputation lookup (only the OpenPhish feed and local checks).' });
    for (const c of checks.filter((x) => x.id.startsWith('urls.') && x.status === 'failed')) gaps.push({ critical: false, text: `${c.label} failed${c.detail ? `: ${c.detail}` : ''}.` });
  }

  /* attachments */
  const real = parse.attachments.map((a, i) => ({ a, i })).filter((x) => !x.a.inline);
  if (real.length) {
    cov.attachment.active = true;
    let sum = 0;
    for (const { a, i } of real) {
      const st = done(`attach.${i}.static`);
      const rep = checks.some((c) => c.id.startsWith(`attach.${i}.hash.`) && c.status === 'complete');
      sum += (st ? 0.5 : 0) + (rep ? 0.5 : 0);
      if (!st && !rep) gaps.push({ critical: true, text: `Attachment "${a.filename ?? `#${i + 1}`}" has not been assessed: ${a.hash ? 'no reputation lookup completed' : 'there is no file or hash to check'}.` });
      else if (!rep) gaps.push({ critical: false, text: `Attachment "${a.filename ?? `#${i + 1}`}": no hash reputation lookup completed.` });
    }
    cov.attachment.coverage = sum / real.length;
  }

  /* content */
  const content = byId.get('content.rules');
  cov.content.coverage = content?.status === 'complete' ? (parse.content.analysis.languageSupported ? 1 : 0.3) : 0;
  if (content?.status !== 'complete') gaps.push({ critical: false, text: 'The message wording was not analysed (no body text).' });
  // Unread wording is not clean wording: a message whose language could not be read (or translated) is never cleared.
  else if (!parse.content.analysis.languageSupported) gaps.push({ critical: true, text: `The message wording could not be analysed${parse.content.analysis.language?.name && parse.content.analysis.language.name !== 'unknown' ? ` (${parse.content.analysis.language.name}, not translated)` : ' in this language'}, so it cannot be cleared. Have someone who reads the language review it.` });

  return { byDimension: cov, gaps, pending };
}

/* ------------------------------------------------------------------ the engine */

const unavailable = (why: string): Verdict => ({
  label: 'analysis_unavailable', headline: why, risk: 0, confidence: { level: 'low', score: 0, notes: [] }, rule: null, highRisk: null, reasons: [], mitigating: [], conflicts: [],
  gaps: [{ critical: true, text: why }], coverage: 0, provisional: false, dimensions: [], contributions: [], unmapped: [], indicators: [],
  actions: ['Check that the headers or message body were pasted, then try again.'], notes: [],
});

export function computeVerdict(input: VerdictInput): Verdict {
  const now = input.now ?? Date.now();
  const T: Thresholds = { ...THRESHOLDS, ...input.tuning?.thresholds };
  const { parse } = input;
  if (!parse) return unavailable('The message could not be parsed, so no investigation was possible.');
  const realAttachments = parse.attachments.filter((a) => !a.inline);
  if (!parse.forensics && !parse.content.text && !parse.links.length && !realAttachments.length && !parse.indicators.emails.length && !parse.indicators.domains.length && !parse.indicators.ips.length) {
    return unavailable('There was nothing to analyse: no headers, body, links, attachments or sender details.');
  }

  const findings = input.findings;
  const sharedInfra = findings.some((f) => f.id === 'sender_infra_shared_provider');

  /* 1. contributions */
  const contributions: Contribution[] = findings.map((f) => {
    const { points, mapped } = pointsFor(f, input.tuning?.points);
    const mult = {
      exactness: EXACTNESS_FACTOR[f.exactness], reliability: RELIABILITY_FACTOR[f.reliability], trust: TRUST_FACTOR[f.trust], freshness: freshnessFactor(f.observedAt, now),
      context: sharedInfra && SHARED_INFRA_AFFECTED.has(f.id) ? SHARED_INFRA_FACTOR : 1,
    };
    const value = points * mult.exactness * mult.reliability * mult.trust * mult.freshness * mult.context;
    return { findingId: f.id, title: f.title, dimension: f.dimension, severity: f.severity, group: groupOf(f), base: points, mapped, multipliers: mult, value: Math.round(value * 10) / 10, counted: 0, source: f.source };
  });

  /* 2. independence: the strongest in a group counts in full, the rest at 25%, capped at 150% of the strongest */
  const groups = new Map<string, Contribution[]>();
  for (const c of contributions) {
    if (c.group === null) { c.counted = c.value; continue; }
    (groups.get(c.group) ?? groups.set(c.group, []).get(c.group)!).push(c);
  }
  for (const list of groups.values()) {
    list.sort((a, b) => b.value - a.value);
    const max = list[0].value;
    let total = 0;
    list.forEach((c, i) => {
      const want = i === 0 ? c.value : c.value * GROUP_REST_FACTOR;
      c.counted = Math.max(0, Math.min(want, max * GROUP_CAP - total));
      total += c.counted;
    });
  }

  /* 3. dimensions and risk */
  const cov = assessCoverage(parse, input.checks);
  const dims: DimensionScore[] = DIMS.map((d) => {
    const list = contributions.filter((c) => c.dimension === d);
    const points = list.reduce((s, c) => s + c.counted, 0);
    const active = cov.byDimension[d].active || list.some((c) => c.counted > 0);
    return { dimension: d, weight: DIMENSION_WEIGHTS[d], effectiveWeight: 0, active, points: Math.round(points * 10) / 10, score: Math.round(100 * (1 - Math.exp(-points / T.saturation))), coverage: cov.byDimension[d].coverage, findings: list.length };
  });
  // Coverage is averaged over the areas that APPLY to this message (a dimension that only has findings counts as active).
  const applicableW = dims.filter((d) => cov.byDimension[d.dimension].active).reduce((s, d) => s + d.weight, 0) || 1;
  for (const d of dims) d.effectiveWeight = d.active ? d.weight / applicableW : 0;
  const coverage = Math.round(dims.reduce((s, d) => s + d.effectiveWeight * d.coverage, 0) * 100) / 100;
  // Risk combines the areas like independent pieces of evidence (a weighted "noisy OR"): each area leaves a share of doubt
  // (1 - score) raised to its relative weight, and risk is what is left after multiplying those doubts. An area with nothing
  // found leaves a factor of 1, so a clean link or attachment can never lower risk (padding a message cannot hide it), and
  // any extra evidence can only raise it. A heavier area (links) moves risk more than a lighter one (content) of equal score.
  const maxW = Math.max(...dims.map((d) => d.weight));
  const doubt = dims.reduce((p, d) => p * Math.pow(1 - Math.min(99.9, d.score) / 100, (T.combineFloor + (1 - T.combineFloor) * (d.weight / maxW)) * T.combineScale), 1);
  const risk = Math.round(100 * (1 - doubt));

  /* 4. evidence helpers */
  const byId = (pred: (f: Finding) => boolean) => findings.filter(pred);
  const meaningful = contributions.filter((c) => c.counted >= T.meaningful);
  const maxCounted = Math.max(0, ...contributions.map((c) => c.counted));
  const conflicts = [...new Set(findings.filter((f) => ['auth_conflict', 'spf_independent_disagrees', 'dmarc_policy_not_applied'].includes(f.id)).map((f) => f.detail))];
  if (findings.some((f) => f.id === 'attachment_hash_known_good') && findings.some((f) => f.id === 'attachment_hash_malicious')) conflicts.push('A file hash is reported both as a known file and as malware.');

  /* 5. verdict rules */
  const URL_STRONG = new Set(['url_listed_phishing', 'url_listed_malware']);
  const confirmUrl = (f: Finding) => (URL_STRONG.has(norm(f.id)) && atLeast(f.severity, 'high') && f.exactness === 'exact') || (norm(f.id) === 'url_engine_detections' && f.severity === 'critical' && f.exactness === 'exact');
  const CONFIRMING = new Set(['url_engine_detections', 'url_scan_malicious', 'url_listed_phishing', 'url_listed_malware', 'url_threat_intel_rating', 'url_dns_blocked']);
  const IMPERSONATION = new Set(['sender_domain_lookalikes_claimed_org', 'sender_domain_homograph', 'sender_domain_lookalike', 'sender_domain_brand_misuse', 'display_name_brand_spoof', 'content_brand_impersonation']);

  let rule: RuleHit | null = null;
  const hit = (id: string, text: string, fs: Finding[]) => { rule = { id, text, findingIds: [...new Set(fs.map((f) => f.id))] }; };

  const mal = byId((f) => f.id === 'attachment_hash_malicious' && f.severity === 'critical');
  const urlHit = byId(confirmUrl);
  if (mal.length) hit('exact_malware_hash', `An attachment's exact hash is confirmed as malware: ${mal[0].title}.`, mal);
  else if (urlHit.length) hit('exact_url_confirmed', `A link's exact destination is confirmed as ${urlHit.some((f) => norm(f.id) === 'url_listed_phishing') ? 'phishing' : 'malicious'} by a trusted source: ${urlHit[0].title}.`, urlHit);
  else {
    // two independent sources against the same exact URL
    const perUrl = new Map<string, Finding[]>();
    for (const f of byId((f) => CONFIRMING.has(norm(f.id)) && atLeast(f.severity, 'high') && f.exactness === 'exact' && !!f.indicator)) (perUrl.get(f.indicator!.value) ?? perUrl.set(f.indicator!.value, []).get(f.indicator!.value)!).push(f);
    const multi = [...perUrl.values()].find((l) => new Set(l.map((f) => f.source)).size >= 2);
    const impersonation = byId((f) => IMPERSONATION.has(f.id) && atLeast(f.severity, 'medium'));
    const strongDestination = byId((f) => CONFIRMING.has(norm(f.id)) && atLeast(f.severity, 'high') && (f.exactness === 'exact' || f.exactness === 'related') && f.source !== 'url-heuristics');
    const credForm = byId((f) => f.id === 'attachment_html_credential_form');
    const extortion = byId((f) => f.id === 'content_extortion' && (f.evidence?.length ?? 0) >= 2);
    if (multi) hit('independent_confirmation', `${new Set(multi.map((f) => f.source)).size} independent sources flag the same exact URL: ${[...new Set(multi.map((f) => f.source))].join(', ')}.`, multi);
    else if (impersonation.length && strongDestination.length) hit('impersonation_with_bad_destination', 'The sender impersonates a trusted organisation and a link or file leads to a destination flagged by an external source.', [...impersonation, ...strongDestination]);
    else if (credForm.length && (impersonation.length || byId((f) => f.id === 'content_credential_request' || f.id === 'link_text_mismatch').length)) hit('credential_form_attachment', 'An attachment contains a sign-in form and the message uses impersonation or credential-harvesting wording: a classic credential-phishing page delivered as a file.', [...credForm, ...impersonation]);
    else if (extortion.length) hit('extortion_scam', 'The message is an extortion scam: it threatens exposure unless a cryptocurrency payment is made.', extortion);
  }

  /* 6. suspicious / legitimate / inconclusive */
  const critGaps = cov.gaps.filter((g) => g.critical);
  const onlyAuth = contributions.filter((c) => c.counted > 0).every((c) => c.dimension === 'authentication');
  const onlyIp = contributions.filter((c) => c.counted > 0).every((c) => c.group?.startsWith('ip_reputation') || c.group?.startsWith('address_reputation'));
  const strongSingle = maxCounted >= T.strongSingle;
  const suspicious = risk >= T.suspiciousRisk || strongSingle || (meaningful.length >= 2 && risk >= T.twoSignalsRisk);

  let label: VerdictLabel;
  let headline: string;
  const notes: string[] = [];
  // When a verdict rule decides MALICIOUS, floor the risk so the number does not contradict the label.
  const ruleFloor = rule ? T.maliciousFloor : 0;
  if (rule) { label = 'malicious'; headline = (rule as RuleHit).text; }
  else if (suspicious) {
    label = 'suspicious';
    headline = onlyAuth ? 'Authentication problems with no other threat evidence: suspicious, but authentication alone does not prove an email is malicious.'
      : onlyIp ? 'Only the sender\'s IP or address has a bad reputation: that alone is not enough to call the email malicious.'
      : 'Meaningful warning signs were found, but nothing confirms the email as malicious.';
  } else if (conflicts.length) { label = 'inconclusive'; headline = 'The evidence conflicts with itself, so no confident call can be made.'; }
  else if (critGaps.length || coverage < T.legitimateCoverage) { label = 'inconclusive'; headline = 'Important checks have not completed, so the investigation cannot clear this email.'; }
  else if (risk < T.legitimateRisk && meaningful.length === 0) { label = 'likely_legitimate'; headline = 'No meaningful threat indicators were found. That is not a guarantee: no automated check can promise an email is safe.'; }
  else { label = 'inconclusive'; headline = meaningful.length ? 'One warning sign was found, which is not enough to decide either way.' : 'Several minor oddities were found but nothing decisive.'; }
  if (label === 'suspicious' && onlyAuth) notes.push('Rule applied: SPF / DKIM / DMARC failure alone is never enough to declare an email malicious.');
  if (label === 'suspicious' && onlyIp) notes.push('Rule applied: a bad reputation on an associated IP or address is Suspicious at most.');

  /* 7. reasons: the strongest groups, in plain language */
  const reasonGroups = new Map<string, Contribution[]>();
  for (const c of contributions.filter((x) => x.counted > 0)) {
    const key = c.group ?? `single:${c.findingId}:${c.title}`;
    (reasonGroups.get(key) ?? reasonGroups.set(key, []).get(key)!).push(c);
  }
  const reasons: Reason[] = [...reasonGroups.values()]
    .map((list) => {
      const top = list.slice().sort((a, b) => b.value - a.value)[0];
      const f = findings.find((x) => x.id === top.findingId && x.title === top.title)!;
      return { title: top.title, detail: f.detail, severity: top.severity, dimension: top.dimension, points: Math.round(list.reduce((s, c) => s + c.counted, 0) * 10) / 10, findingIds: [...new Set(list.map((c) => c.findingId))] };
    })
    .sort((a, b) => b.points - a.points)
    .slice(0, 7);

  /* 8. supporting evidence (never subtracts risk) */
  const mitigating: string[] = [];
  const auth = parse.forensics?.authentication;
  if (auth?.dmarc?.result === 'pass' && auth.dmarc.trust === 'receiver_reported') mitigating.push('The receiving server reported DMARC pass (as supplied in the headers).');
  if (auth?.alignment.dkimAligned) mitigating.push('A DKIM signature aligns with the From domain.');
  if (auth?.alignment.spfAligned) mitigating.push('SPF passed for the From domain.');
  if (findings.some((f) => f.id === 'spf_independent_pass')) mitigating.push('Spectrix re-checked SPF and the sending IP is authorised by the envelope domain.');
  if (findings.some((f) => f.id === 'attachment_hash_known_good')) mitigating.push('An attachment matches a known file in the CIRCL database.');
  if (mitigating.length) notes.push('These show the sender is authenticated, not that the message is harmless: an authenticated sender can still send phishing.');

  /* 8b. high-risk Suspicious: patterns an analyst would act on as an attack although nothing is confirmed by threat intel */
  let highRisk: Verdict['highRisk'] = null;
  if (label === 'suspicious') {
    const has = (id: string, min: Severity = 'low') => findings.some((f) => f.id === id && atLeast(f.severity, min));
    const SENDER_CORROBORATION: [string, Severity, string][] = [
      ['sender_address_fraud_score', 'medium', 'the sender address has a high fraud score'],
      ['sender_address_recent_abuse', 'low', 'the sender address was recently used for abuse'],
      ['sender_domain_new', 'medium', 'the sender domain is less than 30 days old'],
      ['sender_domain_lookalike', 'low', 'the sender domain imitates another domain'],
      ['sender_domain_homograph', 'low', 'the sender domain uses look-alike characters'],
      ['sender_domain_lookalikes_claimed_org', 'low', 'the sender domain imitates the organisation it claims to be'],
    ];
    const corroborated = SENDER_CORROBORATION.filter(([id, min]) => has(id, min)).map(([, , why]) => why);
    const strongAreas = dims.filter((d) => d.active && d.score >= T.convergentAreaScore);
    if (has('bec_payment_reply_redirect') && corroborated.length) {
      highRisk = { id: 'bec_pattern', title: 'High risk: matches business email compromise (invoice / payment fraud)', detail: `The message asks for payment, sends replies to a different organisation, and ${corroborated.slice(0, 2).join(' and ')}.` };
    } else if (strongAreas.length >= 3 && risk >= T.convergentRisk) {
      highRisk = { id: 'convergent_evidence', title: 'High risk: strong warning signs from several independent areas', detail: `${strongAreas.map((d) => d.dimension).join(', ')} each point to an attack, although no single item is confirmed by threat intelligence.` };
    }
    if (highRisk) {
      headline = `${highRisk.title}. ${highRisk.detail} Nothing is confirmed by threat intelligence, so it stays Suspicious, but handle it as a likely attack.`;
      notes.push('High-risk Suspicious: the risk score is raised to at least ' + T.highRiskFloor + '.');
    }
  }

  /* 9. confidence: how firmly the evidence supports THIS label, not how many checks ran (that is coverage, reported apart).
        It rises with the distance from the decision threshold, with independent areas agreeing and with good sources. */
  const independentDims = new Set(contributions.filter((c) => c.counted >= 5).map((c) => c.dimension)).size;
  const countedTotal = contributions.reduce((s, c) => s + c.counted, 0);
  // share of the counted evidence that is about the exact subject, from a trusted source
  const quality = countedTotal ? contributions.filter((c) => c.multipliers.trust >= 0.9 && c.multipliers.exactness === 1 && c.multipliers.reliability >= 0.8).reduce((s, c) => s + c.counted, 0) / countedTotal : 0;
  const span = (x: number, lo: number, hi: number) => Math.max(0, Math.min(1, (x - lo) / (hi - lo)));
  const confNotes: string[] = [];
  let conf: number;
  if (label === 'malicious') {
    conf = 82 + (independentDims >= 2 ? 8 : 0) + (quality >= 0.5 ? 6 : 0) - (conflicts.length ? 8 : 0);
    confNotes.push('Decided by a verdict rule based on direct evidence about the exact URL, file or sender.');
  } else if (label === 'suspicious') {
    // margin past the Suspicious line, by risk or by the single strongest signal
    const margin = Math.max(span(risk, T.suspiciousRisk - 8, T.suspiciousRisk + 32), span(maxCounted, T.strongSingle - 5, T.strongSingle + 25));
    conf = 30 + 30 * margin + 15 * Math.min(1, independentDims / 3) + 10 * quality + 15 * coverage;
    if (margin < 0.35) confNotes.push('The evidence is only just past the Suspicious line.');
    if (independentDims <= 1) confNotes.push('The warning signs come from a single area.');
    if (highRisk) conf += 5;
  } else if (label === 'likely_legitimate') {
    const margin = span(T.legitimateRisk - risk, 0, T.legitimateRisk);
    conf = 35 + 15 * margin + 40 * coverage + (mitigating.length ? 8 : 0);
  } else {
    // Inconclusive means the evidence does not support a call either way, so it is never reported with high confidence.
    conf = Math.min(T.highConfidence - 15, 20 + 35 * coverage);
    confNotes.push('Inconclusive: the evidence does not support a confident call either way.');
  }
  if (label !== 'malicious') {
    conf -= (conflicts.length ? 15 : 0) + (critGaps.length ? 10 : 0);
    if (critGaps.length) confNotes.push(`${critGaps.length} important check${critGaps.length === 1 ? '' : 's'} did not complete.`);
    if (conflicts.length) confNotes.push('Some evidence conflicts.');
  }
  if (cov.pending) { conf -= 10; confNotes.push('Lookups are still running; the verdict may change.'); }
  if (coverage < 0.5) confNotes.push('Less than half of the expected checks completed.');
  const score = Math.round(clamp(conf, 5, 98));
  const level = score >= T.highConfidence ? 'high' : score >= T.mediumConfidence ? 'medium' : 'low';

  /* 10. indicators worth blocking or hunting for */
  const seen = new Set<string>();
  const indicators: Indicator[] = [];
  for (const f of [...findings].sort((a, b) => SEV[b.severity] - SEV[a.severity])) {
    if (!f.indicator || !atLeast(f.severity, 'medium') || f.exactness === 'contextual') continue;
    const key = `${f.indicator.type}:${f.indicator.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    indicators.push({ type: f.indicator.type, value: f.indicator.value, reason: f.title, severity: f.severity });
  }

  /* 11. what to do next */
  const actions: string[] = [];
  const hasCred = findings.some((f) => ['content_credential_request', 'attachment_html_credential_form', 'link_text_mismatch'].includes(f.id));
  if (label === 'malicious') {
    actions.push('Do not click links or open attachments in this message.');
    actions.push('Block the sender, the sending domain and the listed URLs / file hashes at the mail gateway and web proxy.');
    actions.push('Search for and remove the same message from other mailboxes.');
    actions.push(`If anyone clicked a link or opened a file${hasCred ? ' or entered credentials' : ''}: reset the password, revoke active sessions and review recent sign-ins and mailbox rules.`);
    actions.push('Keep the headers and the indicators below with the incident ticket.');
  } else if (label === 'suspicious' && highRisk?.id === 'bec_pattern') {
    actions.push('Do not pay, change bank details or reply to this message.');
    actions.push('Confirm the invoice and payment details with the supplier using contact details you already hold (not the ones in this e-mail).');
    actions.push('Alert your finance / accounts-payable team and check whether any payment to these details was already made; if so, contact your bank at once to try to recall it.');
    actions.push('Block the sender and Reply-To addresses at the mail gateway and search for the same message in other mailboxes.');
    actions.push('Report it to your security team as attempted business email compromise.');
  } else if (label === 'suspicious') {
    actions.push('Treat the message as unverified: do not click links, open attachments or act on requests in it.');
    if (highRisk) actions.push('Handle it as a likely attack: block the sender and search for the same message in other mailboxes.');
    actions.push('Confirm the request with the sender through a different channel, using a phone number or address you already know.');
    if (critGaps.length) actions.push('Complete the checks listed under "What is missing": they could confirm or clear it.');
    actions.push('If it looks like a brand or colleague impersonation, report it to your security team.');
  } else if (label === 'inconclusive') {
    for (const g of critGaps.slice(0, 4)) actions.push(g.text);
    if (!critGaps.length) actions.push('Review the findings and the missing checks, and verify the sender through a different channel.');
  } else if (label === 'likely_legitimate') {
    actions.push('No action is indicated by this analysis. Stay cautious about unexpected requests for money, credentials or urgent action, whoever appears to send them.');
  } else actions.push('Provide the message and try again.');

  return {
    // The number never contradicts the label: Malicious is at least maliciousFloor, anything else stays below it.
    label, headline, risk: rule ? clamp(Math.max(risk, ruleFloor)) : Math.min(highRisk ? Math.max(risk, T.highRiskFloor) : risk, T.nonMaliciousCap), confidence: { level, score, notes: confNotes }, rule, highRisk, reasons, mitigating, conflicts, gaps: cov.gaps.sort((a, b) => Number(b.critical) - Number(a.critical)),
    coverage, provisional: cov.pending, dimensions: dims, contributions: contributions.sort((a, b) => b.counted - a.counted), unmapped: [...new Set(contributions.filter((c) => !c.mapped).map((c) => c.findingId))],
    indicators, actions, notes,
  };
}
