import type { CheckResult, Dimension, Exactness, Finding, Reliability, Severity, Stage, TrustLevel } from './types';

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

type FindingInit = Pick<Finding, 'id' | 'dimension' | 'severity' | 'title' | 'detail'> & Partial<Omit<Finding, 'id' | 'dimension' | 'severity' | 'title' | 'detail'>>;

/** Builds a Finding with conservative defaults: an observation is "related", from our own parsing, and derived. */
export function makeFinding(f: FindingInit): Finding {
  return {
    source: 'header-forensics',
    exactness: 'related' as Exactness,
    reliability: 'medium' as Reliability,
    trust: 'derived' as TrustLevel,
    ...f,
  };
}

export const sortFindings = (list: Finding[]): Finding[] => [...list].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

/** Drops exact repeats (same rule on the same indicator) so one fact never counts twice. */
export function dedupeFindings(list: Finding[]): Finding[] {
  const seen = new Set<string>();
  return list.filter((f) => {
    const key = `${f.id}|${f.source}|${f.indicator?.type ?? ''}|${f.indicator?.value ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export const check = (id: string, stage: Stage, label: string, status: CheckResult['status'], result: string | null, detail?: string): CheckResult => ({
  id,
  stage,
  label,
  status,
  result,
  ...(detail ? { detail } : {}),
});

export const dimensionLabel: Record<Dimension, string> = {
  authentication: 'Sender authenticity',
  infrastructure: 'Sender infrastructure',
  url: 'URLs and destinations',
  attachment: 'Attachments',
  content: 'Content and impersonation',
};
