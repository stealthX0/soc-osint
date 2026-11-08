import { idOf, labelOf } from '../../../shared/phishing/sender';
import type { CheckResult, Stage } from '../../../shared/phishing/types';
import type { RowStatus } from './common';
import type { Slot } from './hooks';

/** One row of the check status table, including lookups that have not returned yet. */
export interface CheckRowX { id: string; label: string; stage: Stage; status: RowStatus; result?: string | null; detail?: string }

/** Sender-stage rows: finished checks as reported, unfinished ones as "running", and requests that errored as "failed". */
export function senderRows(slots: Slot[]): CheckRowX[] {
  return slots.flatMap<CheckRowX>((s) => {
    if (s.res) return s.res.checks;
    if (s.state === 'running') return [{ id: idOf(s.req), label: labelOf(s.req), stage: 'sender', status: 'running' }];
    return [{ id: idOf(s.req), label: labelOf(s.req), stage: 'sender', status: 'failed', result: null, detail: s.error }];
  });
}

export function allCheckRows(parts: { parse: CheckResult[]; skipped: CheckResult[]; slots: Slot[]; links: CheckResult[]; attachments: CheckResult[] }): CheckRowX[] {
  return [...parts.parse, ...parts.skipped, ...senderRows(parts.slots), ...parts.links, ...parts.attachments];
}

export type ChipStatus = 'complete' | 'running' | 'not run' | 'failed';
export interface PipelineChip { id: string; label: string; status: ChipStatus; failed: number; skipped: number; total: number }

const STAGES: { id: string; label: string; stages: Stage[] }[] = [
  { id: 'parse', label: 'Parse', stages: ['parse'] },
  { id: 'headers', label: 'Headers and authentication', stages: ['headers', 'authentication'] },
  { id: 'sender', label: 'Sender intelligence', stages: ['sender'] },
  { id: 'urls', label: 'Links', stages: ['urls'] },
  { id: 'attachments', label: 'Attachments', stages: ['attachments'] },
  { id: 'content', label: 'Wording', stages: ['content'] },
];

/**
 * One chip per pipeline stage. A stage with no (applicable) checks is "not run" (for example, links nobody has investigated yet);
 * any failed check makes the stage "failed" rather than hiding it inside a "complete".
 */
export function buildPipeline(rows: CheckRowX[], verdict: { provisional: boolean; unavailable: boolean }): PipelineChip[] {
  const chips: PipelineChip[] = STAGES.map((s) => {
    const mine = rows.filter((r) => s.stages.includes(r.stage) && r.status !== 'not_applicable');
    const failed = mine.filter((r) => r.status === 'failed').length;
    const skipped = mine.filter((r) => r.status === 'skipped').length;
    const status: ChipStatus = !mine.length ? 'not run' : mine.some((r) => r.status === 'running') ? 'running' : failed > 0 ? 'failed' : 'complete';
    return { id: s.id, label: s.label, status, failed, skipped, total: mine.length };
  });
  chips.push({ id: 'verdict', label: 'Verdict', status: verdict.unavailable ? 'failed' : verdict.provisional ? 'running' : 'complete', failed: verdict.unavailable ? 1 : 0, skipped: 0, total: 1 });
  return chips;
}
