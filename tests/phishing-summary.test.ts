/** The dashboard's short reasoning: accurate for every outcome, and much shorter than the full reasons. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeVerdict } from '../shared/phishing/verdict';
import { parseSubmission } from '../shared/phishing/parse';
import { dedupeFindings } from '../shared/phishing/findings';
import { summarizeReasoning } from '../shared/phishing/summary';
import { CORPUS } from './fixtures/phishing-corpus';
import { EXAMPLE_FORM, buildInput } from '../src/pages/phishing/formHelpers';

const verdictOf = async (s: { input: never; findings?: never[]; checks?: never[] }) => {
  const r = await parseSubmission(s.input);
  return computeVerdict({ parse: r, findings: dedupeFindings([...r.findings, ...(s.findings ?? [])]), checks: [...r.checks, ...(s.checks ?? [])], now: Date.parse('2026-11-07') });
};

describe('reasoning summary', () => {
  it('summarises the training example in a fraction of the full reasoning', async () => {
    const v = await verdictOf({ input: buildInput(EXAMPLE_FORM) as never });
    const x = summarizeReasoning(v);
    const full = v.reasons.map((r) => `${r.title}. ${r.detail}`).join(' ');
    const short = [x.summary, ...x.points.map((p) => p.text), x.caveat ?? ''].join(' ');
    assert.ok(short.length < full.length / 2, `${short.length} vs ${full.length}`);
    assert.match(x.summary, /^Suspicious: \d+ warning signs/);
    assert.ok(x.points.length <= 7 && x.points.length > 0);
    assert.equal(x.points[0].text, v.reasons[0].title.replace(/\.$/, ''));
    assert.match(x.caveat ?? '', /stops short of Malicious/);
  });

  it('every corpus sample gets a summary that names its outcome, with no long explanations', async () => {
    for (const s of CORPUS) {
      const v = await verdictOf(s as never);
      const x = summarizeReasoning(v);
      const word = { malicious: 'Malicious', suspicious: 'Suspicious', likely_legitimate: 'Likely legitimate', inconclusive: 'Inconclusive', analysis_unavailable: '' }[v.label];
      assert.ok(x.summary.startsWith(word), `${s.id}: ${x.summary}`);
      for (const p of x.points) assert.ok(!v.reasons.some((r) => r.detail && p.text.includes(r.detail)), `${s.id}: a point repeats a long detail`);
      if (v.label === 'malicious') assert.ok(!/In its favour/.test(x.caveat ?? ''), `${s.id}: no "in its favour" next to Malicious`);
    }
  });
});
