import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeVerdict } from '../shared/phishing/verdict';
import { parseSubmission } from '../shared/phishing/parse';
import { dedupeFindings } from '../shared/phishing/findings';
import { CORPUS } from './fixtures/phishing-corpus';

/** The calibration corpus is a regression suite for the verdict rules: see docs/phishing-calibration.md. */
describe('verdict calibration corpus', () => {
  for (const s of CORPUS) {
    it(`${s.id}: ${s.description}`, async () => {
      const r = await parseSubmission(s.input);
      const findings = dedupeFindings([...r.findings, ...(s.findings ?? [])]);
      const v = computeVerdict({ parse: r, findings, checks: [...r.checks, ...(s.checks ?? [])], now: Date.parse('2026-11-07') });
      assert.ok(s.expect.includes(v.label), `expected ${s.expect.join(' or ')} but got ${v.label} (risk ${v.risk}, coverage ${v.coverage}); reasons: ${v.reasons.map((x) => x.title).join('; ')}; gaps: ${v.gaps.map((g) => g.text.slice(0, 50)).join('; ')}`);
    });
  }
  it('has samples of every outcome so the corpus cannot drift into one-sidedness', () => {
    const labels = new Set(CORPUS.flatMap((s) => s.expect));
    for (const l of ['likely_legitimate', 'suspicious', 'malicious', 'inconclusive']) assert.ok(labels.has(l as never), l);
    assert.ok(CORPUS.length >= 25);
    assert.equal(new Set(CORPUS.map((s) => s.id)).size, CORPUS.length);
  });
});
