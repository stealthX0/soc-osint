import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeVerdict } from '../shared/phishing/verdict';
import { parseSubmission } from '../shared/phishing/parse';
import { dedupeFindings } from '../shared/phishing/findings';
import { toCalibrationRecord, replayInput, parseCalibrationFile, digest } from '../shared/phishing/calibrationRecord';
import { CORPUS } from './fixtures/phishing-corpus';

test('a labelled record replays to the same verdict for every corpus sample', async () => {
  for (const s of CORPUS) {
    const parse = await parseSubmission(s.input);
    const findings = dedupeFindings([...parse.findings, ...(s.findings ?? [])]);
    const checks = [...parse.checks, ...(s.checks ?? [])];
    const v = computeVerdict({ parse, findings, checks });
    const rec = toCalibrationRecord({ analyst: 'phishing', verdict: v, parse, findings, checks });
    const again = computeVerdict(replayInput(JSON.parse(JSON.stringify(rec))));
    assert.equal(again.label, v.label, s.id);
    assert.equal(again.risk, v.risk, s.id);
    assert.equal(again.highRisk?.id ?? null, v.highRisk?.id ?? null, s.id);
  }
});

test('a record carries no message content, addresses or URLs', async () => {
  const s = CORPUS.find((x) => x.id.startsWith('S28'))!;
  const parse = await parseSubmission(s.input);
  const findings = dedupeFindings([...parse.findings, ...(s.findings ?? [])]);
  const v = computeVerdict({ parse, findings, checks: [...parse.checks, ...(s.checks ?? [])] });
  const json = JSON.stringify(toCalibrationRecord({ analyst: 'bec', verdict: v, parse, findings, checks: [...parse.checks, ...(s.checks ?? [])] }));
  for (const leak of ['vendor-ops.example', 'alumni-mail', 'ACH', 'lnvoice', 'Brendan', '@', 'http']) assert.ok(!json.includes(leak), `leaks ${leak}`);
  assert.equal(digest('https://x.example/'), digest('https://x.example/'));
  assert.notEqual(digest('https://x.example/'), digest('https://y.example/'));
});

test('imported files are validated', () => {
  assert.equal(parseCalibrationFile({ records: [{ analyst: 'bec', findings: [], checks: [], message: {} }, { nope: 1 }] }).length, 1);
  assert.equal(parseCalibrationFile('junk').length, 0);
});
