/**
 * Calibration report for the phishing verdict engine.
 *
 *   npm run calibrate:phishing
 *
 * Runs every sample in tests/fixtures/phishing-corpus.ts, prints what the engine decided against what an analyst would accept,
 * a confusion matrix, and how stable the result is when each threshold is nudged. Use it after adding real (anonymised)
 * samples or after changing shared/phishing/verdictRules.ts. See docs/phishing-calibration.md.
 */
import { computeVerdict, type Verdict, type VerdictLabel } from '../shared/phishing/verdict';
import { parseSubmission } from '../shared/phishing/parse';
import { dedupeFindings } from '../shared/phishing/findings';
import { THRESHOLDS, type Thresholds } from '../shared/phishing/verdictRules';
import { CORPUS } from '../tests/fixtures/phishing-corpus';

const NOW = Date.parse('2026-11-07');
const parsed = await Promise.all(CORPUS.map((s) => parseSubmission(s.input)));

function run(tuning?: Partial<Thresholds>): Verdict[] {
  return CORPUS.map((s, i) => computeVerdict({ parse: parsed[i], findings: dedupeFindings([...parsed[i].findings, ...(s.findings ?? [])]), checks: [...parsed[i].checks, ...(s.checks ?? [])], now: NOW, tuning: tuning ? { thresholds: tuning } : undefined }));
}
const accuracy = (vs: Verdict[]) => vs.filter((v, i) => CORPUS[i].expect.includes(v.label)).length;

const base = run();
const pad = (s: string | number, n: number) => String(s).padEnd(n);
console.log(`\n${pad('sample', 34)}${pad('expected', 26)}${pad('got', 20)}${pad('risk', 6)}${pad('conf', 6)}${pad('cov', 6)}ok`);
console.log('-'.repeat(104));
CORPUS.forEach((s, i) => {
  const v = base[i];
  const good = s.expect.includes(v.label);
  console.log(`${pad(s.id.slice(0, 33), 34)}${pad(s.expect.join('|'), 26)}${pad(v.label, 20)}${pad(v.risk, 6)}${pad(v.confidence.score, 6)}${pad(v.coverage.toFixed(2), 6)}${good ? 'yes' : 'NO  <-- ' + v.headline.slice(0, 60)}`);
});
const acc = accuracy(base);
console.log(`\nAgreement with the analyst labels: ${acc}/${CORPUS.length} (${Math.round((100 * acc) / CORPUS.length)}%)`);

/* confusion matrix on the primary (first) expected label */
const labels: VerdictLabel[] = ['malicious', 'suspicious', 'inconclusive', 'likely_legitimate', 'analysis_unavailable'];
const matrix = new Map<string, number>();
CORPUS.forEach((s, i) => { const exp = s.expect.includes(base[i].label) ? base[i].label : s.expect[0]; matrix.set(`${exp}>${base[i].label}`, (matrix.get(`${exp}>${base[i].label}`) ?? 0) + 1); });
console.log('\nConfusion matrix (rows: analyst, columns: engine)');
console.log(pad('', 20) + labels.map((l) => pad(l.slice(0, 11), 13)).join(''));
for (const r of labels.slice(0, 4)) console.log(pad(r, 20) + labels.map((c) => pad(matrix.get(`${r}>${c}`) ?? 0, 13)).join(''));

/* the two mistakes that matter most */
const missedMalicious = CORPUS.filter((s, i) => s.expect.length === 1 && s.expect[0] === 'malicious' && base[i].label !== 'malicious');
const clearedBad = CORPUS.filter((s, i) => !s.expect.includes('likely_legitimate') && base[i].label === 'likely_legitimate');
console.log(`\nMalicious samples not called malicious: ${missedMalicious.length}   Bad samples cleared as likely legitimate: ${clearedBad.length}  (the second must be 0)`);

/* sensitivity: nudge one threshold at a time */
console.log('\nSensitivity (agreement out of ' + CORPUS.length + '; the current value is marked *)');
const sweeps: [keyof Thresholds, number[]][] = [
  ['suspiciousRisk', [20, 25, 30, 35, 40, 50]], ['strongSingle', [10, 12, 15, 18, 22]], ['meaningful', [6, 8, 10, 12, 15]],
  ['twoSignalsRisk', [12, 16, 20, 25, 30]], ['legitimateRisk', [6, 9, 12, 16, 20, 25]], ['legitimateCoverage', [0.4, 0.55, 0.7, 0.85]],
];
for (const [key, values] of sweeps) {
  console.log(`  ${pad(key, 20)}${values.map((v) => `${v === THRESHOLDS[key] ? '*' : ' '}${v}: ${accuracy(run({ [key]: v }))}`).join('   ')}`);
}
process.exitCode = acc === CORPUS.length && clearedBad.length === 0 ? 0 : 1;
