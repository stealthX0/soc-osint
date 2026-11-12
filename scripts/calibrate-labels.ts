/**
 * Replays analyst-labelled investigations through the current verdict engine.
 *
 *   npm run calibrate:labels -- spectrix-calibration-2026-11-12.json
 *
 * The file is the "Download labelled set" export from the dashboard. For each record the engine is re-run on the stored
 * findings and check statuses (no lookups are repeated) and compared with the analyst's label:
 *   phishing   -> malicious or suspicious     bec -> suspicious or malicious
 *   legitimate -> likely legitimate or inconclusive        unsure -> ignored
 * The number that must stay at 0 is "bad mail cleared": phishing/BEC the engine called likely legitimate.
 */
import { readFileSync } from 'node:fs';
import { computeVerdict, type VerdictLabel } from '../shared/phishing/verdict';
import { THRESHOLDS, type Thresholds } from '../shared/phishing/verdictRules';
import { ACCEPTED, parseCalibrationFile, replayInput, type CalibrationRecord } from '../shared/phishing/calibrationRecord';

const file = process.argv[2];
if (!file) { console.error('Usage: npm run calibrate:labels -- <labelled-set.json>'); process.exit(1); }
const records = parseCalibrationFile(JSON.parse(readFileSync(file, 'utf8'))).filter((r) => r.analyst !== 'unsure');
if (!records.length) { console.error('No usable labelled records in the file.'); process.exit(1); }

const run = (tuning?: Partial<Thresholds>) => records.map((r) => computeVerdict({ ...replayInput(r), tuning: tuning ? { thresholds: tuning } : undefined }));
const score = (vs: ReturnType<typeof run>) => vs.filter((v, i) => ACCEPTED[records[i].analyst].includes(v.label)).length;
const cleared = (vs: ReturnType<typeof run>) => vs.filter((v, i) => records[i].analyst !== 'legitimate' && v.label === 'likely_legitimate').length;

const base = run();
const pad = (s: string | number, n: number) => String(s).padEnd(n);
console.log(`\n${pad('record', 20)}${pad('analyst', 12)}${pad('engine now', 20)}${pad('risk', 6)}${pad('then', 20)}ok`);
console.log('-'.repeat(84));
base.forEach((v, i) => {
  const r: CalibrationRecord = records[i];
  console.log(`${pad(r.id.slice(2, 18), 20)}${pad(r.analyst, 12)}${pad(v.label + (v.highRisk ? '*' : ''), 20)}${pad(v.risk, 6)}${pad(r.engine.label, 20)}${ACCEPTED[r.analyst].includes(v.label) ? 'yes' : 'NO'}`);
});
console.log(`\nAgreement: ${score(base)}/${records.length} (${Math.round((100 * score(base)) / records.length)}%)   Bad mail cleared as likely legitimate: ${cleared(base)} (must be 0)   * = high risk`);

const labels: VerdictLabel[] = ['malicious', 'suspicious', 'inconclusive', 'likely_legitimate'];
console.log('\nConfusion (rows: analyst, columns: engine)');
console.log(pad('', 12) + labels.map((l) => pad(l, 18)).join(''));
for (const a of ['phishing', 'bec', 'legitimate'] as const) {
  const idx = records.map((r, i) => (r.analyst === a ? i : -1)).filter((i) => i >= 0);
  if (idx.length) console.log(pad(a, 12) + labels.map((l) => pad(idx.filter((i) => base[i].label === l).length, 18)).join(''));
}

console.log('\nThreshold sensitivity (agreement / bad mail cleared; * = current)');
const nudge: Partial<Record<keyof Thresholds, number[]>> = { suspiciousRisk: [20, 24, 28, 32, 36, 40], legitimateRisk: [9, 12, 15, 18, 21], strongSingle: [10, 15, 20], meaningful: [6, 10, 14] };
for (const [k, vals] of Object.entries(nudge) as [keyof Thresholds, number[]][]) {
  console.log(`  ${pad(k, 18)}${vals.map((x) => { const vs = run({ [k]: x }); return pad(`${x === THRESHOLDS[k] ? '*' : ''}${x}: ${score(vs)}/${cleared(vs)}`, 14); }).join('')}`);
}
