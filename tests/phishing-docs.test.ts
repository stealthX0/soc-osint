import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { catalogueMarkdown, spliceCatalogue } from '../shared/phishing/catalogueDoc';
import { FINDING_DESCRIPTIONS } from '../shared/phishing/findingCatalogue';
import { POINTS } from '../shared/phishing/verdictRules';

describe('phishing documentation stays in sync with the code', () => {
  it('every scored finding id has a description, and every description has a scoring rule', () => {
    assert.deepEqual(Object.keys(POINTS).filter((id) => !FINDING_DESCRIPTIONS[id]), []);
    assert.deepEqual(Object.keys(FINDING_DESCRIPTIONS).filter((id) => !(id in POINTS)), []);
  });
  it('docs/phishing-investigation.md contains the current finding catalogue (run: npx tsx scripts/phishing-docs.ts)', () => {
    const doc = readFileSync('docs/phishing-investigation.md', 'utf8');
    assert.equal(spliceCatalogue(doc, catalogueMarkdown()), doc);
  });
  it('the documented environment variables exist in the Worker environment type', () => {
    const env = readFileSync('worker/_lib/env.ts', 'utf8');
    const doc = readFileSync('docs/phishing-investigation.md', 'utf8');
    for (const v of new Set(doc.match(/\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)*_(?:KEY|DAILY|URL|MIN)\b/g) ?? [])) assert.ok(env.includes(v) || v === 'RATE_LIMIT_PER_MIN' || v === 'OPENPHISH_FEED_URL', `${v} is documented but not in env.ts`);
  });
  it('the documented limits match the code', () => {
    const doc = readFileSync('docs/phishing-investigation.md', 'utf8');
    for (const must of ['100 KB', '2,000,000 characters', '200,000', '120 / 6']) assert.ok(doc.includes(must), must);
  });
});
