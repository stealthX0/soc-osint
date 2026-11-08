/**
 * Regenerates the finding catalogue inside docs/phishing-investigation.md from the scoring tables.
 *   npx tsx scripts/phishing-docs.ts          # rewrite the section
 * tests/phishing-docs.test.ts fails when the file is out of date.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { catalogueMarkdown, spliceCatalogue } from '../shared/phishing/catalogueDoc';

const path = new URL('../docs/phishing-investigation.md', import.meta.url);
const next = spliceCatalogue(readFileSync(path, 'utf8'), catalogueMarkdown());
writeFileSync(path, next);
console.log('docs/phishing-investigation.md catalogue updated');
