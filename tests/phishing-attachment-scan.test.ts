import { test } from 'node:test';
import assert from 'node:assert/strict';
import { convertActiveScan } from '../shared/phishing/attachments';

test('a file VirusTotal already knows is reported as "existing report used", not as a gap or a clean scan', () => {
  const r = convertActiveScan({ status: 'known', reason: 'VirusTotal already scanned this exact file on 2026-11-01 (0 of 62 engines flag it).' }, { index: 1, filename: 'a.pdf', sha256: 'a'.repeat(64) });
  assert.equal(r.findings.length, 0);
  assert.equal(r.checks[0].status, 'not_applicable');
  assert.equal(r.checks[0].result, 'existing report used');
  assert.equal(r.checks[0].id, 'attach.1.scan.virustotal');
});
