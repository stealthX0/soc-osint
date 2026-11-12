import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dmyUtc, dmyTimeUtc, dmyLocal, dmyTimeLocal } from '../shared/dates';

test('dates are shown in the Indian DD/MM/YYYY format', () => {
  assert.equal(dmyUtc('2026-11-07T10:30:00Z'), '07/11/2026');
  assert.equal(dmyTimeUtc('2026-11-07T10:30:59Z'), '07/11/2026 10:30 UTC');
  assert.match(dmyLocal(Date.UTC(2026, 10, 7, 12)) ?? '', /^\d{2}\/\d{2}\/2026$/);
  assert.match(dmyTimeLocal(Date.UTC(2026, 10, 7, 12)) ?? '', /^\d{2}\/\d{2}\/2026, \d{2}:\d{2}:\d{2} (am|pm)$/);
});

test('empty values give null and unparseable text is passed through unchanged', () => {
  assert.equal(dmyUtc(null), null);
  assert.equal(dmyTimeUtc(''), null);
  assert.equal(dmyUtc('not a date'), 'not a date');
});
