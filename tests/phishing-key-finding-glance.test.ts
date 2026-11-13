import { test } from 'node:test';
import assert from 'node:assert/strict';
import { glance } from '../src/pages/phishing/keyFindingGlance';
import type { Finding } from '../shared/phishing/types';

const f = (id: string, severity: Finding['severity'], title: string) => ({ id, severity, title } as Finding);

test('a known finding gets its plain-language headline and its title as the summary', () => {
  assert.deepEqual(glance('url', 'bad', true, [f('url_listed_phishing', 'critical', 'Link is on a phishing blocklist')]), { headline: 'Known Phishing Link', summary: 'Link is on a phishing blocklist' });
  assert.equal(glance('url', 'warn', true, [f('url_redirect_cross_domain', 'medium', 'x')]).headline, 'Redirecting Link');
  assert.equal(glance('authentication', 'warn', true, [f('display_name_brand_spoof', 'high', 'x')]).headline, 'Impersonated Sender');
});

test('an unmapped or minor finding falls back to a headline by area and risk', () => {
  assert.equal(glance('content', 'bad', true, [f('something_new', 'high', 'x')]).headline, 'Phishing Wording');
  assert.equal(glance('url', 'info', true, [f('url_shortener', 'low', 'Uses a link shortener')]).headline, 'Minor Link Notes');
});

test('quiet areas say so without calling the message safe', () => {
  assert.equal(glance('infrastructure', 'good', true, []).headline, 'No Warning Signs');
  assert.equal(glance('attachment', 'neutral', false, []).headline, 'Not Checked');
  assert.equal(glance('authentication', 'good', true, [f('internal_m365_message', 'info', 'Internal Microsoft 365 message')]).headline, 'Internal Message');
  for (const g of [glance('url', 'good', true, []), glance('url', 'neutral', false, [])]) assert.doesNotMatch(`${g.headline} ${g.summary}`, /safe|clean|legitimate/i);
});
