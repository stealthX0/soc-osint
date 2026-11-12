import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectLanguage, chunkText, translateForAnalysis, type Translator } from '../shared/phishing/language';
import { parseSubmission } from '../shared/phishing/parse';
import { workersAiTranslator, TRANSLATE_MODEL } from '../worker/_lib/translate';
import { resetRateLimitMemory, takeProviderBudget } from '../worker/_lib/ratelimit';

const FR = 'Votre identifiant Cloud a été bloqué. Vos photos et vidéos seront supprimées. Vérifiez votre mot de passe immédiatement pour éviter la suspension de votre compte.';
const EN = 'Your Cloud ID has been blocked. Your photos and videos will be deleted. Verify your password immediately to avoid the suspension of your account.';
/** A fake translator: the French sample maps to its English text, anything else is returned unchanged. */
const fake: Translator = async (texts) => texts.map((t) => (t.includes('identifiant Cloud') ? EN : t === 'Compte bloqué' ? 'Account blocked' : t));

test('detects common languages locally and leaves English alone', () => {
  assert.equal(detectLanguage(FR).code, 'fr');
  assert.equal(detectLanguage('Sie haben eine Zahlung auf Ihrem Konto erhalten. Bitte bestätigen Sie die Zahlung innerhalb von 24 Stunden.').code, 'de');
  assert.equal(detectLanguage('Informamos que seu CPF foi identificado com pendência de renegociação. Regularize agora para evitar bloqueio.').code, 'pt');
  assert.equal(detectLanguage('お支払い情報を更新してください。アカウントは二十四時間以内に停止されます。ご確認をお願いいたします。').code, 'ja');
  assert.equal(detectLanguage('Please pay the attached invoice today by bank transfer, the amount is overdue and must be settled.').code, 'en');
  assert.equal(detectLanguage('Hi').code, null, 'too short to tell');
});

test('chunks long text at sentence boundaries without losing words', () => {
  const t = Array.from({ length: 60 }, (_, i) => `Sentence number ${i} is here.`).join(' ');
  const c = chunkText(t, 200);
  assert.ok(c.length > 3 && c.every((x) => x.length <= 200));
  assert.equal(c.join(' ').split(/\s+/).length, t.split(/\s+/).length);
});

test('non-English wording is translated, then the English rules find the lure', async () => {
  const r = await parseSubmission({ subject: 'Compte bloqué', body: FR }, { translate: fake });
  assert.equal(r.content.analysis.language?.status, 'translated');
  assert.equal(r.content.analysis.language?.name, 'French');
  assert.equal(r.content.analysis.languageSupported, true);
  assert.ok(r.findings.some((f) => f.id === 'content_credential_request'), r.findings.map((f) => f.id).join(','));
  assert.equal(r.checks.find((c) => c.id === 'content.translate')?.status, 'complete');
  assert.match(r.content.analysis.language?.translatedText ?? '', /Verify your password/);
});

test('without translation a Latin-script foreign language is reported as not analysed, not as clean', async () => {
  const r = await parseSubmission({ body: FR });
  assert.equal(r.content.analysis.languageSupported, false);
  assert.ok(r.findings.some((f) => f.id === 'content_language_not_analysed'));
  assert.equal(r.checks.find((c) => c.id === 'content.translate')?.status, 'skipped');
  const failing = await translateForAnalysis(null, FR, async () => { throw new Error('quota'); });
  assert.equal(failing.status, 'unavailable');
});

test('English needs no translation and the translator is never called', async () => {
  let called = 0;
  const r = await parseSubmission({ body: EN }, { translate: async (t) => { called++; return t; } });
  assert.equal(called, 0);
  assert.equal(r.checks.find((c) => c.id === 'content.translate'), undefined);
});

test('the Workers AI translator: off without the binding, model call shape, failures return null, daily cap', async () => {
  resetRateLimitMemory();
  assert.equal(workersAiTranslator({} as never), undefined);
  assert.equal(workersAiTranslator({ AI: { run: async () => ({}) }, TRANSLATE_CONTENT: 'false' } as never), undefined);
  const calls: unknown[] = [];
  const tr = workersAiTranslator({ AI: { run: async (model: string, input: Record<string, unknown>) => { calls.push([model, input]); return { translated_text: `EN:${input.text}` }; } } } as never)!;
  assert.deepEqual(await tr(['un', 'deux'], 'fr'), ['EN:un', 'EN:deux']);
  assert.deepEqual(calls[0], [TRANSLATE_MODEL, { text: 'un', source_lang: 'fr', target_lang: 'en' }]);
  const broken = workersAiTranslator({ AI: { run: async () => { throw new Error('4006: daily free allocation exceeded'); } } } as never)!;
  assert.equal(await broken(['x'], 'fr'), null);
  resetRateLimitMemory();
  const t0 = Date.now();
  for (let i = 0; i < 40; i++) assert.equal((await takeProviderBudget({} as never, 'translate', t0)).ok, true);
  assert.equal((await takeProviderBudget({} as never, 'translate', t0)).ok, false, 'the 41st message that day is not translated');
});

import { computeVerdict } from '../shared/phishing/verdict';
import { mail, SENDER_DONE } from './fixtures/phishing-corpus';
test('a message whose language could not be read is never cleared as likely legitimate', async () => {
  const r = await parseSubmission({ headers: mail({ from: 'support@cloud.example' }), body: FR });
  const v = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...SENDER_DONE] });
  assert.notEqual(v.label, 'likely_legitimate');
  assert.ok(v.gaps.some((g) => g.critical && /French, not translated/.test(g.text)));
});
