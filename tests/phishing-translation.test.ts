import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectLanguage, chunkText, translateForAnalysis, type Translator } from '../shared/phishing/language';
import { parseSubmission } from '../shared/phishing/parse';
import { workersAiTranslator, TRANSLATE_MODEL } from '../worker/_lib/translate';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';

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

test('the Workers AI translator: off without the binding, model call shape, failures return null, no cap of its own', async () => {
  resetRateLimitMemory();
  assert.equal(workersAiTranslator({} as never), undefined);
  assert.equal(workersAiTranslator({ AI: { run: async () => ({}) }, TRANSLATE_CONTENT: 'false' } as never), undefined);
  const calls: unknown[] = [];
  const tr = workersAiTranslator({ AI: { run: async (model: string, input: Record<string, unknown>) => { calls.push([model, input]); return { translated_text: `EN:${input.text}` }; } } } as never)!;
  assert.deepEqual(await tr(['un', 'deux'], 'fr'), ['EN:un', 'EN:deux']);
  assert.deepEqual(calls[0], [TRANSLATE_MODEL, { text: 'un', source_lang: 'fr', target_lang: 'en' }]);
  const broken = workersAiTranslator({ AI: { run: async () => { throw new Error('4006: daily free allocation exceeded'); } } } as never)!;
  assert.equal(await broken(['x'], 'fr'), null);
  // no daily cap of the tool's own: the 41st (and every later) message that day still goes to Workers AI
  let runs = 0;
  const uncapped = workersAiTranslator({ AI: { run: async () => { runs++; return { translated_text: 'x' }; } } } as never)!;
  for (let i = 0; i < 60; i++) assert.deepEqual(await uncapped(['y'], 'fr'), ['x']);
  assert.equal(runs, 60);
});

test('all the text the wording rules read is translated (no 5,000 / 2,000-character limit)', async () => {
  const long = `${FR} `.repeat(60); // ~9,000 characters
  let sent = 0;
  const r = await translateForAnalysis(null, long, async (t) => { sent = t.join('').length; return t; });
  assert.equal(r.partial, false);
  assert.ok(sent > 8500, String(sent));
  const ja = 'お支払い情報を更新してください。アカウントは二十四時間以内に停止されます。'.repeat(150); // ~5,500 characters
  const rj = await translateForAnalysis(null, ja, async (t) => { sent = t.join('').length; return t; });
  assert.equal(rj.partial, false);
  assert.ok(sent > 5000, String(sent));
  // a 20,000-character message (the most the parse reads) fits a browser translation too
  const huge = `${FR}\n`.repeat(140).slice(0, 20_000);
  const req = (await translateForAnalysis(null, huge)).request!;
  assert.ok(validatePretranslated({ source: 'fr', pieces: req.pieces, out: req.pieces }), `${req.pieces.length} pieces`);
});

import { computeVerdict } from '../shared/phishing/verdict';
import { mail, SENDER_DONE } from './fixtures/phishing-corpus';
test('a message whose language could not be read is never cleared as likely legitimate', async () => {
  const r = await parseSubmission({ headers: mail({ from: 'support@cloud.example' }), body: FR });
  const v = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...SENDER_DONE] });
  assert.notEqual(v.label, 'likely_legitimate');
  assert.ok(v.gaps.some((g) => g.critical && /French, not translated/.test(g.text)));
});

/* ------------------------------------------- in-browser fallback (Chrome / Edge built-in Translator API) */
import { validatePretranslated } from '../shared/phishing/language';
import { translateInBrowser } from '../src/lib/browserTranslate';
import { onRequestPost } from '../worker/api/phishing/parse';

test('when Cloudflare cannot translate, the parse returns the exact pieces for the browser', async () => {
  const exhausted: Translator = async () => null; // budget spent / 4006 daily allocation exceeded
  const r = await parseSubmission({ subject: 'Compte bloqué', body: FR }, { translate: exhausted });
  assert.equal(r.content.analysis.language?.status, 'unavailable');
  assert.equal(r.translationRequest?.source, 'fr');
  assert.equal(r.translationRequest?.languageName, 'French');
  assert.equal(r.translationRequest?.pieces[0], 'Compte bloqué');
  assert.equal(r.translationRequest?.pieces.slice(1).join(' ').replace(/\s+/g, ' '), FR);
  const none = await parseSubmission({ body: FR });
  assert.ok(none.translationRequest, 'also when Workers AI is off');
  assert.equal((await parseSubmission({ body: EN })).translationRequest, undefined);
});

test('a browser translation of exactly those pieces is used instead of Workers AI', async () => {
  const req = (await parseSubmission({ subject: 'Compte bloqué', body: FR })).translationRequest!;
  const pre = validatePretranslated({ engine: 'browser', source: 'fr', pieces: req.pieces, out: ['Account blocked', EN] })!;
  let cloudflare = 0;
  const r = await parseSubmission({ subject: 'Compte bloqué', body: FR }, { pretranslated: pre, translate: async (t) => { cloudflare++; return t; } });
  assert.equal(cloudflare, 0);
  assert.equal(r.content.analysis.language?.status, 'translated');
  assert.equal(r.content.analysis.language?.engine, 'browser');
  assert.equal(r.translationRequest, undefined);
  assert.ok(r.findings.some((f) => f.id === 'content_credential_request'));
  assert.match(r.checks.find((c) => c.id === 'content.translate')?.result ?? '', /in the browser/);
  // Workers AI translations are labelled as such
  assert.equal((await parseSubmission({ body: FR }, { translate: fake })).content.analysis.language?.engine, 'workers-ai');
});

test('a browser translation for different text, or malformed, is ignored', async () => {
  const wrong = validatePretranslated({ source: 'fr', pieces: ['autre chose'], out: ['something else'] })!;
  const r = await parseSubmission({ body: FR }, { pretranslated: wrong });
  assert.equal(r.content.analysis.language?.status, 'unavailable');
  assert.ok(r.translationRequest);
  for (const bad of [null, 'x', { source: 'fr', pieces: ['a'], out: [] }, { source: '<script>', pieces: ['a'], out: ['b'] }, { source: 'fr', pieces: Array(201).fill('a'), out: Array(201).fill('b') }, { source: 'fr', pieces: ['a'], out: [1] }]) {
    assert.equal(validatePretranslated(bad), null, JSON.stringify(bad)?.slice(0, 60));
  }
});

test('a language m2m100 does not cover can still be translated by the browser, which detects it', async () => {
  const FI = 'Tilisi on lukittu. Vahvista salasanasi välittömästi, muuten tilisi poistetaan pysyvästi huomenna. Kiitos yhteistyöstä.';
  const r = await parseSubmission({ body: FI });
  if (r.content.analysis.language?.status !== 'unsupported') return; // franc may map it to a covered language
  assert.equal(r.translationRequest?.source, null, 'the browser detects the language itself');
  const pre = validatePretranslated({ source: 'fi', pieces: r.translationRequest!.pieces, out: ['Your account is locked. Verify your password immediately, otherwise your account will be permanently deleted tomorrow.'] })!;
  const t = await parseSubmission({ body: FI }, { pretranslated: pre });
  assert.equal(t.content.analysis.language?.status, 'translated');
  assert.equal(t.content.analysis.language?.name, 'Finnish');
});

test('the parse endpoint uses browserTranslation and skips Workers AI', async () => {
  const req = (await parseSubmission({ body: FR })).translationRequest!;
  let aiCalls = 0;
  const env = { AI: { run: async () => { aiCalls++; return { translated_text: 'x' }; } } };
  const post = async (body: unknown) => {
    const res = await onRequestPost({ request: new Request('https://x/api/phishing/parse', { method: 'POST', body: JSON.stringify(body) }), env } as never);
    return ((await res.json()) as { data: { content: { analysis: { language?: { status: string; engine?: string } } } } }).data;
  };
  const d = await post({ body: FR, browserTranslation: { source: 'fr', pieces: req.pieces, out: [EN] } });
  assert.equal(aiCalls, 0);
  assert.equal(d.content.analysis.language?.engine, 'browser');
});

/** Minimal stand-in for Chrome / Edge's built-in Translator + LanguageDetector globals. */
function fakeBrowser(o: { availability: string; detect?: string; refuseCreate?: boolean }) {
  const g = globalThis as Record<string, unknown>;
  const created: string[] = [];
  g.Translator = {
    availability: async () => o.availability,
    create: async (p: { sourceLanguage: string; monitor?: (m: { addEventListener: (t: string, cb: (e: { loaded: number }) => void) => void }) => void }) => {
      if (o.refuseCreate) throw Object.assign(new Error('Requires user activation'), { name: 'NotAllowedError' });
      p.monitor?.({ addEventListener: (_t, cb) => cb({ loaded: 1 }) });
      created.push(p.sourceLanguage);
      return { translate: async (t: string) => `EN(${t.slice(0, 10)})`, destroy() {} };
    },
  };
  g.LanguageDetector = { availability: async () => 'available', create: async () => ({ detect: async () => [{ detectedLanguage: o.detect ?? 'und', confidence: 0.9 }], destroy() {} }) };
  return { created, restore: () => { delete g.Translator; delete g.LanguageDetector; } };
}

test('browser translator: translates when the pack is present, asks first when it must download', async () => {
  const req = { source: 'fr', languageName: 'French', pieces: ['un', 'deux'], partial: false };
  let b = fakeBrowser({ availability: 'available' });
  const ok = await translateInBrowser(req, { allowDownload: false });
  assert.ok(ok.ok && ok.value.out.length === 2 && ok.value.source === 'fr');
  b.restore();
  b = fakeBrowser({ availability: 'downloadable' });
  const ask = await translateInBrowser(req, { allowDownload: false });
  assert.equal(!ask.ok && ask.reason, 'needs_download');
  assert.equal(b.created.length, 0, 'no download without a click');
  let progress = 0;
  assert.equal((await translateInBrowser(req, { allowDownload: true, onProgress: (x) => { progress = x; } })).ok, true);
  assert.equal(progress, 1);
  b.restore();
  b = fakeBrowser({ availability: 'downloadable', refuseCreate: true });
  const refused = await translateInBrowser(req, { allowDownload: true });
  assert.equal(!refused.ok && refused.reason, 'needs_download');
  b.restore();
  b = fakeBrowser({ availability: 'unavailable' });
  assert.equal(((await translateInBrowser(req, { allowDownload: true })) as { reason?: string }).reason, 'unsupported_language');
  b.restore();
  assert.equal(((await translateInBrowser(req, { allowDownload: true })) as { reason?: string }).reason, 'unsupported_browser');
  b = fakeBrowser({ availability: 'available', detect: 'fi' });
  const det = await translateInBrowser({ ...req, source: null, languageName: 'fin' }, { allowDownload: false });
  assert.ok(det.ok && det.value.source === 'fi');
  b.restore();
});

test('Chinese, Japanese, Korean and Thai go in smaller pieces so m2m100 does not cut them short', async () => {
  let longest = 0, count = 0;
  const spy: Translator = async (t) => { count = t.length; longest = Math.max(...t.map((x) => x.length)); return t; };
  const ja = 'お支払い情報を更新してください。アカウントは二十四時間以内に停止されます。'.repeat(150);
  await translateForAnalysis(null, ja, spy);
  assert.ok(longest <= 150, `ja piece ${longest}`);
  await translateForAnalysis(null, `${FR} `.repeat(20), spy);
  assert.ok(longest > 150 && longest <= 700, `fr piece ${longest}`);
  // the most a dense-script message can produce (20,000 characters) still fits a browser translation
  const big = 'お支払い情報を更新してください。'.repeat(1300).slice(0, 20_000);
  const req = (await translateForAnalysis(null, big)).request!;
  assert.ok(req.pieces.length > 120 && !!validatePretranslated({ source: 'ja', pieces: req.pieces, out: req.pieces }), `${req.pieces.length} pieces`);
  void count;
});
