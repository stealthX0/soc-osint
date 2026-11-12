/**
 * Language detection and machine translation for the wording rules (which are written for English).
 *
 * Detection is local and free (franc-min, trigram statistics; no network). Translation is done by a Translator the caller
 * supplies: the Worker passes one backed by Cloudflare Workers AI (`@cf/meta/m2m100-1.2b`), limited only by Cloudflare's
 * own free daily allowance (see worker/_lib/translate.ts). Tests pass a fake. Without a translator the message is simply reported
 * as "language not analysed", as before.
 */
import { franc } from 'franc-min';

/** franc's ISO 639-3 codes mapped to the ISO 639-1 codes the m2m100 translation model accepts, with an English name. */
const LANGS: Record<string, [string, string]> = {
  eng: ['en', 'English'], spa: ['es', 'Spanish'], por: ['pt', 'Portuguese'], fra: ['fr', 'French'], deu: ['de', 'German'], ita: ['it', 'Italian'],
  nld: ['nl', 'Dutch'], pol: ['pl', 'Polish'], ron: ['ro', 'Romanian'], ces: ['cs', 'Czech'], hun: ['hu', 'Hungarian'], swe: ['sv', 'Swedish'],
  tur: ['tr', 'Turkish'], ind: ['id', 'Indonesian'], zlm: ['ms', 'Malay'], vie: ['vi', 'Vietnamese'], tgl: ['tl', 'Tagalog'], ceb: ['ceb', 'Cebuano'],
  jav: ['jv', 'Javanese'], sun: ['su', 'Sundanese'], swh: ['sw', 'Swahili'], hau: ['ha', 'Hausa'], yor: ['yo', 'Yoruba'], ibo: ['ig', 'Igbo'],
  zul: ['zu', 'Zulu'], som: ['so', 'Somali'], lin: ['ln', 'Lingala'], plt: ['mg', 'Malagasy'], fuv: ['ff', 'Fulah'], ilo: ['ilo', 'Ilocano'],
  hrv: ['hr', 'Croatian'], bos: ['bs', 'Bosnian'], srp: ['sr', 'Serbian'], azj: ['az', 'Azerbaijani'], uzn: ['uz', 'Uzbek'],
  rus: ['ru', 'Russian'], ukr: ['uk', 'Ukrainian'], bel: ['be', 'Belarusian'], bul: ['bg', 'Bulgarian'], kaz: ['kk', 'Kazakh'],
  arb: ['ar', 'Arabic'], urd: ['ur', 'Urdu'], pes: ['fa', 'Persian'], pbu: ['ps', 'Pashto'],
  hin: ['hi', 'Hindi'], mar: ['mr', 'Marathi'], npi: ['ne', 'Nepali'], ben: ['bn', 'Bengali'], guj: ['gu', 'Gujarati'], pan: ['pa', 'Punjabi'],
  tam: ['ta', 'Tamil'], kan: ['kn', 'Kannada'], mal: ['ml', 'Malayalam'], sin: ['si', 'Sinhala'], ori: ['or', 'Odia'],
  cmn: ['zh', 'Chinese'], jpn: ['ja', 'Japanese'], kor: ['ko', 'Korean'], tha: ['th', 'Thai'], mya: ['my', 'Burmese'], khm: ['km', 'Khmer'],
  lao: ['lo', 'Lao'], ell: ['el', 'Greek'], heb: ['he', 'Hebrew'], kat: ['ka', 'Georgian'], hye: ['hy', 'Armenian'], amh: ['am', 'Amharic'],
};

export interface DetectedLanguage {
  /** ISO 639-1 (or 639-3 when there is no 2-letter code), or null when the language is unknown / the text too short. */
  code: string | null;
  name: string;
  /** Can the translation model take this language? */
  translatable: boolean;
}

/** Letters only: links, addresses, numbers and markup are noise for language statistics. */
const sample = (text: string) => text.replace(/https?:\/\/\S+|[\w.+-]+@[\w.-]+|<[^>]{0,200}>|&[a-z#0-9]+;/gi, ' ').replace(/[^\p{L}\s'’-]+/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 4000);

/** Very common English words: trigram statistics are unreliable on short business notes ("Same room, 3pm?"). */
const EN_WORDS = new Set('the a an and or of to in on at for with by from is are was were be been it this that these those you your we our us i me my he she they them their his her not no yes can will would should could please thanks thank hi hello dear regards best kind if as so but do does did have has had all any more about here there when what which who how get let know see attached invoice payment account'.split(' '));
const englishShare = (s: string) => { const w = s.toLowerCase().match(/[a-z']+/g) ?? []; return w.length ? w.filter((x) => EN_WORDS.has(x)).length / w.length : 0; };

export function detectLanguage(text: string): DetectedLanguage {
  const s = sample(text);
  const letters = (s.match(/\p{L}/gu) ?? []).length;
  if (letters < 25) return { code: null, name: 'unknown', translatable: false };
  // Plenty of everyday English words: English, whatever the trigram statistics say about a short text.
  if (englishShare(s) >= 0.2) return { code: 'en', name: 'English', translatable: true };
  const iso3 = franc(s, { minLength: 20 });
  // Short Latin-script text with no clear winner is not enough to call it a foreign language.
  if (letters < 60 && /^[\p{Script=Latin}\s'’-]+$/u.test(s)) return { code: null, name: 'unknown', translatable: false };
  const hit = LANGS[iso3];
  if (!hit) return { code: iso3 === 'und' ? null : iso3, name: iso3 === 'und' ? 'unknown' : iso3, translatable: false };
  return { code: hit[0], name: hit[1], translatable: true };
}

/** Translates each text from `source` into English; null when translation is unavailable (budget spent, error). */
export type Translator = (texts: string[], source: string) => Promise<string[] | null>;

/** Text sent for translation: all of what the wording rules read (the parse stops at this many characters for every message). */
export const TRANSLATE_MAX_CHARS = 20_000;
const CHUNK = 700;
/**
 * Scripts written without spaces (Chinese, Japanese, Thai, …) and Korean pack far more meaning per character, so a
 * 700-character piece can need more than m2m100's ~200-token output and come back cut short. They get smaller pieces.
 */
const DENSE_CHUNK = 150;
const DENSE = new Set(['zh', 'ja', 'ko', 'th', 'my', 'km', 'lo']);

/** Splits text at paragraph, then sentence, then word boundaries into pieces the model handles well. */
export function chunkText(text: string, max = CHUNK): string[] {
  const out: string[] = [];
  let cur = '';
  const push = () => { if (cur.trim()) out.push(cur.trim()); cur = ''; };
  for (const piece of text.split(/(?<=[.!?。！？])\s+|\n{2,}|\n/)) {
    let p = piece.trim();
    if (!p) continue;
    while (p.length > max) { // one very long "sentence": cut at a space
      const at = p.lastIndexOf(' ', max) > max / 2 ? p.lastIndexOf(' ', max) : max;
      if (cur) push();
      out.push(p.slice(0, at).trim());
      p = p.slice(at).trim();
    }
    if (cur.length + p.length + 1 > max) push();
    cur = cur ? `${cur}\n${p}` : p;
  }
  push();
  return out;
}

/** Which engine produced a translation. */
export type TranslationEngine = 'workers-ai' | 'browser';

/**
 * The exact pieces the server wanted translated, returned when it could not translate them (Workers AI budget spent,
 * model error, binding off, or a language m2m100 does not cover). The browser can translate them with its built-in
 * on-device Translator API (Chrome 138+, Edge 148+) and send them back as a PretranslatedText.
 */
export interface TranslationRequest {
  /** BCP 47 code of the source language, or null when the browser should detect it (language m2m100 does not know). */
  source: string | null;
  languageName: string;
  pieces: string[];
  partial: boolean;
}

/** A translation made in the analyst's browser, sent back with a repeat of the parse request. */
export interface PretranslatedText {
  engine: 'browser';
  source: string;
  pieces: string[];
  out: string[];
}

const BCP47 = /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/;
/** Validates a client-supplied PretranslatedText (anything malformed is ignored, never an error). */
export function validatePretranslated(raw: unknown): PretranslatedText | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const strs = (v: unknown) => (Array.isArray(v) && v.length > 0 && v.length <= 200 && v.every((x) => typeof x === 'string' && x.length <= 4000) ? (v as string[]) : null);
  const pieces = strs(r.pieces), out = strs(r.out);
  if (typeof r.source !== 'string' || !BCP47.test(r.source) || !pieces || !out || pieces.length !== out.length) return null;
  return { engine: 'browser', source: r.source, pieces, out };
}

/** English name of a BCP 47 language code ("ja" -> "Japanese"), or the code itself. */
export function languageName(code: string): string {
  try { return new Intl.DisplayNames(['en'], { type: 'language' }).of(code) ?? code; } catch { return code; }
}

export interface TranslationResult {
  language: DetectedLanguage;
  /** 'not_needed' (English / unknown / no text), 'translated', 'unavailable' (no translator, budget or error), 'unsupported'. */
  status: 'not_needed' | 'translated' | 'unavailable' | 'unsupported';
  /** Set when status is 'translated'. */
  engine?: TranslationEngine;
  subject: string | null;
  text: string;
  /** True when only the first TRANSLATE_MAX_CHARS characters were translated. */
  partial: boolean;
  detail: string;
  /** Set when status is 'unavailable' or 'unsupported': what the browser could translate instead. */
  request?: TranslationRequest;
}

const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Detects the language of subject + body and, when it is not English, translates both: with `pretranslated` when the
 * browser already did it for exactly these pieces, otherwise with `translate` (Workers AI).
 */
export async function translateForAnalysis(subject: string | null, text: string, translate?: Translator, pretranslated?: PretranslatedText | null): Promise<TranslationResult> {
  const language = detectLanguage(`${subject ?? ''}\n${text}`);
  const same = { language, subject, text, partial: false };
  if (!language.code || language.code === 'en') return { ...same, status: 'not_needed', detail: language.code ? 'The message is in English.' : 'Too little text to tell the language.' };
  const max = TRANSLATE_MAX_CHARS;
  const hasSubject = !!subject?.trim();
  const pieces = [...(hasSubject ? [subject!.trim()] : []), ...chunkText(text.slice(0, max), DENSE.has(language.code) ? DENSE_CHUNK : CHUNK)];
  const partial = text.length > max;
  const done = (out: string[], engine: TranslationEngine, lang: DetectedLanguage, how: string): TranslationResult => ({
    language: lang, status: 'translated', engine, partial,
    subject: hasSubject ? out[0] : subject, text: out.slice(hasSubject ? 1 : 0).join('\n'),
    detail: `Machine-translated from ${lang.name} to English ${how} before the wording rules ran${partial ? ` (first ${max.toLocaleString('en')} characters)` : ''}. Quoted evidence is from the translation.`,
  });
  const usable = (out: string[] | null | undefined): out is string[] => !!out && out.length === pieces.length && !out.every((x) => !x?.trim());

  // 1. The browser translated exactly these pieces (sent back after the server could not translate them).
  if (pretranslated && sameList(pretranslated.pieces, pieces) && usable(pretranslated.out)) {
    const lang = language.translatable ? language : { code: pretranslated.source, name: languageName(pretranslated.source), translatable: true };
    return done(pretranslated.out, 'browser', lang, 'in your browser (its built-in on-device translator; the Cloudflare translation was unavailable)');
  }
  const request: TranslationRequest = { source: language.translatable ? language.code : null, languageName: language.name, pieces, partial };
  if (!language.translatable) return { ...same, status: 'unsupported', request, detail: `The message appears to be in ${language.name}, which the Cloudflare translation model does not cover.` };
  if (!translate) return { ...same, status: 'unavailable', request, detail: `The message appears to be in ${language.name}; machine translation is not available here.` };
  // 2. Cloudflare Workers AI (free daily allowance).
  let out: string[] | null = null;
  try { out = await translate(pieces, language.code); } catch { out = null; }
  if (!usable(out)) return { ...same, status: 'unavailable', request, detail: `The message appears to be in ${language.name}, but machine translation failed or its free daily allowance is used up.` };
  return done(out, 'workers-ai', language, '(Cloudflare Workers AI)');
}
