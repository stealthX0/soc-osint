/**
 * Language detection and machine translation for the wording rules (which are written for English).
 *
 * Detection is local and free (franc-min, trigram statistics; no network). Translation is done by a Translator the caller
 * supplies: the Worker passes one backed by Cloudflare Workers AI (`@cf/meta/m2m100-1.2b`) that only runs inside the free
 * daily allocation (see worker/_lib/translate.ts). Tests pass a fake. Without a translator the message is simply reported
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

/**
 * Most text sent for translation per message (the Workers AI free allocation is shared by every investigation). Scripts
 * without spaces (Chinese, Japanese, Korean, Thai, …) cost about one token per character, so they get less.
 */
export const TRANSLATE_MAX_CHARS = 5000;
const DENSE_SCRIPT_MAX_CHARS = 2000;
const DENSE = new Set(['zh', 'ja', 'ko', 'th', 'my', 'km', 'lo']);
const CHUNK = 700;

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

export interface TranslationResult {
  language: DetectedLanguage;
  /** 'not_needed' (English / unknown / no text), 'translated', 'unavailable' (no translator, budget or error), 'unsupported'. */
  status: 'not_needed' | 'translated' | 'unavailable' | 'unsupported';
  subject: string | null;
  text: string;
  /** True when only the first TRANSLATE_MAX_CHARS characters were translated. */
  partial: boolean;
  detail: string;
}

/** Detects the language of subject + body and, when it is not English, translates both with `translate`. */
export async function translateForAnalysis(subject: string | null, text: string, translate?: Translator): Promise<TranslationResult> {
  const language = detectLanguage(`${subject ?? ''}\n${text}`);
  const same = { language, subject, text, partial: false };
  if (!language.code || language.code === 'en') return { ...same, status: 'not_needed', detail: language.code ? 'The message is in English.' : 'Too little text to tell the language.' };
  if (!language.translatable) return { ...same, status: 'unsupported', detail: `The message appears to be in ${language.name}, which the translation model does not cover.` };
  if (!translate) return { ...same, status: 'unavailable', detail: `The message appears to be in ${language.name}; machine translation is not available here.` };
  const max = DENSE.has(language.code) ? DENSE_SCRIPT_MAX_CHARS : TRANSLATE_MAX_CHARS;
  const body = text.slice(0, max);
  const pieces = [...(subject?.trim() ? [subject.trim()] : []), ...chunkText(body)];
  let out: string[] | null = null;
  try { out = await translate(pieces, language.code); } catch { out = null; }
  if (!out || out.length !== pieces.length || out.every((x) => !x?.trim())) return { ...same, status: 'unavailable', detail: `The message appears to be in ${language.name}, but machine translation failed or its free daily allowance is used up.` };
  const tSubject = subject?.trim() ? out[0] : subject;
  const tText = out.slice(subject?.trim() ? 1 : 0).join('\n');
  const partial = text.length > max;
  return { language, status: 'translated', subject: tSubject, text: tText, partial, detail: `Machine-translated from ${language.name} to English before the wording rules ran${partial ? ` (first ${max.toLocaleString('en')} characters)` : ''}. Quoted evidence is from the translation.` };
}
