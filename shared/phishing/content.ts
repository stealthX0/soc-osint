/**
 * Step 5: phishing content and behavioural analysis (deterministic layer).
 *
 * Reads the WORDING of a message for the lures phishing uses: urgency, credential and payment requests, payment
 * redirection, gift cards, extortion, delivery and document-share lures, QR codes, hidden or obfuscated text and brand
 * impersonation. It is pure (no network, no model) and every hit carries a short quoted excerpt, so the analyst can see
 * exactly what triggered it.
 *
 * Calibration principles
 *  - These are INDICATORS FOR REVIEW, never a verdict. Genuine password resets, invoices and security alerts use the same
 *    words, so single hits are low severity. Weight comes from combinations, and the verdict engine adds the sender,
 *    link and attachment evidence.
 *  - The rules read English. A message in another script gets an explicit "not analysed" note: fewer indicators must not
 *    be mistaken for a clean bill of health.
 *  - The message is untrusted input. Text is only matched against fixed patterns; nothing in it is interpreted or obeyed.
 */
import { BRANDS, isOfficial } from '../url';
import { registrableOf } from './domains';
import { eachTag, stripTags } from './html';
import { makeFinding } from './findings';
import type { Finding, Severity } from './types';

export type ContentCategoryId =
  | 'urgency' | 'credential' | 'financial' | 'gift_card' | 'payment_redirection' | 'payroll' | 'bec' | 'extortion'
  | 'delivery' | 'advance_fee' | 'document_share' | 'attachment_lure' | 'qr' | 'image_only' | 'hidden_text' | 'obfuscation' | 'brand'
  | 'payment_demand' | 'forwarded_thread';

export interface ContentMatch { rule: string; excerpt: string }
export interface ContentCategory { id: ContentCategoryId; label: string; strong: boolean; matches: ContentMatch[] }

export type IntentId = 'credential_harvesting' | 'financial_fraud' | 'business_email_compromise' | 'delivery_scam' | 'malware_delivery' | 'extortion' | 'account_impersonation' | 'advance_fee' | 'unknown';
export interface ContentIntent { id: IntentId; label: string; confidence: 'low' | 'medium' | 'high'; reasons: string[] }

export interface ContentAnalysis {
  /** False when there was no text to read. */
  analysed: boolean;
  chars: number;
  /** Share of letters that are Latin script. The rules are written for English / Latin-script text. */
  latinShare: number;
  languageSupported: boolean;
  categories: ContentCategory[];
  intents: ContentIntent[];
  notes: string[];
}

export interface ContentInput {
  subject: string | null;
  text: string;
  html: string | null;
  linkCount: number;
  attachments: { filename: string | null; inline: boolean; declaredType: string | null }[];
  displayName: string | null;
  fromDomain: string | null;
  fromIsFreeMail: boolean;
}

/* ------------------------------------------------- receiver-added banners */

/**
 * Text the RECEIVING mail system adds above the message (Microsoft's "You don't often get email from…" first-contact
 * tip with its aka.ms link, "Caution: this email came from outside the organisation" notices, "[EXTERNAL]" tags). The
 * sender did not write it, so it must not count as the sender's wording or links. Exported for parse.ts and tests.
 */
const BANNERS: RegExp[] = [
  /\[?[ \t]*You don'?t often get e-?mail from [^\]\n]{1,250}(?:\n[^\]\n]{0,250}?Learn why this is important[^\]\n]*)?\]?/gi,
  /^[ \t]*\[?(?:caution|warning|notice|attention|external(?: e-?mail| sender)?)\]?\s*[:!-]?\s*this (?:e-?mail|message) (?:came|originated|was sent|is) from (?:outside|an external)[^\n]*(?:\n(?!\s*\n)[^\n]*){0,3}/gim,
  /^[ \t]*\[external\][ \t]*/gim,
];
/** Links that only receiving systems insert (never the sender's): ignored by link analysis. */
export const RECEIVER_BANNER_LINK = /^https?:\/\/aka\.ms\/(?:LearnAboutSenderIdentification|LearnAboutSpoofing|AboutExternalSenders)\b/i;
export function stripReceiverBanners(text: string): { text: string; removed: number } {
  let removed = 0;
  let out = text;
  for (const re of BANNERS) out = out.replace(re, () => { removed++; return ''; });
  return { text: removed ? out.replace(/^\s+/, '') : text, removed };
}

/* ------------------------------------------------------------------ rules */

interface Rule { id: string; category: ContentCategoryId; strong?: boolean; re: RegExp }

const W = String.raw`[^.!?\n]`; // "within the same sentence"
const rx = (s: string) => new RegExp(s, 'i');

const RULES: Rule[] = [
  // urgency (strong = it states a consequence, not just a hurry)
  { id: 'consequence_account', category: 'urgency', strong: true, re: rx(String.raw`\b(account|mailbox|e-?mail|access|service|subscription|card|profile|password)\b${W}{0,60}\b(will be|has been|is being|was|been|may be|shall be|is now|has)\b${W}{0,20}\b(suspended|disabled|deactivated|terminated|closed|locked|restricted|limited|blocked|deleted|cancell?ed|expired)\b`) },
  { id: 'deadline_or_else', category: 'urgency', strong: true, re: rx(String.raw`\b(within|in the next|in)\s+(\d{1,3}|one|two|three|six|twelve|twenty[- ]four|forty[- ]eight)\s*(hours?|hrs?|minutes?|mins?|days?)\b${W}{0,70}\b(or|otherwise|else|before|to avoid|will)\b`) },
  { id: 'urgency_words', category: 'urgency', re: rx(String.raw`\b(immediate(ly)?|urgent(ly)?|right away|act now|as soon as possible|final (notice|warning|reminder)|last (chance|warning)|time[- ]sensitive|expires? (today|tonight|soon)|failure to (comply|respond|verify|act))\b`) },

  // credential harvesting
  { id: 'verify_credentials', category: 'credential', strong: true, re: rx(String.raw`\b(verify|confirm|validate|re-?verify|update|reset|re-?enter|enter|provide|submit|authenticate|re-?activate|unlock|secure)\b${W}{0,40}\b(password|passcode|credentials?|log-?in details|sign-?in details|username|security (code|question)|one[- ]time (code|password)|otp|identity|account (details|information)|social security)\b`) },
  { id: 'password_expiry_or_quota', category: 'credential', strong: true, re: rx(String.raw`\b(password|mailbox|e-?mail account|account)\b${W}{0,40}\b(expir(e|es|ed|ing)|is full|storage (is )?(full|limit)|quota|exceeded)\b`) },
  { id: 'security_alert_lure', category: 'credential', re: rx(String.raw`\b(unusual|suspicious|unauthori[sz]ed|unrecognized|irregular) (sign[- ]?in|log-?in|activity|access|attempt)\b`) },
  { id: 'signin_call_to_action', category: 'credential', re: rx(String.raw`\b(sign|log)[ -]?in (to|with|here|below|now|again)\b|\bclick (here|below) to (verify|confirm|sign|log|restore|unlock|keep)\b`) },

  // financial requests
  { id: 'update_payment_details', category: 'financial', strong: true, re: rx(String.raw`\b(update|confirm|verify|provide|change|re-?enter)\b${W}{0,40}\b(bank(ing)? (details|account|information)|billing (details|information|address)|payment (details|method|information)|card (number|details|information)|credit card|direct deposit)\b`) },
  { id: 'overdue_payment', category: 'financial', re: rx(String.raw`\b(overdue|outstanding|unpaid|past due)\b${W}{0,30}\b(invoice|payment|balance|bill|amount)\b`) },
  { id: 'refund_lure', category: 'financial', re: rx(String.raw`\b(refund|tax refund|rebate|reimbursement)\b${W}{0,40}\b(claim|pending|eligible|available|waiting|issued|approved)\b`) },
  // bank-transfer vocabulary and account identifiers used worldwide (the company operates in 40+ countries)
  { id: 'transfer_rails', category: 'financial', re: rx(String.raw`\b(wire transfer|bank transfer|telegraphic transfer|ach (transfer|payment|credit|debit)|via ach|by ach|swift( code|/bic)?|bic code|iban|routing number|aba number|sort code|ifsc( code)?|bsb( number)?|clabe|chave pix|pix key|upi id|vpa|neft|rtgs|imps|chaps|fedwire|sepa (transfer|payment|credit)|faster payments?|interac e-?transfer|payid|cnaps|zengin|furikomi|giro transfer|western union|moneygram)\b`) },

  // a direct instruction to pay: by a named payment rail, and/or right now (genuine reminders usually give a due date)
  { id: 'pay_by_rail', category: 'payment_demand', re: rx(String.raw`\b(pay|remit|settle|process|release|send|wire|transfer|make)\b${W}{0,40}\b(via|by|through|using|with|over) (ach|wire( transfer)?|bank transfer|telegraphic transfer|swift|fedwire|zelle|eft|electronic (funds )?transfer|bacs|chaps|faster payments?|sepa( instant)?|ideal|bizum|blik|swish|mobilepay|vipps|neft|rtgs|imps|upi|pix|spei|interac( e-?transfer)?|e-?transfer|payid|osko|npp|bpay|paynow|promptpay|duitnow|instapay|pesonet|fps|bi-?fast|napas|eft ?pos|giro|furikomi|zengin|cnaps|alipay|wechat pay|m-?pesa|western union|moneygram|crypto(currency)?|bitcoin|usdt)\b`) },
  { id: 'pay_urgently', category: 'payment_demand', re: rx(String.raw`\b(pay|remit|settle|process|release|wire|transfer)\b${W}{0,40}\b(today|tonight|immediately|asap|right away|right now|now|urgently|by (eod|end of (the )?day|close of business|cob|noon)|this (morning|afternoon|evening)|within the hour)\b`) },

  // gift cards (a BEC / scam staple: legitimate organisations do not ask for them)
  { id: 'gift_card_request', category: 'gift_card', strong: true, re: rx(String.raw`\b(buy|purchase|get|send|need|pick up|grab)\b${W}{0,50}\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|amazon cards?|prepaid cards?)\b|\b(gift ?cards?)\b${W}{0,40}\b(codes?|numbers?|scratch|photo|picture|back of)\b`) },

  // payment redirection (invoice fraud)
  { id: 'bank_details_changed', category: 'payment_redirection', strong: true, re: rx(String.raw`\b(our|my|the company'?s?|new|updated|changed)\b${W}{0,30}\b(bank(ing)?|account|payment) (details|information|account|number)\b${W}{0,40}\b(has|have|had|is|are|were)? ?(changed|updated|new|moved|different)\b|\b(changed|updated|new|different)\b${W}{0,30}\b(bank(ing)? (details|information|account)|account (details|number))\b`) },
  { id: 'remit_to_new_account', category: 'payment_redirection', strong: true, re: rx(String.raw`\b(remit|send|make|route|wire|transfer|redirect)\b${W}{0,40}\b(payment|funds|the balance|the amount|future payments)\b${W}{0,40}\b(to the (new|following|below|attached)|new account|updated account|account below)\b|\bdo not (use|pay (to|into)) (the )?(old|previous|former) (account|bank)\b`) },

  // payroll diversion
  { id: 'payroll_change', category: 'payroll', strong: true, re: rx(String.raw`\b(payroll|salary|direct deposit|pay ?check|paycheque)\b${W}{0,50}\b(redirect|new (bank|account)|switch(ed)? to|chang(e|ed|ing) (my|our|the|your) (bank|account|details))\b|\b(change|update|switch)\b${W}{0,30}\b(my|our) (direct deposit|payroll|salary|bank)\b`) },

  // business-email-compromise probes (short, link-free asks)
  { id: 'availability_probe', category: 'bec', re: rx(String.raw`\b(are you (available|at your desk|free|in the office|there)|need (a|your) (quick )?(favou?r|help|assistance)|let me know when you('re| are) (available|free)|quick task|are you at your desk)\b`) },
  { id: 'secrecy_or_no_calls', category: 'bec', re: rx(String.raw`\b(keep (this|it) (confidential|between us|quiet)|do not (call|phone)|don'?t call|i('m| am) (in a meeting|travell?ing|unavailable to (talk|call))|only (reach|contact) me (by|via) (e-?mail|text))\b`) },

  // extortion / sextortion
  { id: 'crypto_threat', category: 'extortion', strong: true, re: rx(String.raw`\b(hack(ed)?|recorded|webcam|camera|your (device|computer|phone)|adult (site|video|content)|porn|video of you|your contacts|expose|leak|compromising)\b${W}{0,120}\b(bitcoin|btc|ethereum|usdt|monero|crypto(currency)?)\b|\b(bitcoin|btc|ethereum|usdt|monero|crypto(currency)?)\b${W}{0,120}\b(hack(ed)?|recorded|webcam|camera|expose|leak|video of you|compromising)\b`) },
  { id: 'btc_wallet', category: 'extortion', strong: true, re: /\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/ },

  // delivery notification scams
  { id: 'delivery_problem', category: 'delivery', re: rx(String.raw`\b(package|parcel|shipment|delivery|consignment)\b${W}{0,60}\b(could not|couldn'?t|unable to|failed|on hold|held|pending|undeliverable|missed|returned|customs|redeliver|re-?schedule|address (is )?(incorrect|incomplete))\b`) },
  { id: 'delivery_fee', category: 'delivery', re: rx(String.raw`\b(customs|redelivery|shipping|delivery|handling) (fee|charge|payment)\b`) },

  // advance-fee / prize
  { id: 'prize_or_inheritance', category: 'advance_fee', re: rx(String.raw`\b(you (have )?won|winner|lottery|inheritance|beneficiary|unclaimed (funds|prize)|million (dollars|usd|pounds|euros)|next of kin)\b`) },

  // "someone shared a document with you" lures
  { id: 'document_share', category: 'document_share', re: rx(String.raw`\b(shared|sent)\b${W}{0,20}\b(a |an |the )?(document|file|folder|invoice|proposal|contract|voice ?(mail|message)|fax|secure message)\b|\b(review and sign|view (the )?(document|file|message)|open (the )?(document|file|message)|access (the )?(document|file))\b`) },

  // lures that point at an attachment
  { id: 'attached_lure', category: 'attachment_lure', re: rx(String.raw`\b(attached|attachment|enclosed|find attached|see attached|please find)\b${W}{0,70}\b(invoice|receipt|payment|remittance|purchase order|statement|document|voice ?(mail|message)|fax|scan(ned)?|contract|quote|order|bank slip|swift)\b|\b(invoice|payment (receipt|advice|confirmation)|remittance advice|purchase order|voice ?(mail|message)|fax|scanned document|shipping document|bank slip|swift copy|proforma)\b${W}{0,50}\b(attached|attachment|enclosed)\b`) },

  // QR codes (quishing evades link scanners)
  { id: 'qr_instruction', category: 'qr', re: rx(String.raw`\bscan\b${W}{0,50}\b(qr|code|barcode)\b|\bqr[ -]?code\b${W}{0,60}\b(scan|verify|authenticat|log-?in|sign|mfa|2fa|secure|access)\b|\bscan (this|the|your) (code|barcode) with your (phone|mobile|camera)\b`) },
];

const LABELS: Record<ContentCategoryId, string> = {
  urgency: 'Urgency and threats', credential: 'Credential harvesting', financial: 'Financial request', gift_card: 'Gift-card request', payment_redirection: 'Payment redirection',
  payroll: 'Payroll diversion', bec: 'Business-email-compromise style ask', extortion: 'Extortion', delivery: 'Delivery notification lure', advance_fee: 'Prize / advance-fee lure',
  document_share: 'Document-share lure', attachment_lure: 'Attachment lure', qr: 'QR-code lure', image_only: 'Image-only body', hidden_text: 'Hidden text', obfuscation: 'Text obfuscation', brand: 'Brand impersonation',
  payment_demand: 'Payment instruction', forwarded_thread: 'Forwarded third-party thread',
};

/* ----------------------------------------------------------------- helpers */

const ZERO_WIDTH = /[\u200b\u200c\u200d\u2060\ufeff\u00ad]/g;
const normalise = (s: string) => s.normalize('NFKC').replace(ZERO_WIDTH, '').replace(/[ \t\u00a0]+/g, ' ');

function excerpt(text: string, index: number, length: number): string {
  const from = Math.max(0, index - 35);
  const to = Math.min(text.length, index + length + 45);
  return `${from > 0 ? '…' : ''}${text.slice(from, to).replace(/\s+/g, ' ').trim()}${to < text.length ? '…' : ''}`.slice(0, 160);
}

function latinShareOf(text: string): number {
  const letters = text.match(/\p{L}/gu) ?? [];
  if (!letters.length) return 1;
  const latin = letters.filter((c) => /\p{Script=Latin}/u.test(c)).length;
  return latin / letters.length;
}

/** A word that mixes Latin letters with Cyrillic / Greek look-alikes ("рaypal"): used to slip past keyword filters. */
function mixedScriptWords(text: string): string[] {
  const out: string[] = [];
  for (const w of text.match(/\p{L}{3,}/gu) ?? []) {
    if (/\p{Script=Latin}/u.test(w) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(w)) out.push(w);
    if (out.length >= 5) break;
  }
  return out;
}

/**
 * Look-alike spellings inside the Latin alphabet: "lnvoice" (lowercase L for capital I), "paypa1", "rnicrosoft". Used to
 * slip finance and brand words past keyword filters. Only words that become a known sensitive word after ONE swap are
 * reported, so ordinary text does not trigger it. Returns [as written, intended] pairs.
 */
const SENSITIVE = new Set(['invoice', 'invoices', 'payment', 'payments', 'account', 'accounts', 'verify', 'password', 'remittance', 'statement', 'transfer', 'banking', 'billing', 'urgent', 'overdue', 'microsoft', 'office', 'outlook', 'paypal', 'docusign', 'amazon', 'apple', 'netflix', 'login', 'signin', 'wallet', 'refund', 'receipt', 'payroll', 'mailbox']);
const SWAPS: [string, string][] = [['l', 'i'], ['I', 'l'], ['1', 'l'], ['1', 'i'], ['0', 'o'], ['rn', 'm'], ['vv', 'w'], ['5', 's'], ['3', 'e']];
export function latinLookalikes(text: string): [string, string][] {
  const out: [string, string][] = [];
  const seen = new Set<string>();
  const tokens = text.match(/[A-Za-z0-9]{4,24}/g) ?? [];
  for (const t of tokens.slice(0, 6000)) {
    if (out.length >= 5) break;
    if (seen.has(t)) continue;
    seen.add(t);
    const lower = t.toLowerCase();
    if (SENSITIVE.has(lower)) continue;
    // reference numbers written with a lowercase L where "INV" belongs: "lNVP917891", "lnv-4411"
    if (/^l(?:NV|nv)[A-Za-z]?[-_]?\d{3,}/.test(t)) { out.push([t, `I${t.slice(1)}`]); continue; }
    let hit: string | null = null;
    for (const [from, to] of SWAPS) {
      for (let i = t.indexOf(from); i >= 0 && !hit; i = t.indexOf(from, i + 1)) {
        const cand = (t.slice(0, i) + to + t.slice(i + from.length)).toLowerCase();
        if (SENSITIVE.has(cand)) hit = cand;
      }
      if (hit) break;
    }
    if (hit) out.push([t, hit]);
  }
  return out;
}

/**
 * A forwarded or quoted e-mail header block inside the body ("From: … Sent: … To: … Subject: …"). Returns the quoted
 * sender's address and how much text sits above it (the forwarder's own note).
 */
export function quotedThread(body: string): { address: string; domain: string; noteChars: number } | null {
  const m = /(^|\n)[ \t>]*(?:-{2,}\s*(?:original|forwarded) message\s*-{2,}\s*\n[ \t>]*)?(?:from|de|von)\s*:[^\n]*?([\w.+-]+@((?:[\w-]+\.)+[a-z]{2,}))[^\n]*\n(?:[^\n]*\n){0,2}?[ \t>]*(?:sent|date|envoy[ée]|gesendet)\s*:/i.exec(body);
  if (!m) return null;
  const note = body.slice(0, m.index).replace(/\s+/g, ' ').trim();
  return { address: m[2].toLowerCase(), domain: m[3].toLowerCase(), noteChars: note.length };
}

/** Amount of text hidden with CSS. Linear: only the first 500 KB is scanned and only 40 hidden blocks are measured. */
function hiddenText(htmlIn: string): number {
  const html = htmlIn.length > 500_000 ? htmlIn.slice(0, 500_000) : htmlIn;
  if (!/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|max-height\s*:\s*0|mso-hide\s*:\s*all/i.test(html)) return 0;
  const lower = html.toLowerCase();
  let total = 0;
  let blocks = 0;
  eachTag(html, ['span', 'div', 'p', 'td', 'font'], 20_000, (name, attrs, _start, end) => {
    if (blocks >= 40) return;
    if (!/style\s*=\s*["'][^"']{0,500}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|max-height\s*:\s*0|mso-hide\s*:\s*all)/i.test(attrs)) return;
    blocks++;
    const close = lower.indexOf(`</${name}`, end);
    const inner = html.slice(end, close < 0 ? end + 2000 : Math.min(close, end + 20_000));
    total += stripTags(inner).replace(/&[a-z#0-9]+;/gi, ' ').replace(/[\s\u200b-\u200d\u2060\ufeff]+/g, ' ').trim().length;
  });
  return total;
}

/* -------------------------------------------------------------------- main */

export function analyzeContent(input: ContentInput): { analysis: ContentAnalysis; findings: Finding[] } {
  const findings: Finding[] = [];
  const notes: string[] = [];
  const subject = normalise(input.subject ?? '');
  const body = normalise(input.text ?? '');
  const hay = subject && body ? `${subject}\n${body}` : subject || body;

  const analysis: ContentAnalysis = { analysed: !!hay.trim(), chars: hay.length, latinShare: 1, languageSupported: true, categories: [], intents: [], notes };
  if (!analysis.analysed) {
    notes.push('There is no message text to read, so wording could not be assessed.');
    return { analysis, findings };
  }

  analysis.latinShare = latinShareOf(hay);
  const letterCount = (hay.match(/\p{L}/gu) ?? []).length;
  if (letterCount >= 30 && analysis.latinShare < 0.6) {
    analysis.languageSupported = false;
    notes.push('Most of the text is not in Latin script. The wording rules read English, so few indicators here does NOT mean the message is clean.');
    findings.push(makeFinding({ id: 'content_language_not_analysed', dimension: 'content', severity: 'info', title: 'Message wording could not be analysed in this language', detail: 'The wording rules are written for English. Judge this message on its sender, links and attachments, or have someone who reads the language review it.', source: 'content-rules', exactness: 'exact', reliability: 'high' }));
  }

  const cats = new Map<ContentCategoryId, ContentCategory>();
  const addMatch = (id: ContentCategoryId, rule: string, text: string, index: number, length: number, strong = false) => {
    const c = cats.get(id) ?? { id, label: LABELS[id], strong: false, matches: [] };
    if (strong) c.strong = true;
    if (c.matches.length < 4 && !c.matches.some((m) => m.rule === rule)) c.matches.push({ rule, excerpt: excerpt(text, index, length) });
    cats.set(id, c);
  };

  /* look-alike spellings ("lnvoice"): note them, then read the text as intended so the other rules are not evaded */
  const filenames = input.attachments.filter((a) => !a.inline && a.filename).map((a) => a.filename as string).join(' ');
  const lookalikes = latinLookalikes(`${hay}\n${filenames}`);
  let read = hay;
  for (const [as, meant] of lookalikes) read = read.split(as).join(meant);

  for (const r of RULES) {
    // wire-style rules run on the whole text; the first hit per rule is enough to quote
    const m = r.re.exec(read);
    if (m) addMatch(r.category, r.id, read, m.index, m[0].length, !!r.strong);
  }
  /* a payment instruction that names a rail AND demands it now is the strong form ("Please pay via ACH today") */
  const pd = cats.get('payment_demand');
  if (pd && pd.matches.some((x) => x.rule === 'pay_by_rail') && pd.matches.some((x) => x.rule === 'pay_urgently')) pd.strong = true;

  /* forwarded third-party thread: a short note above a quoted e-mail from an unrelated organisation */
  const thread = quotedThread(body);
  const fromReg = registrableOf(input.fromDomain);
  if (thread && fromReg && registrableOf(thread.domain) !== fromReg && thread.noteChars <= 400) {
    addMatch('forwarded_thread', 'forwarded_external_thread', body, Math.max(0, body.toLowerCase().indexOf(thread.address)), thread.address.length);
  }

  /* BEC: a short, link-free request is the signal; long newsletters that say "quick task" are not */
  const bec = cats.get('bec');
  if (bec && (input.linkCount > 0 || body.length > 900)) cats.delete('bec');

  /* gift cards need the request wording, not just a mention (handled by the rule) */

  /* attachment lure without an attachment */
  const hasAttachment = input.attachments.some((a) => !a.inline);
  if (cats.has('attachment_lure') && !hasAttachment) notes.push('The text refers to an attachment, but none was included in what you pasted. Attach it (or paste the full .eml) to have it checked.');

  /* image-only body: QR codes and text-in-images evade every text and link rule */
  const inlineImages = input.attachments.filter((a) => a.inline && (a.declaredType ?? '').startsWith('image/')).length;
  const prose = body.replace(/https?:\/\/\S+/gi, '').replace(/\s+/g, ' ').trim();
  if (inlineImages > 0 && prose.length < 60) {
    cats.set('image_only', { id: 'image_only', label: LABELS.image_only, strong: false, matches: [{ rule: 'image_only', excerpt: `${inlineImages} embedded image(s) and only ${prose.length} characters of text` }] });
  }

  /* hidden text */
  if (input.html) {
    const hidden = hiddenText(input.html);
    if (hidden > 150) cats.set('hidden_text', { id: 'hidden_text', label: LABELS.hidden_text, strong: false, matches: [{ rule: 'hidden_text', excerpt: `${hidden} characters of text are hidden with CSS (display:none, zero font size, ...)` }] });
  }

  /* obfuscation: look-alike letters and invisible characters inside words */
  const mixed = mixedScriptWords(hay);
  const zw = ((input.text ?? '') + (input.subject ?? '')).match(ZERO_WIDTH)?.length ?? 0;
  if (mixed.length) cats.set('obfuscation', { id: 'obfuscation', label: LABELS.obfuscation, strong: true, matches: [{ rule: 'mixed_script', excerpt: `Words mixing Latin with Cyrillic / Greek letters: ${mixed.join(', ')}` }] });
  else if (lookalikes.length) cats.set('obfuscation', { id: 'obfuscation', label: LABELS.obfuscation, strong: true, matches: [{ rule: 'latin_lookalike', excerpt: `Look-alike spellings: ${lookalikes.map(([a, b]) => `"${a}" (${b})`).join(', ')}` }] });
  else if (zw >= 6) cats.set('obfuscation', { id: 'obfuscation', label: LABELS.obfuscation, strong: false, matches: [{ rule: 'zero_width', excerpt: `${zw} invisible characters inside the text` }] });

  /* brand impersonation in the wording (the display-name case is covered by the identity analysis) */
  // a lure that makes a QR code or a brand mention suspicious: weak urgency words alone ("sale ends today") do not count
  const lureNow = [...cats.values()].some((k) => ['credential', 'financial', 'payment_redirection', 'document_share'].includes(k.id) || (k.id === 'urgency' && k.strong));
  const reg = registrableOf(input.fromDomain);
  if (reg) {
    const display = normalise(input.displayName ?? '').toLowerCase();
    const sub = subject.toLowerCase();
    const lower = body.toLowerCase();
    for (const brand of Object.keys(BRANDS)) {
      if (brand.length < 5 || isOfficial(brand, input.fromDomain ?? '', reg)) continue;
      const word = new RegExp(`\\b${brand}\\b`, 'g');
      if (display.includes(brand)) continue;
      const inSubject = word.test(sub);
      const count = (lower.match(word) ?? []).length;
      if (inSubject || (count >= 2 && lureNow)) {
        const idx = lower.search(new RegExp(`\\b${brand}\\b`));
        addMatch('brand', `brand_${brand}`, idx >= 0 ? body : subject, idx >= 0 ? idx : 0, brand.length, true);
        break;
      }
    }
  }

  analysis.categories = [...cats.values()];

  /* ------------------------------------------------------------ findings */
  const ev = (c: ContentCategory) => c.matches.map((m) => m.excerpt);
  // specific, high-precision patterns (a request for gift cards, a change of bank details, a crypto threat) are more reliable than general lure wording
  const SPECIFIC = new Set(['content_gift_card_request', 'content_payment_redirection', 'content_payroll_diversion', 'content_extortion', 'content_brand_impersonation', 'content_text_obfuscation']);
  const F = (id: string, c: ContentCategory, severity: Severity, title: string, detail: string) =>
    findings.push(makeFinding({ id, dimension: 'content', severity, title, detail, source: 'content-rules', exactness: 'exact', reliability: SPECIFIC.has(id) || (id === 'content_bec_request' && input.fromIsFreeMail) ? 'medium' : 'low', evidence: ev(c) }));
  const get = (id: ContentCategoryId) => cats.get(id);
  let c: ContentCategory | undefined;

  if ((c = get('urgency'))) F('content_urgency', c, c.strong ? 'low' : 'info', c.strong ? 'Urgent wording that threatens consequences' : 'Urgent wording', 'Pressure to act quickly is a staple of phishing, and also of ordinary billing and security notices. Weigh it with the sender and links.');
  if ((c = get('credential'))) F('content_credential_request', c, 'low', c.strong ? 'Asks you to verify, reset or re-enter account credentials' : 'Account-security wording', 'Genuine password resets and security alerts use this language too: check whether the sign-in link goes to the real service.');
  if ((c = get('financial'))) F('content_financial_request', c, 'low', 'Asks about bank, card or payment details', 'Requests to confirm or update payment information are a common fraud pretext.');
  if ((c = get('gift_card'))) F('content_gift_card_request', c, 'medium', 'Asks for gift cards', 'Legitimate organisations do not ask staff or customers to buy gift cards or send their codes. This is a classic scam and BEC request.');
  if ((c = get('payment_redirection'))) F('content_payment_redirection', c, 'medium', 'Says bank details have changed or asks for payment to a new account', 'Invoice-redirection fraud depends on exactly this message. Confirm any change by phoning a known number, not one from the message.');
  if ((c = get('payroll'))) F('content_payroll_diversion', c, 'medium', 'Asks to change payroll or direct-deposit details', 'Payroll diversion attacks impersonate an employee to move their salary to an attacker account. Verify with the employee in person or by phone.');
  if ((c = get('bec'))) F('content_bec_request', c, input.fromIsFreeMail ? 'medium' : 'low', 'Short, link-free request typical of business-email-compromise', `${input.fromIsFreeMail ? 'It comes from a consumer mailbox, which strengthens the pattern. ' : ''}Attackers start with a harmless-looking ask ("are you available?") before the real request.`);
  if ((c = get('extortion'))) F('content_extortion', c, 'medium', 'Extortion or sextortion pattern', 'Threats to expose material unless a cryptocurrency payment is made are almost always bulk scams: the claims about hacking or recordings are untrue.');
  if ((c = get('delivery'))) F('content_delivery_scam', c, 'low', 'Parcel-delivery problem notice', 'Failed-delivery messages are a common lure for credential and card theft. Check the carrier on its own website.');
  if ((c = get('advance_fee'))) F('content_advance_fee', c, 'low', 'Prize, inheritance or windfall wording', 'Unsolicited windfalls that require a fee or personal details are advance-fee fraud.');
  if ((c = get('document_share'))) F('content_document_share_lure', c, 'low', 'Document, voicemail or fax "shared with you" wording', 'These lures lead to fake Microsoft / DocuSign / Dropbox sign-in pages. Legitimate share notices exist too: check where the button leads.');
  if ((c = get('attachment_lure'))) F('content_attachment_lure', c, 'low', 'Wording that pushes you to open an attached invoice, receipt or voicemail', 'Invoice, receipt, remittance and voicemail lures are the most common cover for malicious attachments.');
  if ((c = get('qr'))) F('content_qr_lure', c, lureNow ? 'medium' : 'low', 'Tells you to scan a QR code', 'QR codes hide the destination from link scanners and move the attack to your phone, which is less protected. Treat unexpected QR codes asking you to sign in as phishing.');
  if ((c = get('image_only'))) F('content_image_only_body', c, 'low', 'Message is mostly images', 'Text rendered as an image, or a QR code, bypasses text and link analysis. Look at the message itself.');
  if ((c = get('hidden_text'))) F('content_hidden_text', c, 'low', 'Large amount of hidden text', 'Hidden text is used to dilute spam filters. Marketing pre-headers are short; this much hidden text is unusual.');
  if ((c = get('obfuscation'))) F('content_text_obfuscation', c, c.strong ? 'medium' : 'low', c.matches[0].rule === 'latin_lookalike' ? 'Key words are spelt with look-alike characters (such as "lnvoice" for "invoice")' : c.strong ? 'Words mix look-alike letters from other alphabets' : 'Invisible characters inside the text', 'Look-alike letters and invisible characters are used to slip words past keyword filters. Genuine senders have no reason to misspell their own invoice or brand.');
  if ((c = get('payment_demand'))) F('content_payment_demand', c, c.strong ? 'medium' : 'low', c.strong ? 'Instructs you to pay now by a specific method (such as "pay via ACH today")' : 'Instructs you to make a payment', 'A direct instruction to send money, especially immediately and by a named transfer method, is the core of invoice and business-email-compromise fraud. Genuine reminders give a due date and are verified through known contacts.');
  if ((c = get('forwarded_thread'))) F('content_forwarded_thread', c, 'low', 'Forwards an e-mail thread from an unrelated organisation with only a short note', 'Fraudsters paste a fabricated "forwarded" conversation (often an invoice) to make a request look already approved. Check the original with the named organisation directly.');
  if ((c = get('brand'))) F('content_brand_impersonation', c, 'medium', `The message speaks as ${c.matches[0].rule.replace('brand_', '')} but the sender is not ${c.matches[0].rule.replace('brand_', '')}`, `The subject or text uses the ${c.matches[0].rule.replace('brand_', '')} brand while the sender domain (${reg ?? 'unknown'}) is not one of that brand's domains.`);

  /* combination: several different lures together are what separates phishing from an ordinary notice */
  const LURES: ContentCategoryId[] = ['urgency', 'credential', 'financial', 'gift_card', 'payment_redirection', 'payroll', 'extortion', 'delivery', 'advance_fee', 'document_share', 'attachment_lure', 'qr', 'payment_demand', 'forwarded_thread'];
  const present = LURES.filter((k) => cats.has(k));
  if (present.length >= 3) {
    findings.push(makeFinding({
      id: 'content_multiple_lure_signals', dimension: 'content', severity: 'medium', title: `${present.length} different lure types appear together`,
      detail: `The wording combines ${present.map((k) => LABELS[k].toLowerCase()).join(', ')}. One of these alone is common in genuine mail; the combination is characteristic of phishing.`,
      source: 'content-rules', exactness: 'exact', reliability: 'low', evidence: present.slice(0, 4).map((k) => `${LABELS[k]}: ${cats.get(k)!.matches[0].excerpt}`),
    }));
  }

  /* ------------------------------------------------------------- intents */
  const intents: ContentIntent[] = [];
  const has = (k: ContentCategoryId) => cats.has(k);
  const conf = (n: number): ContentIntent['confidence'] => (n >= 3 ? 'high' : n === 2 ? 'medium' : 'low');
  const pushIntent = (id: IntentId, label: string, reasons: ContentCategoryId[]) => { const r = reasons.filter(has); if (r.length) intents.push({ id, label, confidence: conf(r.length + (r.some((k) => cats.get(k)!.strong) ? 1 : 0)), reasons: r.map((k) => LABELS[k]) }); };
  pushIntent('credential_harvesting', 'Credential harvesting', ['credential', 'urgency', 'document_share', 'qr']);
  pushIntent('financial_fraud', 'Financial fraud / payment redirection', ['payment_redirection', 'payment_demand', 'financial', 'payroll', 'gift_card', 'urgency']);
  pushIntent('business_email_compromise', 'Business email compromise', ['bec', 'gift_card', 'payment_redirection', 'payroll', 'payment_demand', 'forwarded_thread']);
  pushIntent('delivery_scam', 'Delivery notification scam', ['delivery']);
  pushIntent('malware_delivery', 'Malware delivery via attachment', ['attachment_lure', 'document_share']);
  pushIntent('extortion', 'Extortion', ['extortion']);
  pushIntent('account_impersonation', 'Brand / account impersonation', ['brand']);
  pushIntent('advance_fee', 'Advance-fee / prize scam', ['advance_fee']);
  const rank = { high: 0, medium: 1, low: 2 } as const;
  analysis.intents = intents.sort((a, b) => rank[a.confidence] - rank[b.confidence]);
  if (!analysis.intents.length) analysis.intents = [{ id: 'unknown', label: 'No phishing intent recognised from the wording', confidence: 'low', reasons: [] }];

  return { analysis, findings };
}
