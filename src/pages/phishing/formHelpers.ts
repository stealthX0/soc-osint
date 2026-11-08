import { LIMITS, type PhishingInput } from '../../../shared/phishing/types';

export interface FormFields { headers: string; subject: string; body: string; email: string; displayName: string; domain: string; ip: string; urls: string; attachments: string }
export const EMPTY_FORM: FormFields = { headers: '', subject: '', body: '', email: '', displayName: '', domain: '', ip: '', urls: '', attachments: '' };

const HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
export function parseAttachmentLines(text: string): { name?: string; hash?: string }[] {
  return text.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
    const tokens = line.split(/[\s,|]+/).filter(Boolean);
    const hash = tokens.find((t) => HASH.test(t));
    const name = tokens.filter((t) => t !== hash).join(' ');
    return { ...(name ? { name } : {}), ...(hash ? { hash } : {}) };
  });
}

export function buildInput(f: FormFields): PhishingInput {
  return {
    headers: f.headers, subject: f.subject, body: f.body,
    sender: { email: f.email, displayName: f.displayName, domain: f.domain, ip: f.ip },
    urls: f.urls.split('\n').map((u) => u.trim()).filter(Boolean),
    attachments: parseAttachmentLines(f.attachments),
  };
}

/* ------------------------------------------------------------------- .eml files */

export const EML_MAX_BYTES = 3 * 1024 * 1024;
const mb = (n: number) => `${(n / (1024 * 1024)).toFixed(1)} MB`;

/** Size gate for a dropped or chosen .eml file (3 MB). */
export function checkEmlFile(file: { name: string; size: number }): { ok: true } | { ok: false; message: string } {
  if (file.size === 0) return { ok: false, message: `${file.name} is empty.` };
  if (file.size > EML_MAX_BYTES) return { ok: false, message: `${file.name} is ${mb(file.size)}. Files larger than ${mb(EML_MAX_BYTES)} are not loaded: export the message without large attachments, or paste its headers and body.` };
  return { ok: true };
}
export const emlLoadedMessage = (name: string, bytes: number): string => `Loaded ${name}: ${bytes.toLocaleString('en-US')} bytes placed in the raw headers box.`;

/* ------------------------------------------------------- files attached in the form */

/** Most files that can be attached to one analysis (each is hashed in the browser and looked up by hash). */
export const MAX_ATTACHED_FILES = 5;

/** Adds chosen files to the attached list, skipping duplicates and anything over the per-file or count limit. Returns the new list and what was refused. */
export function addAttachedFiles(current: File[], chosen: File[], maxBytes: number, fmt: (n: number) => string): { files: File[]; errors: string[] } {
  const files = [...current];
  const errors: string[] = [];
  for (const f of chosen) {
    if (files.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified)) continue;
    if (f.size === 0) { errors.push(`${f.name} is empty.`); continue; }
    if (f.size > maxBytes) { errors.push(`${f.name} is ${fmt(f.size)}. Files over ${fmt(maxBytes)} cannot be analysed in the browser: compute its SHA-256 yourself and add it to the box instead.`); continue; }
    if (files.length >= MAX_ATTACHED_FILES) { errors.push(`At most ${MAX_ATTACHED_FILES} files can be attached; ${f.name} was not added.`); continue; }
    files.push(f);
  }
  return { files, errors };
}

/* ------------------------------------------------------------ input sanity checks */

/** Text pasted into the headers box that has no header lines at all, so it is probably the message body. */
export function looksLikeBody(text: string): boolean {
  const lines = text.split(/\r?\n/).filter((l) => l.trim()).slice(0, 12);
  if (lines.join('').length < 40) return false;
  if (/^\s*</.test(lines[0])) return true;
  return !lines.some((l) => /^[A-Za-z][A-Za-z0-9-]*:(?:[ \t]|$)/.test(l) && !/^\s/.test(l));
}

export interface SizeReport { requestBytes: number; requestLimit: number; remaining: number; headerBytes: number; headerLimit: number; bodyChars: number; bodyLimit: number; level: 'ok' | 'warn' | 'over' }
const enc = new TextEncoder();

/** How much of the size limits the current form uses (the parse request is limited as a whole). */
export function measureForm(f: FormFields): SizeReport {
  const requestBytes = enc.encode(JSON.stringify(buildInput(f))).length;
  const headerPart = f.headers.split(/\r?\n\r?\n/)[0] ?? '';
  const headerBytes = enc.encode(headerPart).length;
  const bodyChars = f.body.length + Math.max(0, f.headers.length - headerPart.length);
  const remaining = LIMITS.requestBytes - requestBytes;
  const over = remaining < 0 || headerBytes > LIMITS.headerBytes || bodyChars > LIMITS.bodyChars;
  const warn = remaining < LIMITS.requestBytes * 0.1 || headerBytes > LIMITS.headerBytes * 0.9;
  return { requestBytes, requestLimit: LIMITS.requestBytes, remaining, headerBytes, headerLimit: LIMITS.headerBytes, bodyChars, bodyLimit: LIMITS.bodyChars, level: over ? 'over' : warn ? 'warn' : 'ok' };
}

export const fmtKB = (n: number): string => (n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)} MB` : `${Math.max(0, Math.round(n / 1000))} KB`);

/* --------------------------------------------------------------- training sample */

/** A clearly fake training phishing message: reserved *.example domains and documentation IPs (203.0.113.0/24). */
export const EXAMPLE_FORM: FormFields = {
  headers: [
    'Received: from mail-gw.paypa1-secure.example (mail-gw.paypa1-secure.example [203.0.113.45])',
    '\tby mx.example.com with ESMTPS id TRAINING0001 for <victim@example.com>;',
    '\tFri, 06 Nov 2026 08:14:22 +0000',
    'Authentication-Results: mx.example.com;',
    '\tspf=fail smtp.mailfrom=bounce.paypa1-secure.example;',
    '\tdkim=none;',
    '\tdmarc=fail (p=none) header.from=paypal-support.example',
    'From: "PayPal Support" <support@paypal-support.example>',
    'Reply-To: <recovery-desk@mailbox-help.example>',
    'Return-Path: <bounce@bounce.paypa1-secure.example>',
    'To: victim@example.com',
    'Subject: Action required: your account will be suspended today',
    'Date: Fri, 06 Nov 2026 08:14:20 +0000',
    'Message-ID: <training-sample-0001@paypa1-secure.example>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
  ].join('\n'),
  subject: '',
  body: [
    'TRAINING SAMPLE. This is not a real message; every address and link in it is fictional (reserved example domains).',
    '',
    'Dear customer,',
    '',
    'We detected unusual activity and your account will be suspended within 24 hours unless you verify your password and confirm your payment details.',
    '',
    'Verify your account now: https://paypa1-secure.example/verify/account',
    '',
    'Failure to act immediately will result in permanent closure.',
    '',
    'PayPal Security Team',
  ].join('\n'),
  email: 'support@paypal-support.example',
  displayName: 'PayPal Support',
  domain: 'paypal.com',
  ip: '203.0.113.45',
  urls: '',
  attachments: 'Invoice_4491.pdf.exe',
};
