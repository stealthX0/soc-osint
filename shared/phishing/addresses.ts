/** RFC 5322 address-list parsing (display names, quoted strings, comments) and RFC 2047 encoded-word decoding. */
import { parseEmail } from '../domain';
import { registrableOf } from './domains';

function b64ToBytes(s: string): Uint8Array {
  const clean = s.replace(/[^A-Za-z0-9+/_-]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(clean + '='.repeat((4 - (clean.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Quoted-printable to bytes. `header` mode is RFC 2047 "Q" encoding (underscore = space, no soft line breaks). */
export function qpToBytes(s: string, header = false): Uint8Array {
  const t = header ? s.replace(/_/g, ' ') : s.replace(/=\r?\n/g, '');
  const enc = new TextEncoder();
  const out: number[] = [];
  for (const part of t.split(/(=[0-9A-Fa-f]{2})/)) {
    if (/^=[0-9A-Fa-f]{2}$/.test(part)) out.push(parseInt(part.slice(1), 16));
    else for (const b of enc.encode(part)) out.push(b);
  }
  return Uint8Array.from(out);
}

export function decodeBytes(bytes: Uint8Array, charset: string | null | undefined): string {
  try {
    return new TextDecoder(charset?.trim().toLowerCase() || 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

export { b64ToBytes };

const WORD = /=\?([^?\s]+?)(?:\*[\w-]+)?\?([bq])\?([^?]*)\?=/gi;

/** Decodes "=?UTF-8?B?...?=" / "=?utf-8?Q?...?=" words anywhere in a header value. */
export function decodeMimeWords(s: string): string {
  if (!s || !s.includes('=?')) return s;
  const joined = s.replace(/(\?=)\s+(?==\?)/g, '$1'); // whitespace between adjacent encoded words is not part of the text
  return joined.replace(WORD, (m, charset: string, enc: string, text: string) => {
    try {
      return decodeBytes(enc.toLowerCase() === 'b' ? b64ToBytes(text) : qpToBytes(text, true), charset);
    } catch {
      return m;
    }
  });
}

export interface Mailbox {
  raw: string;
  display: string | null;
  address: string | null;
  local: string | null;
  /** ASCII (punycode) domain, validated. */
  domain: string | null;
  registrable: string | null;
}

function splitList(v: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = false;
  let angle = false;
  let comment = 0;
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '\\' && i + 1 < v.length) { cur += c + v[++i]; continue; }
    if (comment) { if (c === '(') comment++; else if (c === ')') comment--; cur += c; continue; }
    if (quote) { if (c === '"') quote = false; cur += c; continue; }
    if (c === '"') quote = true;
    else if (c === '(') comment++;
    else if (c === '<') angle = true;
    else if (c === '>') angle = false;
    else if ((c === ',' || c === ';') && !angle) { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function parseMailbox(raw: string): Mailbox {
  const decoded = decodeMimeWords(raw.trim());
  const noComments = decoded.replace(/\((?:[^()\\]|\\.)*\)/g, ' ');
  const angle = noComments.match(/<([^<>]*)>\s*$/) ?? noComments.match(/<([^<>]*)>/);
  let display: string | null = null;
  let addrText: string;
  if (angle) {
    addrText = angle[1].trim();
    display = noComments.slice(0, angle.index).trim().replace(/^"([\s\S]*)"$/, '$1').replace(/\\(.)/g, '$1').trim() || null;
  } else {
    addrText = noComments.trim().replace(/^"|"$/g, '');
  }
  addrText = addrText.replace(/^mailto:/i, '').replace(/^<|>$/g, '').trim();
  const parsed = parseEmail(addrText);
  return {
    raw: raw.trim(),
    display,
    address: parsed ? `${parsed.local}@${parsed.domain}` : null,
    local: parsed?.local ?? null,
    domain: parsed?.domain ?? null,
    registrable: parsed ? registrableOf(parsed.domain) : null,
  };
}

export const parseAddressList = (v: string | null | undefined): Mailbox[] => (v ? splitList(v).map(parseMailbox).filter((m) => m.address || m.display || m.raw) : []);
