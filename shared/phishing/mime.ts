/**
 * MIME parsing for pasted e-mail: multipart trees, transfer decoding, charsets, text/HTML bodies and attachments.
 * Pure and bounded (part count, depth); nothing here executes or renders content.
 */
import { parseHeaderBlock } from '../headers';
import { b64ToBytes, decodeBytes, decodeMimeWords, qpToBytes } from './addresses';
import { htmlToText, looksLikeHtml } from './html';
import { LIMITS } from './types';

export interface HeaderValue { value: string; params: Record<string, string> }

/** "multipart/mixed; boundary=abc" -> { value, params }. Handles quoting and RFC 2231 (filename*=UTF-8''...) forms. */
export function parseHeaderValue(v: string): HeaderValue {
  const chunks: string[] = [];
  let cur = '';
  let quote = false;
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '\\' && quote && i + 1 < v.length) { cur += c + v[++i]; continue; }
    if (c === '"') quote = !quote;
    if (c === ';' && !quote) { chunks.push(cur); cur = ''; continue; }
    cur += c;
  }
  chunks.push(cur);
  const value = (chunks.shift() ?? '').trim().toLowerCase();
  const raw: Record<string, string> = {};
  for (const ch of chunks) {
    const i = ch.indexOf('=');
    if (i < 1) continue;
    const name = ch.slice(0, i).trim().toLowerCase();
    let val = ch.slice(i + 1).trim();
    if (val.startsWith('"')) val = val.replace(/^"([\s\S]*?)"\s*$/, '$1').replace(/\\(.)/g, '$1');
    if (!(name in raw)) raw[name] = val;
  }
  const params: Record<string, string> = {};
  const continued = new Map<string, { n: number; v: string; ext: boolean }[]>();
  for (const [name, val] of Object.entries(raw)) {
    const m = name.match(/^([^*]+)\*(\d+)?(\*)?$/);
    if (!m) { params[name] = val; continue; }
    const [, base, idx, ext] = m;
    if (idx === undefined) { params[base] = decodeExt(val); continue; }
    const list = continued.get(base) ?? [];
    list.push({ n: Number(idx), v: val, ext: !!ext });
    continued.set(base, list);
  }
  for (const [base, list] of continued) {
    list.sort((a, b) => a.n - b.n);
    params[base] ??= list.map((p, i) => (i === 0 && p.ext ? decodeExt(p.v) : p.ext ? decodePct(p.v) : p.v)).join('');
  }
  return { value, params };
}

function decodePct(s: string, charset = 'utf-8'): string {
  const bytes = Uint8Array.from(s.replace(/%([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0));
  return decodeBytes(bytes, charset);
}
function decodeExt(s: string): string {
  const m = s.match(/^([^']*)'[^']*'([\s\S]*)$/);
  return m ? decodePct(m[2], m[1] || 'utf-8') : s;
}

export interface MimePart {
  contentType: string;
  params: Record<string, string>;
  disposition: string | null;
  filename: string | null;
  contentId: string | null;
  encoding: string;
  /** Decoded text for text/* parts, else null. */
  text: string | null;
  /** Decoded bytes for non-text parts, else null. */
  bytes: Uint8Array | null;
  children: MimePart[];
}

const hv = (pairs: [string, string][], name: string) => pairs.find(([n]) => n.toLowerCase() === name)?.[1] ?? null;

function splitHeadBody(t: string): { head: string; body: string } {
  if (t.startsWith('\n')) return { head: '', body: t.slice(1) };
  if (!/^[!-9;-~]+:/.test(t)) return { head: '', body: t }; // does not start with a header line
  const i = t.indexOf('\n\n');
  return i < 0 ? { head: t, body: '' } : { head: t.slice(0, i), body: t.slice(i + 2) };
}

function splitMultipart(body: string, boundary: string): string[] {
  const delim = `--${boundary}`;
  const parts: string[][] = [];
  let cur: string[] | null = null;
  for (const line of body.replace(/\r\n?/g, '\n').split('\n')) {
    const t = line.trimEnd();
    if (t === delim) { if (cur) parts.push(cur); cur = []; continue; }
    if (t === `${delim}--`) { if (cur) parts.push(cur); cur = null; break; }
    cur?.push(line);
  }
  if (cur) parts.push(cur); // tolerate a truncated paste with no closing boundary
  return parts.map((p) => p.join('\n'));
}

interface Budget { parts: number; warnings: string[] }

function decodeLeaf(contentType: string, encoding: string, charset: string | null, body: string): { text: string | null; bytes: Uint8Array | null } {
  const isText = contentType.startsWith('text/');
  const enc = encoding.toLowerCase();
  let bytes: Uint8Array | null = null;
  if (enc === 'base64') {
    try { bytes = b64ToBytes(body); } catch { bytes = null; }
  } else if (enc === 'quoted-printable') {
    bytes = qpToBytes(body);
  }
  if (isText) {
    if (bytes) return { text: decodeBytes(bytes, charset), bytes: null };
    // 7bit / 8bit / binary: the pasted string is already text
    return { text: enc === 'base64' ? '' : body, bytes: null };
  }
  return { text: null, bytes: bytes ?? new TextEncoder().encode(body) };
}

function parsePart(pairs: [string, string][], body: string, depth: number, budget: Budget): MimePart {
  budget.parts++;
  const ct = parseHeaderValue(hv(pairs, 'content-type') ?? 'text/plain');
  const cd = hv(pairs, 'content-disposition');
  const disp = cd ? parseHeaderValue(cd) : null;
  const encoding = (hv(pairs, 'content-transfer-encoding') ?? '7bit').trim().toLowerCase();
  const rawName = disp?.params.filename ?? ct.params.name ?? null;
  const part: MimePart = {
    contentType: ct.value || 'text/plain',
    params: ct.params,
    disposition: disp?.value || null,
    filename: rawName ? decodeMimeWords(rawName).trim() || null : null,
    contentId: hv(pairs, 'content-id')?.replace(/[<>\s]/g, '') || null,
    encoding,
    text: null,
    bytes: null,
    children: [],
  };

  if (part.contentType.startsWith('multipart/') && ct.params.boundary) {
    if (depth >= LIMITS.mimeDepth) { budget.warnings.push('MIME nesting deeper than the supported limit was not parsed.'); return part; }
    for (const raw of splitMultipart(body, ct.params.boundary)) {
      if (budget.parts >= LIMITS.mimeParts) { budget.warnings.push('MIME part limit reached; remaining parts were not parsed.'); break; }
      const { head, body: pb } = splitHeadBody(raw);
      part.children.push(parsePart(head ? parseHeaderBlock(head) : [], pb, depth + 1, budget));
    }
    return part;
  }
  const leaf = decodeLeaf(part.contentType, encoding, ct.params.charset ?? null, body);
  part.text = leaf.text;
  part.bytes = leaf.bytes;
  return part;
}

export interface RawAttachment {
  filename: string | null;
  declaredType: string;
  inline: boolean;
  size: number;
  bytes: Uint8Array | null;
}

export interface ExtractedMessage {
  text: string;
  html: string | null;
  bodyKind: 'none' | 'plain' | 'html' | 'multipart';
  attachments: RawAttachment[];
  partCount: number;
  truncated: boolean;
  warnings: string[];
}

/**
 * @param pairs  top-level header [name, value] pairs (Content-Type / Content-Transfer-Encoding decide how the body is read)
 * @param body   the body exactly as pasted
 */
export function extractMessage(pairs: [string, string][], body: string): ExtractedMessage {
  const budget: Budget = { parts: 0, warnings: [] };
  const trimmed = body.replace(/\r\n?/g, '\n');
  if (!trimmed.trim()) return { text: '', html: null, bodyKind: 'none', attachments: [], partCount: 0, truncated: false, warnings: [] };

  let root = parsePart(pairs, trimmed, 0, budget);
  const declaredMultipart = root.contentType.startsWith('multipart/');
  if (declaredMultipart && !root.children.length) {
    budget.warnings.push('The headers declare a multipart message but the pasted body has no MIME boundaries; it was read as plain text / HTML.');
    root = parsePart([], trimmed, 0, budget);
  }

  const plain: string[] = [];
  const html: string[] = [];
  const attachments: RawAttachment[] = [];
  const walk = (p: MimePart) => {
    if (p.children.length) { p.children.forEach(walk); return; }
    const isAttachment = p.disposition === 'attachment' || !!p.filename || (!p.contentType.startsWith('text/') && !p.contentType.startsWith('multipart/'));
    if (isAttachment) {
      const size = p.bytes?.byteLength ?? (p.text ? new TextEncoder().encode(p.text).byteLength : 0);
      attachments.push({
        filename: p.filename,
        declaredType: p.contentType,
        inline: p.disposition === 'inline' || (!!p.contentId && p.contentType.startsWith('image/') && p.disposition !== 'attachment'),
        size,
        bytes: p.bytes ?? (p.text !== null ? new TextEncoder().encode(p.text) : null),
      });
      return;
    }
    if (p.text === null) return;
    if (p.contentType === 'text/html') html.push(p.text);
    else if (p.contentType === 'text/plain' || p.contentType === 'text/x-amp-html') plain.push(p.text);
    else if (looksLikeHtml(p.text)) html.push(p.text);
    else plain.push(p.text);
  };
  walk(root);

  // A body pasted without MIME structure but containing markup is HTML.
  if (!root.children.length && !html.length && plain.length === 1 && looksLikeHtml(plain[0]) && root.contentType === 'text/plain') {
    html.push(plain.pop()!);
  }

  const htmlJoined = html.length ? html.join('\n') : null;
  let text = plain.length ? plain.join('\n').trim() : htmlJoined ? htmlToText(htmlJoined) : '';
  let truncated = false;
  if (text.length > LIMITS.textChars) { text = text.slice(0, LIMITS.textChars); truncated = true; }

  return {
    text,
    html: htmlJoined,
    bodyKind: root.children.length ? 'multipart' : htmlJoined ? 'html' : 'plain',
    attachments,
    partCount: budget.parts,
    truncated,
    warnings: budget.warnings,
  };
}
