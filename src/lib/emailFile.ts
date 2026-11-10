/**
 * Reads an email file chosen or dropped in the phishing form and turns it into form input:
 *   - .eml   RFC 5322 / MIME message
 *   - .mbox  Unix mailbox (one or more messages; the first is loaded)
 *   - .msg   Outlook message (OLE2 / Compound File Binary container with MAPI properties)
 *
 * Output: the header block (for the raw headers box), a body the parse stage can read (for the body box) and every
 * non-inline attachment as a File, so attachments are inspected, hashed and actively scanned like attached files.
 * Attachment bytes are deliberately NOT left in the body, which keeps large emails (up to 10 MB) inside the parse
 * request's size limits. Pure parsing: nothing here renders or executes content.
 */
import { parseHeaderBlock } from '../../shared/headers';
import { extractMessage, parseHeaderValue } from '../../shared/phishing/mime';
import { LIMITS } from '../../shared/phishing/types';

export const EMAIL_FILE_MAX_BYTES = 10 * 1024 * 1024;
export const EMAIL_FILE_ACCEPT = '.eml,.msg,.mbox,message/rfc822,application/vnd.ms-outlook,application/mbox,text/plain';

export type EmailFileFormat = 'eml' | 'msg' | 'mbox';

export interface ParsedEmailFile {
  format: EmailFileFormat;
  headers: string;
  body: string;
  attachments: File[];
  /** Short notes for the analyst (messages in an mbox, skipped parts, truncation). */
  notes: string[];
}

const mb = (n: number) => `${(n / (1024 * 1024)).toFixed(1)} MB`;

/** Size and type gate for a dropped or chosen email file. */
export function checkEmailFile(file: { name: string; size: number }): { ok: true } | { ok: false; message: string } {
  if (file.size === 0) return { ok: false, message: `${file.name} is empty.` };
  if (file.size > EMAIL_FILE_MAX_BYTES) return { ok: false, message: `${file.name} is ${mb(file.size)}. Email files larger than ${mb(EMAIL_FILE_MAX_BYTES)} are not loaded.` };
  return { ok: true };
}

const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

export function detectFormat(name: string, bytes: Uint8Array): EmailFileFormat {
  if (CFB_MAGIC.every((b, i) => bytes[i] === b)) return 'msg';
  const ext = name.toLowerCase().split('.').pop() ?? '';
  if (ext === 'msg') return 'msg';
  if (ext === 'mbox' || ext === 'mbx') return 'mbox';
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, 5));
  return head === 'From ' ? 'mbox' : 'eml';
}

export async function parseEmailFile(file: File): Promise<ParsedEmailFile> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const format = detectFormat(file.name, bytes);
  if (format === 'msg') return parseMsg(bytes);
  const text = new TextDecoder('utf-8').decode(bytes);
  if (format === 'mbox') {
    const { first, count } = firstMboxMessage(text);
    if (!first) throw new Error('No messages were found in the mailbox file.');
    const out = parseRfc822(first, 'mbox');
    if (count > 1) out.notes.unshift(`The mailbox holds ${count} messages; the first one was loaded.`);
    return out;
  }
  return parseRfc822(text, 'eml');
}

/* ================================================================== RFC 822 */

function splitMessage(raw: string): { head: string; body: string } {
  const t = raw.replace(/\r\n?/g, '\n').replace(/^\s*\n/, '');
  const i = t.indexOf('\n\n');
  return i < 0 ? { head: t, body: '' } : { head: t.slice(0, i), body: t.slice(i + 2) };
}

const header = (pairs: [string, string][], name: string) => pairs.find(([n]) => n.toLowerCase() === name)?.[1] ?? null;

function parseRfc822(raw: string, format: 'eml' | 'mbox'): ParsedEmailFile {
  const { head, body } = splitMessage(raw);
  const notes: string[] = [];
  if (!/^[!-9;-~]+:/m.test(head)) throw new Error('This file does not contain email headers.');
  const pairs = parseHeaderBlock(head);
  const msg = extractMessage(pairs, body);
  notes.push(...msg.warnings);
  const attachments = toFiles(msg.attachments.filter((a) => !a.inline && a.bytes).map((a) => ({ name: a.filename, type: a.declaredType, bytes: a.bytes! })));

  const ct = parseHeaderValue(header(pairs, 'content-type') ?? 'text/plain');
  let outBody: string;
  if (ct.value.toLowerCase().startsWith('multipart/') && ct.params.boundary) {
    // Rebuild the multipart body with only the readable text, using the message's own boundary so the headers stay untouched.
    outBody = textMultipart(ct.params.boundary, msg.text, msg.html);
  } else {
    // Single-part message: the body is already in the encoding the headers declare.
    outBody = body;
  }
  return { format, headers: head, body: clampBody(outBody, notes), attachments, notes };
}

/** A multipart body holding just the message text (HTML preferred, else plain text), every part 8-bit UTF-8. */
function textMultipart(boundary: string, text: string, html: string | null): string {
  const part = html
    ? `Content-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n${html}`
    : `Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n${text}`;
  return `--${boundary}\n${part}\n--${boundary}--\n`;
}

function clampBody(body: string, notes: string[]): string {
  const max = LIMITS.bodyChars - 1000;
  if (body.length <= max) return body;
  notes.push('The message body was very long and has been shortened for analysis.');
  return body.slice(0, max);
}

/* ===================================================================== mbox */

function firstMboxMessage(text: string): { first: string | null; count: number } {
  const t = text.replace(/\r\n?/g, '\n');
  // A message starts at a "From " line that begins the file or follows a blank line.
  const starts: number[] = [];
  const re = /(^|\n\n)From [^\n]*\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t))) { starts.push(m.index + m[1].length); re.lastIndex = m.index + m[0].length; }
  if (!starts.length) return { first: t.trim() ? t : null, count: t.trim() ? 1 : 0 };
  const end = starts[1] ?? t.length;
  const chunk = t.slice(starts[0], end);
  const msg = chunk.slice(chunk.indexOf('\n') + 1).replace(/^>(>*From )/gm, '$1');
  return { first: msg, count: starts.length };
}

/* =========================================================== attachments */

function toFiles(list: { name: string | null; type: string; bytes: Uint8Array }[]): File[] {
  const used = new Set<string>();
  return list.map((a, i) => {
    let name = (a.name ?? '').replace(/[\\/]/g, '_').trim() || `attachment-${i + 1}${extFor(a.type)}`;
    if (used.has(name)) name = `${i + 1}-${name}`;
    used.add(name);
    return new File([a.bytes as unknown as BlobPart], name, { type: a.type || 'application/octet-stream' });
  });
}

const extFor = (type: string) => (type === 'message/rfc822' ? '.eml' : type === 'application/pdf' ? '.pdf' : type.startsWith('text/html') ? '.html' : '.bin');

/* ======================================================= Outlook .msg (CFB) */

interface DirEntry { name: string; type: number; left: number; right: number; child: number; start: number; size: number }

const NOSTREAM = 0xffffffff;
const ENDOFCHAIN = 0xfffffffe;

/** Minimal read-only Compound File Binary reader (MS-CFB): directory tree and stream contents. */
class Cfb {
  private dv: DataView;
  private sectorSize: number;
  private miniSectorSize: number;
  private miniCutoff: number;
  private fat: number[] = [];
  private miniFat: number[] = [];
  private miniStream: Uint8Array = new Uint8Array(0);
  readonly dir: DirEntry[] = [];

  constructor(private bytes: Uint8Array) {
    if (!CFB_MAGIC.every((b, i) => bytes[i] === b)) throw new Error('This is not an Outlook .msg file (no compound-file signature).');
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.sectorSize = 1 << this.dv.getUint16(0x1e, true);
    this.miniSectorSize = 1 << this.dv.getUint16(0x20, true);
    this.miniCutoff = this.dv.getUint32(0x38, true);
    const firstDir = this.dv.getUint32(0x30, true);
    const firstMiniFat = this.dv.getUint32(0x3c, true);
    let difatSector = this.dv.getUint32(0x44, true);
    const numDifat = this.dv.getUint32(0x48, true);

    // DIFAT: 109 entries in the header, then chained DIFAT sectors.
    const fatSectors: number[] = [];
    for (let i = 0; i < 109; i++) { const s = this.dv.getUint32(0x4c + i * 4, true); if (s < 0xfffffffa) fatSectors.push(s); }
    const per = this.sectorSize / 4;
    for (let n = 0; n < numDifat && difatSector < 0xfffffffa && n < 10_000; n++) {
      const off = this.offset(difatSector);
      for (let i = 0; i < per - 1; i++) { const s = this.u32(off + i * 4); if (s < 0xfffffffa) fatSectors.push(s); }
      difatSector = this.u32(off + (per - 1) * 4);
    }
    for (const s of fatSectors) { const off = this.offset(s); for (let i = 0; i < per; i++) this.fat.push(this.u32(off + i * 4)); }

    const dirBytes = this.readChain(firstDir, this.fat, this.sectorSize, (s) => this.sector(s));
    for (let o = 0; o + 128 <= dirBytes.length; o += 128) {
      const v = new DataView(dirBytes.buffer, dirBytes.byteOffset + o, 128);
      const nameLen = Math.min(64, v.getUint16(64, true));
      const name = new TextDecoder('utf-16le').decode(dirBytes.subarray(o, o + Math.max(0, nameLen - 2)));
      this.dir.push({ name, type: v.getUint8(66), left: v.getUint32(68, true), right: v.getUint32(72, true), child: v.getUint32(76, true), start: v.getUint32(116, true), size: v.getUint32(120, true) });
    }
    const root = this.dir[0];
    if (!root || root.type !== 5) throw new Error('The .msg file has no root storage.');
    if (firstMiniFat < 0xfffffffa) {
      const mf = this.readChain(firstMiniFat, this.fat, this.sectorSize, (s) => this.sector(s));
      for (let o = 0; o + 4 <= mf.length; o += 4) this.miniFat.push(new DataView(mf.buffer, mf.byteOffset + o, 4).getUint32(0, true));
    }
    this.miniStream = this.readChain(root.start, this.fat, this.sectorSize, (s) => this.sector(s)).subarray(0, root.size);
  }

  private u32(off: number) { return off + 4 <= this.bytes.length ? this.dv.getUint32(off, true) : ENDOFCHAIN; }
  private offset(sector: number) { return (sector + 1) * this.sectorSize; }
  private sector(s: number) { const o = this.offset(s); return this.bytes.subarray(o, Math.min(o + this.sectorSize, this.bytes.length)); }
  private miniSector(s: number) { const o = s * this.miniSectorSize; return this.miniStream.subarray(o, Math.min(o + this.miniSectorSize, this.miniStream.length)); }

  private readChain(start: number, table: number[], size: number, get: (s: number) => Uint8Array, limit = Infinity): Uint8Array {
    const chunks: Uint8Array[] = [];
    let total = 0;
    const seen = new Set<number>();
    for (let s = start; s !== ENDOFCHAIN && s < 0xfffffffa && !seen.has(s) && total < limit; s = table[s] ?? ENDOFCHAIN) {
      seen.add(s);
      const c = get(s);
      chunks.push(c);
      total += c.length;
      if (c.length < size) break;
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }

  /** Contents of a stream entry. */
  read(e: DirEntry): Uint8Array {
    if (e.size === 0) return new Uint8Array(0);
    const data = e.size < this.miniCutoff
      ? this.readChain(e.start, this.miniFat, this.miniSectorSize, (s) => this.miniSector(s), e.size)
      : this.readChain(e.start, this.fat, this.sectorSize, (s) => this.sector(s), e.size);
    return data.subarray(0, e.size);
  }

  /** Direct children of a storage entry (walks the red-black sibling tree). */
  children(e: DirEntry): DirEntry[] {
    const out: DirEntry[] = [];
    const stack = [e.child];
    const seen = new Set<number>();
    while (stack.length) {
      const i = stack.pop()!;
      if (i === NOSTREAM || i >= this.dir.length || seen.has(i)) continue;
      seen.add(i);
      const d = this.dir[i];
      out.push(d);
      stack.push(d.left, d.right);
    }
    return out;
  }
}

/** MAPI property ids read from the message (PidTag... names in comments). */
const P = {
  headers: 0x007d, // PidTagTransportMessageHeaders
  subject: 0x0037, // PidTagSubject
  body: 0x1000, // PidTagBody
  html: 0x1013, // PidTagHtml (binary) / PidTagBodyHtml (string)
  senderName: 0x0c1a, // PidTagSenderName
  senderEmail: 0x0c1f, // PidTagSenderEmailAddress
  senderSmtp: 0x5d01, // PidTagSenderSmtpAddress
  displayTo: 0x0e04, // PidTagDisplayTo
  messageId: 0x1035, // PidTagInternetMessageId
  attachLongName: 0x3707, // PidTagAttachLongFilename
  attachName: 0x3704, // PidTagAttachFilename
  attachData: 0x3701, // PidTagAttachDataBinary / embedded message
  attachMime: 0x370e, // PidTagAttachMimeTag
  displayName: 0x3001, // PidTagDisplayName
} as const;

type Props = Map<number, { type: number; entry: DirEntry }>;

function propsOf(cfb: Cfb, storage: DirEntry): Props {
  const m: Props = new Map();
  for (const c of cfb.children(storage)) {
    const hit = /^__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})$/.exec(c.name);
    if (hit) m.set(parseInt(hit[1], 16), { type: parseInt(hit[2], 16), entry: c });
  }
  return m;
}

function str(cfb: Cfb, props: Props, id: number): string | null {
  const p = props.get(id);
  if (!p || p.entry.type !== 2) return null;
  const b = cfb.read(p.entry);
  if (p.type === 0x001f) return new TextDecoder('utf-16le').decode(b).replace(/\0+$/, '');
  if (p.type === 0x001e) return decodeAnsi(b).replace(/\0+$/, '');
  if (p.type === 0x0102) return decodeAnsi(b);
  return null;
}

/** 8-bit strings: UTF-8 when valid, else Windows-1252. */
function decodeAnsi(b: Uint8Array): string {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch { return new TextDecoder('windows-1252').decode(b); }
}

interface MsgContent { head: string; plain: string | null; html: string | null; hadHeaders: boolean; files: { name: string | null; type: string; bytes: Uint8Array }[]; notes: string[] }

/** Reads one message storage: the root of a .msg file, or an Outlook item embedded in it as an attachment. */
function readMsgStorage(cfb: Cfb, storage: DirEntry, depth: number): MsgContent {
  const props = propsOf(cfb, storage);
  const notes: string[] = [];
  const subject = str(cfb, props, P.subject);
  const plain = str(cfb, props, P.body);
  const htmlEntry = props.get(P.html);
  let html = htmlEntry ? (htmlEntry.type === 0x0102 ? decodeHtmlBytes(cfb.read(htmlEntry.entry)) : str(cfb, props, P.html)) : null;
  let text = plain;

  let head = (str(cfb, props, P.headers) ?? '').replace(/\r\n?/g, '\n').trim();
  const hadHeaders = !!head;
  if (!head) {
    // Messages that never crossed the internet (drafts, internal Exchange mail) carry no transport headers: rebuild the basics.
    const name = str(cfb, props, P.senderName);
    const addr = str(cfb, props, P.senderSmtp) ?? str(cfb, props, P.senderEmail);
    const lines: string[] = [];
    if (addr && addr.includes('@')) lines.push(`From: ${name ? `"${name.replace(/"/g, "'")}" ` : ''}<${addr}>`);
    else if (name) lines.push(`From: ${name}`);
    const to = str(cfb, props, P.displayTo);
    if (to) lines.push(`To: ${to}`);
    if (subject) lines.push(`Subject: ${subject}`);
    const mid = str(cfb, props, P.messageId);
    if (mid) lines.push(`Message-ID: ${mid}`);
    lines.push('MIME-Version: 1.0');
    head = lines.join('\n');
  }

  const files: MsgContent['files'] = [];
  for (const c of cfb.children(storage)) {
    if (c.type !== 1 || !c.name.startsWith('__attach_version1.0_')) continue;
    const ap = propsOf(cfb, c);
    const name = str(cfb, ap, P.attachLongName) ?? str(cfb, ap, P.attachName) ?? str(cfb, ap, P.displayName);
    const mime = (str(cfb, ap, P.attachMime) ?? 'application/octet-stream').toLowerCase();
    const data = ap.get(P.attachData);
    if (!data) continue;
    if (data.entry.type === 1) {
      // An attached Outlook item (forwarded email): rebuild it as an .eml so it is scanned and can be analysed on its own.
      if (depth >= 2) { notes.push(`A nested Outlook item "${name ?? 'attached message'}" was not extracted.`); continue; }
      const inner = readMsgStorage(cfb, data.entry, depth + 1);
      const eml = toEml(inner);
      files.push({ name: `${(name ?? 'attached-message').replace(/\.msg$/i, '')}.eml`, type: 'message/rfc822', bytes: new TextEncoder().encode(eml) });
      continue;
    }
    const bytes = cfb.read(data.entry);
    if (mime === 'multipart/signed' || (name ?? '').toLowerCase() === 'smime.p7m') {
      // Clear-signed S/MIME: Outlook keeps the whole signed MIME message as one attachment. Unwrap it.
      const unwrapped = unwrapMime(bytes);
      if (unwrapped) {
        files.push(...unwrapped.files);
        if (!html && unwrapped.html) html = unwrapped.html;
        if (!text?.trim() && unwrapped.text) text = unwrapped.text;
        notes.push('The message is S/MIME signed; the signed content was unwrapped (the signature itself was not verified).');
        continue;
      }
    }
    files.push({ name, type: mime, bytes });
  }
  return { head, plain: text, html, hadHeaders, files, notes };
}

/** The readable parts and attachments of a MIME message held as bytes (e.g. the signed body of an S/MIME .msg). */
function unwrapMime(bytes: Uint8Array): { text: string; html: string | null; files: MsgContent['files'] } | null {
  const raw = new TextDecoder('utf-8').decode(bytes);
  if (!/^content-type:/im.test(raw.slice(0, 2000))) return null;
  const { head, body } = splitMessage(raw);
  const msg = extractMessage(parseHeaderBlock(head), body);
  return { text: msg.text, html: msg.html, files: msg.attachments.filter((a) => !a.inline && a.bytes).map((a) => ({ name: a.filename, type: a.declaredType, bytes: a.bytes! })) };
}

/** A self-contained .eml text for a message read from a .msg (headers plus a simple text/HTML body; no attachments). */
function toEml(m: MsgContent): string {
  const boundary = `spectrix-msg-${Math.random().toString(36).slice(2, 12)}`;
  const head = replaceHeaders(m.head, ['content-type', 'content-transfer-encoding'], [`Content-Type: multipart/alternative; boundary="${boundary}"`]);
  return `${head}\n\n${textMultipart(boundary, m.plain ?? '', m.html)}`;
}

function parseMsg(bytes: Uint8Array): ParsedEmailFile {
  const cfb = new Cfb(bytes);
  const m = readMsgStorage(cfb, cfb.dir[0], 0);
  const notes = [...m.notes];
  if (!m.hadHeaders) notes.unshift('The .msg file has no internet headers (it may be a draft or internal Exchange message); a minimal header set was built from its properties, so routing and authentication cannot be assessed.');
  // The transport headers describe the original MIME layout; replace it with a simple text body the parse stage can read.
  const boundary = `spectrix-msg-${Math.random().toString(36).slice(2, 12)}`;
  const head = replaceHeaders(m.head, ['content-type', 'content-transfer-encoding'], [`Content-Type: multipart/alternative; boundary="${boundary}"`]);
  const body = textMultipart(boundary, m.plain ?? '', m.html);
  return { format: 'msg', headers: head, body: clampBody(body, notes), attachments: toFiles(m.files), notes };
}

function decodeHtmlBytes(b: Uint8Array): string {
  const sniff = new TextDecoder('latin1').decode(b.subarray(0, 2048));
  const cs = /charset\s*=\s*["']?([A-Za-z0-9_-]+)/i.exec(sniff)?.[1];
  if (cs) { try { return new TextDecoder(cs.toLowerCase()).decode(b); } catch { /* fall through */ } }
  return decodeAnsi(b);
}

/** Drops the named headers (with their folded continuation lines) and appends replacements. */
function replaceHeaders(head: string, drop: string[], add: string[]): string {
  const out: string[] = [];
  let skipping = false;
  for (const line of head.split('\n')) {
    if (/^[ \t]/.test(line)) { if (!skipping) out.push(line); continue; }
    const name = line.slice(0, line.indexOf(':')).trim().toLowerCase();
    skipping = line.includes(':') && drop.includes(name);
    if (!skipping) out.push(line);
  }
  return [...out, ...add].join('\n');
}
