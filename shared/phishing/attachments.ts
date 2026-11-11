/**
 * Step 4 of the phishing investigation: attachment analysis. Pure (no network) and runtime-agnostic: it runs in the
 * Worker (the parse stage, for attachments embedded in a pasted message), in the browser (for a file the analyst drops
 * in), and in tests.
 *
 * Output contract (consumed by the Step 6 verdict engine). Finding ids, all with dimension "attachment":
 *   reputation (from /api/file/hash):  attachment_hash_malicious | attachment_hash_suspicious | attachment_hash_known_good | attachment_hash_unknown
 *   static (bytes or filename):        attachment_dangerous_type | attachment_double_extension | attachment_type_mismatch | attachment_macro_present |
 *                                      attachment_html_credential_form | attachment_pdf_active_content | attachment_archive_dangerous_content |
 *                                      attachment_password_protected | attachment_embedded_urls | attachment_high_entropy | attachment_not_inspected
 * Check ids (stage "attachments"):     attach.<n>.static,  attach.<n>.hash.<virustotal|malwarebazaar|circl|hybrid>  and  attach.<n>.scan.virustotal
 *   active scan (file uploaded to VirusTotal): attachment_hash_malicious | attachment_hash_suspicious (same ids and thresholds)
 *
 * These findings describe a FILE. They never say whether the email is malicious, an unknown hash is never worded as
 * safe, and a provider that failed or was skipped is reported as such. Attachments are never executed or rendered.
 */
import { eachTag } from './html';
import { detectType, inspect } from '../fileAnalysis';
import type { FileAnalysisReport, FileReputation } from '../types';
import { check, makeFinding } from './findings';
import type { CheckResult, Finding } from './types';

/* -------------------------------------------------- wire types (shared by the Worker and the page) */

export interface AttachmentHashRequest { hash: string; hashType: 'md5' | 'sha1' | 'sha256'; filename?: string; index: number }
export interface AttachmentHashResponse {
  request: AttachmentHashRequest;
  findings: Finding[];
  checks: CheckResult[];
  /** The raw hash lookup (null when the lookup as a whole could not run). */
  data: FileReputation | null;
}

/* ------------------------------------------------------------------ tables */

/** Executables, scripts and launchers: dangerous by themselves. */
export const HIGH_RISK_EXTENSIONS: ReadonlySet<string> = new Set(['exe', 'scr', 'com', 'pif', 'msi', 'dll', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'bat', 'cmd', 'lnk', 'jar', 'cpl', 'reg']);
/** Containers and active formats used to get past mail filters or mark-of-the-web. */
export const MEDIUM_RISK_EXTENSIONS: ReadonlySet<string> = new Set(['iso', 'img', 'vhd', 'vhdx', 'cab', 'one', 'zip', 'rar', '7z', 'gz', 'html', 'htm', 'shtml', 'svg', 'docm', 'xlsm', 'pptm', 'xlam']);
/** Extensions a reader takes for an ordinary document: a dangerous type hiding behind one of these is the classic lure. */
const DOCUMENT_EXTENSIONS: ReadonlySet<string> = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'csv', 'odt', 'ods', 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'bmp', 'tif', 'tiff', 'mp3', 'mp4', 'wav']);
const ARCHIVE_EXTENSIONS: ReadonlySet<string> = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'iso', 'img']);

export const MAX_STATIC_BYTES = 3_000_000;
const SRC = 'attachment-analysis';

type Family = 'pdf' | 'image' | 'media' | 'text' | 'office' | 'archive' | 'html' | 'program' | 'script';

export const baseName = (raw: string): string => raw.split(/[\\/]/).pop() ?? raw;

/** Extension as Windows sees it: trailing dots and spaces are ignored. */
export const extensionOfName = (name: string): string | null => {
  const base = baseName(name).replace(/[.\s\u00a0]+$/, '').toLowerCase();
  const i = base.lastIndexOf('.');
  const e = i > 0 ? base.slice(i + 1).replace(/\s+/g, '') : '';
  return /^[a-z0-9_-]{1,12}$/.test(e) ? e : null;
};

function extFamily(ext: string | null): Family | null {
  if (!ext) return null;
  if (ext === 'pdf') return 'pdf';
  if (['jpg', 'jpeg', 'jpe', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'ico'].includes(ext)) return 'image';
  if (['mp3', 'mp4', 'wav', 'm4a', 'avi', 'mov', 'wmv'].includes(ext)) return 'media';
  if (['txt', 'log', 'csv', 'md', 'json'].includes(ext)) return 'text';
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'dot', 'dotx', 'xlt', 'odt', 'ods', 'odp', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam'].includes(ext)) return 'office';
  if (['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'iso', 'img', 'vhd', 'vhdx'].includes(ext)) return 'archive';
  if (['html', 'htm', 'xhtml', 'shtml', 'svg', 'mht', 'mhtml'].includes(ext)) return 'html';
  if (['exe', 'dll', 'scr', 'com', 'pif', 'msi', 'cpl', 'sys', 'jar'].includes(ext)) return 'program';
  if (['js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'bat', 'cmd', 'reg', 'lnk', 'sh', 'py'].includes(ext)) return 'script';
  return null;
}

function mimeFamily(t: string | null | undefined): Family | 'generic' {
  const m = (t ?? '').toLowerCase().split(';')[0].trim();
  if (!m || m === 'application/octet-stream' || m === 'binary/octet-stream' || m === 'application/x-unknown' || m === 'application/unknown') return 'generic';
  if (m === 'image/svg+xml' || m === 'text/html' || m === 'application/xhtml+xml') return 'html';
  if (m === 'application/pdf') return 'pdf';
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('audio/') || m.startsWith('video/')) return 'media';
  if (m === 'text/plain' || m === 'text/csv') return 'text';
  if (/^application\/(msword|vnd\.ms-(excel|powerpoint|word)|vnd\.openxmlformats-officedocument|vnd\.oasis\.opendocument|rtf)/.test(m) || m === 'text/rtf') return 'office';
  if (/^application\/(zip|x-zip|x-zip-compressed|x-rar|vnd\.rar|x-7z-compressed|gzip|x-gzip|x-tar)/.test(m)) return 'archive';
  if (/^application\/(x-msdownload|x-msdos-program|x-dosexec|vnd\.microsoft\.portable-executable|x-executable)/.test(m)) return 'program';
  return 'generic';
}

/** Is a declared Content-Type plausible for this kind of file? Scripts may be labelled text; OOXML Office files are zips. */
const compatible = (declared: Family | 'generic', actual: Family): boolean =>
  declared === 'generic' || declared === actual || (declared === 'text' && (actual === 'script' || actual === 'html')) || (declared === 'archive' && actual === 'office') || (declared === 'office' && actual === 'archive');

/* ------------------------------------------------------------- name rules */

const BIDI = /[\u202a-\u202e\u2066-\u2069]/;
const PADDING = / {5,}|[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u3164\u2800]{3,}/;
const showControls = (s: string) => s.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`);

/** Which attachment a finding or check is about. `index` is its position in the parse stage's attachment list. */
export interface Subject { index: number; filename: string | null; sha256: string | null }
const indicatorOf = (s: Subject): Finding['indicator'] => (s.sha256 ? { type: 'hash', value: s.sha256 } : { type: 'filename', value: s.filename ?? `attachment ${s.index + 1}` });

type FindingFields = Omit<Parameters<typeof makeFinding>[0], 'dimension' | 'source' | 'indicator' | 'exactness'>;
const mk = (s: Subject, exactness: 'exact' | 'related', f: FindingFields): Finding => makeFinding({ dimension: 'attachment', source: SRC, exactness, indicator: indicatorOf(s), trust: 'derived', ...f });

/**
 * Filename (and declared Content-Type) rules. With `hasBytes` false (the analyst only typed a name) the findings are
 * about the NAME, so exactness is "related": the real file might be something else entirely.
 */
export function analyzeAttachmentName(subject: Subject, declaredType: string | null, hasBytes: boolean): Finding[] {
  const raw = subject.filename;
  if (!raw) return [];
  const out: Finding[] = [];
  const exactness = hasBytes ? 'exact' : 'related';
  const name = baseName(raw);
  const trimmed = name.replace(/[.\s\u00a0]+$/, '');
  const parts = trimmed.toLowerCase().split('.');
  const ext = extensionOfName(name);
  const prev = parts.length >= 3 ? parts[parts.length - 2].replace(/\s+/g, '') : null;

  if (ext && (HIGH_RISK_EXTENSIONS.has(ext) || MEDIUM_RISK_EXTENSIONS.has(ext))) {
    const high = HIGH_RISK_EXTENSIONS.has(ext);
    out.push(mk(subject, exactness, {
      id: 'attachment_dangerous_type', severity: high ? 'high' : 'medium', reliability: high ? 'medium' : 'low',
      title: high ? `Attachment is a program, script or launcher (.${ext})` : `Attachment is a container or active format often used to evade filters (.${ext})`,
      detail: high
        ? 'Executables, scripts and shortcut files run as soon as they are opened. Legitimate senders almost never email them.'
        : 'Disk images, archives, web pages and macro-enabled Office files are widely used to deliver malware or fake login pages past mail scanners. Many are also used legitimately, so this is a prompt for review.',
      evidence: [name],
    }));
  }

  if (prev && ext && DOCUMENT_EXTENSIONS.has(prev) && HIGH_RISK_EXTENSIONS.has(ext)) {
    out.push(mk(subject, exactness, {
      id: 'attachment_double_extension', severity: 'high', reliability: 'high',
      title: `Double extension ".${prev}.${ext}": a ${extFamily(ext) === 'script' ? 'script' : 'program'} dressed as a document`,
      detail: `The name starts like a .${prev} file but ends in ".${ext}". Mail clients and Windows often hide the last extension, so the recipient sees ".${prev}".`,
      evidence: [name],
    }));
  }
  if (BIDI.test(name)) {
    out.push(mk(subject, exactness, {
      id: 'attachment_double_extension', severity: 'high', reliability: 'high',
      title: 'File name contains a hidden text-direction control character',
      detail: 'Right-to-left override characters reverse part of the displayed name so an executable looks like a document. There is no legitimate reason for them in an attachment name.',
      evidence: [showControls(name)],
    }));
  }
  if (PADDING.test(trimmed)) {
    out.push(mk(subject, exactness, {
      id: 'attachment_double_extension', severity: 'high', reliability: 'medium',
      title: 'File name is padded with spaces to push the real extension out of view',
      detail: 'Long runs of spaces hide the true extension in narrow file lists, so "invoice.pdf          .exe" looks like a PDF.',
      evidence: [showControls(name.replace(/\s{2,}/g, ' … '))],
    }));
  }
  if (trimmed.length !== name.length) {
    out.push(mk(subject, exactness, {
      id: 'attachment_double_extension', severity: 'high', reliability: 'medium',
      title: 'File name ends in trailing spaces or dots',
      detail: 'Windows ignores trailing spaces and dots, so the file still opens as its real type while filters that compare the end of the name are bypassed.',
      evidence: [JSON.stringify(name)],
    }));
  }

  const df = mimeFamily(declaredType);
  const ef = extFamily(ext);
  if (declaredType && df !== 'generic' && ef && !compatible(df, ef)) {
    out.push(mk(subject, exactness, {
      id: 'attachment_type_mismatch', severity: 'medium', reliability: 'medium',
      title: `Declared type (${declaredType.split(';')[0].trim()}) does not match the .${ext} extension`,
      detail: 'The message labels this attachment as one kind of file while its name says another. One of the two is misleading.',
      evidence: [`${name} · ${declaredType}`],
    }));
  }
  return out;
}

/* ------------------------------------------------------------ byte rules */

export interface AttachmentStaticSummary {
  index: number;
  filename: string | null;
  detectedType: string | null;
  typeId: string | null;
  entropy: number | null;
  size: number | null;
  inspected: boolean;
  note?: string;
  /** URLs and IPs found inside the file, so the page can feed them to the link stage. */
  urls: string[];
  ips: string[];
}

export interface StaticResult { findings: Finding[]; check: CheckResult; summary: AttachmentStaticSummary }

const NOISE_URL = /^https?:\/\/(?:[a-z0-9.-]*\.)?(?:w3\.org|openxmlformats\.org|schemas\.microsoft\.com|purl\.org|ns\.adobe\.com|xmlsoft\.org)\b/i;
const latin1 = new TextDecoder('latin1');
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const labelOf = (s: Subject) => s.filename ?? (s.sha256 ? `${s.sha256.slice(0, 12)}…` : `attachment ${s.index + 1}`);
const staticCheck = (s: Subject, status: CheckResult['status'], result: string | null, detail?: string) => check(`attach.${s.index}.static`, 'attachments', `Static analysis: ${labelOf(s)}`, status, result, detail);
const notInspected = (s: Subject, title: string, detail: string) => mk(s, 'exact', { id: 'attachment_not_inspected', severity: 'info', reliability: 'high', title, detail: `${detail} This is a coverage gap, not a clean result.` });

/** Static analysis of the real bytes. Never executes or renders the file. */
export function analyzeAttachmentBytes(bytes: Uint8Array, subject: Subject, declaredType: string | null): StaticResult {
  const name = subject.filename ?? '';
  const empty: AttachmentStaticSummary = { index: subject.index, filename: subject.filename, detectedType: null, typeId: null, entropy: null, size: bytes.byteLength, inspected: false, urls: [], ips: [] };
  const nameFindings = analyzeAttachmentName(subject, declaredType, true);

  if (bytes.byteLength === 0) {
    return { findings: [...nameFindings, notInspected(subject, 'Attachment has no content to inspect', 'The attachment part is empty, so only its name was checked.')], check: staticCheck(subject, 'skipped', 'empty attachment', 'No bytes were present.'), summary: { ...empty, note: 'empty' } };
  }
  if (bytes.byteLength > MAX_STATIC_BYTES) {
    return { findings: [...nameFindings, notInspected(subject, 'Attachment is too large to inspect here', `Only the name was checked: files over ${(MAX_STATIC_BYTES / 1e6).toFixed(0)} MB are not analysed.`)], check: staticCheck(subject, 'skipped', 'too large', `${bytes.byteLength.toLocaleString('en-US')} bytes`), summary: { ...empty, note: 'too large' } };
  }

  let r: ReturnType<typeof inspect>;
  try {
    r = inspect(bytes, name || 'attachment');
  } catch (e) {
    return { findings: [...nameFindings, notInspected(subject, 'Attachment could not be analysed', 'Static analysis failed on this file, so only its name was checked.')], check: staticCheck(subject, 'failed', 'inspection failed', e instanceof Error ? e.message : 'unknown error'), summary: { ...empty, note: 'inspection failed' } };
  }

  const out: Finding[] = [...nameFindings];
  const has = (re: RegExp) => r.findings.find((x) => re.test(x.title));
  const ext = name ? extensionOfName(name) : null;
  const claimsDocument = !!ext && DOCUMENT_EXTENSIONS.has(ext);
  const type = detectType(bytes);
  const isProgramOrScript = ['pe', 'dos', 'elf', 'macho', 'script'].includes(type.id);

  // Real content that is a program, script or shortcut, whatever the name says.
  if ((isProgramOrScript || type.id === 'lnk') && !(ext && HIGH_RISK_EXTENSIONS.has(ext))) {
    out.push(mk(subject, 'exact', { id: 'attachment_dangerous_type', severity: 'high', reliability: 'high', title: `File content is a ${type.label}`, detail: 'The bytes of this attachment are a program, script or shortcut, regardless of what the name suggests.', evidence: [type.label] }));
  }

  // Magic bytes versus the extension.
  if (has(/does not match the content|Executable code with a document/i)) {
    out.push(mk(subject, 'exact', {
      id: 'attachment_type_mismatch', severity: isProgramOrScript && claimsDocument ? 'high' : 'medium', reliability: 'high',
      title: isProgramOrScript && claimsDocument ? `Named like a document (.${ext}) but the content is a ${type.label}` : `Extension .${ext ?? '?'} does not match the content (${type.label})`,
      detail: isProgramOrScript ? 'The file is a program or script under another name: the extension and the real content disagree.' : 'The file may be misnamed or deliberately disguised: the extension and the real content disagree.',
      evidence: [`${name} → ${type.label}`],
    }));
  }
  // Magic bytes versus the declared Content-Type.
  const realFamily: Family | null = type.id === 'pdf' ? 'pdf' : ['png', 'jpeg', 'gif'].includes(type.id) ? 'image' : ['pe', 'dos', 'elf', 'macho'].includes(type.id) ? 'program' : type.id === 'lnk' || type.id === 'script' ? 'script'
    : type.id === 'html' ? 'html' : ['zip', 'rar', '7z', 'gzip', 'tar', 'cab', 'iso'].includes(type.id) ? 'archive' : type.id === 'ole' || type.id === 'rtf' ? 'office' : null;
  const declared = mimeFamily(declaredType);
  if (declaredType && declared !== 'generic' && realFamily && !compatible(declared, realFamily)) {
    const hidesProgram = (realFamily === 'program' || realFamily === 'script') && ['pdf', 'image', 'media', 'text', 'office'].includes(declared);
    out.push(mk(subject, 'exact', {
      id: 'attachment_type_mismatch', severity: hidesProgram ? 'high' : 'medium', reliability: 'high',
      title: `Declared type (${declaredType.split(';')[0].trim()}) does not match the content (${type.label})`,
      detail: 'The message labels this attachment as one kind of file but its bytes are another.', evidence: [`${declaredType} → ${type.label}`],
    }));
  }

  // Macros
  const macro = has(/VBA macro project|VBA macros/i);
  if (macro) {
    const auto = has(/Macro runs automatically/i);
    out.push(mk(subject, 'exact', {
      id: 'attachment_macro_present', severity: auto ? 'high' : 'medium', reliability: 'medium',
      title: auto ? 'Office file contains a macro that runs automatically on open' : 'Office file contains a VBA macro project',
      detail: auto ? 'Auto-run procedures (such as AutoOpen or Document_Open) execute as soon as the user enables content.' : 'Macros can download and run programs once the user enables content. The macro itself was not examined.',
      evidence: [macro.title, ...(auto ? [auto.title] : [])],
    }));
  }

  // HTML / SVG: credential forms
  const htmlLike = type.id === 'html' || (['html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml'].includes(ext ?? '') && (type.id === 'text' || type.id === 'unknown'));
  if (htmlLike) {
    const body = latin1.decode(bytes.subarray(0, 2_000_000));
    // linear scan: a file of "<input <input <input ..." must not make this quadratic
    let pw: string | null = null;
    let form: string | null = null;
    let action = '';
    eachTag(body.length > 800_000 ? body.slice(0, 800_000) : body, ['input', 'form'], 20_000, (name, attrs) => {
      if (name === 'input' && !pw && /\btype\s*=\s*["']?password/i.test(attrs)) pw = `<input ${attrs.trim()}>`;
      if (name === 'form' && !form) {
        const m = attrs.match(/\baction\s*=\s*["']?\s*((?:https?:)?\/\/[^"'\s>]+)/i);
        if (m) { form = `<form ${attrs.trim()}>`; action = m[1]; }
      }
    });
    if (pw || form) {
      out.push(mk(subject, 'exact', {
        id: 'attachment_html_credential_form', severity: 'high', reliability: 'medium',
        title: pw && form ? 'Web page attachment asks for a password and posts it to an external address' : pw ? 'Web page attachment contains a password field' : 'Web page attachment contains a form that posts to an external address',
        detail: 'A web page delivered as an attachment that collects credentials is a standard way to harvest logins: the page runs from the recipient’s own disk, so link scanners never see it.',
        evidence: [...(pw ? [clip((pw as string).replace(/\s+/g, ' '), 120)] : []), ...(form ? [`form action: ${clip(action, 120)}`] : [])],
      }));
    }
  }

  // PDF active content
  const pdf = r.findings.filter((x) => /^PDF (runs JavaScript|contains JavaScript|can launch|has \d+ embedded)/i.test(x.title));
  if (pdf.length) {
    out.push(mk(subject, 'exact', {
      id: 'attachment_pdf_active_content', severity: 'medium', reliability: 'medium',
      title: 'PDF contains JavaScript, launch actions or embedded files',
      detail: 'Active content in a PDF can run code or open another file. Ordinary invoices and letters rarely need any.',
      evidence: pdf.map((x) => clip(`${x.title}${x.detail ? ` (${x.detail})` : ''}`, 140)),
    }));
  }

  // Archives
  const entries = r.archive?.entries ?? [];
  const isOoxml = entries.some((e) => /^(word|xl|ppt)\//i.test(e.name));
  if (entries.length && !isOoxml && !['jar', 'apk'].includes(ext ?? '')) {
    const bad = entries.filter((e) => { const x = extensionOfName(e.name); return !!x && (HIGH_RISK_EXTENSIONS.has(x) || (MEDIUM_RISK_EXTENSIONS.has(x) && !ARCHIVE_EXTENSIONS.has(x))); });
    if (bad.length) {
      out.push(mk(subject, 'exact', {
        id: 'attachment_archive_dangerous_content', severity: 'high', reliability: 'high',
        title: `Archive contains ${bad.length} program, script or active-format file${bad.length === 1 ? '' : 's'}`,
        detail: 'Files that run or contain active content are packed inside this archive, where mail scanners cannot see them.',
        evidence: bad.slice(0, 6).map((e) => e.name),
      }));
    }
  }

  // Encryption: contents cannot be inspected
  const encEntries = entries.filter((e) => e.encrypted).length;
  const pdfEnc = !!has(/PDF is encrypted/i);
  const oleEnc = type.id === 'ole' && /E\0?n\0?c\0?r\0?y\0?p\0?t\0?e\0?d\0?P\0?a\0?c\0?k\0?a\0?g\0?e/.test(latin1.decode(bytes.subarray(0, Math.min(bytes.length, 4_000_000))));
  if (encEntries || pdfEnc || oleEnc) {
    out.push(mk(subject, 'exact', {
      id: 'attachment_password_protected', severity: 'medium', reliability: 'high',
      title: encEntries ? 'Archive contains password-protected entries' : pdfEnc ? 'PDF is encrypted' : 'Office document is encrypted',
      detail: 'Encryption stops antivirus and mail scanners from seeing the content, and it stopped this analysis too. Attackers often put the password in the email body for exactly that reason.',
      evidence: [encEntries ? `${encEntries} encrypted entr${encEntries === 1 ? 'y' : 'ies'}` : pdfEnc ? '/Encrypt in the PDF' : 'EncryptedPackage stream'],
    }));
  }

  // Archive formats whose contents this analysis does not unpack
  if (['rar', '7z', 'gzip', 'tar', 'cab', 'iso'].includes(type.id) && !entries.length) {
    out.push(notInspected(subject, `Contents of this ${type.label} were not inspected`, 'This archive format is not unpacked here, so what it contains is unknown.'));
  }

  // Embedded URLs and IPs
  const urls = [...new Set(r.strings.urls.filter((u) => !NOISE_URL.test(u)))].slice(0, 25);
  const ips = [...new Set(r.strings.ips)].slice(0, 15);
  if (urls.length || ips.length) {
    out.push(mk(subject, 'exact', {
      id: 'attachment_embedded_urls', severity: 'info', reliability: 'high',
      title: `${urls.length ? `${urls.length} URL${urls.length === 1 ? '' : 's'}` : ''}${urls.length && ips.length ? ' and ' : ''}${ips.length ? `${ips.length} IP address${ips.length === 1 ? '' : 'es'}` : ''} found inside the file`,
      detail: 'These can be investigated like links in the message body.', evidence: [...urls.slice(0, 5), ...ips.slice(0, 3)],
    }));
  }

  // Supporting signal
  const ent = has(/Very high entropy/i);
  if (ent) out.push(mk(subject, 'exact', { id: 'attachment_high_entropy', severity: 'info', reliability: 'low', title: 'Content looks compressed, packed or encrypted', detail: 'High entropy is a supporting signal only: compressed and encrypted data is normal for many file types.', evidence: [ent.title] }));

  // Everything else the static pass noticed is context for the analyst, listed on the check row but not scored.
  const mapped = /does not match the content|Executable code with a document|VBA macro|VBA macros|Macro runs automatically|^PDF (runs|contains|can launch|has \d+ embedded)|PDF is encrypted|Very high entropy|password-protected|Double extension|right-to-left|Windows shortcut|Script file|Disk image|No suspicious traits/i;
  const others = r.findings.filter((x) => x.severity !== 'info' && !mapped.test(x.title)).map((x) => x.title);

  const summary: AttachmentStaticSummary = { index: subject.index, filename: subject.filename, detectedType: type.label, typeId: type.id, entropy: r.entropy, size: bytes.byteLength, inspected: true, urls, ips };
  const detail = [others.length ? `Other traits noted (not scored): ${others.slice(0, 5).join('; ')}.` : '', 'No traits found does not mean a file is safe.'].filter(Boolean).join(' ');
  return { findings: out, check: staticCheck(subject, 'complete', `${type.label}, entropy ${r.entropy.toFixed(1)}`, detail), summary };
}

/* ------------------------------------------------- the whole parsed message */

interface RawPart { filename: string | null; declaredType: string | null; inline: boolean; bytes: Uint8Array | null }
interface MetaLike { filename: string | null; declaredType: string | null; size: number | null; inline: boolean; hash: string | null; origin: 'embedded' | 'supplied' }

/**
 * Static analysis for every attachment the parse stage found or was given. `raw[i]` lines up with `metas[i]` for embedded
 * attachments (the parser lists them first). Supplied entries have no bytes: only the filename rules run, and their static
 * check is reported as skipped, never as complete.
 */
export function analyzeAttachmentSet(raw: RawPart[], metas: MetaLike[]): { findings: Finding[]; checks: CheckResult[]; summaries: AttachmentStaticSummary[]; limits: string[] } {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const summaries: AttachmentStaticSummary[] = [];
  const limits: string[] = [];
  metas.forEach((m, index) => {
    const subject: Subject = { index, filename: m.filename, sha256: m.hash && m.hash.length === 64 ? m.hash : null };
    if (m.origin === 'embedded' && m.inline) {
      checks.push(staticCheck(subject, 'not_applicable', 'inline part', 'Embedded image or signature part; not analysed as an attachment.'));
      return;
    }
    if (m.origin === 'embedded') {
      const res = analyzeAttachmentBytes(raw[index]?.bytes ?? new Uint8Array(), subject, m.declaredType);
      findings.push(...res.findings);
      checks.push(res.check);
      summaries.push(res.summary);
      return;
    }
    findings.push(...analyzeAttachmentName(subject, null, false));
    checks.push(staticCheck(subject, 'skipped', 'no file bytes', 'Only a name or hash was supplied, so only the file-name rules ran. Drop the file into the Attachments tab to analyse it in your browser.'));
    summaries.push({ index, filename: m.filename, detectedType: null, typeId: null, entropy: null, size: null, inspected: false, note: 'no file bytes', urls: [], ips: [] });
  });
  if (metas.some((m) => m.origin === 'supplied')) limits.push('Attachments that were only named or hashed were not inspected, because no file content was available.');
  return { findings, checks, summaries, limits };
}

/** Static analysis of a file in the browser (in memory, on the analyst's device). Uploading for an active scan is a separate step. */
export const analyzeDroppedFile = (bytes: Uint8Array, index: number, filename: string, sha256: string): StaticResult => analyzeAttachmentBytes(bytes, { index, filename, sha256 }, null);

/* ------------------------------------------------------- reputation (hash) */

const PROVIDERS = [
  { id: 'virustotal', label: 'VirusTotal', match: /^VirusTotal/i },
  { id: 'malwarebazaar', label: 'MalwareBazaar', match: /^MalwareBazaar/i },
  { id: 'circl', label: 'CIRCL hashlookup', match: /^CIRCL/i },
  { id: 'hybrid', label: 'Hybrid Analysis', match: /^Hybrid/i },
] as const;

export interface ReputationContext { index: number; filename?: string | null }

const vtTotal = (v: NonNullable<FileReputation['virustotal']>) => v.malicious + v.suspicious + v.harmless + v.undetected;
const isoDate = (s: string | null | undefined) => (s && !Number.isNaN(Date.parse(s)) ? new Date(s).toISOString() : null);

/**
 * Converts a /api/file/hash result into at most ONE reputation finding (malicious, suspicious, known_good or unknown,
 * strongest first) plus one visible check row per provider the lookup reported.
 */
export function convertFileReputation(rep: FileReputation, ctx: ReputationContext): { findings: Finding[]; checks: CheckResult[] } {
  const label = ctx.filename ?? `attachment ${ctx.index + 1}`;
  const hash = rep.sha256 ?? rep.hash;
  const vt = rep.virustotal?.observed ? rep.virustotal : null;
  const mb = rep.malwarebazaar?.observed ? rep.malwarebazaar : null;
  const hy = rep.hybrid?.observed ? rep.hybrid : null;
  const ci = rep.circl;
  const base = { dimension: 'attachment' as const, exactness: 'exact' as const, trust: 'independently_verified' as const, indicator: { type: 'hash' as const, value: hash } };

  const hyVerdict = hy?.verdict ?? '';
  const hyMalicious = !!hy && /malicious/i.test(hyVerdict) && !/no specific/i.test(hyVerdict);
  const hySuspicious = !!hy && !hyMalicious && /suspicious/i.test(hyVerdict);
  const evidence: string[] = [];
  if (mb) evidence.push(`MalwareBazaar: listed${mb.signature ? ` as ${mb.signature}` : ''}${mb.firstSeen ? `, first seen ${mb.firstSeen}` : ''}`);
  if (vt && (vt.malicious > 0 || vt.suspicious > 0)) evidence.push(`VirusTotal: ${vt.malicious} of ${vtTotal(vt)} engines flag it as malicious${vt.suspicious ? `, ${vt.suspicious} as suspicious` : ''}${vt.threatLabel ? `; threat label ${vt.threatLabel}` : ''}`);
  if (hy && (hyMalicious || hySuspicious)) evidence.push(`Hybrid Analysis: ${hyVerdict}${hy.threatScore !== null ? ` (threat score ${hy.threatScore})` : ''}${hy.family ? `, family ${hy.family}` : ''}`);
  const threatNames = [...new Set([vt?.threatLabel, mb?.signature, hy?.family].filter(Boolean) as string[])];
  const observedAt = isoDate(vt?.lastAnalysis) ?? isoDate(mb?.firstSeen);

  const findings: Finding[] = [];
  const critical = !!mb || (vt?.malicious ?? 0) >= 10 || ((vt?.malicious ?? 0) >= 5 && !!vt?.threatLabel) || hyMalicious;
  const high = !critical && !!vt && vt.malicious >= 3 && vt.malicious <= 9;
  const suspicious = !critical && !high && (((vt?.malicious ?? 0) >= 1) || (vt?.suspicious ?? 0) >= 3 || hySuspicious || !!ci?.knownMalicious);

  if (critical || high) {
    const multiEngine = !!vt && vt.malicious >= 3;
    findings.push(makeFinding({
      ...base, id: 'attachment_hash_malicious', severity: critical ? 'critical' : 'high', observedAt,
      source: mb ? 'MalwareBazaar' : multiEngine ? 'VirusTotal' : 'Hybrid Analysis', reliability: mb || multiEngine ? 'high' : 'medium',
      title: mb ? `This exact file is a known malware sample${mb.signature ? ` (${mb.signature})` : ''}` : multiEngine ? `${vt!.malicious} of ${vtTotal(vt!)} antivirus engines flag this exact file as malicious` : `Sandbox verdict for this exact file: ${hyVerdict}`,
      detail: `The file ${label} matches a hash that threat-intelligence sources report as malware${threatNames.length ? ` (${threatNames.join(', ')})` : ''}. This describes the file; whether the email is malicious is decided separately.`,
      evidence,
    }));
  } else if (suspicious) {
    findings.push(makeFinding({
      ...base, id: 'attachment_hash_suspicious', severity: 'medium', observedAt, reliability: 'medium',
      source: vt && (vt.malicious > 0 || vt.suspicious >= 3) ? 'VirusTotal' : hy ? 'Hybrid Analysis' : 'CIRCL hashlookup',
      title: vt && vt.malicious > 0 ? `${vt.malicious} of ${vtTotal(vt)} antivirus engine${vt.malicious === 1 ? '' : 's'} flag this exact file` : vt && vt.suspicious >= 3 ? `${vt.suspicious} of ${vtTotal(vt)} antivirus engines flag this exact file as suspicious` : hySuspicious ? `Sandbox verdict for this exact file: ${hyVerdict}` : 'CIRCL hashlookup flags this exact file',
      detail: 'One or two detections can be generic heuristics or false positives; look at which engines flagged it before drawing conclusions.',
      evidence: ci?.knownMalicious ? [...evidence, `CIRCL hashlookup: ${ci.knownMalicious}`] : evidence,
    }));
  } else if (ci?.known) {
    findings.push(makeFinding({
      ...base, id: 'attachment_hash_known_good', severity: 'info', source: 'CIRCL hashlookup', reliability: 'medium',
      title: 'This exact file is in the CIRCL known-files database',
      detail: `It matches a file seen in software and reference collections${ci.fileName ? ` (${ci.fileName})` : ''}. That is mitigating context only: it does not prove this attachment is harmless here, since attackers also send genuine files.`,
      evidence: [hash],
    }));
  } else if (!vt && !mb && !hy) {
    const responded = rep.providers.filter((p) => p.ok && !p.skipped).length;
    const unavailable = rep.providers.filter((p) => !p.ok).length;
    if (responded > 0) {
      findings.push(makeFinding({
        ...base, id: 'attachment_hash_unknown', severity: 'info', source: 'file-hash-lookup', reliability: unavailable ? 'low' : 'medium',
        title: 'No provider that responded has seen this exact file',
        detail: `Unknown is not the same as safe: new, rare or targeted malware has usually not been reported yet.${unavailable ? ` ${unavailable} provider${unavailable === 1 ? '' : 's'} could not be checked (see the check status table).` : ''}`,
        evidence: [hash, `no detections from the ${responded} provider${responded === 1 ? '' : 's'} that responded`],
      }));
    }
  }

  const checks: CheckResult[] = [];
  for (const p of rep.providers) {
    const def = PROVIDERS.find((x) => x.match.test(p.name));
    if (!def) continue;
    const status: CheckResult['status'] = p.skipped ? 'skipped' : p.ok ? 'complete' : 'failed';
    let result: string | null = null;
    if (status === 'complete') {
      if (def.id === 'virustotal') result = rep.virustotal?.observed ? `${rep.virustotal.malicious} of ${vtTotal(rep.virustotal)} engines flag it` : 'not seen';
      else if (def.id === 'malwarebazaar') result = rep.malwarebazaar?.observed ? 'listed as a malware sample' : 'not listed';
      else if (def.id === 'circl') result = rep.circl?.known ? (rep.circl.knownMalicious ? 'flagged as known malicious' : 'known file') : 'not in the known-files database';
      else result = rep.hybrid?.observed ? (rep.hybrid.verdict ?? 'report found') : 'no report';
    }
    checks.push({ ...check(`attach.${ctx.index}.hash.${def.id}`, 'attachments', `${def.label} hash lookup: ${label}`, status, result, p.error ? p.error.slice(0, 200) : undefined), ...(p.ms ? { ms: p.ms } : {}) });
  }
  return { findings, checks };
}

/** All four provider rows marked failed, for when the lookup as a whole could not run. Never a clean result. */
export const failedReputationChecks = (ctx: ReputationContext, message: string): CheckResult[] =>
  PROVIDERS.map((p) => check(`attach.${ctx.index}.hash.${p.id}`, 'attachments', `${p.label} hash lookup: ${ctx.filename ?? `attachment ${ctx.index + 1}`}`, 'failed', null, message.slice(0, 200)));

/* ------------------------------------------------------- active scan (upload) */

export interface ActiveScanContext { index: number; filename: string; sha256: string }
export type ActiveScanOutcome =
  | { status: 'completed'; report: FileAnalysisReport }
  | { status: 'pending'; link: string | null }
  | { status: 'skipped'; reason: string }
  /** VirusTotal already had a recent report for the exact file (from the hash lookup), so it was not uploaded again. */
  | { status: 'known'; reason: string }
  | { status: 'failed'; reason: string };

/**
 * Converts the outcome of uploading a file to VirusTotal and waiting for its scan into at most one finding (using the
 * same ids and thresholds as the hash lookup, so the verdict engine scores it identically) and one check row.
 * A scan that did not finish, or could not run, is never reported as clean.
 */
export function convertActiveScan(outcome: ActiveScanOutcome, ctx: ActiveScanContext): { findings: Finding[]; checks: CheckResult[] } {
  const id = `attach.${ctx.index}.scan.virustotal`;
  const label = `VirusTotal active scan: ${ctx.filename}`;
  if (outcome.status === 'known') return { findings: [], checks: [check(id, 'attachments', label, 'not_applicable', 'existing report used', outcome.reason.slice(0, 240))] };
  if (outcome.status === 'skipped') return { findings: [], checks: [check(id, 'attachments', label, 'skipped', null, outcome.reason.slice(0, 200))] };
  if (outcome.status === 'failed') return { findings: [], checks: [check(id, 'attachments', label, 'failed', null, outcome.reason.slice(0, 200))] };
  if (outcome.status === 'pending') {
    return { findings: [], checks: [check(id, 'attachments', label, 'failed', 'scan not finished', `The file was uploaded but VirusTotal had not finished scanning it in time.${outcome.link ? ` Check the report later: ${outcome.link}` : ''}`)] };
  }
  const s = outcome.report.stats;
  if (!s) return { findings: [], checks: [check(id, 'attachments', label, 'failed', null, 'VirusTotal returned no scan statistics.')] };
  const total = s.total;
  const result = `${s.malicious} of ${total} engines flag it${s.suspicious ? `, ${s.suspicious} suspicious` : ''}`;
  const checks = [check(id, 'attachments', label, 'complete', result, outcome.report.link ?? undefined)];
  const base = { dimension: 'attachment' as const, exactness: 'exact' as const, trust: 'independently_verified' as const, indicator: { type: 'hash' as const, value: ctx.sha256 }, source: 'VirusTotal', observedAt: new Date().toISOString() };
  const names = [...new Set(outcome.report.detections.map((d) => d.result).filter(Boolean) as string[])].slice(0, 5);
  const evidence = [`VirusTotal active scan: ${s.malicious} of ${total} engines flag it as malicious${s.suspicious ? `, ${s.suspicious} as suspicious` : ''}`, ...(names.length ? [`Detections: ${names.join(', ')}`] : [])];
  const findings: Finding[] = [];
  if (s.malicious >= 3) {
    findings.push(makeFinding({
      ...base, id: 'attachment_hash_malicious', severity: s.malicious >= 10 ? 'critical' : 'high', reliability: 'high',
      title: `${s.malicious} of ${total} antivirus engines flag this exact file as malicious (fresh scan)`,
      detail: `The attachment ${ctx.filename} was uploaded to VirusTotal and scanned. This describes the file; whether the email is malicious is decided separately.`,
      evidence,
    }));
  } else if (s.malicious >= 1 || s.suspicious >= 3) {
    findings.push(makeFinding({
      ...base, id: 'attachment_hash_suspicious', severity: 'medium', reliability: 'medium',
      title: s.malicious >= 1 ? `${s.malicious} of ${total} antivirus engine${s.malicious === 1 ? '' : 's'} flag this exact file (fresh scan)` : `${s.suspicious} of ${total} antivirus engines flag this exact file as suspicious (fresh scan)`,
      detail: 'One or two detections can be generic heuristics or false positives; look at which engines flagged it before drawing conclusions.',
      evidence,
    }));
  }
  return { findings, checks };
}
