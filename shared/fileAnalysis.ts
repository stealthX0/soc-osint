/**
 * Static file inspection that runs entirely in the browser (or Node, for tests): nothing is uploaded.
 *
 * This is triage, not a verdict. It looks for traits that are common in malicious files (packing, macros, embedded
 * scripts, auto-run PDF actions, suspicious imports) and for signs that a file is not what its name claims. A file
 * with no findings is NOT proven safe, and a file with findings is not proven malicious.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high';
export interface Finding { severity: Severity; title: string; detail?: string }

export interface PeSection { name: string; virtualSize: number; rawSize: number; entropy: number; executable: boolean; writable: boolean }
export interface PeInfo {
  machine: string; bits: 32 | 64; isDll: boolean; subsystem: string | null; timestamp: string | null; entryPoint: number;
  sections: PeSection[]; imports: { dll: string; functions: string[] }[]; suspiciousImports: string[];
  hasSignature: boolean; overlayBytes: number;
}
export interface ArchiveEntry { name: string; size: number; compressedSize: number; encrypted: boolean }
export interface StringsInfo { urls: string[]; ips: string[]; emails: string[]; registryKeys: string[]; suspicious: string[]; total: number }

export interface FileAnalysis {
  name: string;
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
  /** Human-readable detected type, from magic bytes (not the extension). */
  type: string;
  typeId: string;
  extension: string | null;
  entropy: number;
  pe: PeInfo | null;
  archive: { entries: ArchiveEntry[]; truncated: boolean; totalEntries: number } | null;
  strings: StringsInfo;
  findings: Finding[];
  /** 0-100 triage score derived from the findings. Higher means more suspicious traits, never "safe". */
  score: number;
  level: 'no-findings' | 'low' | 'medium' | 'high';
  analyzedBytes: number;
}

/* ------------------------------------------------------------------ helpers */

const enc = new TextDecoder('latin1');
const u16 = (b: Uint8Array, o: number) => (o >= 0 && o + 2 <= b.length ? b[o] | (b[o + 1] << 8) : 0);
const u32 = (b: Uint8Array, o: number) => (o >= 0 && o + 4 <= b.length ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : 0);
const startsWith = (b: Uint8Array, sig: number[], at = 0) => b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v);
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));

export function shannonEntropy(b: Uint8Array, start = 0, end = b.length): number {
  const len = Math.max(0, Math.min(end, b.length) - start);
  if (len === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < start + len; i++) counts[b[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / len;
    e -= p * Math.log2(p);
  }
  return e;
}

/* --------------------------------------------------------------------- MD5 */
// Pure-JS MD5 (WebCrypto has no MD5). Used only to look files up by hash; never for security decisions.
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

export function md5(data: Uint8Array): string {
  const len = data.length;
  const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, (len * 8) >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(len / 0x20000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < padded.length; off += 64) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + dv.getUint32(off + g * 4, true)) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << MD5_S[i]) | (F >>> (32 - MD5_S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true); odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return [...out].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');

/* ----------------------------------------------------------- type detection */

interface TypeInfo { id: string; label: string }
const EXEC_EXT = new Set(['exe', 'dll', 'scr', 'com', 'pif', 'sys', 'cpl', 'msi', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'hta', 'lnk', 'jar', 'reg', 'msc', 'iso', 'img', 'chm', 'apk', 'appx', 'msix', 'sh', 'elf', 'bin', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'ppam']);
const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'csv', 'odt', 'ods']);
const EXT_FOR_TYPE: Record<string, string[]> = {
  pe: ['exe', 'dll', 'scr', 'sys', 'cpl', 'com', 'ocx', 'efi', 'pif', 'bin', 'tmp', 'dat'],
  elf: ['elf', 'so', 'bin', 'o', 'out', ''],
  macho: ['dylib', 'bundle', 'bin', 'o', ''],
  pdf: ['pdf'], rtf: ['rtf', 'doc'], png: ['png'], jpeg: ['jpg', 'jpeg', 'jpe'], gif: ['gif'],
  zip: ['zip', 'jar', 'apk', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'dotx', 'dotm', 'xltx', 'xltm', 'odt', 'ods', 'odp', 'xpi', 'appx', 'msix', 'nupkg', 'whl', 'epub', 'war', 'ear', 'aar'],
  ole: ['doc', 'xls', 'ppt', 'msi', 'msg', 'dot', 'xlt', 'pot', 'xla', 'ppa', 'pps', 'vsd', 'pub', 'db', 'suo'],
  rar: ['rar'], '7z': ['7z'], gzip: ['gz', 'tgz'], tar: ['tar'], lnk: ['lnk'],
  cab: ['cab', 'msu'], iso: ['iso', 'img'],
};

export function detectType(b: Uint8Array): TypeInfo {
  if (startsWith(b, [0x4d, 0x5a])) {
    const pe = u32(b, 0x3c);
    return startsWith(b, [0x50, 0x45, 0, 0], pe) ? { id: 'pe', label: 'Windows executable (PE)' } : { id: 'dos', label: 'DOS executable (MZ)' };
  }
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return { id: 'elf', label: 'ELF executable (Linux/Unix)' };
  if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xce, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xfe, 0xed, 0xfa, 0xce]) || startsWith(b, [0xfe, 0xed, 0xfa, 0xcf])) return { id: 'macho', label: 'Mach-O executable (macOS)' };
  if (startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return { id: 'macho', label: 'Mach-O universal binary or Java class' };
  if (startsWith(b, ascii('%PDF-'))) return { id: 'pdf', label: 'PDF document' };
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return { id: 'zip', label: 'ZIP-based container (ZIP, Office OOXML, JAR, APK…)' };
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { id: 'ole', label: 'OLE2 compound file (legacy Office, MSI)' };
  if (startsWith(b, ascii('Rar!'))) return { id: 'rar', label: 'RAR archive' };
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { id: '7z', label: '7-Zip archive' };
  if (startsWith(b, [0x1f, 0x8b])) return { id: 'gzip', label: 'GZIP archive' };
  if (startsWith(b, ascii('ustar'), 257)) return { id: 'tar', label: 'TAR archive' };
  if (startsWith(b, ascii('MSCF'))) return { id: 'cab', label: 'Cabinet (CAB) archive' };
  if (startsWith(b, ascii('CD001'), 0x8001)) return { id: 'iso', label: 'ISO disk image' };
  if (startsWith(b, [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0])) return { id: 'lnk', label: 'Windows shortcut (LNK)' };
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return { id: 'png', label: 'PNG image' };
  if (startsWith(b, [0xff, 0xd8, 0xff])) return { id: 'jpeg', label: 'JPEG image' };
  if (startsWith(b, ascii('GIF8'))) return { id: 'gif', label: 'GIF image' };
  if (startsWith(b, ascii('{\\rtf'))) return { id: 'rtf', label: 'Rich Text Format (RTF)' };
  const head = enc.decode(b.subarray(0, 512));
  if (/^#!\s*\/\S+/.test(head)) return { id: 'script', label: 'Shell/script (shebang)' };
  if (/^\s*<\?xml|^\s*<(!doctype html|html)/i.test(head)) return { id: 'html', label: /<html|<!doctype html/i.test(head) ? 'HTML document' : 'XML document' };
  const sample = b.subarray(0, 4096);
  let printable = 0;
  for (const c of sample) if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  if (sample.length && printable / sample.length > 0.95) return { id: 'text', label: 'Text / script' };
  return { id: 'unknown', label: 'Unknown binary data' };
}

/* ---------------------------------------------------------------------- PE */

const MACHINES: Record<number, string> = { 0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA-64', 0x1c4: 'ARMv7 Thumb-2' };
const SUBSYSTEMS: Record<number, string> = { 1: 'Native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console', 9: 'Windows CE', 10: 'EFI application', 14: 'Xbox' };

/** APIs that are individually common in benign software but, in combination, characterise injectors and droppers. */
const SUSPICIOUS_APIS: Record<string, string> = {
  VirtualAllocEx: 'process injection', WriteProcessMemory: 'process injection', CreateRemoteThread: 'process injection', NtUnmapViewOfSection: 'process hollowing',
  SetThreadContext: 'process hollowing', QueueUserAPC: 'process injection', NtWriteVirtualMemory: 'process injection', RtlCreateUserThread: 'process injection',
  URLDownloadToFileA: 'download', URLDownloadToFileW: 'download', InternetOpenUrlA: 'network', InternetOpenUrlW: 'network', WinExec: 'execution',
  IsDebuggerPresent: 'anti-debug', CheckRemoteDebuggerPresent: 'anti-debug', NtQueryInformationProcess: 'anti-debug',
  SetWindowsHookExA: 'keylogging', SetWindowsHookExW: 'keylogging', GetAsyncKeyState: 'keylogging', GetKeyboardState: 'keylogging',
  CryptEncrypt: 'crypto (ransomware/stealers)', CryptAcquireContextA: 'crypto', CryptAcquireContextW: 'crypto', AdjustTokenPrivileges: 'privilege change',
  RegSetValueExA: 'persistence', RegSetValueExW: 'persistence', CreateServiceA: 'persistence', CreateServiceW: 'persistence', OpenProcessToken: 'privilege change',
  LoadLibraryA: 'dynamic loading', LoadLibraryW: 'dynamic loading', GetProcAddress: 'dynamic loading', ShellExecuteA: 'execution', ShellExecuteW: 'execution',
};
const NOISY = new Set(['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'ShellExecuteA', 'ShellExecuteW', 'OpenProcessToken', 'RegSetValueExA', 'RegSetValueExW', 'IsDebuggerPresent', 'CryptAcquireContextA', 'CryptAcquireContextW']);
const PACKER_SECTIONS = /^(upx\d?|\.?aspack|\.?adata|\.?mpress\d?|\.?petite|\.?themida|\.?vmp\d|\.?enigma\d?|\.?nsp\d|pec\d*|\.?packed|\.?yp|\.?perplex)/i;

function cstr(b: Uint8Array, o: number, max = 256): string {
  let s = '';
  for (let i = o; i < b.length && i < o + max && b[i] !== 0; i++) s += String.fromCharCode(b[i]);
  return s;
}

export function parsePE(b: Uint8Array): PeInfo | null {
  const peOff = u32(b, 0x3c);
  if (!startsWith(b, [0x4d, 0x5a]) || !startsWith(b, [0x50, 0x45, 0, 0], peOff) || peOff > b.length - 24) return null;
  const nSections = u16(b, peOff + 6);
  const timestamp = u32(b, peOff + 8);
  const optSize = u16(b, peOff + 20);
  const chars = u16(b, peOff + 22);
  const opt = peOff + 24;
  const magic = u16(b, opt);
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const entryPoint = u32(b, opt + 16);
  const subsystem = u16(b, opt + 68);
  const ddOff = opt + (is64 ? 112 : 96);
  const nDirs = Math.min(u32(b, opt + (is64 ? 108 : 92)), 16);
  const dir = (i: number) => (i < nDirs ? { rva: u32(b, ddOff + i * 8), size: u32(b, ddOff + i * 8 + 4) } : { rva: 0, size: 0 });

  const secOff = opt + optSize;
  const rawSecs: { name: string; vsize: number; vaddr: number; rawSize: number; rawPtr: number; flags: number }[] = [];
  for (let i = 0; i < Math.min(nSections, 96); i++) {
    const o = secOff + i * 40;
    if (o + 40 > b.length) break;
    rawSecs.push({ name: cstr(b.subarray(o, o + 8), 0, 8), vsize: u32(b, o + 8), vaddr: u32(b, o + 12), rawSize: u32(b, o + 16), rawPtr: u32(b, o + 20), flags: u32(b, o + 36) });
  }
  const rvaToOff = (rva: number): number => {
    for (const s of rawSecs) {
      if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize)) return s.rawPtr + (rva - s.vaddr);
    }
    return rva < 0x1000 ? rva : -1;
  };

  const sections: PeSection[] = rawSecs.map((s) => ({
    name: s.name, virtualSize: s.vsize, rawSize: s.rawSize,
    entropy: s.rawSize > 0 && s.rawPtr < b.length ? shannonEntropy(b, s.rawPtr, s.rawPtr + s.rawSize) : 0,
    executable: !!(s.flags & 0x20000000), writable: !!(s.flags & 0x80000000),
  }));

  // Import table (bounded: malformed files must not make us loop or allocate without limit)
  const imports: PeInfo['imports'] = [];
  const suspiciousImports: string[] = [];
  const imp = dir(1);
  const impOff = imp.rva ? rvaToOff(imp.rva) : -1;
  if (impOff >= 0) {
    for (let i = 0; i < 128; i++) {
      const d = impOff + i * 20;
      if (d + 20 > b.length) break;
      const nameRva = u32(b, d + 12);
      const thunkRva = u32(b, d) || u32(b, d + 16);
      if (!nameRva && !thunkRva) break;
      const nameOff = rvaToOff(nameRva);
      if (nameOff < 0) break;
      const dll = cstr(b, nameOff, 64);
      const fns: string[] = [];
      let t = rvaToOff(thunkRva);
      const step = is64 ? 8 : 4;
      for (let n = 0; n < 4000 && t >= 0 && t + step <= b.length; n++, t += step) {
        const v = is64 ? u32(b, t) : u32(b, t);
        const hi = is64 ? u32(b, t + 4) : 0;
        if (!v && !hi) break;
        const byOrdinal = is64 ? (hi & 0x80000000) !== 0 : (v & 0x80000000) !== 0;
        if (byOrdinal) { fns.push(`#${v & 0xffff}`); continue; }
        const fo = rvaToOff(v & 0x7fffffff);
        if (fo >= 0) fns.push(cstr(b, fo + 2, 80));
      }
      imports.push({ dll, functions: fns.slice(0, 400) });
      for (const f of fns) if (SUSPICIOUS_APIS[f] && !suspiciousImports.includes(f)) suspiciousImports.push(f);
    }
  }

  const lastRaw = rawSecs.reduce((m, s) => Math.max(m, s.rawPtr + s.rawSize), 0);
  const cert = dir(4);
  return {
    machine: MACHINES[u16(b, peOff + 4)] ?? `0x${u16(b, peOff + 4).toString(16)}`,
    bits: is64 ? 64 : 32, isDll: !!(chars & 0x2000), subsystem: SUBSYSTEMS[subsystem] ?? null,
    timestamp: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    entryPoint, sections, imports, suspiciousImports,
    hasSignature: cert.size > 0, overlayBytes: Math.max(0, b.length - lastRaw - (cert.size || 0)),
  };
}

/* -------------------------------------------------------------------- ZIP */

export function parseZip(b: Uint8Array, maxEntries = 400): { entries: ArchiveEntry[]; total: number } | null {
  // Locate the End Of Central Directory record (scan back over a possible comment).
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65_535); i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const total = u16(b, eocd + 10);
  let p = u32(b, eocd + 16);
  const entries: ArchiveEntry[] = [];
  for (let i = 0; i < total && i < maxEntries; i++) {
    if (p + 46 > b.length || u32(b, p) !== 0x02014b50) break;
    const flags = u16(b, p + 8);
    const csize = u32(b, p + 20), usize = u32(b, p + 24);
    const nlen = u16(b, p + 28), xlen = u16(b, p + 30), clen = u16(b, p + 32);
    let name = enc.decode(b.subarray(p + 46, Math.min(b.length, p + 46 + nlen)));
    if (flags & 0x800) name = new TextDecoder('utf-8').decode(b.subarray(p + 46, Math.min(b.length, p + 46 + nlen)));
    entries.push({ name, size: usize, compressedSize: csize, encrypted: !!(flags & 1) });
    p += 46 + nlen + xlen + clen;
  }
  return { entries, total };
}

/* ---------------------------------------------------------------- strings */

const URL_RE = /https?:\/\/[^\s"'<>\\^`{}|)\]\x00-\x1f]{4,200}/gi;
const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{2,40}@[A-Za-z0-9.-]{3,60}\.[A-Za-z]{2,10}\b/g;
const REG_RE = /\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\w\\ .{}-]{4,120}/g;
const SUSPICIOUS_TERMS = [
  'powershell', 'cmd.exe', '-encodedcommand', ' -enc ', 'frombase64string', 'invoke-expression', 'iex(', 'iex ', 'downloadstring', 'downloadfile', 'invoke-webrequest',
  'wscript.shell', 'wscript.exe', 'cscript', 'mshta', 'regsvr32', 'certutil', 'bitsadmin', 'rundll32', 'schtasks', 'vssadmin', 'wmic ', 'net user', 'netsh',
  'currentversion\\run', 'mimikatz', 'sekurlsa', 'meterpreter', 'cobalt', 'amsiscanbuffer', 'virtualalloc', 'createremotethread', 'writeprocessmemory', 'shellcode',
  'autoopen', 'auto_open', 'document_open', 'workbook_open', 'createobject', 'eval(', 'unescape(', 'fromcharcode', 'activexobject', 'wmi', 'bypass', 'hidden',
  'your files have been encrypted', 'bitcoin', '.onion', 'decrypt', 'ransom',
];

function extractStrings(b: Uint8Array, limit: number): string[] {
  const out: string[] = [];
  const end = Math.min(b.length, limit);
  // ASCII runs
  let start = -1;
  for (let i = 0; i <= end; i++) {
    const c = i < end ? b[i] : 0;
    const printable = c >= 32 && c < 127;
    if (printable) { if (start < 0) start = i; }
    else {
      if (start >= 0 && i - start >= 6) out.push(enc.decode(b.subarray(start, Math.min(i, start + 2000))));
      start = -1;
    }
    if (out.length > 60_000) break;
  }
  // UTF-16LE runs (strings may start at an odd offset, so scan both alignments)
  const wide: string[] = [];
  for (const parity of [0, 1]) {
    let cur = '';
    for (let i = parity; i + 1 < end; i += 2) {
      const lo = b[i], hi = b[i + 1];
      if (hi === 0 && lo >= 32 && lo < 127) cur += String.fromCharCode(lo);
      else {
        if (cur.length >= 6) wide.push(cur.slice(0, 2000));
        cur = '';
      }
      if (wide.length > 20_000) break;
    }
    if (cur.length >= 6) wide.push(cur);
  }
  return out.concat(wide);
}

export function analyzeStrings(b: Uint8Array, limit = 16 * 1024 * 1024): StringsInfo {
  const all = extractStrings(b, limit);
  const joined = all.join('\n');
  const uniq = (re: RegExp, cap: number, filter?: (s: string) => boolean) => {
    const set = new Set<string>();
    for (const m of joined.matchAll(re)) {
      if (filter && !filter(m[0])) continue;
      set.add(m[0]);
      if (set.size >= cap) break;
    }
    return [...set];
  };
  const lower = joined.toLowerCase();
  const suspicious = SUSPICIOUS_TERMS.filter((t) => lower.includes(t.toLowerCase())).map((t) => t.trim());
  return {
    urls: uniq(URL_RE, 40),
    // version-number-like strings (e.g. 1.2.3.4 in file metadata) are noisy, so skip addresses that start with 0 or are reserved
    ips: uniq(IP_RE, 30, (ip) => !/^(0\.|127\.|255\.)/.test(ip)),
    emails: uniq(EMAIL_RE, 20),
    registryKeys: uniq(REG_RE, 20),
    suspicious: [...new Set(suspicious)].slice(0, 40),
    total: all.length,
  };
}

/* ----------------------------------------------------------------- hashing */

export async function hashBytes(b: Uint8Array): Promise<{ md5: string; sha1: string; sha256: string }> {
  const [s1, s256] = await Promise.all([crypto.subtle.digest('SHA-1', b as unknown as BufferSource), crypto.subtle.digest('SHA-256', b as unknown as BufferSource)]);
  return { md5: md5(b), sha1: hex(s1), sha256: hex(s256) };
}

/* -------------------------------------------------------------------- main */

const RLO = /[‪-‮⁦-⁩]/;
const SEV_WEIGHT: Record<Severity, number> = { info: 0, low: 6, medium: 16, high: 32 };

export function extensionOf(name: string): string | null {
  const base = name.split(/[\\/]/).pop() ?? '';
  const i = base.lastIndexOf('.');
  return i > 0 && i < base.length - 1 ? base.slice(i + 1).toLowerCase() : null;
}

/** Inspects the bytes and filename. Pure and synchronous apart from hashing; see `analyzeFile` for the async wrapper. */
export function inspect(bytes: Uint8Array, name: string): Omit<FileAnalysis, 'md5' | 'sha1' | 'sha256'> {
  const t = detectType(bytes);
  const ext = extensionOf(name);
  const findings: Finding[] = [];
  const add = (severity: Severity, title: string, detail?: string) => findings.push({ severity, title, detail });
  const entropy = shannonEntropy(bytes);

  /* name vs content */
  if (RLO.test(name)) add('high', 'Filename contains a right-to-left override character', 'Used to disguise an executable extension (e.g. "invoice‮fdp.exe" displays as "invoiceexe.pdf").');
  const parts = (name.split(/[\\/]/).pop() ?? '').toLowerCase().split('.');
  if (parts.length >= 3 && DOC_EXT.has(parts[parts.length - 2]) && EXEC_EXT.has(parts[parts.length - 1])) {
    add('high', `Double extension ".${parts[parts.length - 2]}.${parts[parts.length - 1]}"`, 'A document-looking name hiding an executable type is a classic malware lure.');
  }
  const execTypes = new Set(['pe', 'dos', 'elf', 'macho']);
  if (ext && EXT_FOR_TYPE[t.id] && !EXT_FOR_TYPE[t.id].includes(ext)) {
    const looksExecutable = execTypes.has(t.id);
    add(looksExecutable ? 'high' : 'medium', `Extension ".${ext}" does not match the content (${t.label})`, looksExecutable ? 'An executable disguised under a non-executable extension.' : 'The file may be misnamed or deliberately disguised.');
  }
  if (ext && DOC_EXT.has(ext) && execTypes.has(t.id)) add('high', 'Executable code with a document or image extension');
  if (t.id === 'script' || (t.id === 'text' && ext && ['ps1', 'vbs', 'js', 'bat', 'cmd', 'hta', 'wsf', 'sh'].includes(ext))) add('low', 'Script file', 'Scripts run directly when opened; review the contents before executing.');
  if (t.id === 'lnk') add('medium', 'Windows shortcut file', 'LNK files are frequently used to launch hidden commands; check the strings below for what it runs.');
  if (t.id === 'iso') add('low', 'Disk image', 'Disk images are used to bypass mark-of-the-web protections.');

  /* packing / encryption */
  if (bytes.length > 4096 && entropy > 7.4 && !['zip', 'gzip', 'rar', '7z', 'jpeg', 'png', 'cab'].includes(t.id)) {
    add('medium', `Very high entropy (${entropy.toFixed(2)} / 8)`, 'The content looks compressed, packed or encrypted, which hides what the file does.');
  }

  /* format-specific */
  let pe: PeInfo | null = null;
  let archive: FileAnalysis['archive'] = null;
  const latin = t.id === 'pdf' || t.id === 'rtf' || t.id === 'ole' || t.id === 'text' || t.id === 'html' || t.id === 'script' ? enc.decode(bytes.subarray(0, Math.min(bytes.length, 16 * 1024 * 1024))) : '';

  if (t.id === 'pe') {
    pe = parsePE(bytes);
    if (!pe) add('medium', 'Malformed PE header', 'The file claims to be a Windows executable but its headers do not parse; malformed headers are used to evade analysis.');
    else {
      if (pe.timestamp) {
        const ts = Date.parse(pe.timestamp);
        if (ts > Date.now() + 86_400_000) add('low', 'Compile timestamp is in the future', pe.timestamp);
        if (ts < Date.parse('1995-01-01')) add('low', 'Compile timestamp is implausibly old or zeroed', pe.timestamp);
      }
      const packer = pe.sections.find((s) => PACKER_SECTIONS.test(s.name));
      if (packer) add('high', `Packer-style section name "${packer.name}"`, 'Common for UPX, ASPack, MPRESS, Themida and similar packers.');
      const wx = pe.sections.filter((s) => s.executable && s.writable);
      if (wx.length) add('medium', 'Section is both writable and executable', wx.map((s) => s.name).join(', '));
      const hot = pe.sections.filter((s) => s.entropy > 7.2 && s.rawSize > 2048);
      if (hot.length) add('medium', 'High-entropy section', hot.map((s) => `${s.name} (${s.entropy.toFixed(2)})`).join(', '));
      const hollow = pe.sections.filter((s) => s.executable && s.rawSize === 0 && s.virtualSize > 0x1000);
      if (hollow.length) add('medium', 'Executable section with no data on disk', 'Code that is filled in at run time, typical of unpackers: ' + hollow.map((s) => s.name).join(', '));
      if (pe.sections.length === 0 || pe.sections.length > 12) add('low', `Unusual number of sections (${pe.sections.length})`);
      if (pe.imports.length > 0 && pe.imports.reduce((n, i) => n + i.functions.length, 0) < 6 && !pe.isDll) add('medium', 'Almost no imports', 'Packed files often import only a loader stub such as LoadLibrary and GetProcAddress.');
      const strong = pe.suspiciousImports.filter((f) => !NOISY.has(f));
      if (strong.length >= 3) add('high', 'Several injection/evasion-related API imports', strong.slice(0, 10).join(', '));
      else if (strong.length) add('low', 'Notable API imports', strong.join(', '));
      if (pe.overlayBytes > 1_000_000) add('low', `Large data appended after the executable (${Math.round(pe.overlayBytes / 1024)} KB)`, 'An overlay can hold an embedded payload or installer data.');
      if (!pe.hasSignature) add('info', 'Not digitally signed', 'Most legitimate commercial software is signed; many small utilities are not.');
      else add('info', 'Contains a digital signature block', 'The signature was not cryptographically validated here, so it does not prove authenticity.');
    }
  }

  if (t.id === 'elf' && lower(bytes, 'upx!')) add('high', 'UPX packer signature');

  if (t.id === 'zip') {
    const z = parseZip(bytes);
    if (z) {
      archive = { entries: z.entries, truncated: z.total > z.entries.length, totalEntries: z.total };
      const names = z.entries.map((e) => e.name.toLowerCase());
      const has = (re: RegExp) => names.find((n) => re.test(n));
      if (has(/(^|\/)vbaproject\.bin$/)) add('high', 'Contains a VBA macro project', 'Office files with macros are a leading malware delivery method (docm/xlsm, or macros hidden in docx).');
      if (names.some((n) => n.startsWith('word/') || n.startsWith('xl/') || n.startsWith('ppt/')) && has(/embeddings\//)) add('medium', 'Office document with embedded objects');
      if (has(/activex/)) add('medium', 'Office document with ActiveX controls');
      if (has(/(^|\/)meta-inf\/manifest\.mf$/)) add('info', 'Java archive (JAR)');
      if (has(/^androidmanifest\.xml$/)) add('info', 'Android package (APK)', 'Review requested permissions before installing.');
      const execInside = z.entries.filter((e) => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|hta|lnk|jar|msi|wsf|iso)$/i.test(e.name)).slice(0, 8);
      if (execInside.length && !names.some((n) => n.startsWith('word/') || n.startsWith('xl/') || n.startsWith('ppt/'))) add('medium', 'Archive contains executable or script files', execInside.map((e) => e.name).join(', '));
      if (z.entries.some((e) => e.encrypted)) add('medium', 'Contains password-protected entries', 'Encryption prevents antivirus scanning and is common in phishing attachments.');
      const comp = z.entries.reduce((n, e) => n + e.compressedSize, 0), unc = z.entries.reduce((n, e) => n + e.size, 0);
      if (comp > 0 && unc / comp > 200 && unc > 100_000_000) add('medium', 'Extreme compression ratio', 'May be a decompression bomb.');
      if (z.entries.some((e) => /(^|\/)\.\.(\/|$)/.test(e.name) || /^[a-z]:|^\//i.test(e.name))) add('medium', 'Entries with path traversal or absolute paths', 'Can write outside the extraction folder (zip-slip).');
    }
  }

  if (t.id === 'ole') {
    // OLE stream names are UTF-16, so drop the NUL bytes before matching
    const flat = latin.replace(/\0/g, '');
    const hasVba = /_VBA_PROJECT|Attribute VB_|\bMacros\b.*\bVBA\b/s.test(flat) || /\bVBA(?:_PROJECT)?\b/.test(flat.slice(0, 2_000_000));
    if (hasVba) add('high', 'Legacy Office file with VBA macros', 'Check the strings below for auto-run procedures and shell/download calls.');
    if (/(AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec)/i.test(flat)) add('high', 'Macro runs automatically when the file is opened');
  }

  if (t.id === 'pdf') {
    const count = (re: RegExp) => (latin.match(re) ?? []).length;
    const js = count(/\/(JavaScript|JS)\b/g), open = count(/\/(OpenAction|AA)\b/g), launch = count(/\/Launch\b/g), emb = count(/\/EmbeddedFile\b/g);
    const rich = count(/\/(RichMedia|XFA)\b/g), enc2 = count(/\/Encrypt\b/g), objstm = count(/\/ObjStm\b/g), uri = count(/\/URI\b/g), hexNames = count(/\/[A-Za-z]*#[0-9A-Fa-f]{2}/g);
    if (js && open) add('high', 'PDF runs JavaScript automatically on open', `${js} JavaScript and ${open} auto-action reference(s).`);
    else if (js) add('medium', 'PDF contains JavaScript', `${js} reference(s).`);
    if (launch) add('high', 'PDF can launch external programs (/Launch)');
    if (emb) add('medium', `PDF has ${emb} embedded file(s)`);
    if (rich) add('low', 'PDF uses RichMedia/XFA content', 'Historically used for exploits.');
    if (enc2) add('low', 'PDF is encrypted', 'Encryption hides content from scanners.');
    if (hexNames) add('medium', 'PDF keywords are obfuscated with #-escapes', 'Used to evade simple keyword scanners.');
    if (objstm > 20) add('low', `Many object streams (${objstm})`, 'Can hide objects from basic parsers.');
    if (uri) add('info', `${uri} link(s) in the PDF`);
  }

  if (t.id === 'rtf') {
    if (/\\objdata|\\objemb|\\objautlink/i.test(latin)) add('high', 'RTF with embedded OLE objects', 'A common carrier for document exploits (e.g. equation editor).');
    if (/\\\*\\(?:template|attachedtemplate)\s*\{?\\?\*?\s*https?:/i.test(latin) || /\\\*\\?objupdate/i.test(latin)) add('medium', 'RTF fetches remote content');
  }

  if (t.id === 'text' || t.id === 'script' || t.id === 'html') {
    const s = latin;
    if (/powershell(?:\.exe)?\s+[^\n]*-(?:e|enc|encodedcommand)\b/i.test(s)) add('high', 'Encoded PowerShell command');
    if (/(?:iex|invoke-expression)\s*[\(\s]/i.test(s) && /(downloadstring|downloadfile|webclient|invoke-webrequest|frombase64string)/i.test(s)) add('high', 'PowerShell download-and-execute pattern');
    if (/eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)/i.test(s)) add('high', 'Obfuscated JavaScript (eval of decoded data)');
    if (/[A-Za-z0-9+/]{400,}={0,2}/.test(s)) add('medium', 'Very long Base64 blob', 'Often an embedded payload.');
    if (/ActiveXObject\s*\(\s*["']WScript\.Shell/i.test(s) || /CreateObject\s*\(\s*["']WScript\.Shell/i.test(s)) add('high', 'Script launches commands through WScript.Shell');
    if (/<script[^>]*>[\s\S]{0,200}(document\.write\(unescape|eval\()/i.test(s)) add('medium', 'HTML page with obfuscated script');
  }

  /* strings across all types */
  const analyzed = Math.min(bytes.length, 16 * 1024 * 1024);
  const strings = analyzeStrings(bytes);
  const hot = strings.suspicious.filter((x) => !['hidden', 'bypass', 'wmi', 'decrypt', 'cobalt', 'bitcoin'].includes(x.toLowerCase()));
  if (strings.suspicious.length) {
    const strongTerms = hot.filter((x) => /^(?:powershell|cmd\.exe|frombase64string|invoke-expression|downloadstring|mshta|regsvr32|certutil|bitsadmin|mimikatz|sekurlsa|meterpreter|amsiscanbuffer|shellcode|vssadmin|your files have been encrypted|\.onion|currentversion\\run)$/i.test(x));
    if (strongTerms.length >= 3) add('medium', 'Multiple suspicious command/tool strings', strongTerms.slice(0, 8).join(', '));
    else add('info', 'Notable strings', hot.slice(0, 10).join(', ') || strings.suspicious.slice(0, 8).join(', '));
  }
  if (strings.urls.some((u) => /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(u))) add('low', 'References URLs that use a raw IP address');
  if (strings.registryKeys.some((k) => /\\Run(Once)?\b/i.test(k))) add('medium', 'References autorun registry keys', 'A persistence mechanism.');

  if (bytes.length === 0) add('info', 'File is empty');
  if (!findings.some((f) => f.severity !== 'info')) add('info', 'No suspicious traits found by this static check', 'This is not proof the file is safe. Check the reputation sources and treat unknown files with care.');

  const score = Math.min(100, findings.reduce((n, f) => n + SEV_WEIGHT[f.severity], 0));
  const level: FileAnalysis['level'] = findings.every((f) => f.severity === 'info') ? 'no-findings' : score >= 45 ? 'high' : score >= 16 ? 'medium' : 'low';
  return { name, size: bytes.length, type: t.label, typeId: t.id, extension: ext, entropy, pe, archive, strings, findings, score, level, analyzedBytes: analyzed };
}

function lower(b: Uint8Array, needle: string): boolean {
  const n = ascii(needle);
  const end = Math.min(b.length, 8 * 1024 * 1024) - n.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < n.length; j++) if (b[i + j] !== n[j]) continue outer;
    return true;
  }
  return false;
}

export async function analyzeFile(bytes: Uint8Array, name: string): Promise<FileAnalysis> {
  const [hashes, r] = await Promise.all([hashBytes(bytes), Promise.resolve(inspect(bytes, name))]);
  return { ...r, ...hashes };
}
