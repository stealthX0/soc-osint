/** Hostname / domain / e-mail helpers (pure, runtime-agnostic). */
import { parseIP } from './ip';

const LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * Normalises user input into a lowercase ASCII (punycode) hostname.
 * Accepts bare hosts, URLs ("https://Example.com/path"), e-mail addresses and trailing dots.
 * Returns null when the result is not a syntactically valid DNS name.
 */
export function normalizeHostname(input: string): string | null {
  let s = input.trim();
  if (!s || s.length > 2048) return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''); // strip scheme
  s = s.replace(/^[^@/]*@/, ''); // strip user@ (also e-mail local part)
  s = s.split(/[/?#]/)[0]; // strip path/query
  if (!s.startsWith('[')) s = s.replace(/:\d+$/, ''); // strip :port (not for IPv6 literals)
  s = s.replace(/\.$/, '').toLowerCase();
  if (!s) return null;
  if (parseIP(s.replace(/^\[|\]$/g, ''))) return null; // IP literals are not hostnames
  let ascii: string;
  try {
    ascii = new URL(`http://${s}`).hostname; // applies IDNA / punycode
  } catch {
    return null;
  }
  return isValidHostname(ascii) ? ascii : null;
}

export function isValidHostname(h: string): boolean {
  if (h.length === 0 || h.length > 253) return false;
  const labels = h.split('.');
  return labels.every((l) => l.length >= 1 && l.length <= 63 && LABEL.test(l));
}

/** Registrable-looking domain: at least two labels and an alphabetic (or xn--) TLD. */
export function normalizeDomain(input: string): string | null {
  const h = normalizeHostname(input);
  if (!h) return null;
  const labels = h.split('.');
  if (labels.length < 2) return null;
  const tld = labels[labels.length - 1];
  if (!/^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return null;
  return h;
}

export function parseEmail(input: string): { local: string; domain: string } | null {
  const m = input.trim().match(/^([^\s@<>()[\],;:]+)@([^\s@<>()[\],;:]+)$/);
  if (!m) return null;
  const domain = normalizeDomain(m[2]);
  return domain ? { local: m[1], domain } : null;
}

/** Strips obfuscation commonly used when sharing IOCs (hxxp, [.], (dot), etc.). */
export function refang(s: string): string {
  return s
    .replace(/hxxp/gi, 'http')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*(\.|dot)\s*\]|\(\s*(\.|dot)\s*\)|\{\s*(\.|dot)\s*\}/gi, '.')
    .replace(/\[\s*@\s*\]|\(\s*at\s*\)|\[\s*at\s*\]/gi, '@');
}

/** Makes an IOC safe to paste into chat / tickets without creating a live link. */
export function defang(s: string): string {
  return s
    .replace(/https?:\/\//gi, (m) => m.replace(/^http/i, 'hxxp'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

export type InputKind = 'ipv4' | 'ipv6' | 'email' | 'url' | 'domain' | 'hash' | 'cve' | 'asn' | 'text';

/** Best-effort classification of whatever the user pasted into the omnibox. */
export function detectInput(raw: string): { kind: InputKind; value: string } {
  const value = refang(raw.trim());
  if (!value) return { kind: 'text', value };
  const ip = parseIP(value);
  if (ip) return { kind: ip.version === 4 ? 'ipv4' : 'ipv6', value };
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) return { kind: 'hash', value };
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return { kind: 'cve', value: value.toUpperCase() };
  if (/^AS\d{1,10}$/i.test(value)) return { kind: 'asn', value: value.toUpperCase() };
  if (/^https?:\/\//i.test(value)) {
    if (normalizeHostname(value)) return { kind: 'url', value };
    try {
      // URLs whose host is a raw IP (common for malware delivery) are still URLs
      if (parseIP(new URL(value).hostname.replace(/^\[|\]$/g, ''))) return { kind: 'url', value };
    } catch { /* not a URL */ }
    return { kind: 'text', value };
  }
  const email = parseEmail(value);
  if (email) return { kind: 'email', value };
  const domain = normalizeDomain(value);
  if (domain && !/\s/.test(value)) return { kind: 'domain', value: domain };
  return { kind: 'text', value };
}
