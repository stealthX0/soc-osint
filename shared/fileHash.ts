export type HashAlgo = 'md5' | 'sha1' | 'sha256';

/** Accepts an MD5, SHA-1 or SHA-256 hex digest (any case, surrounding whitespace) and returns it normalised. */
export function normalizeHash(raw: string): { hash: string; algo: HashAlgo } | null {
  const hash = raw.trim().toLowerCase();
  if (!/^[a-f0-9]+$/.test(hash)) return null;
  if (hash.length === 32) return { hash, algo: 'md5' };
  if (hash.length === 40) return { hash, algo: 'sha1' };
  if (hash.length === 64) return { hash, algo: 'sha256' };
  return null;
}
