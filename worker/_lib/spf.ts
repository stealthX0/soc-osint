import { resolveData } from './doh';
import { isSpfRecord, parseSpf } from '../../shared/emailAuth';

export interface SpfLookupCount { total: number; truncated: boolean; loops: boolean }

/**
 * Counts the DNS-querying terms an SPF evaluation would trigger (RFC 7208 section 4.6.4: limit 10),
 * following include:/redirect= recursively. Capped to avoid runaway fan-out.
 */
export async function countSpfLookups(root: string, rootRecord: string, maxQueries = 12): Promise<SpfLookupCount> {
  let total = 0;
  let queries = 0;
  let truncated = false;
  let loops = false;
  const seen = new Set<string>([root]);

  async function walk(record: string, depth: number): Promise<void> {
    const parsed = parseSpf(record);
    total += parsed.directLookups;
    const targets = [...parsed.includes, ...(parsed.redirect ? [parsed.redirect] : [])];
    for (const t of targets) {
      const name = t.toLowerCase();
      if (seen.has(name)) { loops = true; continue; }
      seen.add(name);
      if (depth >= 6 || queries >= maxQueries) { truncated = true; continue; }
      queries++;
      try {
        const txt = (await resolveData(name, 'TXT')).find(isSpfRecord);
        if (txt) await walk(txt, depth + 1);
      } catch {
        truncated = true;
      }
    }
  }
  await walk(rootRecord, 0);
  return { total, truncated, loops };
}
