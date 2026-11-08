/**
 * Step 7: local investigation history. The last 20 investigations are kept in this browser's localStorage and nowhere
 * else. What is stored is ONLY the exported report object (see shared/phishing/report.ts) plus an id and a timestamp:
 * never the pasted headers, the message body or any attachment.
 *
 * Pure except for the storage object it is given, so tests inject a fake (including one that throws). A history write must
 * never throw into the UI: every storage call is guarded, and every entry read back is re-validated and re-cleaned.
 */
import { readJSON, writeJSON } from './storage';
import { parseStoredReport, type Report } from '../../shared/phishing/report';
import type { VerdictLabel } from '../../shared/phishing/verdict';

export const HISTORY_KEY = 'spectrix.phishing.history.v1';
export const HISTORY_ENABLED_KEY = 'spectrix.phishing.history.enabled';
export const HISTORY_MAX = 20;

export interface HistoryEntry { id: string; savedAt: string; report: Report }

/** The two storage calls the history needs. The default wraps the app's guarded readJSON / writeJSON. */
export interface HistoryStore { read<T>(key: string, fallback: T): T; write(key: string, value: unknown): void }
export const browserStore: HistoryStore = { read: readJSON, write: writeJSON };

const safeRead = (store: HistoryStore): unknown => {
  try { return store.read<unknown>(HISTORY_KEY, []); } catch { return []; }
};
const safeWrite = (store: HistoryStore, entries: HistoryEntry[]): boolean => {
  try { store.write(HISTORY_KEY, entries); return true; } catch { return false; }
};

function cleanEntry(raw: unknown): HistoryEntry | null {
  if (!raw || typeof raw !== 'object') return null;
  const e = raw as Record<string, unknown>;
  if (typeof e.id !== 'string' || !e.id || e.id.length > 80 || typeof e.savedAt !== 'string' || Number.isNaN(Date.parse(e.savedAt))) return null;
  const report = parseStoredReport(e.report);
  return report ? { id: e.id, savedAt: new Date(e.savedAt).toISOString(), report } : null;
}

/** Entries newest first. Corrupt JSON, wrong shapes and damaged entries are dropped, never thrown. */
export function loadHistory(store: HistoryStore = browserStore): HistoryEntry[] {
  const raw = safeRead(store);
  if (!Array.isArray(raw)) return [];
  const out: HistoryEntry[] = [];
  const ids = new Set<string>();
  for (const item of raw) {
    const e = cleanEntry(item);
    if (e && !ids.has(e.id)) { ids.add(e.id); out.push(e); }
    if (out.length >= HISTORY_MAX) break;
  }
  return out.sort((a, b) => (a.savedAt < b.savedAt ? 1 : a.savedAt > b.savedAt ? -1 : 0));
}

export const newHistoryId = (now = Date.now()): string => `h-${now.toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

/**
 * Adds (or replaces, when `id` already exists) an entry and keeps the newest 20. Returns the history as stored.
 * Anything that is not a valid report is refused, and only report fields are kept.
 */
export function saveToHistory(report: Report, opts: { store?: HistoryStore; id?: string; now?: number } = {}): HistoryEntry[] {
  const store = opts.store ?? browserStore;
  const clean = parseStoredReport(report);
  if (!clean) return loadHistory(store);
  const now = opts.now ?? Date.now();
  const entry: HistoryEntry = { id: opts.id ?? newHistoryId(now), savedAt: new Date(now).toISOString(), report: clean };
  const next = [entry, ...loadHistory(store).filter((e) => e.id !== entry.id)].slice(0, HISTORY_MAX);
  safeWrite(store, next);
  return next;
}

export function deleteFromHistory(id: string, store: HistoryStore = browserStore): HistoryEntry[] {
  const next = loadHistory(store).filter((e) => e.id !== id);
  safeWrite(store, next);
  return next;
}

export function clearHistory(store: HistoryStore = browserStore): HistoryEntry[] {
  safeWrite(store, []);
  return [];
}

export interface HistoryRow { id: string; date: string; label: VerdictLabel; labelText: string; risk: number; subject: string; fromDomain: string }

const SUBJECT_MAX = 80;
export const truncate = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** What the history list shows for an entry. The subject is cut to 80 characters. */
export function summarizeEntry(e: HistoryEntry): HistoryRow {
  return {
    id: e.id, date: e.savedAt, label: e.report.verdict.label, labelText: e.report.verdict.labelText, risk: e.report.verdict.risk,
    subject: truncate(e.report.message.subject ?? '(no subject)', SUBJECT_MAX), fromDomain: e.report.message.fromDomain ?? 'unknown sender',
  };
}
