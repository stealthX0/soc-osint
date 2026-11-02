import { useCallback, useState } from 'react';

/** localStorage can throw (private mode, blocked cookies): every access is guarded. */
export function readJSON<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}
export function writeJSON(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch { /* ignore */ }
}

export function useStored<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => readJSON(key, initial));
  const set = useCallback(
    (v: T | ((p: T) => T)) => {
      setValue((prev) => {
        const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
        writeJSON(key, next);
        return next;
      });
    },
    [key],
  );
  return [value, set];
}

export interface Recent { label: string; to: string; kind: string; at: number }
const RECENT_KEY = 'tl-recent-v1';

export function pushRecent(item: Omit<Recent, 'at'>) {
  const list = readJSON<Recent[]>(RECENT_KEY, []).filter((r) => r.to !== item.to);
  list.unshift({ ...item, at: Date.now() });
  writeJSON(RECENT_KEY, list.slice(0, 12));
}
export const readRecent = () => readJSON<Recent[]>(RECENT_KEY, []);
export const clearRecent = () => writeJSON(RECENT_KEY, []);
