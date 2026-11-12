/**
 * Date display in the Indian format (DD/MM/YYYY), shared by the browser and the Worker.
 *
 * Machine formats stay ISO 8601: JSON exports, stored history, file names and case ids. These helpers are only for text a
 * person reads. A value that cannot be parsed is returned unchanged rather than hidden.
 */
type DateLike = string | number | Date | null | undefined;

const pad = (n: number) => String(n).padStart(2, '0');

function toDate(v: DateLike): Date | null {
  if (v === null || v === undefined || v === '') return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** DD/MM/YYYY, in UTC (for provider dates and anything shown as UTC). */
export function dmyUtc(v: DateLike): string | null {
  const d = toDate(v);
  if (!d) return v === null || v === undefined || v === '' ? null : String(v);
  return `${pad(d.getUTCDate())}/${pad(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`;
}

/** DD/MM/YYYY HH:MM UTC. */
export function dmyTimeUtc(v: DateLike): string | null {
  const d = toDate(v);
  if (!d) return v === null || v === undefined || v === '' ? null : String(v);
  return `${dmyUtc(d)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/** DD/MM/YYYY in the viewer's local time zone. */
export function dmyLocal(v: DateLike): string | null {
  const d = toDate(v);
  if (!d) return v === null || v === undefined || v === '' ? null : String(v);
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
}

/** DD/MM/YYYY, hh:mm:ss am/pm in the viewer's local time zone. */
export function dmyTimeLocal(v: DateLike): string | null {
  const d = toDate(v);
  if (!d) return v === null || v === undefined || v === '' ? null : String(v);
  const h = d.getHours();
  return `${dmyLocal(d)}, ${pad(h % 12 || 12)}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${h < 12 ? 'am' : 'pm'}`;
}
