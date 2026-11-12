/**
 * Analyst-labelled investigations kept in this browser for calibration (see shared/phishing/calibrationRecord.ts for what a
 * record contains: finding ids and check statuses only, never message content, addresses or URLs). Every storage call is
 * guarded; a damaged store reads back as empty.
 */
import { readJSON, writeJSON } from './storage';
import { CALIBRATION_SCHEMA, parseCalibrationFile, type CalibrationRecord } from '../../shared/phishing/calibrationRecord';

export const LABELS_KEY = 'spectrix.phishing.labels.v1';
export const LABELS_MAX = 1000;

export function loadLabels(): CalibrationRecord[] {
  try { return parseCalibrationFile(readJSON<unknown>(LABELS_KEY, [])); } catch { return []; }
}
/** Adds or replaces (same id) a record, newest first. Returns the new list. */
export function saveLabel(rec: CalibrationRecord): CalibrationRecord[] {
  const next = [rec, ...loadLabels().filter((r) => r.id !== rec.id)].slice(0, LABELS_MAX);
  writeJSON(LABELS_KEY, next);
  return next;
}
export function removeLabel(id: string): CalibrationRecord[] {
  const next = loadLabels().filter((r) => r.id !== id);
  writeJSON(LABELS_KEY, next);
  return next;
}
export function clearLabels(): void { writeJSON(LABELS_KEY, []); }
export function labelsFile(records: CalibrationRecord[]): string {
  return JSON.stringify({ schema: CALIBRATION_SCHEMA, exportedAt: new Date().toISOString(), count: records.length, records }, null, 1);
}
