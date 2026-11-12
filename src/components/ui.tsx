import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { dmyTimeUtc } from '../../shared/dates';
import { Icon } from './icons';
import type { ProviderStatus, Issue } from '../../shared/types';
import type { ApiClientError } from '../lib/api';
import { defang } from '../../shared/domain';

export type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'info' | 'accent';

const TONES: Record<Tone, string> = {
  neutral: 'border-line2 bg-white/[.03] text-muted',
  good: 'border-green/30 bg-green/10 text-green',
  warn: 'border-amber/30 bg-amber/10 text-amber',
  bad: 'border-rose/30 bg-rose/10 text-rose',
  info: 'border-sky/30 bg-sky/10 text-sky',
  accent: 'border-teal/30 bg-teal/10 text-teal',
};

export const Badge = ({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) => (
  <span title={title} className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none whitespace-nowrap ${TONES[tone]}`}>
    {children}
  </span>
);

export const Card = ({ title, action, children, className = '', pad = true }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) => (
  <section className={`rounded-xl border border-line bg-panel/90 shadow-[0_1px_0_rgba(255,255,255,.03)_inset] ${className}`}>
    {(title || action) && (
      <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <h2 className="text-[11px] font-semibold uppercase tracking-[.12em] text-muted">{title}</h2>
        {action}
      </header>
    )}
    <div className={pad ? 'p-4' : ''}>{children}</div>
  </section>
);

export function PageHeader({ icon, title, blurb, badge }: { icon: string; title: string; blurb: string; badge?: ReactNode }) {
  return (
    <div className="mb-5 flex items-start gap-3">
      <div className="grid size-10 shrink-0 place-items-center rounded-xl border border-teal/25 bg-teal/10 text-teal">
        <Icon name={icon} size={20} />
      </div>
      <div className="min-w-0">
        <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">{title}{badge}</h1>
        {blurb && <p className="text-sm text-muted">{blurb}</p>}
      </div>
    </div>
  );
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 text-sm text-muted">
      <span className="size-4 animate-spin rounded-full border-2 border-line2 border-t-teal" />
      {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: ApiClientError | { message: string; code?: string }; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-xl border border-rose/30 bg-rose/10 p-4 text-sm">
      <Icon name="warn" className="mt-0.5 text-rose" />
      <div className="min-w-0 flex-1">
        <p className="font-medium text-rose">{error.message}</p>
        {'code' in error && error.code && <p className="mt-0.5 font-mono text-[11px] text-rose/70">{error.code}</p>}
      </div>
      {onRetry && (
        <button onClick={onRetry} className="inline-flex items-center gap-1 rounded-md border border-rose/30 px-2 py-1 text-xs text-rose hover:bg-rose/10">
          <Icon name="refresh" size={12} /> Retry
        </button>
      )}
    </div>
  );
}

export const Empty = ({ children }: { children: ReactNode }) => (
  <div className="rounded-xl border border-dashed border-line2 p-8 text-center text-sm text-muted">{children}</div>
);

/** Definition list: skips rows whose value is null/undefined/empty. */
export function KV({ rows, mono = false }: { rows: [string, ReactNode][]; mono?: boolean }) {
  const shown = rows.filter(([, v]) => v !== null && v !== undefined && v !== '' && v !== false);
  if (!shown.length) return <p className="text-sm text-faint">No data.</p>;
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {shown.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className={`min-w-0 break-words ${mono ? 'font-mono text-[13px]' : ''}`}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CopyButton({ text, label = 'Copy', className = '' }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { /* ignore */ }
      ta.remove();
    }
    setDone(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setDone(false), 1400);
  };
  return (
    <button type="button" onClick={copy} aria-label={`${label}: ${text.slice(0, 40)}`} className={`inline-flex items-center gap-1 rounded-md border border-line2 px-1.5 py-0.5 text-[11px] text-muted hover:border-teal/40 hover:text-teal ${className}`}>
      <Icon name={done ? 'check' : 'copy'} size={12} />
      {done ? 'Copied' : label}
    </button>
  );
}

/** Value + copy button (+ optional defanged copy for IOCs). */
export function Copyable({ value, ioc = false }: { value: string; ioc?: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className="font-mono text-[13px]">{value}</span>
      <CopyButton text={value} />
      {ioc && <CopyButton text={defang(value)} label="Defanged" />}
    </span>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; icon?: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="mb-4 inline-flex max-w-full gap-1 overflow-x-auto rounded-lg border border-line bg-bg2/80 p-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-sm transition-colors ${value === t.id ? 'bg-teal/15 text-teal shadow-[0_0_0_1px_rgba(45,212,191,.3)]' : 'text-muted hover:text-fg'}`}
        >
          {t.icon && <Icon name={t.icon} size={14} />}
          {t.label}
        </button>
      ))}
    </div>
  );
}

export interface FieldDef { name: string; label: string; placeholder?: string; defaultValue?: string; width?: string; options?: { value: string; label: string }[]; mono?: boolean }

/** Compact multi-field form: calls onSubmit with the values; the parent decides what to do (usually write the URL). */
export function LookupForm({
  fields, submitLabel = 'Look up', onSubmit, busy, extra, values: controlled,
}: {
  fields: FieldDef[]; submitLabel?: string; onSubmit: (v: Record<string, string>) => void; busy?: boolean; extra?: ReactNode; values?: Record<string, string>;
}) {
  const id = useId();
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.name, controlled?.[f.name] ?? f.defaultValue ?? ''])));
  // keep the inputs in sync when the URL changes (back/forward, recent-lookup click)
  useEffect(() => {
    if (controlled) setVals((v) => ({ ...v, ...controlled }));
  }, [JSON.stringify(controlled)]); // eslint-disable-line react-hooks/exhaustive-deps
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit(Object.fromEntries(Object.entries(vals).map(([k, v]) => [k, v.trim()])));
  };
  return (
    <form onSubmit={submit} className="mb-5 flex flex-wrap items-end gap-3 rounded-xl border border-line bg-panel/90 p-3">
      {fields.map((f) => (
        <div key={f.name} className={`flex min-w-0 flex-col gap-1 ${f.width ?? 'flex-1 basis-56'}`}>
          <label htmlFor={`${id}-${f.name}`} className="text-[11px] font-medium uppercase tracking-wider text-muted">{f.label}</label>
          {f.options ? (
            <select id={`${id}-${f.name}`} value={vals[f.name]} onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })} className="h-10 rounded-lg border border-line2 bg-bg2 px-3 text-sm focus:border-teal/60">
              {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          ) : (
            <input
              id={`${id}-${f.name}`}
              value={vals[f.name]}
              onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })}
              placeholder={f.placeholder}
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              className={`h-10 rounded-lg border border-line2 bg-bg2 px-3 text-sm placeholder:text-faint focus:border-teal/60 ${f.mono === false ? '' : 'font-mono'}`}
            />
          )}
        </div>
      ))}
      <button type="submit" disabled={busy} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] transition hover:brightness-110 disabled:opacity-60">
        <Icon name="search" size={15} strokeWidth={2.4} /> {busy ? 'Working…' : submitLabel}
      </button>
      {extra}
    </form>
  );
}

const LEVEL: Record<Issue['level'], { tone: Tone; icon: string }> = {
  error: { tone: 'bad', icon: 'x' },
  warn: { tone: 'warn', icon: 'warn' },
  info: { tone: 'info', icon: 'info' },
};

export function IssueList({ issues, empty = 'No issues detected.' }: { issues: Issue[]; empty?: string }) {
  if (!issues.length) return <p className="flex items-center gap-2 text-sm text-green"><Icon name="check" /> {empty}</p>;
  const order = { error: 0, warn: 1, info: 2 };
  return (
    <ul className="space-y-1.5">
      {[...issues].sort((a, b) => order[a.level] - order[b.level]).map((i, n) => (
        <li key={n} className="flex items-start gap-2 text-sm">
          <span className={`mt-0.5 ${TONES[LEVEL[i.level].tone].split(' ').pop()}`}><Icon name={LEVEL[i.level].icon} size={15} /></span>
          <span>{i.message}</span>
        </li>
      ))}
    </ul>
  );
}

export function ProviderStrip({ providers }: { providers: ProviderStatus[] }) {
  if (!providers.length) return null;
  return (
    <div className="mt-4 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
      <span className="uppercase tracking-wider text-faint">Sources</span>
      {providers.map((p) => (
        <Badge key={p.name} tone={p.skipped ? 'neutral' : p.ok ? 'good' : 'bad'} title={p.error}>
          <Icon name={p.skipped ? 'info' : p.ok ? 'check' : 'x'} size={11} /> {p.name}{p.ok ? ` · ${p.ms}ms` : p.skipped ? (/budget/i.test(p.error ?? '') ? ' · paused (quota)' : ' · not configured') : ' · failed'}
        </Badge>
      ))}
    </div>
  );
}

export function DataTable({ head, rows, empty = 'No records.' }: { head: string[]; rows: ReactNode[][]; empty?: string }) {
  if (!rows.length) return <p className="text-sm text-faint">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[11px] uppercase tracking-wider text-muted">{head.map((h) => <th key={h} className="px-2 py-1.5 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-line/60 last:border-0 align-top">
              {r.map((c, j) => <td key={j} className="px-2 py-1.5">{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const gradeTone = (g: string): Tone => (g === 'A' ? 'good' : g === 'B' ? 'good' : g === 'C' ? 'warn' : 'bad');

export function Grade({ grade, score }: { grade: string; score?: number }) {
  const t = gradeTone(grade);
  const color = { good: 'text-green border-green/40 bg-green/10', warn: 'text-amber border-amber/40 bg-amber/10', bad: 'text-rose border-rose/40 bg-rose/10', neutral: '', info: '', accent: '' }[t];
  return (
    <div className={`grid size-16 shrink-0 place-items-center rounded-xl border text-center ${color}`}>
      <div><div className="text-2xl font-bold leading-none">{grade}</div>{score !== undefined && <div className="mt-0.5 text-[10px] opacity-80">{score}/100</div>}</div>
    </div>
  );
}

export const fmtDate = (iso: string | null | undefined) => {
  return dmyTimeUtc(iso);
};
