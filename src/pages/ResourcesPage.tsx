import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { Badge, Card, CopyButton, Empty, KV, PageHeader } from '../components/ui';
import { Icon } from '../components/icons';
import { Link, navigate, useLocation } from '../lib/router';
import { RESOURCES } from '../data';
import { buildIndex, filterTools, NO_FILTERS, searchIndex, type Filters, type IndexedTool } from '../lib/search';
import { defang } from '../../shared/domain';
import type { Flag, Tool } from '../types/resources';

const PAGE = 60;
const FLAG_LABEL: Partial<Record<Flag, string>> = { api: 'API', local: 'Local install', reg: 'Registration', dork: 'Dork', invite: 'Invite only', depr: 'Deprecated' };
const BUILTIN: Record<string, { to: (host?: string) => string; label: string }> = {
  'email-address': { to: () => '/email', label: 'Run built-in e-mail checks' },
  'domain-name': { to: () => '/domain', label: 'Run built-in domain checks' },
  'ip-mac-address': { to: () => '/ip', label: 'Run built-in IP lookup' },
};

const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };

function ToolRow({ it, selected, onSelect }: { it: IndexedTool; selected: boolean; onSelect: () => void }) {
  const t = it.tool;
  return (
    <li className={`rounded-xl border transition ${selected ? 'border-teal/50 bg-teal/[.07]' : 'border-line bg-panel/90 hover:border-line2'}`}>
      <button onClick={onSelect} aria-pressed={selected} className="block w-full rounded-t-xl p-3 pb-1 text-left">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium">{t.name}</span>
          {t.opsec && <Badge tone={t.opsec === 'passive' ? 'good' : 'warn'}>{t.opsec}</Badge>}
          {t.pricing && <Badge>{t.pricing}</Badge>}
          {t.flags.includes('api') && <Badge tone="info">API</Badge>}
        </div>
        {t.description && <p className="mt-1 line-clamp-2 text-sm text-muted">{t.description}</p>}
      </button>
      <div className="px-3 pb-3">
        <a href={t.url} target="_blank" rel="noopener noreferrer" title={t.url} className="inline-block max-w-full truncate align-top text-xs text-teal hover:underline">{host(t.url)}</a>
      </div>
    </li>
  );
}

function Detail({ it, onClose }: { it: IndexedTool; onClose: () => void }) {
  const t = it.tool;
  const cat = RESOURCES.categories[t.category];
  const builtin = BUILTIN[cat.id];
  return (
    <Card
      title="Details"
      action={<button onClick={onClose} aria-label="Close details" className="rounded-md p-1 text-muted hover:text-fg"><Icon name="x" size={16} /></button>}
    >
      <h2 className="text-lg font-semibold">{t.name}</h2>
      <p className="mb-3 text-xs text-faint">{it.path.join(' › ')}</p>
      <div className="mb-3 flex flex-wrap gap-1.5">
        {t.opsec && <Badge tone={t.opsec === 'passive' ? 'good' : 'warn'}>{t.opsec}</Badge>}
        {t.pricing && <Badge>{t.pricing}</Badge>}
        {t.flags.map((f) => <Badge key={f} tone={f === 'depr' ? 'bad' : 'neutral'}>{FLAG_LABEL[f] ?? f}</Badge>)}
      </div>
      {t.description && <p className="mb-3 text-sm">{t.description}</p>}
      <KV rows={[['Best for', t.bestFor], ['Input', t.input], ['Output', t.output], ['OpSec', t.opsecNote]]} />
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <a href={t.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-lg bg-teal px-3 py-1.5 text-sm font-semibold text-[#04202a] hover:brightness-110">Open {host(t.url)} <Icon name="ext" size={14} /></a>
        <CopyButton text={t.url} label="Copy URL" />
        <CopyButton text={defang(t.url)} label="Defanged" />
      </div>
      {t.opsec === 'active' && <p className="mt-3 rounded-lg border border-amber/30 bg-amber/10 p-2 text-xs text-amber">Active tool: it may contact the target directly and leave traces. Only use it on systems you are authorised to test.</p>}
      {builtin && <Link to={builtin.to()} className="mt-4 inline-flex items-center gap-1.5 text-sm text-teal hover:underline">{builtin.label} <Icon name="arrow" size={14} /></Link>}
    </Card>
  );
}

export default function ResourcesPage() {
  const { params } = useLocation();
  const q = params.get('q') ?? '';
  const toolId = params.get('tool') !== null ? Number(params.get('tool')) : null;
  const cat = params.get('cat') !== null ? Number(params.get('cat')) : null;
  const sub = params.get('sub') !== null ? Number(params.get('sub')) : null;
  const opsec = (params.get('opsec') as Filters['opsec']) || null;
  const pricing = (params.get('pricing') as Filters['pricing']) || null;
  const flags = (params.get('flags')?.split(',').filter(Boolean) ?? []) as Flag[];

  const index = useMemo(() => buildIndex(RESOURCES), []);
  const [text, setText] = useState(q);
  useEffect(() => setText(q), [q]);
  const deferred = useDeferredValue(text);
  const [shown, setShown] = useState(PAGE);

  const set = (patch: Record<string, string | null>, replace = false) => {
    const next = new URLSearchParams(window.location.search);
    for (const [k, v] of Object.entries(patch)) (v === null || v === '' ? next.delete(k) : next.set(k, v));
    const qs = next.toString();
    navigate(`/resources${qs ? `?${qs}` : ''}`, { replace });
  };
  // debounce typing into the URL
  useEffect(() => {
    if (text === q) return;
    const id = window.setTimeout(() => set({ q: text }, true), 220);
    return () => window.clearTimeout(id);
  }, [text]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => setShown(PAGE), [deferred, cat, sub, opsec, pricing, flags.join()]);

  const filters: Filters = { ...NO_FILTERS, category: cat, sub, opsec, pricing, flags };
  const results = useMemo(() => searchIndex(filterTools(index, filters), q), [index, q, cat, sub, opsec, pricing, flags.join()]); // eslint-disable-line react-hooks/exhaustive-deps
  const selected: Tool | undefined = toolId !== null ? RESOURCES.tools[toolId] : undefined;
  const selectedIt = selected ? index[selected.id] : undefined;
  const anyFilter = cat !== null || opsec || pricing || flags.length > 0;

  const chip = (active: boolean, label: string, onClick: () => void) => (
    <button key={label} onClick={onClick} aria-pressed={active} className={`rounded-full border px-2.5 py-1 text-xs transition ${active ? 'border-teal/50 bg-teal/15 text-teal' : 'border-line2 text-muted hover:text-fg'}`}>{label}</button>
  );

  return (
    <div className="max-w-6xl">
      <PageHeader icon="library" title="Resource Directory" blurb={`${RESOURCES.tools.length} curated OSINT and security tools, each rated passive or active so you know what leaves a trace.`} />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-60 flex-1">
          <Icon name="search" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-teal" />
          <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Search tools: phishing, whois, sandbox, breach…" aria-label="Search resources" spellCheck={false} className="h-10 w-full rounded-lg border border-line2 bg-bg2 pl-9 pr-3 text-sm placeholder:text-faint focus:border-teal/60" />
        </div>
        {anyFilter && <button onClick={() => set({ cat: null, sub: null, opsec: null, pricing: null, flags: null })} className="text-xs text-muted hover:text-fg">Clear filters</button>}
      </div>

      {cat !== null && (
        <div className="mb-2 flex flex-wrap gap-1.5" aria-label="Sub-categories">
          {chip(sub === null, `All ${RESOURCES.categories[cat].name}`, () => set({ sub: null }))}
          {RESOURCES.categories[cat].subs.map((s, i) => chip(sub === i, `${s.name} (${s.toolIds.length})`, () => set({ sub: String(i) })))}
        </div>
      )}
      <div className="mb-4 flex flex-wrap gap-1.5">
        {chip(opsec === 'passive', 'Passive', () => set({ opsec: opsec === 'passive' ? null : 'passive' }))}
        {chip(opsec === 'active', 'Active', () => set({ opsec: opsec === 'active' ? null : 'active' }))}
        <span className="mx-1 w-px bg-line" />
        {chip(pricing === 'free', 'Free', () => set({ pricing: pricing === 'free' ? null : 'free' }))}
        {chip(pricing === 'freemium', 'Freemium', () => set({ pricing: pricing === 'freemium' ? null : 'freemium' }))}
        <span className="mx-1 w-px bg-line" />
        {(['api', 'local', 'reg'] as Flag[]).map((f) => chip(flags.includes(f), FLAG_LABEL[f]!, () => set({ flags: (flags.includes(f) ? flags.filter((x) => x !== f) : [...flags, f]).join(',') || null })))}
      </div>

      <p className="mb-2 text-xs text-faint" aria-live="polite">{results.length} result{results.length === 1 ? '' : 's'}{q ? ` for “${q}”` : ''}</p>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div>
          {results.length === 0 ? <Empty>No tools match. Try fewer words or clear a filter.</Empty> : (
            <>
              <ul className="space-y-2">{results.slice(0, shown).map((it) => <ToolRow key={it.tool.id} it={it} selected={it.tool.id === toolId} onSelect={() => set({ tool: String(it.tool.id) })} />)}</ul>
              {results.length > shown && <button onClick={() => setShown(shown + PAGE)} className="mt-3 w-full rounded-lg border border-line2 py-2 text-sm text-muted hover:text-fg">Show {Math.min(PAGE, results.length - shown)} more</button>}
            </>
          )}
        </div>
        <aside className={`${selectedIt ? 'fixed inset-x-0 bottom-0 z-30 max-h-[80vh] overflow-y-auto rounded-t-2xl border-t border-line2 bg-bg p-3 shadow-2xl lg:sticky lg:top-20 lg:z-auto lg:max-h-[calc(100vh-6rem)] lg:rounded-none lg:border-0 lg:bg-transparent lg:p-0 lg:shadow-none' : 'hidden lg:block'}`}>
          {selectedIt ? <Detail it={selectedIt} onClose={() => set({ tool: null })} /> : <div className="hidden rounded-xl border border-dashed border-line2 p-6 text-center text-sm text-faint lg:block">Select a tool to see what it does, its inputs and outputs, and its OpSec rating.</div>}
        </aside>
      </div>
    </div>
  );
}
