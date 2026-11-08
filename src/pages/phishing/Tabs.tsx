import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { Icon } from '../../components/icons';

export interface TabDef<T extends string> { id: T; label: string; icon?: string }

export const tabDomId = (prefix: string, id: string) => `${prefix}-tab-${id}`;
export const panelDomId = (prefix: string, id: string) => `${prefix}-panel-${id}`;

/**
 * WAI-ARIA tabs: role=tablist/tab, aria-selected, aria-controls, a roving tabindex, and Left/Right/Home/End to move.
 * Moving with the keys also selects (automatic activation), which suits panels that are already rendered.
 */
export function TabList<T extends string>({ tabs, value, onChange, prefix = 'ph', ariaLabel = 'Investigation report sections' }: { tabs: TabDef<T>[]; value: T; onChange: (v: T) => void; prefix?: string; ariaLabel?: string }) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const move = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === value);
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = tabs.length - 1;
    if (n < 0) return;
    e.preventDefault();
    onChange(tabs[n].id);
    refs.current[tabs[n].id]?.focus();
  };
  return (
    <div role="tablist" aria-label={ariaLabel} aria-orientation="horizontal" onKeyDown={move} className="ph-tablist mb-4 flex max-w-full gap-1 overflow-x-auto rounded-lg border border-line bg-bg2/80 p-1">
      {tabs.map((t) => {
        const on = value === t.id;
        return (
          <button
            key={t.id} ref={(el) => { refs.current[t.id] = el; }} type="button" role="tab" id={tabDomId(prefix, t.id)} aria-selected={on} aria-controls={panelDomId(prefix, t.id)} tabIndex={on ? 0 : -1}
            onClick={() => onChange(t.id)}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal ${on ? 'bg-teal/15 text-teal shadow-[0_0_0_1px_rgba(45,212,191,.3)]' : 'text-muted hover:text-fg'}`}
          >
            {t.icon && <Icon name={t.icon} size={14} />}
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

/** Every panel stays mounted (so lookups, dropped files and filters keep their state); only the selected one is shown. */
export function TabPanel({ id, active, prefix = 'ph', children }: { id: string; active: boolean; prefix?: string; children: ReactNode }) {
  return (
    <div role="tabpanel" id={panelDomId(prefix, id)} aria-labelledby={tabDomId(prefix, id)} hidden={!active} tabIndex={0} data-panel={id} className="ph-panel rounded-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-teal">
      {children}
    </div>
  );
}
