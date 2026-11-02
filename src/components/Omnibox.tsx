import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from 'react';
import { Icon } from './icons';
import { navigate } from '../lib/router';
import { routeFor } from '../lib/omnibox';

export function Omnibox({ autoFocus = false, large = false }: { autoFocus?: boolean; large?: boolean }) {
  const [value, setValue] = useState('');
  const ref = useRef<HTMLInputElement>(null);
  const id = useId();
  const route = useMemo(() => (value.trim() ? routeFor(value) : null), [value]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
      if ((e.key === '/' && !typing) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) {
        // the layout renders one instance per breakpoint; only the visible one reacts
        if (!ref.current || ref.current.offsetParent === null) return;
        e.preventDefault();
        ref.current?.focus();
        ref.current?.select();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!route) return;
    navigate(route.to);
    setValue('');
    ref.current?.blur();
  };

  return (
    <form onSubmit={submit} role="search" className="relative w-full">
      <label htmlFor={id} className="sr-only">Search or paste an IP, domain, URL, e-mail or hash</label>
      <Icon name="search" className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-teal" size={large ? 20 : 16} />
      <input
        id={id}
        ref={ref}
        value={value}
        autoFocus={autoFocus}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Paste an IP, domain, URL, e-mail or hash — or search tools"
        spellCheck={false}
        autoComplete="off"
        className={`w-full rounded-xl border border-line2 bg-bg2/90 pr-28 text-fg placeholder:text-faint focus:border-teal/60 focus:shadow-[0_0_0_1px_rgba(45,212,191,.35),0_0_24px_rgba(45,212,191,.12)] ${large ? 'h-14 pl-12 text-base' : 'h-10 pl-10 text-sm'}`}
      />
      <div className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center gap-2">
        {route ? <span className="hidden rounded-md border border-teal/30 bg-teal/10 px-1.5 py-0.5 text-[11px] text-teal sm:inline">{route.kind === 'text' ? 'search' : route.kind}</span> : <kbd className="hidden sm:inline">/</kbd>}
      </div>
    </form>
  );
}
