import { useEffect, useState, type ReactNode } from 'react';
import { Icon } from './icons';
import { Omnibox } from './Omnibox';
import { Link, useLocation } from '../lib/router';
import { NAV, SITE_NAME, TAGLINE } from '../config';

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const { pathname } = useLocation();
  const section = (title: string, group: 'tools' | 'library') => (
    <div className="mb-4">
      <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[.14em] text-faint">{title}</p>
      {NAV.filter((n) => n.group === group).map((n) => {
        const active = pathname === n.to || pathname.startsWith(`${n.to}/`);
        return (
          <Link
            key={n.to}
            to={n.to}
            onClick={onNavigate}
            aria-current={active ? 'page' : undefined}
            className={`mb-0.5 flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${active ? 'bg-teal/12 text-teal shadow-[inset_2px_0_0_var(--color-teal)]' : 'text-muted hover:bg-white/[.04] hover:text-fg'}`}
          >
            <Icon name={n.icon} size={17} />
            {n.label}
          </Link>
        );
      })}
    </div>
  );
  return (
    <nav aria-label="Primary" className="p-3">
      <Link to="/" onClick={onNavigate} aria-current={pathname === '/' ? 'page' : undefined} className={`mb-4 flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${pathname === '/' ? 'bg-teal/12 text-teal shadow-[inset_2px_0_0_var(--color-teal)]' : 'text-muted hover:bg-white/[.04] hover:text-fg'}`}>
        <Icon name="home" size={17} /> Dashboard
      </Link>
      {section('Tools', 'tools')}
      {section('Library', 'library')}
    </nav>
  );
}

export function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2.5">
      <span className="grid size-8 place-items-center rounded-[9px] bg-gradient-to-br from-teal to-sky text-[#04202a] shadow-[0_4px_18px_rgba(45,212,191,.3)]"><Icon name="search" size={17} strokeWidth={2.6} /></span>
      <span className="leading-tight">
        <b className="block text-sm tracking-wide">{SITE_NAME}</b>
        <small className="hidden text-[10px] uppercase tracking-[.08em] text-muted sm:block">{TAGLINE}</small>
      </span>
    </Link>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-teal focus:px-3 focus:py-1.5 focus:text-[#04202a]">Skip to content</a>
      <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-panel/90 px-3 py-2.5 backdrop-blur sm:px-4">
        <button onClick={() => setOpen(true)} aria-label="Open navigation" aria-expanded={open} className="grid size-9 place-items-center rounded-lg border border-line2 text-muted hover:text-fg lg:hidden">
          <Icon name="menu" size={18} />
        </button>
        <div className="lg:w-[13.5rem]"><Brand /></div>
        <div className="mx-auto hidden max-w-3xl flex-1 sm:block"><Omnibox /></div>
        <div className="ml-auto text-[11px] text-faint sm:hidden" />
      </header>
      <div className="border-b border-line bg-panel/60 p-2 sm:hidden"><Omnibox /></div>

      <div className="mx-auto flex max-w-[1500px]">
        <aside className="sticky top-[57px] hidden h-[calc(100vh-57px)] w-60 shrink-0 overflow-y-auto border-r border-line lg:block"><NavLinks /></aside>

        {open && (
          <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
            <button className="absolute inset-0 bg-black/60" aria-label="Close navigation" onClick={() => setOpen(false)} />
            <div className="absolute inset-y-0 left-0 w-72 max-w-[85vw] overflow-y-auto border-r border-line bg-panel">
              <div className="flex items-center justify-between border-b border-line p-3"><Brand /><button onClick={() => setOpen(false)} aria-label="Close" className="grid size-8 place-items-center rounded-lg text-muted hover:text-fg"><Icon name="x" /></button></div>
              <NavLinks onNavigate={() => setOpen(false)} />
            </div>
          </div>
        )}

        <main id="main" tabIndex={-1} className="min-w-0 flex-1 px-4 py-6 outline-none sm:px-6 lg:px-8">
          {children}
          <footer className="mt-12 border-t border-line pt-4 text-xs text-faint">
            <p>
              Lookups use free public data sources and are rate limited. Passive lookups never contact your target; HTTP and latency checks are <b className="text-amber">active</b> and
              send requests to it. Only probe systems you are authorised to test. No account, no tracking; recent lookups are stored only in your browser.
            </p>
          </footer>
        </main>
      </div>
    </div>
  );
}
