import { useEffect, useMemo, useRef, useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react';

import { matchPath } from './match';
export { matchPath };

/* A deliberately tiny History-API router: the app has ~10 flat routes and no nested layouts. */

const EVENT = 'tl:navigate';

function subscribe(cb: () => void) {
  window.addEventListener('popstate', cb);
  window.addEventListener(EVENT, cb);
  return () => {
    window.removeEventListener('popstate', cb);
    window.removeEventListener(EVENT, cb);
  };
}
const snapshot = () => window.location.pathname + window.location.search;

export function navigate(to: string, opts: { replace?: boolean } = {}) {
  const from = snapshot();
  if (to === from) return;
  const samePath = new URL(to, window.location.origin).pathname === window.location.pathname;
  window.history[opts.replace ? 'replaceState' : 'pushState'](null, '', to);
  window.dispatchEvent(new Event(EVENT));
  if (!samePath) window.scrollTo(0, 0);
}

export function useLocation() {
  const key = useSyncExternalStore(subscribe, snapshot, () => '/');
  return useMemo(() => {
    const u = new URL(key, 'http://x');
    return { pathname: u.pathname, search: u.search, params: u.searchParams, key };
  }, [key]);
}

/** Read/write one query-string value (used so every lookup is a shareable URL). */
export function useQueryParam(name: string): [string, (v: string | null, replace?: boolean) => void] {
  const { params, pathname } = useLocation();
  const value = params.get(name) ?? '';
  const set = (v: string | null, replace = false) => {
    const next = new URLSearchParams(window.location.search);
    if (v === null || v === '') next.delete(name);
    else next.set(name, v);
    const qs = next.toString();
    navigate(pathname + (qs ? `?${qs}` : ''), { replace });
  };
  return [value, set];
}

export function Link({ to, onClick, children, ...rest }: { to: string; children?: ReactNode } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  const handle = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || rest.target === '_blank') return;
    e.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} onClick={handle} {...rest}>
      {children}
    </a>
  );
}

export interface RouteDef { path: string; render: (params: Record<string, string>) => ReactNode }

export function Routes({ routes, fallback }: { routes: RouteDef[]; fallback: ReactNode }) {
  const { pathname } = useLocation();
  // Move focus to <main> after client-side navigation (screen readers/keyboard users), but not on first load.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    document.getElementById('main')?.focus({ preventScroll: true });
  }, [pathname]);
  for (const r of routes) {
    const params = matchPath(r.path, pathname);
    if (params) return <>{r.render(params)}</>;
  }
  return <>{fallback}</>;
}
