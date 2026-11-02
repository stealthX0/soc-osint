import { useEffect, useState } from 'react';
import { Omnibox } from '../components/Omnibox';
import { Badge, Card, KV } from '../components/ui';
import { Icon } from '../components/icons';
import { Link } from '../lib/router';
import { NAV, SITE_NAME } from '../config';
import { api } from '../lib/api';
import { clearRecent, readRecent, type Recent } from '../lib/storage';
import stats from '../data/stats.json';
import type { IpLookup } from '../../shared/types';

function YourConnection() {
  const [state, setState] = useState<{ s: 'loading' | 'ok' | 'err'; d?: IpLookup }>({ s: 'loading' });
  useEffect(() => {
    const ctrl = new AbortController();
    api<IpLookup>('/api/ip/lookup', { signal: ctrl.signal }).then(
      (r) => setState({ s: 'ok', d: r.data }),
      (e) => !(e instanceof DOMException) && setState({ s: 'err' }),
    );
    return () => ctrl.abort();
  }, []);
  return (
    <Card title="Your connection" action={state.d && <Link to="/ip?me=1" className="text-xs text-teal hover:underline">Details</Link>}>
      {state.s === 'loading' && <p className="text-sm text-muted">Detecting…</p>}
      {state.s === 'err' && <p className="text-sm text-faint">Unavailable (the API may not be running locally).</p>}
      {state.d && (
        <KV mono rows={[
          ['IP', state.d.ip],
          ['Location', [state.d.geo?.city, state.d.geo?.country].filter(Boolean).join(', ') || null],
          ['Network', state.d.network ? [state.d.network.asn, state.d.network.org].filter(Boolean).join(' · ') : null],
        ]} />
      )}
    </Card>
  );
}

export function Dashboard() {
  const [recent, setRecent] = useState<Recent[]>([]);
  useEffect(() => setRecent(readRecent()), []);
  const tools = NAV.filter((n) => n.group === 'tools');

  return (
    <div className="mx-auto max-w-6xl">
      <section className="mb-8 mt-2 text-center">
        <p className="mb-3 inline-flex items-center gap-2 rounded-full border border-teal/25 bg-teal/10 px-3 py-1 text-xs text-teal"><Icon name="lock" size={13} /> Free · no account · passive by default</p>
        <h1 className="mb-2 text-3xl font-semibold tracking-tight sm:text-4xl">{SITE_NAME}: investigate any <span className="text-teal">IP</span>, <span className="text-sky">domain</span> or <span className="text-indigo">e-mail</span></h1>
        <p className="mx-auto mb-6 max-w-2xl text-muted">Paste an indicator and we route it to the right tool. Results merge several data providers into one readable report.</p>
        <div className="mx-auto max-w-2xl"><Omnibox large /></div>
        <p className="mt-2 text-xs text-faint">Try <Link to="/ip?q=1.1.1.1" className="text-muted underline-offset-2 hover:text-teal hover:underline">1.1.1.1</Link>, <Link to="/domain?q=example.com" className="text-muted underline-offset-2 hover:text-teal hover:underline">example.com</Link> or <Link to="/email?q=gmail.com" className="text-muted underline-offset-2 hover:text-teal hover:underline">gmail.com</Link></p>
      </section>

      <section aria-label="Tools" className="mb-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {tools.map((t) => (
          <Link key={t.to} to={t.to} className="group rounded-xl border border-line bg-panel/90 p-4 transition hover:border-teal/40 hover:shadow-[0_0_0_1px_rgba(45,212,191,.25),0_0_24px_rgba(45,212,191,.08)]">
            <div className="mb-2 flex items-center justify-between"><span className="grid size-9 place-items-center rounded-lg border border-line2 bg-bg2 text-teal"><Icon name={t.icon} size={18} /></span><Icon name="arrow" className="text-faint transition group-hover:translate-x-0.5 group-hover:text-teal" /></div>
            <h2 className="font-medium">{t.label}</h2>
            <p className="text-sm text-muted">{t.blurb}</p>
          </Link>
        ))}
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        <YourConnection />
        <Card title="Resource library" action={<Link to="/resources" className="text-xs text-teal hover:underline">Browse</Link>}>
          <p className="mb-3 text-sm text-muted">A curated directory of {stats.tools} OSINT and security tools with passive/active OpSec ratings, plus {stats.playbooks} investigation playbooks.</p>
          <div className="flex flex-wrap gap-1.5"><Badge tone="good">{stats.passive} passive</Badge><Badge tone="warn">{stats.active} active</Badge><Badge>{stats.free} free</Badge><Badge>{stats.withApi} with API</Badge></div>
        </Card>
        <Card title="Recent lookups" action={recent.length > 0 && <button onClick={() => { clearRecent(); setRecent([]); }} className="text-xs text-muted hover:text-fg">Clear</button>}>
          {recent.length ? (
            <ul className="space-y-1">{recent.slice(0, 6).map((r) => <li key={r.to}><Link to={r.to} className="flex items-center justify-between gap-2 rounded-md px-2 py-1 text-sm hover:bg-white/[.04]"><span className="truncate font-mono text-[13px]">{r.label}</span><Badge>{r.kind}</Badge></Link></li>)}</ul>
          ) : <p className="text-sm text-faint">Nothing yet. Lookups you run are remembered in this browser only.</p>}
        </Card>
      </div>

      <section className="mt-8">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[.14em] text-muted">Start an investigation</h2>
        <Link to="/playbooks" className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel/90 p-4 hover:border-teal/40">
          <div><p className="font-medium">Investigation playbooks</p><p className="text-sm text-muted">Suspicious IP, phishing e-mail, unknown file, domain, CVE triage and more, each as a checklist with the right tools.</p></div>
          <Icon name="arrow" className="text-teal" />
        </Link>
      </section>
    </div>
  );
}
