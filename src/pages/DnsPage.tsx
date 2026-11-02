import { useEffect } from 'react';
import { PageHeader, LookupForm, Card, Badge, DataTable, ProviderStrip, JsonToggle, Empty, Tabs, CopyButton } from '../components/ui';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { DnsLookup, DnsPropagation } from '../../shared/types';

const TYPES = ['ALL', 'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR', 'DNSKEY', 'DS'];
const SOURCES: Record<string, string> = { cloudflare: 'Cloudflare 1.1.1.1', google: 'Google 8.8.8.8', quad9: 'Quad9 9.9.9.9' };

const statusTone = (s: string) => (s === 'NOERROR' ? 'good' : s === 'NXDOMAIN' ? 'warn' : 'bad');

export default function DnsPage() {
  const { params } = useLocation();
  const name = params.get('name') ?? '';
  const type = params.get('type') ?? 'ALL';
  const resolver = params.get('resolver') ?? 'cloudflare';
  const mode = params.get('mode') === 'propagation' ? 'propagation' : 'lookup';

  const lookup = useApi<DnsLookup>('/api/dns/lookup', mode === 'lookup' && name ? { name, type, resolver } : null);
  const prop = useApi<DnsPropagation>('/api/dns/propagation', mode === 'propagation' && name ? { name, type: type === 'ALL' ? 'A' : type } : null);

  useEffect(() => {
    if (name && (lookup.data || prop.data)) pushRecent({ label: name, to: `/dns?name=${encodeURIComponent(name)}&type=${type}${mode === 'propagation' ? '&mode=propagation' : ''}`, kind: 'DNS' });
  }, [lookup.data, prop.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const go = (patch: Record<string, string>) => {
    const next = new URLSearchParams({ name, type, resolver, mode, ...patch });
    for (const [k, v] of [...next]) if (!v) next.delete(k);
    navigate(`/dns?${next}`);
  };

  return (
    <div className="max-w-5xl">
      <PageHeader icon="network" title="DNS Intelligence" blurb="Query records over DNS-over-HTTPS and compare answers across independent public resolvers." badge={<Badge tone="good">passive</Badge>} />
      <Tabs tabs={[{ id: 'lookup', label: 'Record lookup', icon: 'search' }, { id: 'propagation', label: 'Propagation check', icon: 'refresh' }]} value={mode} onChange={(m) => go({ mode: m })} />
      <LookupForm
        values={{ name, type, resolver }}
        busy={lookup.status === 'loading' || prop.status === 'loading'}
        fields={[
          { name: 'name', label: 'Domain or IP (for PTR)', placeholder: 'example.com', width: 'flex-[2] basis-60' },
          { name: 'type', label: 'Type', options: TYPES.map((t) => ({ value: t, label: t })), width: 'w-28' },
          ...(mode === 'lookup' ? [{ name: 'resolver', label: 'Resolver', options: Object.entries(SOURCES).map(([value, label]) => ({ value, label })), width: 'w-48' }] : []),
        ]}
        onSubmit={(v) => go({ name: v.name, type: v.type, ...(v.resolver ? { resolver: v.resolver } : {}) })}
      />

      {mode === 'lookup' ? (
        <Result state={lookup} idle={<Empty>Enter a domain to see its records. Choose <b>ALL</b> for the common types at once.</Empty>}>
          {(d) => (
            <div className="space-y-4">
              <p className="text-sm text-muted">Answers for <span className="font-mono text-fg">{d.name}</span> from {d.resolver}</p>
              {d.results.map((r) => (
                <Card key={r.type} title={<span className="flex items-center gap-2">{r.type}<Badge tone={statusTone(r.status)}>{r.status}</Badge>{r.authenticated && <Badge tone="good" title="Resolver validated the DNSSEC chain">DNSSEC validated</Badge>}</span>} pad={r.records.length > 0}>
                  {r.records.length ? (
                    <DataTable head={['Name', 'Type', 'TTL', 'Data', '']} rows={r.records.map((x) => [<span key="n" className="font-mono text-xs">{x.name}</span>, x.type, `${x.ttl}s`, <span key="d" className="break-all font-mono text-[13px]">{x.data}</span>, <CopyButton key="c" text={x.data} />])} />
                  ) : <p className="px-4 py-3 text-sm text-faint">{r.status === 'ERROR' ? 'This query failed.' : 'No records.'}</p>}
                </Card>
              ))}
              <ProviderStrip providers={d.providers} />
              <JsonToggle data={d} />
            </div>
          )}
        </Result>
      ) : (
        <Result state={prop} idle={<Empty>Enter a domain to compare what Cloudflare, Google and Quad9 currently return.</Empty>}>
          {(d) => (
            <div className="space-y-4">
              <Card>
                <div className="flex items-center gap-3">
                  <Badge tone={d.consistent ? 'good' : 'warn'}>{d.consistent ? 'consistent' : 'inconsistent'}</Badge>
                  <p className="text-sm">{d.consistent ? `All responding resolvers agree on the ${d.type} records for ${d.name}.` : `Resolvers disagree on ${d.type} for ${d.name}. A recent change may still be propagating.`}</p>
                </div>
              </Card>
              <div className="grid gap-4 md:grid-cols-3">
                {d.resolvers.map((r) => (
                  <Card key={r.resolver} title={r.resolver}>
                    <div className="mb-2 flex items-center gap-2"><Badge tone={statusTone(r.status)}>{r.status}</Badge>{r.ms > 0 && <span className="text-xs text-faint">{r.ms} ms</span>}</div>
                    {r.error ? <p className="text-sm text-rose">{r.error}</p> : r.records.length ? <ul className="space-y-1">{r.records.map((x, i) => <li key={i} className="break-all font-mono text-[13px]">{x.data} <span className="text-faint">· {x.ttl}s</span></li>)}</ul> : <p className="text-sm text-faint">No records</p>}
                  </Card>
                ))}
              </div>
              <p className="text-xs text-faint">{d.note}</p>
              <JsonToggle data={d} />
            </div>
          )}
        </Result>
      )}
    </div>
  );
}
