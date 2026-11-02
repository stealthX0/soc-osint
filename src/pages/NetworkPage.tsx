import { useEffect } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, DataTable, JsonToggle, Empty, Tabs, Copyable } from '../components/ui';
import { Result } from '../components/Result';
import { Icon } from '../components/icons';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { LatencyResult } from '../../shared/types';
import type { CidrInfo } from '../../shared/ip';

type SubnetResult = CidrInfo & { contains: { ip: string; inside: boolean | null } | null };

export default function NetworkPage() {
  const { params } = useLocation();
  const tab = params.get('tab') === 'subnet' ? 'subnet' : 'latency';
  const target = params.get('target') ?? '';
  const samples = params.get('samples') ?? '3';
  const scheme = params.get('scheme') ?? 'https';
  const cidr = params.get('cidr') ?? '';
  const contains = params.get('contains') ?? '';

  const lat = useApi<LatencyResult>('/api/network/latency', tab === 'latency' && target ? { target, samples, scheme } : null);
  const sub = useApi<SubnetResult>('/api/network/subnet', tab === 'subnet' && cidr ? { cidr, contains } : null);

  useEffect(() => {
    if (lat.data) pushRecent({ label: lat.data.target, to: `/network?target=${encodeURIComponent(lat.data.target)}`, kind: 'Latency' });
  }, [lat.data]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-5xl">
      <PageHeader icon="pulse" title="Network Diagnostics" blurb="HTTP latency from the Cloudflare edge, and a subnet calculator for IPv4 and IPv6." />
      <Tabs tabs={[{ id: 'latency', label: 'HTTP latency', icon: 'pulse' }, { id: 'subnet', label: 'Subnet calculator', icon: 'network' }]} value={tab} onChange={(t) => navigate(`/network?tab=${t}`)} />

      {tab === 'latency' ? (
        <>
          <p className="mb-4 flex items-start gap-2 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber"><Icon name="warn" className="mt-0.5" /> Active check: sends up to 5 HTTP requests to the target. Cloudflare Workers cannot send ICMP pings, so this measures HTTP time-to-first-byte.</p>
          <LookupForm values={{ target, samples, scheme }} busy={lat.status === 'loading'}
            fields={[{ name: 'target', label: 'Host or public IP', placeholder: 'example.com' }, { name: 'scheme', label: 'Scheme', options: [{ value: 'https', label: 'HTTPS' }, { value: 'http', label: 'HTTP' }], width: 'w-28' }, { name: 'samples', label: 'Samples', options: ['1', '3', '5'].map((v) => ({ value: v, label: v })), width: 'w-24' }]}
            submitLabel="Measure" onSubmit={(v) => navigate(`/network?tab=latency&target=${encodeURIComponent(v.target)}&scheme=${v.scheme}&samples=${v.samples}`)} />
          <Result state={lat} idle={<Empty>Enter a host to measure response time from the edge.</Empty>}>
            {(d) => (
              <div className="space-y-4">
                {d.stats ? (
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                    {([['Min', d.stats.min, 'ms'], ['Average', d.stats.avg, 'ms'], ['Max', d.stats.max, 'ms'], ['Jitter', d.stats.jitter, 'ms'], ['Success', d.stats.successRate, '%']] as const).map(([k, v, u]) => (
                      <Card key={k}><p className="text-[11px] uppercase tracking-wider text-muted">{k}</p><p className="mt-1 font-mono text-2xl">{v}<span className="ml-0.5 text-sm text-faint">{u}</span></p></Card>
                    ))}
                  </div>
                ) : <Card><p className="text-sm text-rose">All {d.samples.length} requests failed.</p></Card>}
                <Card title="Samples"><DataTable head={['#', 'Result', 'Status', 'TTFB', 'Total']} rows={d.samples.map((s, i) => [i + 1, <Badge key="r" tone={s.ok ? 'good' : 'bad'}>{s.ok ? 'ok' : 'failed'}</Badge>, s.status ?? s.error ?? '—', s.ttfbMs !== undefined ? `${s.ttfbMs} ms` : '—', s.totalMs !== undefined ? `${s.totalMs} ms` : '—'])} /></Card>
                <Card title="Vantage point"><KV rows={[['Target', d.address ? `${d.target} (${d.address})` : d.target], ['Measured from', d.vantage.colo ? `Cloudflare ${d.vantage.colo}${d.vantage.country ? ` · ${d.vantage.country}` : ''}` : 'Cloudflare edge']]} /><p className="mt-2 text-xs text-faint">{d.vantage.note}</p></Card>
                <JsonToggle data={d} />
              </div>
            )}
          </Result>
        </>
      ) : (
        <>
          <LookupForm values={{ cidr, contains }} busy={sub.status === 'loading'} submitLabel="Calculate"
            fields={[{ name: 'cidr', label: 'CIDR block or IP', placeholder: '192.168.1.0/24 or 2001:db8::/32' }, { name: 'contains', label: 'Is this IP inside? (optional)', placeholder: '192.168.1.77', width: 'flex-1 basis-48' }]}
            onSubmit={(v) => navigate(`/network?tab=subnet&cidr=${encodeURIComponent(v.cidr)}${v.contains ? `&contains=${encodeURIComponent(v.contains)}` : ''}`)} />
          <Result state={sub} idle={<Empty>Enter a CIDR block such as <span className="font-mono">10.0.0.0/22</span>.</Empty>}>
            {(d) => (
              <div className="space-y-4">
                {d.hostBitsSet && <p className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">Host bits were set in the input; the network address is {d.network}.</p>}
                {d.contains && <Card><Badge tone={d.contains.inside ? 'good' : 'bad'}>{d.contains.ip} is {d.contains.inside ? 'inside' : 'outside'} {d.cidr}</Badge></Card>}
                <Card title={d.cidr}>
                  <KV mono rows={[['Network', d.network], ['Netmask', d.netmask], ['Wildcard', d.wildcard], ['Broadcast', d.broadcast], ['First host', d.firstHost], ['Last host', d.lastHost], ['Total addresses', BigInt(d.totalAddresses).toLocaleString('en-US')], ['Usable hosts', BigInt(d.usableHosts).toLocaleString('en-US')], ['Scope', d.scope]]} />
                </Card>
                <JsonToggle data={d} />
              </div>
            )}
          </Result>
        </>
      )}
    </div>
  );
}
