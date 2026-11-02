import { useEffect } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, Copyable, IssueList, ProviderStrip, JsonToggle, DataTable, Empty } from '../components/ui';
import { Icon } from '../components/icons';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { IpLookup } from '../../shared/types';

const PIVOTS = (ip: string): [string, string][] => [
  ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${ip}`],
  ['Shodan', `https://www.shodan.io/host/${ip}`],
  ['GreyNoise', `https://viz.greynoise.io/ip/${ip}`],
  ['AbuseIPDB', `https://www.abuseipdb.com/check/${ip}`],
  ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${ip}`],
  ['BGP.HE.net', `https://bgp.he.net/ip/${ip}`],
];

const SCOPE_TONE = { public: 'good', private: 'warn', loopback: 'warn', 'link-local': 'warn', cgnat: 'warn', multicast: 'warn', documentation: 'neutral', reserved: 'neutral', unspecified: 'neutral' } as const;

export default function IpPage() {
  const { params } = useLocation();
  const q = params.get('q') ?? '';
  const me = params.get('me') === '1';
  const state = useApi<IpLookup>('/api/ip/lookup', me ? {} : q ? { q } : null);

  useEffect(() => {
    if (state.data) pushRecent({ label: state.data.ip, to: `/ip?q=${encodeURIComponent(state.data.ip)}`, kind: 'IP' });
  }, [state.data?.ip]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-5xl">
      <PageHeader icon="globe" title="IP Intelligence" blurb="Geolocation, ASN, passive exposure, reverse DNS and reputation, merged from several providers." badge={<Badge tone="good">passive</Badge>} />
      <LookupForm
        fields={[{ name: 'q', label: 'IPv4 or IPv6 address', placeholder: '8.8.8.8 or 2606:4700:4700::1111' }]}
        values={{ q }}
        busy={state.status === 'loading'}
        onSubmit={(v) => navigate(v.q ? `/ip?q=${encodeURIComponent(v.q)}` : '/ip')}
        extra={<button type="button" onClick={() => navigate('/ip?me=1')} className="inline-flex h-10 items-center gap-2 rounded-lg border border-line2 px-3 text-sm text-muted hover:border-teal/40 hover:text-teal"><Icon name="pin" size={15} /> My IP</button>}
      />
      <Result state={state} idle={<Empty>Enter an IP address, or choose <b>My IP</b>. Private and reserved ranges are classified locally and never sent to third parties.</Empty>}>
        {(d) => (
          <div className="space-y-4">
            <Card>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <Copyable value={d.ip} ioc />
                <Badge tone={SCOPE_TONE[d.scope]}>{d.scope}</Badge>
                <Badge>IPv{d.version}</Badge>
                {d.flags.map((f) => <Badge key={f} tone="warn">{f}</Badge>)}
              </div>
              <p className="mt-1 text-sm text-muted">{d.scopeLabel}</p>
              {!d.isPublic && <p className="mt-3 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">This is not a publicly routable address, so no external lookups were made. It only has meaning inside a private network.</p>}
            </Card>

            {d.isPublic && (
              <div className="grid gap-4 md:grid-cols-2">
                <Card title="Location">
                  {d.geo ? (
                    <KV rows={[
                      ['Country', d.geo.country && `${d.geo.country}${d.geo.countryCode ? ` (${d.geo.countryCode})` : ''}`],
                      ['Region', d.geo.region], ['City', d.geo.city], ['Postal', d.geo.postal],
                      ['Coordinates', d.geo.latitude !== null && d.geo.longitude !== null ? `${d.geo.latitude}, ${d.geo.longitude}` : null],
                      ['Time zone', d.geo.timezone],
                    ]} />
                  ) : <p className="text-sm text-faint">No geolocation data from any provider.</p>}
                  <p className="mt-3 text-[11px] text-faint">IP geolocation is approximate (often city-level at best) and unreliable for mobile, VPN and cloud addresses.</p>
                </Card>
                <Card title="Network">
                  {d.network ? <KV rows={[['ASN', d.network.asn], ['Organisation', d.network.org], ['ISP', d.network.isp], ['Domain', d.network.domain], ['Announced prefix', d.network.prefix]]} mono /> : <p className="text-sm text-faint">No ASN data.</p>}
                  <div className="mt-3 border-t border-line pt-3"><KV rows={[['Reverse DNS', d.reverseDns.length ? d.reverseDns.join(', ') : <span className="text-faint">none</span>], ['PTR name', <span key="p" className="text-faint">{d.ptrName}</span>]]} mono /></div>
                </Card>

                <Card title="Passive exposure (Shodan InternetDB)">
                  {d.exposure ? (
                    d.exposure.ports.length + d.exposure.vulns.length + d.exposure.hostnames.length === 0 ? (
                      <p className="text-sm text-muted">No open ports or known vulnerabilities on record. That only means Shodan has not observed any, not that none exist.</p>
                    ) : (
                      <div className="space-y-3">
                        <div><p className="mb-1 text-xs text-muted">Open ports</p><div className="flex flex-wrap gap-1.5">{d.exposure.ports.map((p) => <Badge key={p} tone="info">{p}</Badge>)}</div></div>
                        {d.exposure.vulns.length > 0 && (
                          <div><p className="mb-1 text-xs text-muted">Known CVEs ({d.exposure.vulns.length})</p>
                            <div className="flex flex-wrap gap-1.5">{d.exposure.vulns.slice(0, 24).map((v) => <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer"><Badge tone="bad">{v}</Badge></a>)}</div></div>
                        )}
                        {d.exposure.hostnames.length > 0 && <KV rows={[['Hostnames', d.exposure.hostnames.join(', ')]]} mono />}
                        {d.exposure.tags.length > 0 && <div className="flex flex-wrap gap-1.5">{d.exposure.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div>}
                      </div>
                    )
                  ) : <p className="text-sm text-faint">Provider unavailable.</p>}
                </Card>

                <Card title="Reputation (AbuseIPDB)">
                  {d.reputation ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3">
                        <div className={`text-3xl font-bold ${d.reputation.abuseConfidence >= 50 ? 'text-rose' : d.reputation.abuseConfidence >= 10 ? 'text-amber' : 'text-green'}`}>{d.reputation.abuseConfidence}%</div>
                        <p className="text-sm text-muted">abuse confidence over the last 90 days</p>
                      </div>
                      <KV rows={[['Reports', `${d.reputation.totalReports} from ${d.reputation.distinctReporters} reporter(s)`], ['Last reported', d.reputation.lastReportedAt], ['Usage type', d.reputation.usageType], ['Tor exit', d.reputation.isTor ? 'yes' : null], ['Allow-listed', d.reputation.isWhitelisted ? 'yes' : null]]} />
                    </div>
                  ) : <p className="text-sm text-faint">Not available. The site operator can enable this by setting an <code className="font-mono">ABUSEIPDB_API_KEY</code> secret. Use the pivot links below meanwhile.</p>}
                </Card>

                <Card title="Internet noise (GreyNoise)" className="md:col-span-2">
                  {d.greynoise ? (
                    d.greynoise.observed ? (
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge tone={d.greynoise.classification === 'malicious' ? 'bad' : d.greynoise.classification === 'benign' ? 'good' : 'neutral'}>{d.greynoise.classification}</Badge>
                          {d.greynoise.noise && <Badge tone="warn" title="Seen scanning or attacking the internet">internet noise</Badge>}
                          {d.greynoise.riot && <Badge tone="info" title="Rule It Out: a common business service such as a CDN or public DNS">RIOT: common service</Badge>}
                        </div>
                        <KV rows={[['Name', d.greynoise.name], ['Last seen', d.greynoise.lastSeen]]} />
                        {d.greynoise.link && <a href={d.greynoise.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in GreyNoise <Icon name="ext" size={13} /></a>}
                        <p className="text-[11px] text-faint">&quot;Noise&quot; means the address was seen mass-scanning the internet. It is a triage hint, not proof of targeted activity against you.</p>
                      </div>
                    ) : <p className="text-sm text-muted">Not observed scanning the internet and not in the RIOT list of common business services. An unlisted address is not necessarily harmless.</p>
                  ) : <p className="text-sm text-faint">Not available. The site operator can enable this by setting a <code className="font-mono">GREYNOISE_API_KEY</code> secret.</p>}
                </Card>
              </div>
            )}

            <Card title="Pivot to other sources" action={<span className="text-[11px] text-faint">opens third-party sites</span>}>
              <div className="flex flex-wrap gap-2">
                {PIVOTS(d.ip).map(([n, u]) => (
                  <a key={n} href={u} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-lg border border-line2 px-2.5 py-1.5 text-sm text-muted hover:border-teal/40 hover:text-teal">{n}<Icon name="ext" size={13} /></a>
                ))}
              </div>
            </Card>

            <ProviderStrip providers={d.providers} />
            <JsonToggle data={d} />
          </div>
        )}
      </Result>
    </div>
  );
}
