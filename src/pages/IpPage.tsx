import { useEffect } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, Copyable, IssueList, ProviderStrip, DataTable, Empty } from '../components/ui';
import { Icon } from '../components/icons';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { IpLookup, ProviderStatus } from '../../shared/types';

/**
 * Empty state for an optional provider card. A missing key (provider skipped) and a failed call
 * (bad key, quota, outage) look identical when the data is null, so read the provider status.
 */
function NotAvailable({ providers, provider, secret, extra }: { providers: ProviderStatus[]; provider: string; secret: string; extra?: string }) {
  const p = providers.find((x) => x.name.startsWith(provider));
  if (p?.skipped && p.error && /budget/i.test(p.error)) {
    return <p className="text-sm text-amber">{provider} is temporarily paused to protect its API quota ({p.error}). Try again shortly.</p>;
  }
  if (p && !p.skipped && !p.ok) {
    return (
      <p className="text-sm text-amber">
        {provider} lookup failed{p.error ? `: ${p.error}` : '.'} Check that the <code className="font-mono">{secret}</code> secret holds a valid key, then try again in a couple of minutes.
      </p>
    );
  }
  return (
    <p className="text-sm text-faint">
      Not available. The site operator can enable this by setting {/^[AEIOU]/.test(secret) ? 'an' : 'a'} <code className="font-mono">{secret}</code> secret.{extra}
    </p>
  );
}

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
                  <p className="mt-3 text-[11px] text-faint">IP geolocation is approximate (often city-level at best) and unreliable for mobile, VPN and cloud addresses.{d.geoSource && <> Source: {d.geoSource}{d.geoSource !== 'ipapi.is' ? ' (fallback)' : ''}.</>}</p>
                </Card>
                <Card title="Network">
                  {d.network ? <KV rows={[['ASN', d.network.asn], ['Organisation', d.network.org], ['ISP', d.network.isp], ['Domain', d.network.domain], ['Announced prefix', d.network.prefix]]} mono /> : <p className="text-sm text-faint">No ASN data.</p>}
                  <div className="mt-3 border-t border-line pt-3"><KV rows={[['Reverse DNS', d.reverseDns.length ? d.reverseDns.join(', ') : <span className="text-faint">none</span>], ['PTR name', <span key="p" className="text-faint">{d.ptrName}</span>]]} mono /></div>
                </Card>

                <Card title="Network type">
                  {d.netType ? (
                    <div className="space-y-3">
                      <div className="flex flex-wrap gap-1.5">
                        {d.netType.isVpn && <Badge tone="warn">VPN</Badge>}
                        {d.netType.isProxy && <Badge tone="warn">proxy</Badge>}
                        {d.netType.isTor && <Badge tone="bad">Tor</Badge>}
                        {d.netType.isDatacenter && <Badge tone="info">datacenter / hosting</Badge>}
                        {d.netType.isMobile && <Badge tone="info">mobile network</Badge>}
                        {d.netType.isCrawler && <Badge tone="neutral">known crawler</Badge>}
                        {d.netType.isAbuser && <Badge tone="bad">abuser</Badge>}
                        {!(d.netType.isVpn || d.netType.isProxy || d.netType.isTor || d.netType.isDatacenter || d.netType.isMobile || d.netType.isCrawler || d.netType.isAbuser) && <Badge tone="good">no anonymiser / hosting signals</Badge>}
                      </div>
                      <KV rows={[['Company', d.netType.companyName], ['Type', d.netType.companyType], ['Datacenter', d.netType.datacenter], ['VPN service', d.netType.vpnService], ['Company abuser score', d.netType.companyAbuserScore], ['ASN abuser score', d.netType.asnAbuserScore]]} />
                      <p className="text-[11px] text-faint">Classifications are inferred from address ranges and can be wrong. A VPN or datacenter flag means traffic is likely not from a typical home user, not that it is malicious.</p>
                    </div>
                  ) : <p className="text-sm text-faint">Not available. ipapi.is did not answer, so a fallback provider supplied the location.</p>}
                </Card>

                <Card title="Passive exposure">
                  {d.exposure ? (
                    d.exposure.ports.length + d.exposure.vulns.length + d.exposure.hostnames.length === 0 ? (
                      <p className="text-sm text-muted">No open ports or known vulnerabilities on record. That only means Shodan has not observed any, not that none exist.</p>
                    ) : (
                      <div className="space-y-3">
                        <div><p className="mb-1 text-xs text-muted">Open ports</p><div className="flex flex-wrap gap-1.5">{d.exposure.ports.map((p) => <Badge key={p} tone="info">{p}</Badge>)}</div></div>
                        {d.exposure.vulns.length > 0 && (
                          <div><p className="mb-1 text-xs text-muted">Known CVEs ({d.exposure.vulns.length})</p>
                            <div className="flex flex-wrap gap-1.5">{d.exposure.vulns.slice(0, 24).map((v) => <a key={v} href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer"><Badge tone="bad">{v}</Badge></a>)}</div></div>
                        )}
                        {d.exposure.hostnames.length > 0 && <KV rows={[['Hostnames', d.exposure.hostnames.join(', ')]]} mono />}
                        {d.exposure.tags.length > 0 && <div className="flex flex-wrap gap-1.5">{d.exposure.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div>}
                      </div>
                    )
                  ) : <p className="text-sm text-faint">Provider unavailable.</p>}
                </Card>

                <Card title="Reputation">
                  {d.reputation ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3">
                        <div className={`text-3xl font-bold ${d.reputation.abuseConfidence >= 50 ? 'text-rose' : d.reputation.abuseConfidence >= 10 ? 'text-amber' : 'text-green'}`}>{d.reputation.abuseConfidence}%</div>
                        <p className="text-sm text-muted">abuse confidence over the last 90 days</p>
                      </div>
                      <KV rows={[['Reports', `${d.reputation.totalReports} from ${d.reputation.distinctReporters} reporter(s)`], ['Last reported', d.reputation.lastReportedAt], ['Usage type', d.reputation.usageType], ['Tor exit', d.reputation.isTor ? 'yes' : null], ['Allow-listed', d.reputation.isWhitelisted ? 'yes' : null]]} />
                    </div>
                  ) : <NotAvailable providers={d.providers} provider="AbuseIPDB" secret="ABUSEIPDB_API_KEY" />}
                </Card>

                <Card title="Threat intel">
                  {d.pulsedive ? (
                    d.pulsedive.observed ? (
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge tone={d.pulsedive.risk === 'critical' || d.pulsedive.risk === 'high' ? 'bad' : d.pulsedive.risk === 'medium' ? 'warn' : d.pulsedive.risk === 'low' || d.pulsedive.risk === 'very low' ? 'good' : 'neutral'}>{d.pulsedive.risk} risk</Badge>
                          {d.pulsedive.threats.length > 0 && <Badge tone="warn">{d.pulsedive.threats.length} linked threat{d.pulsedive.threats.length === 1 ? '' : 's'}</Badge>}
                          {d.pulsedive.feeds.length > 0 && <Badge tone="info">{d.pulsedive.feeds.length} feed{d.pulsedive.feeds.length === 1 ? '' : 's'}</Badge>}
                        </div>
                        {d.pulsedive.threats.length > 0 && (
                          <div><p className="mb-1 text-xs text-muted">Linked threats</p>
                            <div className="flex flex-wrap gap-1.5">{d.pulsedive.threats.map((t) => <Badge key={t.name} tone={t.risk === 'high' || t.risk === 'critical' ? 'bad' : 'neutral'} title={t.category ?? undefined}>{t.name}</Badge>)}</div></div>
                        )}
                        {d.pulsedive.feeds.length > 0 && <KV rows={[['Seen in feeds', d.pulsedive.feeds.map((f) => f.name).join(', ')]]} />}
                        {d.pulsedive.riskFactors.length > 0 && (
                          <div><p className="mb-1 text-xs text-muted">Risk factors</p>
                            <ul className="list-disc space-y-0.5 pl-4 text-sm text-muted">{d.pulsedive.riskFactors.map((r) => <li key={r.description}>{r.description}</li>)}</ul></div>
                        )}
                        <KV rows={[['Last seen', d.pulsedive.lastSeen], ['Last updated', d.pulsedive.lastUpdated]]} />
                        <a href={d.pulsedive.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in Pulsedive <Icon name="ext" size={13} /></a>
                        <p className="text-[11px] text-faint">Risk is Pulsedive&apos;s own rating from feeds and scans. &quot;Unknown&quot; or &quot;none&quot; means no evidence was found, not that the address is safe.</p>
                      </div>
                    ) : <p className="text-sm text-muted">Pulsedive has no record of this address. That is not a clean verdict.</p>
                  ) : <NotAvailable providers={d.providers} provider="Pulsedive" secret="PULSEDIVE_API_KEY" />}
                </Card>

                <Card title="Multi-engine verdicts" className="md:col-span-2">
                  {d.virustotal ? (
                    d.virustotal.observed ? (
                      (() => {
                        const v = d.virustotal;
                        const total = v.malicious + v.suspicious + v.harmless + v.undetected;
                        return (
                          <div className="space-y-3">
                            <div className="flex flex-wrap items-center gap-3">
                              <div className={`text-3xl font-bold ${v.malicious >= 5 ? 'text-rose' : v.malicious + v.suspicious > 0 ? 'text-amber' : 'text-green'}`}>{v.malicious}<span className="text-lg text-muted"> / {total}</span></div>
                              <p className="text-sm text-muted">security vendors flagged this IP as malicious</p>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              <Badge tone={v.malicious > 0 ? 'bad' : 'good'}>{v.malicious} malicious</Badge>
                              <Badge tone={v.suspicious > 0 ? 'warn' : 'neutral'}>{v.suspicious} suspicious</Badge>
                              <Badge tone="good">{v.harmless} harmless</Badge>
                              <Badge>{v.undetected} undetected</Badge>
                            </div>
                            <KV rows={[['Community score', v.reputation !== null ? String(v.reputation) : null], ['Community votes', v.votesMalicious + v.votesHarmless > 0 ? `${v.votesMalicious} malicious / ${v.votesHarmless} harmless` : null], ['AS owner', v.asOwner], ['Last analysed', v.lastAnalysis]]} />
                            <a href={v.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in VirusTotal <Icon name="ext" size={13} /></a>
                            <p className="text-[11px] text-faint">Detections come from third-party vendor engines and can include false positives, especially for shared hosting, CDN and cloud addresses. Zero detections does not prove an address is safe.</p>
                          </div>
                        );
                      })()
                    ) : <p className="text-sm text-muted">VirusTotal has no analysis on record for this address. That is not a clean verdict.</p>
                  ) : <NotAvailable providers={d.providers} provider="VirusTotal" secret="VIRUSTOTAL_API_KEY" />}
                </Card>
              </div>
            )}

            <ProviderStrip providers={d.providers} />
          </div>
        )}
      </Result>
    </div>
  );
}
