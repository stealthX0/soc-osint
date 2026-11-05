import { useEffect, type ReactNode } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, Copyable, ProviderStrip, DataTable, Empty, fmtDate, type Tone } from '../components/ui';
import { Icon } from '../components/icons';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { ProviderStatus, UrlLookup, UrlSeverity, UrlSignal, UrlVerdict } from '../../shared/types';

const VERDICT: Record<UrlVerdict, { tone: Tone; label: string; icon: string; blurb: string }> = {
  malicious: { tone: 'bad', label: 'Malicious', icon: 'x', blurb: 'Confirmed by threat intelligence' },
  suspicious: { tone: 'warn', label: 'Suspicious', icon: 'warn', blurb: 'Risk indicators found, not confirmed' },
  no_detections: { tone: 'neutral', label: 'No detections', icon: 'check', blurb: 'Not flagged by the sources that checked it' },
  unknown: { tone: 'info', label: 'Not assessed', icon: 'info', blurb: 'No threat feed could check this URL' },
};
const SEV_TONE: Record<UrlSeverity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const SOURCE: Record<string, string> = {
  heuristic: 'Local check', urlhaus: 'URLhaus', safebrowsing: 'Safe Browsing', virustotal: 'VirusTotal', pulsedive: 'Pulsedive',
  urlscan: 'urlscan.io', 'cloudflare-dns': 'Cloudflare DNS', rdap: 'RDAP', dns: 'DNS', trace: 'Redirect trace', scope: 'Scope',
};

/** Why a source has no data: not configured, paused for quota, or failed. Read from the provider status list. */
function Unavailable({ providers, prefix }: { providers: ProviderStatus[]; prefix: string }) {
  const p = providers.find((x) => x.name.startsWith(prefix));
  if (p?.skipped && /budget/i.test(p.error ?? '')) return <p className="text-sm text-amber">Paused to protect the API quota ({p.error}). Try again shortly.</p>;
  if (p && !p.skipped && !p.ok) return <p className="text-sm text-amber">Lookup failed{p.error ? `: ${p.error}` : '.'}</p>;
  if (p?.skipped) return <p className="text-sm text-faint">Not configured by the site operator.</p>;
  return <p className="text-sm text-faint">Not checked for this URL.</p>;
}

const safeHref = (u?: string) => (u && /^https:\/\//i.test(u) ? u : undefined);

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-1 border-b border-line/60 py-2 last:border-0">
      <span className="w-32 shrink-0 text-xs font-medium uppercase tracking-wider text-muted">{label}</span>
      <div className="min-w-0 flex-1 text-sm">{children}</div>
    </div>
  );
}

function Finding({ s }: { s: UrlSignal }) {
  const href = safeHref(s.link);
  return (
    <li className="flex items-start gap-3 rounded-lg border border-line/70 bg-bg2/50 p-3">
      <Badge tone={SEV_TONE[s.severity]}>{s.severity}</Badge>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{s.title}</p>
        {s.detail && <p className="mt-0.5 break-words text-[13px] text-muted">{s.detail}</p>}
        <p className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-faint">
          <span>{SOURCE[s.source] ?? s.source}</span>
          {s.confirmed && <Badge tone="bad">confirmed listing</Badge>}
          {href && <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-teal hover:underline">details <Icon name="ext" size={11} /></a>}
        </p>
      </div>
    </li>
  );
}

export default function UrlPage() {
  const { params } = useLocation();
  const q = params.get('q') ?? '';
  const trace = params.get('trace') === '1';
  const state = useApi<UrlLookup>('/api/url/lookup', q ? { q, trace: trace ? '1' : '0' } : null);

  useEffect(() => {
    if (state.data) pushRecent({ label: state.data.url.length > 60 ? `${state.data.url.slice(0, 57)}…` : state.data.url, to: `/url?q=${encodeURIComponent(q)}${trace ? '&trace=1' : ''}`, kind: 'URL' });
  }, [state.data?.url]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-5xl">
      <PageHeader icon="shield" title="URL Intelligence" blurb="Check a link against malware and phishing feeds, blocklists and local analysis before anyone clicks it." badge={<Badge tone={trace ? 'warn' : 'good'}>{trace ? 'active trace' : 'passive'}</Badge>} />
      <LookupForm
        fields={[
          { name: 'q', label: 'URL', placeholder: 'https://example.com/login  or  hxxps://evil[.]example[.]com/x' },
          { name: 'trace', label: 'Redirect trace', width: 'basis-60', mono: false, defaultValue: trace ? '1' : '0', options: [{ value: '0', label: 'Off: passive (recommended)' }, { value: '1', label: 'On: visit the link, follow redirects' }] },
        ]}
        values={{ q, trace: trace ? '1' : '0' }}
        submitLabel="Check URL"
        busy={state.status === 'loading'}
        onSubmit={(v) => navigate(v.q ? `/url?q=${encodeURIComponent(v.q)}${v.trace === '1' ? '&trace=1' : ''}` : '/url')}
      />
      <p className="mb-3 flex items-start gap-2 text-[13px] text-muted"><Icon name="info" className="mt-0.5 shrink-0" size={14} /> The full URL (without the #fragment and without any username/password) is sent to the threat-intelligence providers the site operator has enabled. Do not submit links that contain private tokens. Private and internal addresses are analysed locally and never sent anywhere.</p>
      {trace && <p className="mb-4 flex items-start gap-2 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber"><Icon name="warn" className="mt-0.5 shrink-0" /> Active trace: this requests the URL from Cloudflare&rsquo;s network (headers only, up to 8 redirects, private addresses refused). If the link carries a recipient-specific token, the sender may see that it was opened. Sites can also show scanners different content than they show people.</p>}

      <Result state={state} idle={<Empty>Paste a suspicious link. Defanged forms such as <code className="font-mono">hxxps://evil[.]com</code> are accepted. A clean result means &ldquo;no detections&rdquo;, never &ldquo;safe&rdquo;.</Empty>}>
        {(d) => {
          const v = VERDICT[d.verdict];
          const findings = d.signals;
          return (
            <div className="space-y-4">
              <Card>
                <div className="flex flex-wrap items-center gap-3">
                  <Badge tone={v.tone}><Icon name={v.icon} size={13} /> {v.label}</Badge>
                  <span className="text-sm text-muted">{v.blurb}</span>
                  <span className="ml-auto flex items-center gap-2 text-xs text-muted">
                    <Badge tone={d.confidence === 'high' ? 'info' : 'neutral'} title="How much evidence supports this result">{d.confidence} confidence</Badge>
                    <span title="Informational. The verdict follows the rules in the findings, not this number.">risk score {d.score}/100</span>
                  </span>
                </div>
                <p className="mt-3 text-sm">{d.summary}</p>
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted"><span className="uppercase tracking-wider text-faint">URL</span><Copyable value={d.url} ioc /></div>
                <p className="mt-2 text-xs text-faint">Checked by {d.checked} of {d.attempted} intelligence sources. Sources that had no record of this URL are not counted.</p>
              </Card>

              <Card title={`Findings (${findings.filter((s) => s.severity !== 'info').length}${findings.some((s) => s.severity === 'info') ? ` + ${findings.filter((s) => s.severity === 'info').length} notes` : ''})`}>
                {findings.length ? <ul className="space-y-2">{findings.map((s) => <Finding key={s.id} s={s} />)}</ul> : <p className="flex items-center gap-2 text-sm text-muted"><Icon name="check" /> No findings from any source.</p>}
              </Card>

              <div className="grid gap-4 md:grid-cols-2">
                <Card title="URL breakdown">
                  <KV rows={[
                    ['Scheme', d.parts.scheme],
                    ['Host', d.parts.hostUnicode !== d.parts.host ? `${d.parts.hostUnicode} (${d.parts.host})` : d.parts.host],
                    ['Registrable domain', d.parts.registrableDomain],
                    ['Hosting', d.parts.platform ? `Shared platform: ${d.parts.platform}` : d.parts.isIp ? (d.parts.ipObfuscated ? 'Raw IP (obfuscated)' : 'Raw IP address') : 'Own domain'],
                    ['Port', d.parts.port !== null ? String(d.parts.port) : 'default'],
                    ['Path', d.parts.path],
                    ['Query', d.parts.query || 'none'],
                    ['Credentials in URL', d.parts.hasUserinfo ? 'Yes (stripped before lookup)' : 'No'],
                  ]} mono />
                </Card>

                <Card title="Domain">
                  {d.domain ? (
                    <>
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        {d.domain.ageDays !== null ? <Badge tone={d.domain.ageDays <= 30 ? 'bad' : d.domain.ageDays <= 90 ? 'warn' : 'neutral'}>{d.domain.ageDays} days old</Badge> : <Badge>age unknown</Badge>}
                        {d.domain.resolves !== null && <Badge tone={d.domain.resolves ? 'neutral' : 'warn'}>{d.domain.resolves ? 'resolves' : 'does not resolve'}</Badge>}
                      </div>
                      <KV rows={[['Domain', d.domain.name], ['Registered', fmtDate(d.domain.registered)], ['Registrar', d.domain.registrar], ['Addresses', d.domain.addresses.length ? <span className="flex flex-wrap gap-2">{d.domain.addresses.map((a) => <Copyable key={a} value={a} ioc />)}</span> : null]]} />
                      {d.parts.platform && <p className="mt-2 text-xs text-faint">Age is not assessed for shared hosting platforms: the platform&rsquo;s domain says nothing about this page.</p>}
                    </>
                  ) : <p className="text-sm text-faint">Not applicable to an IP address.</p>}
                </Card>

                <Card title="Malware & phishing feeds">
                  <Row label="URLhaus">
                    {d.intel.urlhaus ? (
                      <div className="space-y-1">
                        {d.intel.urlhaus.listed ? <Badge tone="bad">Listed · {d.intel.urlhaus.status}</Badge> : <Badge>Not listed</Badge>}
                        {d.intel.urlhaus.listed && <p className="text-[13px] text-muted">{[d.intel.urlhaus.threat, d.intel.urlhaus.tags.join(', '), d.intel.urlhaus.dateAdded].filter(Boolean).join(' · ')}</p>}
                        <p className="text-[13px] text-muted">Host: {d.intel.urlhaus.host.urlCount ? `${d.intel.urlhaus.host.urlCount} listed URL(s), ${d.intel.urlhaus.host.online} online` : 'no listings'}</p>
                      </div>
                    ) : <Unavailable providers={d.providers} prefix="URLhaus" />}
                  </Row>
                  <Row label="Safe Browsing">
                    {d.intel.safeBrowsing ? (d.intel.safeBrowsing.matches.length ? <div className="flex flex-wrap gap-1.5">{[...new Set(d.intel.safeBrowsing.matches.map((m) => m.threatType.replace(/_/g, ' ').toLowerCase()))].map((t) => <Badge key={t} tone="bad">{t}</Badge>)}</div> : <Badge>No match</Badge>) : <Unavailable providers={d.providers} prefix="Google Safe Browsing" />}
                  </Row>
                  <Row label="Cloudflare DNS">
                    {d.intel.cloudflareDns ? <div className="space-y-1"><Badge tone={d.intel.cloudflareDns.blocked ? 'bad' : 'neutral'}>{d.intel.cloudflareDns.blocked ? 'Blocked' : d.intel.cloudflareDns.blocked === null ? 'Inconclusive' : 'Not blocked'}</Badge><p className="text-[13px] text-muted">{d.intel.cloudflareDns.note}</p></div> : <Unavailable providers={d.providers} prefix="Cloudflare Security DNS" />}
                  </Row>
                </Card>

                <Card title="Multi-engine verdicts">
                  {d.intel.virustotal ? (
                    d.intel.virustotal.found ? (
                      <div className="space-y-2">
                        <div className="flex flex-wrap gap-1.5">
                          <Badge tone={d.intel.virustotal.malicious ? 'bad' : 'neutral'}>{d.intel.virustotal.malicious} malicious</Badge>
                          <Badge tone={d.intel.virustotal.suspicious ? 'warn' : 'neutral'}>{d.intel.virustotal.suspicious} suspicious</Badge>
                          <Badge>{d.intel.virustotal.harmless} harmless</Badge>
                          <Badge>{d.intel.virustotal.undetected} undetected</Badge>
                        </div>
                        {d.intel.virustotal.engines.length > 0 && <p className="break-words text-[13px] text-muted">{d.intel.virustotal.engines.join(' · ')}</p>}
                        {d.intel.virustotal.categories.length > 0 && <p className="text-[13px] text-muted">Categories: {d.intel.virustotal.categories.join(', ')}</p>}
                        <p className="text-xs text-faint">Last analysed {fmtDate(d.intel.virustotal.lastAnalysis)}.{safeHref(d.intel.virustotal.link ?? undefined) && <> <a className="text-teal hover:underline" href={d.intel.virustotal.link!} target="_blank" rel="noopener noreferrer">Full report</a></>}</p>
                      </div>
                    ) : <p className="text-sm text-muted">This URL has never been analysed, so there is no verdict. That is not the same as clean.</p>
                  ) : <Unavailable providers={d.providers} prefix="VirusTotal" />}
                </Card>

                <Card title="Threat intel">
                  {d.intel.pulsedive ? (
                    d.intel.pulsedive.observed ? (
                      <div className="space-y-2">
                        <Badge tone={d.intel.pulsedive.risk === 'critical' || d.intel.pulsedive.risk === 'high' ? 'bad' : d.intel.pulsedive.risk === 'medium' ? 'warn' : 'neutral'}>risk: {d.intel.pulsedive.risk}</Badge>
                        {d.intel.pulsedive.threats.length > 0 && <p className="text-[13px] text-muted">Threats: {d.intel.pulsedive.threats.join(', ')}</p>}
                        {d.intel.pulsedive.feeds.length > 0 && <p className="text-[13px] text-muted">Feeds: {d.intel.pulsedive.feeds.join(', ')}</p>}
                      </div>
                    ) : <p className="text-sm text-muted">No record of this URL.</p>
                  ) : <Unavailable providers={d.providers} prefix="Pulsedive" />}
                </Card>

                <Card title="Prior scans">
                  {d.intel.urlscan ? (
                    d.intel.urlscan.scans ? (
                      <div className="space-y-2">
                        <p className="text-sm">{d.intel.urlscan.scans} recent scan{d.intel.urlscan.scans === 1 ? '' : 's'} of this host{d.intel.urlscan.exactMatches ? `, ${d.intel.urlscan.exactMatches} of this exact URL` : ''}.</p>
                        {d.intel.urlscan.latest && (
                          <KV rows={[
                            ['Latest scan', fmtDate(d.intel.urlscan.latest.date)],
                            ['Verdict', d.intel.urlscan.latest.malicious === null ? 'not available' : d.intel.urlscan.latest.malicious ? <Badge tone="bad">malicious</Badge> : <Badge>no verdict of harm</Badge>],
                            ['Categories', d.intel.urlscan.latest.categories.join(', ') || null],
                            ['Targets', d.intel.urlscan.latest.brands.join(', ') || null],
                            ['Report', safeHref(d.intel.urlscan.latest.resultUrl ?? undefined) ? <a className="text-teal hover:underline" href={d.intel.urlscan.latest.resultUrl!} target="_blank" rel="noopener noreferrer">View scan <Icon name="ext" size={11} /></a> : null],
                          ]} />
                        )}
                      </div>
                    ) : <p className="text-sm text-muted">No public scans of this host.</p>
                  ) : <Unavailable providers={d.providers} prefix="urlscan.io" />}
                </Card>
              </div>

              {d.trace && (
                <Card title="Redirect trace">
                  {d.trace.performed ? (
                    <>
                      <DataTable
                        head={['#', 'Status', 'URL', 'Server IP', 'Time']}
                        rows={d.trace.hops.map((h, i) => [
                          i + 1,
                          h.status === null ? <Badge tone="bad">failed</Badge> : <Badge tone={h.status >= 400 ? 'warn' : h.status >= 300 ? 'info' : 'neutral'}>{h.status}</Badge>,
                          <span key="u" className="block max-w-[28rem] break-all font-mono text-xs" title={h.url}>{h.url}{h.error && <span className="block text-amber">{h.error}</span>}{h.download && <span className="block text-amber">file download ({h.contentType})</span>}</span>,
                          h.ip ?? '',
                          h.ms ? `${h.ms} ms` : '',
                        ])}
                        empty="No hops recorded."
                      />
                      {d.trace.error && <p className="mt-2 text-sm text-amber">{d.trace.error}</p>}
                      {d.trace.finalUrl && <p className="mt-2 text-xs text-faint">Final destination (also checked against the same sources): <span className="break-all font-mono">{d.trace.finalUrl}</span></p>}
                    </>
                  ) : <p className="text-sm text-muted">{d.trace.error ?? 'The trace was not run.'}</p>}
                </Card>
              )}
              <ProviderStrip providers={d.providers} />
            </div>
          );
        }}
      </Result>
    </div>
  );
}
