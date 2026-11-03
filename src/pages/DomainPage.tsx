import { useEffect, useState } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, DataTable, IssueList, ProviderStrip, JsonToggle, Empty, Tabs, Grade, fmtDate, Copyable } from '../components/ui';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import { Icon } from '../components/icons';
import type { CertResult, HttpCheck, WhoisResult } from '../../shared/types';

type Tab = 'whois' | 'ssl' | 'http';

export default function DomainPage() {
  const { params } = useLocation();
  const q = params.get('q') ?? '';
  const tab = (['whois', 'ssl', 'http'].includes(params.get('tab') ?? '') ? params.get('tab') : 'whois') as Tab;
  const [subs, setSubs] = useState(false);

  const whois = useApi<WhoisResult>('/api/domain/whois', tab === 'whois' && q ? { domain: q } : null);
  const ssl = useApi<CertResult>('/api/domain/ssl', tab === 'ssl' && q ? { domain: q, subdomains: subs ? '1' : '0' } : null);
  const http = useApi<HttpCheck>('/api/domain/http', tab === 'http' && q ? { target: q } : null);

  const loaded = whois.data ?? ssl.data ?? http.data;
  useEffect(() => {
    if (loaded && q) pushRecent({ label: q, to: `/domain?q=${encodeURIComponent(q)}&tab=${tab}`, kind: 'Domain' });
  }, [loaded]); // eslint-disable-line react-hooks/exhaustive-deps

  const go = (patch: Record<string, string>) => {
    const next = new URLSearchParams({ q, tab, ...patch });
    for (const [k, v] of [...next]) if (!v) next.delete(k);
    navigate(`/domain?${next}`);
  };
  const busy = [whois, ssl, http].some((s) => s.status === 'loading');

  return (
    <div className="max-w-5xl">
      <PageHeader icon="domain" title="Domain Intelligence" blurb="Registration data, Certificate Transparency history and HTTP security posture." />
      <Tabs
        tabs={[{ id: 'whois', label: 'WHOIS / RDAP', icon: 'list' }, { id: 'ssl', label: 'Certificates', icon: 'lock' }, { id: 'http', label: 'HTTP & headers', icon: 'shield' }]}
        value={tab}
        onChange={(t) => go({ tab: t })}
      />
      <LookupForm fields={[{ name: 'q', label: 'Domain or URL', placeholder: 'example.com' }]} values={{ q }} busy={busy} onSubmit={(v) => go({ q: v.q })}
        extra={tab === 'ssl' ? <label className="flex h-10 items-center gap-2 text-sm text-muted"><input type="checkbox" checked={subs} onChange={(e) => setSubs(e.target.checked)} className="accent-teal" /> Include subdomains</label> : undefined} />

      {tab === 'http' && <p className="mb-4 flex items-start gap-2 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber"><Icon name="warn" className="mt-0.5" /> Active check: this sends real HTTP requests to the target from Cloudflare&apos;s network. Only test hosts you are authorised to probe.</p>}

      {tab === 'whois' && (
        <Result state={whois} idle={<Empty>Enter a domain to fetch its RDAP registration record.</Empty>}>
          {(d) => (
            <div className="space-y-4">
              <Card>
                <div className="flex flex-wrap items-center gap-3"><Copyable value={d.domain} ioc /><Badge tone={d.registered ? 'good' : 'warn'}>{d.registered ? 'registered' : 'not found'}</Badge>
                  {d.ageDays !== null && <Badge tone={d.ageDays < 30 ? 'bad' : d.ageDays < 180 ? 'warn' : 'neutral'}>{d.ageDays} days old</Badge>}
                  {d.dnssecSigned !== null && <Badge tone={d.dnssecSigned ? 'good' : 'neutral'}>DNSSEC {d.dnssecSigned ? 'on' : 'off'}</Badge>}</div>
              </Card>
              {d.registered && (
                <div className="grid gap-4 md:grid-cols-2">
                  <Card title="Registration"><KV rows={[['Registered', fmtDate(d.dates.registered)], ['Last changed', fmtDate(d.dates.updated)], ['Expires', d.dates.expires && `${fmtDate(d.dates.expires)}${d.daysToExpiry !== null ? ` (${d.daysToExpiry} days)` : ''}`]]} /></Card>
                  <Card title="Registrar"><KV rows={[['Name', d.registrar?.name], ['IANA ID', d.registrar?.ianaId], ['Abuse e-mail', d.registrar?.abuseEmail], ['Abuse phone', d.registrar?.abusePhone]]} /></Card>
                  <Card title="Registrant">{d.registrant?.redacted ? <p className="text-sm text-muted">Redacted for privacy (typical since GDPR).</p> : <KV rows={[['Name', d.registrant?.name], ['Organisation', d.registrant?.organization], ['Country', d.registrant?.country]]} />}</Card>
                  <Card title="Name servers">{d.nameservers.length ? <ul className="space-y-1 font-mono text-[13px]">{d.nameservers.map((n) => <li key={n}>{n}</li>)}</ul> : <p className="text-sm text-faint">None listed.</p>}</Card>
                  <Card title="EPP status" className="md:col-span-2"><div className="flex flex-wrap gap-1.5">{d.status.map((s) => <Badge key={s}>{s}</Badge>)}{!d.status.length && <span className="text-sm text-faint">none</span>}</div></Card>
                </div>
              )}
              <Card title="Findings"><IssueList issues={d.issues} /></Card>
              <JsonToggle data={d} />
            </div>
          )}
        </Result>
      )}

      {tab === 'ssl' && (
        <Result state={ssl} idle={<Empty>Enter a domain to list the certificates publicly logged for it.</Empty>}>
          {(d) => (
            <div className="space-y-4">
              <Card><div className="flex flex-wrap items-center gap-3"><Copyable value={d.domain} /><Badge tone={d.active ? 'good' : 'warn'}>{d.active} valid now</Badge><Badge>{d.total} logged</Badge><Badge tone={d.source === 'crt.sh' ? 'warn' : 'neutral'}>{d.source === 'crt.sh' ? 'via crt.sh (fallback)' : 'via ctlogs.dev'}</Badge>{d.wildcard && <Badge tone="info">wildcard issued</Badge>}</div>
                <p className="mt-2 text-xs text-faint">{d.note}</p></Card>
              <Card title="Findings"><IssueList issues={d.issues} empty="No certificate issues found." /></Card>
              {d.issuers.length > 0 && <Card title="Issuers"><div className="flex flex-wrap gap-1.5">{d.issuers.map((i) => <Badge key={i.issuer}>{i.issuer} · {i.count}</Badge>)}</div></Card>}
              <Card title={`Certificates (${d.certificates.length}${d.total > d.certificates.length ? ` of ${d.total}` : ''})`} pad={false}>
                <div className="p-3"><DataTable head={['Status', 'Names', 'Issuer', 'Valid from', 'Expires']} rows={d.certificates.map((c) => [
                  <Badge key="s" tone={c.validNow ? 'good' : 'neutral'}>{c.validNow ? `${c.daysRemaining}d left` : 'expired'}</Badge>,
                  <span key="n" className="break-all font-mono text-xs">{c.names.slice(0, 4).join(', ')}{c.names.length > 4 ? ` +${c.names.length - 4}` : ''}</span>,
                  c.issuer, fmtDate(c.notBefore)?.slice(0, 10), fmtDate(c.notAfter)?.slice(0, 10)])} /></div>
              </Card>
              {d.subdomains && <Card title={`Subdomains seen in certificates (${d.subdomains.length})`}><div className="flex max-h-72 flex-wrap gap-1.5 overflow-auto">{d.subdomains.map((s) => <Badge key={s}>{s}</Badge>)}</div></Card>}
              <JsonToggle data={d} />
            </div>
          )}
        </Result>
      )}

      {tab === 'http' && (
        <Result state={http} idle={<Empty>Enter a domain to follow its redirects and audit its security headers.</Empty>}>
          {(d) => (
            <div className="space-y-4">
              <Card>
                <div className="flex items-center gap-4">
                  <Grade grade={d.audit.grade} score={d.audit.score} />
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2"><Copyable value={d.finalUrl} /><Badge tone={d.status < 400 ? 'good' : 'bad'}>HTTP {d.status}</Badge></div>
                    <div className="flex flex-wrap gap-1.5"><Badge tone={d.httpsReachable ? 'good' : 'bad'}>HTTPS {d.httpsReachable ? 'ok' : 'unavailable'}</Badge>
                      {d.httpUpgradesToHttps !== null && <Badge tone={d.httpUpgradesToHttps ? 'good' : 'warn'}>HTTP {d.httpUpgradesToHttps ? 'redirects to HTTPS' : 'not upgraded'}</Badge>}
                      <Badge>{d.totalMs} ms</Badge>{d.addresses[0] && <Badge>{d.addresses[0]}</Badge>}</div>
                  </div>
                </div>
              </Card>
              <Card title="Redirect chain"><DataTable head={['#', 'URL', 'Status', 'TTFB']} rows={d.chain.map((h, i) => [i + 1, <span key="u" className="break-all font-mono text-xs">{h.url}</span>, <Badge key="s" tone={h.status < 300 ? 'good' : h.status < 400 ? 'info' : 'bad'}>{h.status}</Badge>, `${h.ttfbMs} ms`])} /></Card>
              <Card title="Security headers" pad={false}><div className="p-3"><DataTable head={['Header', 'Result', 'Notes']} rows={d.audit.checks.map((c) => [
                <span key="h" className="font-mono text-xs">{c.header}</span>,
                <Badge key="r" tone={c.status === 'good' ? 'good' : c.status === 'weak' ? 'warn' : 'bad'}>{c.status}</Badge>,
                <span key="n" className="text-muted">{c.note}{c.value && <span className="block break-all font-mono text-[11px] text-faint">{c.value.slice(0, 160)}</span>}</span>])} /></div></Card>
              {d.server.length > 0 && <Card title="Technology disclosure"><KV mono rows={d.server.map((s) => [s.header, s.value])} /></Card>}
              {d.cookies.length > 0 && <Card title="Cookies"><DataTable head={['Name', 'Secure', 'HttpOnly', 'SameSite']} rows={d.cookies.map((c) => [<span key="n" className="font-mono text-xs">{c.name}</span>, c.secure ? 'yes' : <span key="s" className="text-amber">no</span>, c.httpOnly ? 'yes' : 'no', c.sameSite ?? '—'])} /></Card>}
              <Card title="Findings"><IssueList issues={d.issues} /></Card>
              <JsonToggle data={d} />
            </div>
          )}
        </Result>
      )}
    </div>
  );
}
