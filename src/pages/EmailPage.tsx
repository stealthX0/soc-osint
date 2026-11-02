import { useEffect, useState } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, DataTable, IssueList, ProviderStrip, JsonToggle, Empty, Tabs, Grade, Copyable, CopyButton, fmtDate } from '../components/ui';
import { Result } from '../components/Result';
import { Icon } from '../components/icons';
import { useApi, useAction } from '../lib/hooks';
import { api } from '../lib/api';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import type { EmailAuth } from '../../shared/types';
import type { HeaderAnalysis } from '../../shared/headers';

type Tab = 'auth' | 'headers';
const resTone = (r: string | null) => (r === null ? 'neutral' : r === 'pass' ? 'good' : ['fail', 'permerror', 'hardfail', 'temperror'].includes(r) ? 'bad' : 'warn');

function HeaderAnalyzer() {
  const [text, setText] = useState('');
  const act = useAction<HeaderAnalysis, string>(async (headers, signal) => (await api<HeaderAnalysis>('/api/email/headers', { method: 'POST', body: { headers }, signal })).data);
  const d = act.data;
  const dur = (s: number | null) => (s === null ? '—' : s < 0 ? `${s}s` : s < 120 ? `${s}s` : `${Math.round(s / 60)}m`);

  return (
    <div>
      <div className="mb-5 rounded-xl border border-line bg-panel/90 p-3">
        <label htmlFor="hdr" className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-muted">Raw message headers</label>
        <textarea id="hdr" value={text} onChange={(e) => setText(e.target.value)} rows={9} spellCheck={false} placeholder={'Paste the full headers ("Show original" in Gmail, "View message source" in Outlook/Thunderbird)…'} className="w-full resize-y rounded-lg border border-line2 bg-bg2 p-3 font-mono text-xs placeholder:text-faint focus:border-teal/60" />
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <button onClick={() => act.run(text)} disabled={!text.trim() || act.status === 'loading'} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={15} strokeWidth={2.4} /> Analyze</button>
          <button onClick={() => { setText(''); }} className="text-sm text-muted hover:text-fg">Clear</button>
          <span className="text-xs text-faint">Processed in memory only: nothing is stored, logged or sent to third parties.</span>
        </div>
      </div>
      <Result state={{ ...act, cached: false }} idle={<Empty>Paste raw headers above to trace the delivery path and check SPF/DKIM/DMARC results.</Empty>}>
        {(a) => (
          <div className="space-y-4">
            <Card title="Findings"><IssueList issues={a.findings} empty="No problems detected in these headers." /></Card>
            <div className="grid gap-4 md:grid-cols-2">
              <Card title="Authentication results">
                <div className="mb-3 flex flex-wrap gap-2">{(['spf', 'dkim', 'dmarc'] as const).map((k) => <Badge key={k} tone={resTone(a.authentication[k])}>{k.toUpperCase()}: {a.authentication[k] ?? 'n/a'}</Badge>)}</div>
                <KV rows={[['Evaluated by', a.authentication.authservId], ['DKIM signatures', a.dkimSignatures.map((s) => `${s.domain ?? '?'} (${s.selector ?? '?'})`).join(', ') || null]]} mono />
              </Card>
              <Card title="Message">
                <KV mono rows={[['From', a.summary.from], ['To', a.summary.to], ['Subject', a.summary.subject], ['Date', a.summary.date], ['Return-Path', a.summary.returnPath], ['Reply-To', a.summary.replyTo], ['Message-ID', a.summary.messageId], ['Mailer', a.summary.xMailer]]} />
              </Card>
            </div>
            <Card title={`Delivery path (${a.hops.length} hop${a.hops.length === 1 ? '' : 's'}${a.totalDelaySeconds !== null ? `, ${dur(a.totalDelaySeconds)} total` : ''})`}>
              {a.originIp && <p className="mb-3 text-sm">Likely origin: <Copyable value={a.originIp} ioc /> <a className="ml-2 text-teal hover:underline" href={`/ip?q=${a.originIp}`} onClick={(e) => { e.preventDefault(); navigate(`/ip?q=${a.originIp}`); }}>look up</a></p>}
              <DataTable head={['#', 'From', 'By', 'Protocol', 'IPs', 'Time', 'Delay']} rows={a.hops.map((h) => [h.index, <span key="f" className="break-all font-mono text-xs">{h.from ?? '—'}</span>, <span key="b" className="break-all font-mono text-xs">{h.by ?? '—'}</span>, h.with ?? '—', <span key="i" className="font-mono text-xs">{h.ips.map((ip) => <span key={ip} className={h.publicIps.includes(ip) ? 'text-fg' : 'text-faint'}>{ip} </span>)}</span>, fmtDate(h.timestamp)?.replace(' UTC', '') ?? '—', dur(h.delaySeconds)])} empty="No Received headers found." />
            </Card>
            <JsonToggle data={a} />
          </div>
        )}
      </Result>
    </div>
  );
}

export default function EmailPage() {
  const { params } = useLocation();
  const q = params.get('q') ?? '';
  const tab: Tab = params.get('tab') === 'headers' ? 'headers' : 'auth';
  const selectors = params.get('selectors') ?? '';
  const state = useApi<EmailAuth>('/api/email/auth', tab === 'auth' && q ? { domain: q, selectors } : null);

  useEffect(() => {
    if (state.data) pushRecent({ label: state.data.domain, to: `/email?q=${encodeURIComponent(state.data.domain)}`, kind: 'Email' });
  }, [state.data?.domain]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-5xl">
      <PageHeader icon="mail" title="Email Intelligence" blurb="Check whether a domain can be spoofed, and trace where a message really came from." badge={<Badge tone="good">passive</Badge>} />
      <Tabs tabs={[{ id: 'auth', label: 'SPF / DKIM / DMARC', icon: 'shield' }, { id: 'headers', label: 'Header analyzer', icon: 'list' }]} value={tab} onChange={(t) => navigate(`/email?tab=${t}${q && t === 'auth' ? `&q=${encodeURIComponent(q)}` : ''}`)} />
      {tab === 'headers' ? <HeaderAnalyzer /> : (
        <>
          <LookupForm values={{ q, selectors }} busy={state.status === 'loading'}
            fields={[{ name: 'q', label: 'Domain or e-mail address', placeholder: 'example.com' }, { name: 'selectors', label: 'Extra DKIM selectors (optional)', placeholder: 'mail2024, s1024', width: 'flex-1 basis-48' }]}
            onSubmit={(v) => navigate(`/email?q=${encodeURIComponent(v.q)}${v.selectors ? `&selectors=${encodeURIComponent(v.selectors)}` : ''}`)} />
          <Result state={state} idle={<Empty>Enter a domain to grade its e-mail authentication. DKIM selectors cannot be listed from DNS, so common ones are probed; add yours if you know them.</Empty>}>
            {(d) => (
              <div className="space-y-4">
                <Card>
                  <div className="flex items-center gap-4">
                    <Grade grade={d.summary.grade} score={d.summary.score} />
                    <div className="min-w-0 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2"><Copyable value={d.domain} /><Badge tone={d.summary.spoofable ? 'bad' : 'good'}>{d.summary.spoofable ? 'spoofable' : 'protected against spoofing'}</Badge></div>
                      <div className="flex flex-wrap gap-1.5"><Badge tone={d.spf.found ? 'good' : 'bad'}>SPF {d.spf.found ? 'found' : 'missing'}</Badge><Badge tone={d.dmarc.found ? (d.dmarc.parsed?.policy === 'none' ? 'warn' : 'good') : 'bad'}>DMARC {d.dmarc.found ? `p=${d.dmarc.parsed?.policy}` : 'missing'}</Badge><Badge tone={d.dkim.some((k) => k.found) ? 'good' : 'warn'}>DKIM {d.dkim.filter((k) => k.found).length ? `${d.dkim.filter((k) => k.found).length} key(s)` : 'not found'}</Badge><Badge tone={d.mtaSts.found ? 'good' : 'neutral'}>MTA-STS {d.mtaSts.found ? 'on' : 'off'}</Badge></div>
                    </div>
                  </div>
                  {d.summary.notes.length > 0 && <ul className="mt-3 list-disc space-y-0.5 pl-5 text-sm text-muted">{d.summary.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
                </Card>

                <Card title="SPF" action={d.spf.totalLookups !== null && <Badge tone={d.spf.totalLookups > 10 ? 'bad' : d.spf.totalLookups >= 8 ? 'warn' : 'neutral'}>{d.spf.totalLookups}/10 DNS lookups</Badge>}>
                  {d.spf.parsed && <div className="mb-3 flex items-start gap-2"><code className="min-w-0 flex-1 break-all rounded-lg border border-line bg-bg2 p-2 font-mono text-xs">{d.spf.parsed.raw}</code><CopyButton text={d.spf.parsed.raw} /></div>}
                  <IssueList issues={d.spf.issues} empty="SPF looks healthy." />
                </Card>
                <Card title="DMARC" action={d.dmarc.foundAt && <span className="font-mono text-[11px] text-faint">{d.dmarc.foundAt}</span>}>
                  {d.dmarc.parsed && <div className="mb-3 flex items-start gap-2"><code className="min-w-0 flex-1 break-all rounded-lg border border-line bg-bg2 p-2 font-mono text-xs">{d.dmarc.parsed.raw}</code><CopyButton text={d.dmarc.parsed.raw} /></div>}
                  {d.dmarc.parsed && <div className="mb-3"><KV rows={[['Policy', d.dmarc.parsed.policy], ['Subdomain policy', d.dmarc.parsed.subdomainPolicy], ['Applied to', `${d.dmarc.parsed.pct}% of mail`], ['Alignment', `DKIM ${d.dmarc.parsed.adkim === 's' ? 'strict' : 'relaxed'}, SPF ${d.dmarc.parsed.aspf === 's' ? 'strict' : 'relaxed'}`], ['Aggregate reports', d.dmarc.parsed.rua.join(', ')]]} mono /></div>}
                  <IssueList issues={d.dmarc.issues} empty="DMARC looks healthy." />
                </Card>
                <Card title="DKIM keys found">
                  {d.dkim.some((k) => k.found) ? <DataTable head={['Selector', 'Key', 'Notes']} rows={d.dkim.filter((k) => k.found && k.parsed).map((k) => [<span key="s" className="font-mono text-xs">{k.selector}</span>, `${k.parsed!.keyType}${k.parsed!.approxKeyBits ? ` ~${k.parsed!.approxKeyBits} bit` : ''}${k.parsed!.revoked ? ' (revoked)' : ''}`, k.parsed!.issues.length ? <IssueList key="i" issues={k.parsed!.issues} /> : <span key="o" className="text-green">ok</span>])} /> : <p className="text-sm text-muted">None of the {d.dkim.length} common selectors returned a key. Selectors are arbitrary names, so the domain may still sign mail; check a real message&apos;s <code className="font-mono">DKIM-Signature: s=</code> value and add it above.</p>}
                </Card>
                <Card title="Mail servers (MX)">{d.mx.length ? <DataTable head={['Priority', 'Host']} rows={d.mx.map((m) => [m.priority, <span key="h" className="font-mono text-[13px]">{m.host}</span>])} /> : <p className="text-sm text-muted">No MX records: the domain does not accept mail.</p>}</Card>
                <ProviderStrip providers={d.providers} />
                <JsonToggle data={d} />
              </div>
            )}
          </Result>
        </>
      )}
    </div>
  );
}
