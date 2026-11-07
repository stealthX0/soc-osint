import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { PageHeader, Card, Badge, KV, DataTable, Empty, Tabs, Copyable, Spinner, ErrorBox, type Tone } from '../components/ui';
import { Icon } from '../components/icons';
import { useAction } from '../lib/hooks';
import { api } from '../lib/api';
import { navigate } from '../lib/router';
import type { ParseStageResult } from '../../shared/phishing/parse';
import type { Finding, CheckResult, PhishingInput, Severity, TrustLevel } from '../../shared/phishing/types';
import { dedupeFindings, dimensionLabel, sortFindings } from '../../shared/phishing/findings';
import type { ContentAnalysis } from '../../shared/phishing/content';
import { useAttachmentStage } from './phishing/AttachmentPanel';
import { VerdictCard } from './phishing/VerdictCard';
import { computeVerdict } from '../../shared/phishing/verdict';
import { assembleUrlStage, type RankedLink, type UrlStageResult } from '../../shared/phishing/urlTriage';
import { planSenderChecks, labelOf, idOf, type SenderCheckRequest, type SenderCheckResponse } from '../../shared/phishing/sender';

type Tab = 'findings' | 'headers' | 'sender' | 'content' | 'links' | 'attachments' | 'indicators' | 'checks';

const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const trustLabel: Record<TrustLevel, string> = { receiver_reported: 'receiver-reported', unverified: 'unverified', independently_verified: 'verified by Spectrix', derived: 'derived' };
const trustTone = (t: TrustLevel): Tone => (t === 'receiver_reported' ? 'accent' : t === 'independently_verified' ? 'good' : t === 'unverified' ? 'warn' : 'neutral');
const resTone = (r: string | null): Tone => (r === null ? 'neutral' : r === 'pass' ? 'good' : ['fail', 'hardfail', 'permerror'].includes(r) ? 'bad' : 'warn');
const statusTone: Record<CheckResult['status'], Tone> = { complete: 'good', failed: 'bad', skipped: 'warn', not_applicable: 'neutral' };

const HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
function parseAttachmentLines(text: string): { name?: string; hash?: string }[] {
  return text.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
    const tokens = line.split(/[\s,|]+/).filter(Boolean);
    const hash = tokens.find((t) => HASH.test(t));
    const name = tokens.filter((t) => t !== hash).join(' ');
    return { ...(name ? { name } : {}), ...(hash ? { hash } : {}) };
  });
}

const label = 'mb-1 block text-[11px] font-medium uppercase tracking-wider text-muted';
const field = 'w-full rounded-lg border border-line2 bg-bg2 p-2.5 text-sm placeholder:text-faint focus:border-teal/60';

function Section({ n, title, hint, children }: { n: number; title: string; hint?: string; children: ReactNode }) {
  return (
    <Card title={<span><span className="mr-2 text-teal">{n}.</span>{title}</span>}>
      {hint && <p className="mb-3 text-sm text-muted">{hint}</p>}
      <div className="space-y-3">{children}</div>
    </Card>
  );
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="rounded-lg border border-line bg-bg2/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={sevTone[f.severity]}>{f.severity}</Badge>
        <span className="font-medium">{f.title}</span>
      </div>
      <p className="mt-1.5 text-sm text-muted">{f.detail}</p>
      {f.evidence && f.evidence.length > 0 && (
        <div className="mt-2 space-y-1">{f.evidence.filter(Boolean).map((e, i) => <code key={i} className="block break-all rounded border border-line bg-bg2 px-2 py-1 font-mono text-[11px] text-fg/80">{e}</code>)}</div>
      )}
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
        <Badge>{dimensionLabel[f.dimension]}</Badge>
        <Badge tone={trustTone(f.trust)} title="How far this evidence can be believed">{trustLabel[f.trust]}</Badge>
        <Badge title="Does it concern this exact sender / URL / file?">{f.exactness}</Badge>
        <Badge>{f.source}</Badge>
      </div>
    </li>
  );
}


type Slot = { req: SenderCheckRequest; state: 'running' | 'done'; res?: SenderCheckResponse; error?: string };

/** Runs the sender / infrastructure lookups one request at a time (3 in parallel), so each call has its own upstream budget. */
function useSenderStage(parse: ParseStageResult, emailRep: boolean) {
  const plan = useMemo(() => planSenderChecks(parse, { emailRep }), [parse, emailRep]);
  const [slots, setSlots] = useState<Slot[]>([]);
  useEffect(() => {
    const ac = new AbortController();
    setSlots(plan.requests.map((req) => ({ req, state: 'running' as const })));
    let next = 0;
    const worker = async () => {
      while (next < plan.requests.length && !ac.signal.aborted) {
        const i = next++;
        const req = plan.requests[i];
        let patch: Partial<Slot>;
        try {
          const { data } = await api<SenderCheckResponse>('/api/phishing/sender', { method: 'POST', body: req, signal: ac.signal });
          patch = { state: 'done', res: data };
        } catch (e) {
          if (ac.signal.aborted) return;
          patch = { state: 'done', error: e instanceof Error ? e.message : 'The lookup failed.' };
        }
        setSlots((cur) => cur.map((s, j) => (j === i ? { ...s, ...patch } : s)));
      }
    };
    void Promise.all([worker(), worker(), worker()]);
    return () => ac.abort();
  }, [plan]);
  const findings = useMemo(() => slots.flatMap((s) => s.res?.findings ?? []), [slots]);
  const running = slots.filter((s) => s.state === 'running').length;
  return { plan, slots, findings, running };
}

function Metric({ k, v }: { k: string; v: ReactNode }) {
  return <div className="flex justify-between gap-3 border-b border-line/60 py-1 text-sm last:border-0"><span className="text-muted">{k}</span><span className="text-right font-mono text-xs">{v}</span></div>;
}

function SenderPanel({ slots, skipped, running }: { slots: Slot[]; skipped: CheckResult[]; running: number }) {
  const done = slots.filter((s) => s.res?.data);
  return (
    <div className="space-y-4">
      {running > 0 && <Spinner label={`Running ${running} lookup${running === 1 ? '' : 's'}`} />}
      <p className="text-xs text-muted">Reputation describes the IP, domain or address, not this particular message. Mail sent through large providers (Google, Microsoft, mailing services) says little either way.</p>
      <div className="grid gap-4 md:grid-cols-2">
        {done.map(({ res }) => {
          const d = res!.data!;
          if (d.check === 'ip') {
            const v = d.value;
            return (
              <Card key={idOf(res!.request)} title={`IP ${v.ip}`} action={<a className="text-xs text-teal hover:underline" href={`/ip?q=${v.ip}`} onClick={(e) => { e.preventDefault(); navigate(`/ip?q=${v.ip}`); }}>full lookup</a>}>
                <Metric k="Role" v={(res!.request as { role: string }).role.replace(/_/g, ' ')} />
                <Metric k="Network" v={[v.network?.asn, v.network?.org].filter(Boolean).join(' · ') || '—'} />
                <Metric k="Location" v={[v.geo?.city, v.geo?.countryCode].filter(Boolean).join(', ') || '—'} />
                <Metric k="Reverse DNS" v={v.reverseDns[0] ?? 'none'} />
                <Metric k="AbuseIPDB" v={v.reputation ? `${v.reputation.abuseConfidence}% · ${v.reputation.totalReports} reports` : 'not available'} />
                <Metric k="VirusTotal" v={v.virustotal ? `${v.virustotal.malicious} malicious / ${v.virustotal.suspicious} suspicious` : 'not available'} />
                <Metric k="Pulsedive" v={v.pulsedive ? (v.pulsedive.observed ? v.pulsedive.risk : 'not observed') : 'not available'} />
                <div className="mt-2 flex flex-wrap gap-1">{v.netType?.isTor && <Badge tone="bad">Tor</Badge>}{v.netType?.isVpn && <Badge tone="warn">VPN</Badge>}{v.netType?.isProxy && <Badge tone="warn">proxy</Badge>}{v.netType?.isDatacenter && <Badge>datacenter</Badge>}{v.flags.slice(0, 4).map((f) => <Badge key={f}>{f}</Badge>)}</div>
              </Card>
            );
          }
          if (d.check === 'domain') {
            const v = d.value;
            return (
              <Card key={idOf(res!.request)} title={`Domain ${v.domain}`} action={<a className="text-xs text-teal hover:underline" href={`/domain?q=${v.domain}`} onClick={(e) => { e.preventDefault(); navigate(`/domain?q=${v.domain}`); }}>full lookup</a>}>
                <Metric k="Used as" v={(res!.request as { roles: string[] }).roles.map((r) => r.replace(/_/g, ' ')).join(', ') || '—'} />
                <Metric k="Registered" v={v.registered ? (v.ageDays !== null ? `${v.ageDays} day(s) ago` : 'yes') : 'no record'} />
                <Metric k="Registrar" v={v.registrar?.name ?? '—'} />
                <Metric k="Expires in" v={v.daysToExpiry !== null ? `${v.daysToExpiry} day(s)` : '—'} />
                <Metric k="Nameservers" v={v.nameservers.slice(0, 2).join(', ') || '—'} />
              </Card>
            );
          }
          if (d.check === 'auth') {
            const v = d.value;
            return (
              <Card key={idOf(res!.request)} title={`Mail security DNS: ${v.domain}`}>
                <Metric k="SPF" v={v.spf.found ? `${v.spf.parsed?.all ?? ''}all · ${v.spf.totalLookups ?? '?'} lookups` : 'missing'} />
                <Metric k="DMARC" v={v.dmarc.found ? `p=${v.dmarc.parsed?.policy ?? '?'}` : 'missing'} />
                <Metric k="Mail servers (MX)" v={v.mx.slice(0, 2).map((m) => m.host).join(', ') || 'none'} />
                <Metric k="MTA-STS" v={v.mtaSts.found ? 'yes' : 'no'} />
              </Card>
            );
          }
          if (d.check === 'spf') {
            const v = d.value;
            const req = res!.request as { reported: string | null };
            return (
              <Card key={idOf(res!.request)} title={`SPF re-check vs ${v.domain}`} action={<Badge tone="good" title="Re-run by Spectrix against current DNS">verified by Spectrix</Badge>}>
                <Metric k="Sender IP" v={v.ip} />
                <Metric k="Spectrix result" v={<Badge tone={resTone(v.result)}>{v.result}</Badge>} />
                <Metric k="Headers reported" v={req.reported ?? 'not reported'} />
                <Metric k="Decided by" v={v.matched ?? '—'} />
                {v.notes.length > 0 && <p className="mt-2 text-xs text-muted">{v.notes.join(' ')}</p>}
              </Card>
            );
          }
          const v = d.value;
          return (
            <Card key={idOf(res!.request)} title={`Address ${v.email}`}>
              <Metric k="Reputation" v={<Badge tone={v.suspicious ? 'bad' : v.reputation === 'high' ? 'good' : 'neutral'}>{v.reputation ?? 'unknown'}{v.suspicious ? ' · suspicious' : ''}</Badge>} />
              <Metric k="References online" v={v.references} />
              <Metric k="Malicious activity" v={v.details.maliciousActivity ? (v.details.maliciousActivityRecent ? 'yes (recent)' : 'yes') : 'none reported'} />
              <Metric k="Blacklisted" v={v.details.blacklisted ? 'yes' : 'no'} />
              <Metric k="Disposable / free" v={`${v.details.disposable ? 'disposable' : 'no'} / ${v.details.freeProvider ? 'free provider' : 'no'}`} />
              <Metric k="Domain spoofable" v={v.details.spoofable === null ? 'unknown' : v.details.spoofable ? 'yes' : 'no'} />
            </Card>
          );
        })}
      </div>
      {!slots.length && skipped.length === 0 && <Empty>Nothing to look up for this message.</Empty>}
      {slots.filter((s) => s.state === 'done' && !s.res?.data).map((s) => <p key={idOf(s.req)} className="text-sm text-amber">{labelOf(s.req)}: {s.error ?? s.res?.checks[0]?.detail ?? 'no result'}</p>)}
    </div>
  );
}

const verdictTone: Record<string, Tone> = { malicious: 'bad', suspicious: 'warn', no_detections: 'good', unknown: 'neutral' };
const verdictLabel: Record<string, string> = { malicious: 'malicious', suspicious: 'suspicious', no_detections: 'no detections', unknown: 'not assessed' };

/** Folds a later batch into what is already known, then rebuilds findings and check rows from the merged state. */
function mergeStage(prev: UrlStageResult | null, next: UrlStageResult): UrlStageResult {
  const lookups = { ...(prev?.lookups ?? {}), ...next.lookups };
  const lookupErrors = Object.fromEntries(Object.entries({ ...(prev?.lookupErrors ?? {}), ...next.lookupErrors }).filter(([u]) => !lookups[u]));
  const ranked: RankedLink[] = next.ranked.map((l) => ({ ...l, tier: lookups[l.url] || lookupErrors[l.url] ? 'deep' : l.tier }));
  return assembleUrlStage({ ...next, ranked, lookups, lookupErrors, deepChecked: [...new Set([...(prev?.deepChecked ?? []), ...next.deepChecked])], maxDeep: 2 });
}

function LinkInvestigation({ r, input, stage, setStage }: { r: ParseStageResult; input: PhishingInput; stage: UrlStageResult | null; setStage: (fn: (p: UrlStageResult | null) => UrlStageResult | null) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);

  const payload = (deep?: string[]) => ({
    links: r.links.map((l) => ({ url: l.normalized, text: l.text, sources: l.sources, count: l.count, wrapped: !!l.wrapper })),
    context: {
      senderDomains: r.indicators.domains.filter((d) => d.roles.some((x) => ['from', 'return_path', 'dkim', 'sender_header'].includes(x))).map((d) => d.domain),
      claimedDomains: input.sender?.domain ? [input.sender.domain] : [],
      displayName: input.sender?.displayName || r.forensics?.addresses.from[0]?.display || undefined,
      subject: r.content.subject ?? input.subject,
      text: r.content.text.slice(0, 20_000),
    },
    // One full lookup per request: each lookup fans out into many outbound calls, and every request is its own Worker invocation with its own allowance.
    ...(deep ? { deep, maxDeep: deep.length } : { maxDeep: 1 }),
  });

  const call = async (deep?: string[]): Promise<UrlStageResult | null> => {
    try {
      const { data } = await api<UrlStageResult>('/api/phishing/urls', { method: 'POST', body: payload(deep), signal: abort.current?.signal });
      setStage((p) => mergeStage(p, data));
      return data;
    } catch (e) {
      if (!abort.current?.signal.aborted) setError(e instanceof Error ? e.message : 'The link investigation failed.');
      return null;
    }
  };
  const pending = (st: UrlStageResult | null) => (st ? st.deepCandidates.filter((u) => !st.lookups[u] && !st.lookupErrors[u]) : []);

  /** Triage + feed check + the top link, then the runner-up in a second request. */
  const run = async () => {
    abort.current?.abort();
    abort.current = new AbortController();
    setBusy(true); setError(null);
    const first = await call();
    const next = pending(first)[0];
    if (first && next) await call([next]);
    setBusy(false);
  };
  const deepNext = async () => {
    abort.current ??= new AbortController();
    setBusy(true); setError(null);
    const next = pending(stage)[0];
    if (next) await call([next]);
    setBusy(false);
  };
  const remaining = pending(stage);

  return (
    <div className="space-y-3">
      {r.links.length > 0 && (
        <div className="rounded-xl border border-line bg-bg2/60 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => void run()} disabled={busy} className="inline-flex h-9 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={14} strokeWidth={2.4} /> {stage ? 'Re-run link investigation' : 'Investigate links'}</button>
            {remaining.length > 0 && <button onClick={() => void deepNext()} disabled={busy} className="inline-flex h-9 items-center gap-2 rounded-lg border border-line2 px-4 text-sm text-fg hover:border-teal/50 disabled:opacity-50">Deep-check next link ({remaining.length} left)</button>}
            {busy && <Spinner label="Investigating links" />}
          </div>
          <p className="mt-2 text-xs text-muted">Every link is ranked and checked against the OpenPhish feed; the few that matter most also get a full lookup (URLhaus, Safe Browsing, VirusTotal, Pulsedive, urlscan, redirect trace, domain age). <strong>This is an active check:</strong> full URLs are sent to the enabled providers and the destination is requested from Cloudflare’s network, which a recipient-specific link may reveal to the sender. Do not run it on links containing private tokens.</p>
        </div>
      )}
      {error && <p className="rounded-lg border border-red/30 bg-red/10 p-2 text-sm text-red">{error}</p>}

      {stage && stage.claimedBrands.length > 0 && <p className="text-sm text-muted">The message appears to be about: {stage.claimedBrands.map((c) => <Badge key={c.brand} tone="info" title={c.basis}>{c.brand}</Badge>)}</p>}
      {stage && stage.limits.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{stage.limits.map((l) => <li key={l}>{l}</li>)}</ul>}

      {stage ? (
        <DataTable head={['#', 'Destination', 'Why it ranked here', 'Evidence']} rows={stage.ranked.map((l) => {
          const lk = stage.lookups[l.url];
          const err = stage.lookupErrors[l.url];
          return [
            <span key="n" className="font-mono text-xs text-muted" title={`Attention score ${l.score}/100`}>{l.rank}<span className="block text-[10px] text-faint">{l.score}</span></span>,
            <div key="d" className="min-w-0"><Copyable value={l.url} ioc />{l.text && <p className="mt-1 break-all text-xs text-muted">text: {l.text}</p>}{lk?.finalUrl && <p className="mt-1 break-all text-xs text-muted">redirects to <span className="font-mono">{lk.finalUrl}</span></p>}</div>,
            l.reasons.length ? <ul key="w" className="list-disc space-y-0.5 pl-4 text-xs text-muted">{l.reasons.map((x) => <li key={x}>{x}</li>)}</ul> : <span key="w" className="text-xs text-faint">nothing unusual</span>,
            <div key="e" className="flex flex-wrap gap-1">
              {l.openphish?.exact && <Badge tone="bad" title="This exact URL is in the OpenPhish feed">OpenPhish: listed</Badge>}
              {!l.openphish?.exact && (l.openphish?.hostMatches ?? 0) > 0 && <Badge tone="warn" title="Other phishing URLs on this host are in the OpenPhish feed">OpenPhish: host listed</Badge>}
              {lk && <Badge tone={verdictTone[lk.verdict] ?? 'neutral'} title={lk.summary}>{verdictLabel[lk.verdict] ?? lk.verdict} · {lk.checked}/{lk.attempted} sources</Badge>}
              {err && <Badge tone="bad" title={err}>lookup failed</Badge>}
              {!lk && !err && <Badge title="Local heuristics and the OpenPhish feed only">heuristics only</Badge>}
              {l.displayMismatch && <Badge tone="bad">text ≠ destination</Badge>}
              {l.brandMismatch && <Badge tone="warn">not a {l.brandMismatch} domain</Badge>}
              {l.count > 1 && <Badge>×{l.count}</Badge>}
              <a className="text-xs text-teal hover:underline" href={`/url?q=${encodeURIComponent(l.url)}`} onClick={(e) => { e.preventDefault(); navigate(`/url?q=${encodeURIComponent(l.url)}`); }}>open in URL tool</a>
            </div>,
          ];
        })} />
      ) : r.links.length ? <DataTable head={['Destination', 'Visible text', 'Flags', '']} rows={r.links.map((l) => [
        <div key="d" className="min-w-0"><Copyable value={l.normalized} ioc />{l.wrapper && <p className="mt-1 text-xs text-muted">Unwrapped from {l.wrapper.service}{l.wrapper.approximate ? ' (approximate)' : ''}</p>}</div>,
        <span key="t" className="break-all text-sm">{l.text ?? <span className="text-faint">—</span>}</span>,
        <div key="f" className="flex flex-wrap gap-1">
          {l.displayMismatch && <Badge tone="bad" title={`The text shows ${l.displayedHost} but the link goes to ${l.host}`}>text ≠ destination</Badge>}
          {l.isIp && <Badge tone="warn">IP address</Badge>}{l.ipObfuscated && <Badge tone="bad">obfuscated IP</Badge>}{l.hasUserinfo && <Badge tone="bad">credentials in URL</Badge>}
          {l.scheme === 'http' && <Badge tone="warn">no HTTPS</Badge>}{l.count > 1 && <Badge>×{l.count}</Badge>}{l.sources.map((x) => <Badge key={x}>{x}</Badge>)}
        </div>,
        <a key="a" className="text-teal hover:underline" href={`/url?q=${encodeURIComponent(l.normalized)}`} onClick={(e) => { e.preventDefault(); navigate(`/url?q=${encodeURIComponent(l.normalized)}`); }}>investigate</a>,
      ])} /> : <Empty>No links were found. Paste the body (or the URLs) to analyse them.</Empty>}
      {r.skippedLinks.length > 0 && <Card title="Skipped"><ul className="space-y-1 text-sm">{r.skippedLinks.map((s, i) => <li key={i}><code className="break-all font-mono text-xs">{s.value}</code> <span className="text-muted">— {s.reason}</span></li>)}</ul></Card>}
      {stage && stage.skipped.length > 0 && <Card title="Rejected by the link investigation"><ul className="space-y-1 text-sm">{stage.skipped.map((s, i) => <li key={i}><code className="break-all font-mono text-xs">{s.value}</code> <span className="text-muted">— {s.reason}</span></li>)}</ul></Card>}
    </div>
  );
}


const confTone: Record<'low' | 'medium' | 'high', Tone> = { low: 'neutral', medium: 'warn', high: 'bad' };

function ContentPanel({ a, subject }: { a: ContentAnalysis; subject: string | null }) {
  if (!a.analysed) return <Empty>No message text was supplied, so the wording could not be analysed. Paste the email body to check it for urgency, credential and payment requests and other lures.</Empty>;
  const recognised = a.intents.filter((i) => i.id !== 'unknown');
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">These are indicators for review, not a verdict: genuine password resets, invoices and security alerts use the same words. The strongest signal is several different lure types together, combined with the sender and link evidence.</p>
      {!a.languageSupported && <p className="rounded-lg border border-amber/30 bg-amber/10 p-2 text-sm text-amber">Most of this message is not in Latin script. The wording rules read English, so the absence of indicators here does not mean the message is clean.</p>}
      <Card title="Likely intent">
        {recognised.length ? (
          <ul className="space-y-2 text-sm">{recognised.map((i) => <li key={i.id} className="flex flex-wrap items-center gap-2"><Badge tone={confTone[i.confidence]}>{i.confidence}</Badge><span className="font-medium">{i.label}</span><span className="text-xs text-muted">from: {i.reasons.join(', ')}</span></li>)}</ul>
        ) : <p className="text-sm text-muted">No phishing intent was recognised from the wording{subject ? ` of "${subject.slice(0, 80)}"` : ''}. That says nothing about the sender, links or attachments.</p>}
      </Card>
      {a.categories.length > 0 && (
        <Card title={`Wording that triggered a rule (${a.categories.length})`}>
          <ul className="space-y-3">{a.categories.map((c) => (
            <li key={c.id}>
              <div className="flex items-center gap-2"><span className="font-medium">{c.label}</span>{c.strong && <Badge tone="warn" title="States a consequence or asks for a specific sensitive action">strong</Badge>}</div>
              <div className="mt-1 space-y-1">{c.matches.map((m, i) => <code key={i} className="block break-words rounded border border-line bg-bg2 px-2 py-1 font-mono text-[11px] text-fg/80">{m.excerpt}</code>)}</div>
            </li>
          ))}</ul>
        </Card>
      )}
      {a.notes.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{a.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
    </div>
  );
}

function Results({ r, input, emailRep }: { r: ParseStageResult; input: PhishingInput; emailRep: boolean }) {
  const [tab, setTab] = useState<Tab>('findings');
  const sender = useSenderStage(r, emailRep);
  const att = useAttachmentStage(r);
  const [stage, setStage] = useState<UrlStageResult | null>(null);
  const allFindings = useMemo(() => sortFindings(dedupeFindings([...r.findings, ...sender.findings, ...(stage?.findings ?? []), ...att.findings])), [r.findings, sender.findings, stage, att.findings]);
  type Row = CheckResult | { id: string; label: string; status: 'running' };
  const senderRows: Row[] = sender.slots.flatMap<Row>((s) => (s.res ? s.res.checks : s.state === 'running' ? [{ id: idOf(s.req), label: labelOf(s.req), status: 'running' }] : [{ id: idOf(s.req), label: labelOf(s.req), status: 'failed', stage: 'sender', result: null, detail: s.error }]));
  const allChecks: Row[] = [...r.checks, ...sender.plan.skipped, ...senderRows, ...(stage?.checks ?? []), ...att.checks];
  const verdict = useMemo(() => computeVerdict({ parse: r, findings: allFindings, checks: allChecks.map((c) => ({ id: c.id, label: c.label, status: c.status, result: 'result' in c ? c.result : null, detail: 'detail' in c ? c.detail : undefined })) }), [r, allFindings, allChecks]);
  const fx = r.forensics;
  const counts = allFindings.reduce<Record<string, number>>((a, f) => ({ ...a, [f.severity]: (a[f.severity] ?? 0) + 1 }), {});
  const dur = (s: number | null) => (s === null ? '—' : s < 120 ? `${s}s` : `${Math.round(s / 60)}m`);

  return (
    <div className="space-y-4">
      <VerdictCard v={verdict} />
      <p className="text-xs text-faint">Preview: the scoring weights are initial values still being calibrated. Treat the verdict as decision support and read the reasons and what is missing.</p>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).filter((s) => counts[s]).map((s) => <Badge key={s} tone={sevTone[s]}>{counts[s]} {s}</Badge>)}
        {!allFindings.length && sender.running === 0 && <Badge tone="good">no findings so far</Badge>}
        {sender.running > 0 && <Badge tone="info">{sender.running} lookup(s) running</Badge>}
        <span className="text-faint">·</span>
        <span className="text-muted">{r.links.length} link(s), {r.attachments.filter((a) => !a.inline).length} attachment(s)</span>
      </div>
      {r.limits.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{r.limits.map((l) => <li key={l}>{l}</li>)}</ul>}

      <Tabs value={tab} onChange={setTab} tabs={[
        { id: 'findings', label: `Findings (${allFindings.length})`, icon: 'warn' }, { id: 'headers', label: 'Headers & auth', icon: 'mail' }, { id: 'sender', label: 'Sender intel', icon: 'globe' }, { id: 'content', label: 'Content', icon: 'eye' }, { id: 'links', label: `Links (${r.links.length})`, icon: 'ext' },
        { id: 'attachments', label: `Attachments (${r.attachments.length})`, icon: 'file' }, { id: 'indicators', label: 'Indicators', icon: 'list' }, { id: 'checks', label: 'Check status', icon: 'check' },
      ]} />

      {tab === 'findings' && (allFindings.length ? <ul className="space-y-2">{allFindings.map((f, i) => <FindingRow key={`${f.id}${i}`} f={f} />)}</ul> : <Empty>Nothing suspicious was found so far. Use the Links tab to investigate the links.</Empty>)}

      {tab === 'content' && <ContentPanel a={r.content.analysis} subject={r.content.subject} />}

      {tab === 'sender' && <SenderPanel slots={sender.slots} skipped={sender.plan.skipped} running={sender.running} />}

      {tab === 'headers' && (fx ? (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Sending infrastructure" action={<Badge tone={fx.trust.confidence === 'high' ? 'good' : fx.trust.confidence === 'medium' ? 'warn' : 'neutral'}>{fx.trust.confidence} confidence</Badge>}>
              {fx.trust.connectingIp ? (
                <p className="mb-2 text-sm">Connecting IP: <Copyable value={fx.trust.connectingIp} ioc /> <a className="ml-1 text-teal hover:underline" href={`/ip?q=${fx.trust.connectingIp}`} onClick={(e) => { e.preventDefault(); navigate(`/ip?q=${fx.trust.connectingIp}`); }}>look up</a></p>
              ) : <p className="mb-2 text-sm text-muted">No public connecting IP could be established.</p>}
              <KV rows={[['Receiving server', fx.trust.receiverHost], ['Trusted hops', `${fx.trust.trustedHops} of ${fx.hops.length}`], ['IP source', fx.trust.connectingIpSource.replace(/_/g, ' ')], ['Claimed origin (untrusted)', fx.trust.claimedOriginIp]]} mono />
              {fx.trust.notes.length > 0 && <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted">{fx.trust.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
            </Card>
            <Card title="Message">
              <KV mono rows={[['From', fx.summary.from], ['Reply-To', fx.summary.replyTo], ['Return-Path', fx.summary.returnPath], ['To', fx.summary.to], ['Subject', fx.summary.subject], ['Date', fx.summary.date], ['Message-ID', fx.summary.messageId]]} />
            </Card>
          </div>
          <Card title="Authentication (as reported in the headers)">
            <div className="mb-3 flex flex-wrap gap-2">
              {fx.authentication.spf ? <Badge tone={resTone(fx.authentication.spf.result)}>SPF: {fx.authentication.spf.result}</Badge> : <Badge>SPF: n/a</Badge>}
              {fx.authentication.dkim.length ? fx.authentication.dkim.map((d, i) => <Badge key={i} tone={resTone(d.result)}>DKIM: {d.result}{d.domain ? ` (${d.domain})` : ''}</Badge>) : <Badge>DKIM: n/a</Badge>}
              {fx.authentication.dmarc ? <Badge tone={resTone(fx.authentication.dmarc.result)}>DMARC: {fx.authentication.dmarc.result}{fx.authentication.dmarc.policy ? ` p=${fx.authentication.dmarc.policy}` : ''}</Badge> : <Badge>DMARC: n/a</Badge>}
              {fx.authentication.source !== 'none' && <Badge tone={fx.authentication.source === 'receiver_header' ? 'accent' : 'warn'}>{fx.authentication.source === 'receiver_header' ? 'from the receiving server' : 'not tied to the receiving server'}</Badge>}
            </div>
            <KV rows={[
              ['From domain', fx.authentication.alignment.fromDomain],
              ['SPF aligned with From', fx.authentication.alignment.spfAligned === null ? 'unknown' : fx.authentication.alignment.spfAligned ? 'yes' : 'no'],
              ['DKIM aligned with From', fx.authentication.alignment.dkimAligned === null ? 'unknown' : fx.authentication.alignment.dkimAligned ? 'yes' : 'no'],
              ['DKIM signatures', fx.authentication.dkimSignatures.map((s) => `${s.domain ?? '?'} (${s.selector ?? '?'})`).join(', ') || null],
              ['ARC', fx.authentication.arc.present ? `${fx.authentication.arc.instances} hop(s), newest chain ${fx.authentication.arc.newestChainValidation ?? 'unknown'}` : null],
            ]} mono />
            {fx.authentication.conflicts.length > 0 && <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-amber">{fx.authentication.conflicts.map((c) => <li key={c}>{c}</li>)}</ul>}
          </Card>
          {fx.discrepancies.length > 0 && (
            <Card title="What you entered vs what the headers say">
              <DataTable head={['Field', 'You entered', 'Headers say', 'Result']} rows={fx.discrepancies.map((d) => [d.field.replace(/_/g, ' '), <span key="s" className="break-all font-mono text-xs">{d.supplied}</span>, <span key="e" className="break-all font-mono text-xs">{d.extracted ?? '—'}</span>, <span key="k"><Badge tone={d.kind === 'match' ? 'good' : d.kind === 'mismatch' ? 'bad' : 'warn'}>{d.kind.replace(/_/g, ' ')}</Badge><span className="mt-1 block text-xs text-muted">{d.note}</span></span>])} />
            </Card>
          )}
          <Card title={`Delivery path (${fx.hops.length} hop${fx.hops.length === 1 ? '' : 's'}${fx.totalDelaySeconds !== null ? `, ${dur(fx.totalDelaySeconds)} total` : ''})`}>
            <DataTable head={['#', 'Trust', 'From', 'By', 'Client IP', 'Delay']} rows={fx.hops.map((h) => [h.index, <Badge key="t" tone={h.trust === 'trusted' ? 'accent' : 'warn'} title={h.trust === 'trusted' ? 'Added by the receiving organisation' : 'Written before the message reached the receiver: could be forged'}>{h.trust}</Badge>, <span key="f" className="break-all font-mono text-xs">{h.from ?? '—'}</span>, <span key="b" className="break-all font-mono text-xs">{h.by ?? '—'}</span>, <span key="i" className="font-mono text-xs">{h.clientIps.join(', ') || '—'}</span>, dur(h.delaySeconds)])} empty="No Received headers." />
          </Card>
        </div>
      ) : <Empty>No headers were supplied, so there is no routing or authentication data. Paste the raw headers for the strongest analysis.</Empty>)}

      {tab === 'links' && <LinkInvestigation r={r} input={input} stage={stage} setStage={setStage} />}

      {tab === 'attachments' && att.panel}

      {tab === 'indicators' && (
        <div className="grid gap-4 md:grid-cols-2">
          <Card title="IP addresses">{r.indicators.ips.length ? <ul className="space-y-2 text-sm">{r.indicators.ips.map((i) => <li key={i.ip}><Copyable value={i.ip} ioc /> <Badge tone={trustTone(i.trust)}>{i.role.replace(/_/g, ' ')}</Badge>{i.note && <p className="text-xs text-muted">{i.note}</p>}</li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="Domains">{r.indicators.domains.length ? <ul className="space-y-2 text-sm">{r.indicators.domains.map((d) => <li key={d.domain}><Copyable value={d.domain} ioc /> <span className="ml-1">{d.roles.map((x) => <Badge key={x}>{x.replace(/_/g, ' ')}</Badge>)}</span></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="E-mail addresses">{r.indicators.emails.length ? <ul className="space-y-2 text-sm">{r.indicators.emails.map((e) => <li key={e.address}><Copyable value={e.address} ioc /> <span className="ml-1">{e.roles.map((x) => <Badge key={x}>{x.replace(/_/g, ' ')}</Badge>)}</span></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
          <Card title="URLs">{r.indicators.urls.length ? <ul className="space-y-2 text-sm">{r.indicators.urls.map((u) => <li key={u}><Copyable value={u} ioc /></li>)}</ul> : <p className="text-sm text-muted">None.</p>}</Card>
        </div>
      )}

      {tab === 'checks' && (
        <Card title="Checks performed" pad={false}>
          <DataTable head={['Check', 'Status', 'Result']} rows={allChecks.map((c) => [c.label, c.status === 'running' ? <Badge key="s" tone="info">running</Badge> : <Badge key="s" tone={statusTone[c.status]}>{c.status.replace(/_/g, ' ')}</Badge>, <span key="r" className="text-sm">{'result' in c ? c.result ?? '—' : '…'}{'detail' in c && c.detail && <span className="mt-0.5 block text-xs text-muted">{c.detail}</span>}</span>])} />
        </Card>
      )}
    </div>
  );
}

export default function PhishingPage() {
  const [f, setF] = useState({ headers: '', subject: '', body: '', email: '', displayName: '', domain: '', ip: '', urls: '', attachments: '', origin: 'reported' as NonNullable<PhishingInput['origin']> });
  const [emailRep, setEmailRep] = useState(true);
  const [submittedRep, setSubmittedRep] = useState(true);
  const [submitted, setSubmitted] = useState<{ id: number; input: PhishingInput } | null>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const act = useAction<ParseStageResult, PhishingInput>(async (input, signal) => (await api<ParseStageResult>('/api/phishing/parse', { method: 'POST', body: input, signal })).data);

  const submit = () => {
    const input: PhishingInput = {
      headers: f.headers, subject: f.subject, body: f.body, origin: f.origin,
      sender: { email: f.email, displayName: f.displayName, domain: f.domain, ip: f.ip },
      urls: f.urls.split('\n').map((u) => u.trim()).filter(Boolean),
      attachments: parseAttachmentLines(f.attachments),
    };
    setSubmittedRep(emailRep);
    setSubmitted((p) => ({ id: (p?.id ?? 0) + 1, input }));
    return act.run(input);
  };
  const empty = !Object.entries(f).some(([k, v]) => k !== 'origin' && String(v).trim());

  return (
    <div className="max-w-5xl">
      <PageHeader icon="eye" title="Phishing Investigation" blurb="Paste a suspicious email and collect the evidence: where it really came from, whether it authenticates, and where its links lead." badge={<Badge tone="warn">preview</Badge>} />
      <div className="mb-6 space-y-4">
        <Section n={1} title="Email information" hint="Headers are the most valuable input: they reveal the real sending server and the authentication results. Spectrix extracts indicators automatically.">
          <div>
            <label htmlFor="ph-h" className={label}>Raw email headers <Badge tone="accent">recommended</Badge></label>
            <textarea id="ph-h" value={f.headers} onChange={set('headers')} rows={8} spellCheck={false} placeholder={'Paste the full headers ("Show original" in Gmail, "View message source" in Outlook / Thunderbird, or the Internet headers in Outlook properties)…'} className={`${field} resize-y font-mono text-xs`} />
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div><label htmlFor="ph-s" className={label}>Subject</label><input id="ph-s" value={f.subject} onChange={set('subject')} className={field} placeholder="Taken from the headers when available" /></div>
            <div>
              <span className={label}>Where did this email come from?</span>
              <div className="flex gap-1">{([['reported', 'Reported by a user'], ['inbox', 'Found in a mailbox'], ['training', 'Training / test']] as const).map(([v, t]) => <button key={v} type="button" onClick={() => setF((p) => ({ ...p, origin: v }))} aria-pressed={f.origin === v} className={`flex-1 rounded-lg border px-2 py-2 text-xs ${f.origin === v ? 'border-teal/50 bg-teal/10 text-teal' : 'border-line2 text-muted hover:text-fg'}`}>{t}</button>)}</div>
            </div>
          </div>
          <div><label htmlFor="ph-b" className={label}>Email body (optional)</label><textarea id="ph-b" value={f.body} onChange={set('body')} rows={6} spellCheck={false} placeholder="Paste the message body: plain text, HTML source, or the MIME body from a .eml. Links are extracted automatically." className={`${field} resize-y font-mono text-xs`} /></div>
        </Section>

        <Section n={2} title="Sender information" hint="Optional when headers are supplied. What you enter is treated as a clue and compared with the headers; it is never trusted over them.">
          <div className="grid gap-3 md:grid-cols-2">
            <div><label htmlFor="ph-e" className={label}>Sender email address</label><input id="ph-e" value={f.email} onChange={set('email')} className={`${field} font-mono`} placeholder="billing@example.com" /></div>
            <div><label htmlFor="ph-d" className={label}>Sender display name</label><input id="ph-d" value={f.displayName} onChange={set('displayName')} className={field} placeholder="PayPal Support" /></div>
            <div><label htmlFor="ph-o" className={label}>Claimed organisation website</label><input id="ph-o" value={f.domain} onChange={set('domain')} className={`${field} font-mono`} placeholder="paypal.com" /></div>
            <div><label htmlFor="ph-i" className={label}>Sender IP address (unverified)</label><input id="ph-i" value={f.ip} onChange={set('ip')} className={`${field} font-mono`} placeholder="Extracted from the headers when possible" /></div>
          </div>
        </Section>

        <Section n={3} title="Links and attachments">
          <div className="grid gap-3 md:grid-cols-2">
            <div><label htmlFor="ph-u" className={label}>URLs found in the email (one per line)</label><textarea id="ph-u" value={f.urls} onChange={set('urls')} rows={4} spellCheck={false} placeholder={'Links in the body are extracted automatically.\nDefanged URLs (hxxps://evil[.]com) are accepted.'} className={`${field} resize-y font-mono text-xs`} /></div>
            <div><label htmlFor="ph-a" className={label}>Attachment filenames or hashes (one per line)</label><textarea id="ph-a" value={f.attachments} onChange={set('attachments')} rows={4} spellCheck={false} placeholder={'invoice_4491.pdf\nreport.xlsm  <sha256>\n<md5 / sha1 / sha256>'} className={`${field} resize-y font-mono text-xs`} /></div>
          </div>
        </Section>

        <label className="flex cursor-pointer items-start gap-2 text-sm text-muted">
          <input type="checkbox" checked={emailRep} onChange={(e) => setEmailRep(e.target.checked)} className="mt-1 accent-teal" />
          <span>Check the sender address reputation with EmailRep.io. <span className="text-faint">The address is sent to that third-party service. The sender IP and domains are always looked up with Spectrix's IP and domain intelligence providers; the message text and attachments are never sent anywhere.</span></span>
        </label>

        <div className="flex flex-wrap items-center gap-3">
          <button onClick={submit} disabled={empty || act.status === 'loading'} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-5 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={15} strokeWidth={2.4} /> Analyse email</button>
          <button onClick={() => setF({ headers: '', subject: '', body: '', email: '', displayName: '', domain: '', ip: '', urls: '', attachments: '', origin: 'reported' })} className="text-sm text-muted hover:text-fg">Clear</button>
          <span className="text-xs text-faint">Nothing is stored. Investigating links is a separate, explicit step on the Links tab.</span>
        </div>
      </div>

      {act.status === 'loading' && <Spinner label="Analysing" />}
      {act.status === 'error' && act.error && <ErrorBox error={act.error} onRetry={submit} />}
      {act.status === 'success' && act.data && submitted && <Results key={submitted.id} r={act.data} input={submitted.input} emailRep={submittedRep} />}
      {act.status === 'idle' && <Empty>Paste at least the email headers, or a sender, link or attachment, then choose Analyse email.</Empty>}
    </div>
  );
}
