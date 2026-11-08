import { Card, Badge, DataTable, Empty, Copyable, Spinner, type Tone } from '../../components/ui';
import { Icon } from '../../components/icons';
import { navigate } from '../../lib/router';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { LinkStage } from './hooks';

const verdictTone: Record<string, Tone> = { malicious: 'bad', suspicious: 'warn', no_detections: 'good', unknown: 'neutral' };
const verdictLabel: Record<string, string> = { malicious: 'malicious', suspicious: 'suspicious', no_detections: 'no detections', unknown: 'not assessed' };

export function UrlTab({ r, links }: { r: ParseStageResult; links: LinkStage }) {
  const stage = links.stage;
  return (
    <div className="space-y-3">
      {r.links.length > 0 && (
        <div className="rounded-xl border border-line bg-bg2/60 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => void links.run()} disabled={links.busy} className="inline-flex h-9 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={14} strokeWidth={2.4} /> {stage ? 'Re-run link investigation' : 'Investigate links'}</button>
            {links.busy && <Spinner label="Investigating links" />}
          </div>
          <p className="mt-2 text-xs text-muted">Every link is ranked and checked against the OpenPhish feed; the top 3 also get a full lookup (URLhaus, Safe Browsing, VirusTotal, Pulsedive, urlscan, redirect trace, domain age). <strong>This is an active check:</strong> full URLs are sent to the enabled providers and the destination is requested from Cloudflare’s network, which a recipient-specific link may reveal to the sender. Do not run it on links containing private tokens.</p>
        </div>
      )}
      {links.error && <p role="alert" className="rounded-lg border border-red/30 bg-red/10 p-2 text-sm text-red">{links.error}</p>}

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
