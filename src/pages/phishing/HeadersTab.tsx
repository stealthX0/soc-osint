import { Card, Badge, KV, DataTable, Empty, Copyable } from '../../components/ui';
import { navigate } from '../../lib/router';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import { resTone } from './common';

const dur = (s: number | null) => (s === null ? '—' : s < 120 ? `${s}s` : `${Math.round(s / 60)}m`);

export function HeadersTab({ r }: { r: ParseStageResult }) {
  const fx = r.forensics;
  return (
    <>
      {fx ? (
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
      ) : <Empty>No headers were supplied, so there is no routing or authentication data. Paste the raw headers for the strongest analysis.</Empty>}
    </>
  );
}
