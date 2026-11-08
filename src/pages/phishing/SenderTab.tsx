import type { ReactNode } from 'react';
import { Card, Badge, Empty, Spinner } from '../../components/ui';
import { navigate } from '../../lib/router';
import { idOf, labelOf } from '../../../shared/phishing/sender';
import type { CheckResult, Finding } from '../../../shared/phishing/types';
import { FindingRow, resTone } from './common';
import type { Slot } from './hooks';

function Metric({ k, v }: { k: string; v: ReactNode }) {
  return <div className="flex justify-between gap-3 border-b border-line/60 py-1 text-sm last:border-0"><span className="text-muted">{k}</span><span className="text-right font-mono text-xs">{v}</span></div>;
}

export function SenderPanel({ slots, skipped, running }: { slots: Slot[]; skipped: CheckResult[]; running: number }) {
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
            <Card key={idOf(res!.request)} title={`Address ${v.email}`} action={<Badge tone="info" title="Checked by UserCheck.com">UserCheck</Badge>}>
              <Metric k="Domain" v={v.domain} />
              <Metric k="Domain age" v={v.domainAgeDays === null ? 'unknown' : `${v.domainAgeDays.toLocaleString('en-US')} days`} />
              <Metric k="Can receive mail (MX)" v={v.mx === null ? 'unknown' : v.mx ? 'yes' : 'no'} />
              <Metric k="Disposable" v={v.disposable ? 'yes' : 'no'} />
              <Metric k="Spam / abuse domain" v={v.spam ? 'yes' : 'no'} />
              <Metric k="Mailbox type" v={[v.publicDomain ? 'public provider' : null, v.relayDomain ? 'relay service' : null, v.freeSubdomain ? 'free subdomain' : null, v.roleAccount ? 'role account' : null].filter(Boolean).join(', ') || 'ordinary'} />
              {v.didYouMean && <Metric k="Looks like a typo of" v={v.didYouMean} />}
              {(v.spf || v.dmarc) && <Metric k="SPF / DMARC (domain)" v={`${v.spf ?? 'n/a'} / ${v.dmarc ?? 'n/a'}`} />}
            </Card>
          );
        })}
      </div>
      {!slots.length && skipped.length === 0 && <Empty>Nothing to look up for this message.</Empty>}
      {slots.filter((s) => s.state === 'done' && !s.res?.data).map((s) => <p key={idOf(s.req)} className="text-sm text-amber">{labelOf(s.req)}: {s.error ?? s.res?.checks[0]?.detail ?? 'no result'}</p>)}
    </div>
  );
}

/** Findings about who the sender claims to be: look-alike domains, brand and display-name spoofing, free-mail role impersonation. */
const IDENTITY = /brand|lookalike|display_name|homograph|impersonat|spoof/i;
export const identityFindings = (findings: Finding[]): Finding[] => findings.filter((f) => IDENTITY.test(f.id));

export function SenderTab({ slots, skipped, running, findings }: { slots: Slot[]; skipped: CheckResult[]; running: number; findings: Finding[] }) {
  const ident = identityFindings(findings);
  return (
    <div className="space-y-4">
      <SenderPanel slots={slots} skipped={skipped} running={running} />
      <section aria-labelledby="ph-ident">
        <h3 id="ph-ident" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Sender identity findings</h3>
        {ident.length ? <ul className="space-y-2">{ident.map((f, i) => <FindingRow key={`${f.id}${i}`} f={f} />)}</ul> : <p className="text-sm text-muted">No brand, look-alike or display-name findings so far. That depends on the checks that completed; see the check status table.</p>}
      </section>
    </div>
  );
}
