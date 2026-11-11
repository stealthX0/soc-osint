import type { ReactNode } from 'react';
import { Card, Badge, Empty, Spinner } from '../../components/ui';
import { navigate } from '../../lib/router';
import { IPQS_RISKY, IPQS_SUSPICIOUS, idOf, labelOf } from '../../../shared/phishing/sender';
import type { EmailReputation } from '../../../shared/types';
import type { Tone } from '../../components/ui';
import type { CheckResult, Finding } from '../../../shared/phishing/types';
import { TabFindings, resTone } from './common';
import type { Slot } from './hooks';

function Metric({ k, v }: { k: string; v: ReactNode }) {
  return <div className="flex justify-between gap-3 border-b border-line/60 py-1 text-sm last:border-0"><span className="text-muted">{k}</span><span className="text-right font-mono text-xs">{v}</span></div>;
}

const yesNo = (b: boolean | null) => (b === null ? 'unknown' : b ? 'yes' : 'no');
const SMTP: Record<number, string> = { [-1]: 'invalid address', 0: 'server rejects all mail', 1: 'temporary error', 2: 'server accepts all mail', 3: 'address verified' };

/** IPQualityScore mailbox reputation: fraud score first, then whether the mailbox exists, then abuse and domain facts. */
function IpqsCard({ v }: { v: EmailReputation }) {
  const score = v.fraudScore;
  const tone: Tone = score === null ? 'neutral' : score >= IPQS_RISKY ? 'bad' : score >= IPQS_SUSPICIOUS ? 'warn' : 'good';
  const bar = { bad: 'bg-rose', warn: 'bg-amber', good: 'bg-green', neutral: 'bg-line2', info: 'bg-sky', accent: 'bg-teal' }[tone];
  const exists = v.valid === true ? <Badge tone="good">exists</Badge> : v.valid === false ? <Badge tone="warn">not found</Badge> : <Badge>{v.timedOut ? 'server timed out' : 'unconfirmed'}</Badge>;
  const flags: [boolean, string, Tone][] = [
    [v.recentAbuse, 'recent abuse', 'bad'], [v.honeypot, 'spam trap', 'warn'], [v.disposable, 'disposable', 'warn'], [v.frequentComplainer, 'frequent complainer', 'neutral'],
    [v.riskyTld, 'risky TLD', 'warn'], [v.catchAll, 'catch-all server', 'neutral'], [v.generic, 'role address', 'neutral'], [v.freeProvider, 'free mail provider', 'neutral'],
  ];
  return (
    <Card title={`Mailbox ${v.email}`} action={<Badge tone="info" title="Checked by IPQualityScore Email Validation">IPQS</Badge>}>
      <div className="mb-2">
        <div className="flex items-baseline justify-between text-sm">
          <span className="text-muted">Fraud score</span>
          <span className="font-semibold tabular-nums text-fg">{score === null ? 'n/a' : <>{score}<span className="text-xs font-normal text-faint"> / 100</span></>}</span>
        </div>
        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-[#1b2844]" aria-hidden><div className={`h-full rounded-full ${bar}`} style={{ width: `${score ?? 0}%` }} /></div>
        <p className="mt-1 text-[11px] text-faint">75+ suspicious · 90+ risky (IPQS guidance)</p>
      </div>
      <Metric k="Mailbox" v={exists} />
      <Metric k="Mail server check" v={v.smtpScore !== null ? SMTP[v.smtpScore] ?? String(v.smtpScore) : 'unknown'} />
      <Metric k="Recent abuse" v={v.recentAbuse ? <Badge tone="bad">yes</Badge> : 'no'} />
      <Metric k="In a data breach" v={v.leaked ? <span title="Context only: many genuine addresses have been in a breach">yes</span> : 'no'} />
      <Metric k="Spam-trap risk" v={v.honeypot ? 'likely spam trap' : v.spamTrapScore ?? 'unknown'} />
      <Metric k="Domain age" v={v.domainAgeHuman ?? (v.domainRegistered ? v.domainRegistered.slice(0, 10) : 'unknown')} />
      <Metric k="First seen by IPQS" v={v.firstSeenHuman ?? 'unknown'} />
      <Metric k="Mail DNS valid" v={yesNo(v.dnsValid)} />
      <Metric k="Deliverability" v={v.deliverability ?? 'unknown'} />
      {v.suggestedDomain && v.suggestedDomain.toLowerCase() !== v.domain && <Metric k="Looks like a typo of" v={v.suggestedDomain} />}
      {flags.some(([on]) => on) && <div className="mt-2 flex flex-wrap gap-1">{flags.filter(([on]) => on).map(([, label, t]) => <Badge key={label} tone={t}>{label}</Badge>)}</div>}
      {(v.timedOut || v.suspect) && <p className="mt-2 text-xs text-amber">The mail server {v.timedOut ? 'did not answer in time' : 'gave a temporary or catch-all response'}, so whether the mailbox exists is not reliable.</p>}
    </Card>
  );
}

export function SenderPanel({ slots, skipped, running }: { slots: Slot[]; skipped: CheckResult[]; running: number }) {
  const done = slots.filter((s) => s.res?.data);
  return (
    <div className="space-y-4">
      {running > 0 && <Spinner label={`Running ${running} lookup${running === 1 ? '' : 's'}`} />}
      <p className="text-xs text-muted">Reputation describes the IP, domain or address, not this particular message. Mail sent through large providers (Google, Microsoft, mailing services) says little either way.</p>
      <div className="grid items-start gap-4 sm:grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
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
          if (d.check === 'ipqs') return <IpqsCard key={idOf(res!.request)} v={d.value} />;
          const v = d.value;
          return (
            <Card key={idOf(res!.request)} title={`Address ${v.email}`} action={res!.request.check === 'ipqs' && /fallback/i.test(res!.checks[0]?.label ?? '')
              ? <Badge tone="warn" title={res!.checks[0]?.detail ?? 'IPQualityScore was unavailable, so UserCheck.com answered instead'}>UserCheck · fallback</Badge>
              : <Badge tone="info" title="Checked by UserCheck.com">UserCheck</Badge>}>
              <Metric k="Domain" v={v.domain} />
              <Metric k="Domain age" v={v.domainAgeDays === null ? 'unknown' : `${v.domainAgeDays.toLocaleString('en-US')} days`} />
              <Metric k="Can receive mail (MX)" v={v.mx === null ? 'unknown' : v.mx ? 'yes' : 'no'} />
              <Metric k="Disposable" v={v.disposable ? 'yes' : 'no'} />
              <Metric k="Spam / abuse domain" v={v.spam ? 'yes' : 'no'} />
              <Metric k="Mailbox type" v={[v.publicDomain ? 'public provider' : null, v.relayDomain ? 'relay service' : null, v.freeSubdomain ? 'free subdomain' : null, v.roleAccount ? 'role account' : null].filter(Boolean).join(', ') || 'ordinary'} />
              {v.didYouMean && <Metric k="Looks like a typo of" v={v.didYouMean} />}
              {(v.spf || v.dmarc) && <Metric k="SPF / DMARC (domain)" v={`${v.spf ?? 'n/a'} / ${v.dmarc ?? 'n/a'}`} />}
              {res!.request.check === 'ipqs' && /fallback/i.test(res!.checks[0]?.label ?? '') && res!.checks[0]?.detail && <p className="mt-2 text-xs text-amber">{res!.checks[0].detail}</p>}
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
  // Identity findings first: they say who the sender pretends to be. The reputation lookups that follow describe the infrastructure.
  return (
    <div className="space-y-6">
      <TabFindings id="ph-ident" title="Sender identity findings" findings={identityFindings(findings)}
        empty="No brand, look-alike or display-name findings so far. That depends on the checks that completed; see the check status table." />
      <section aria-labelledby="ph-sender-lookups">
        <h3 id="ph-sender-lookups" className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-muted">Sender reputation lookups</h3>
        <SenderPanel slots={slots} skipped={skipped} running={running} />
      </section>
    </div>
  );
}
