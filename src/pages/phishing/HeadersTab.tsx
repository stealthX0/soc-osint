import type { ReactNode } from 'react';
import { Card, Badge, KV, Empty, Spinner, Copyable, type Tone } from '../../components/ui';
import { navigate } from '../../lib/router';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { Finding, Severity } from '../../../shared/phishing/types';
import type { IpLookup } from '../../../shared/types';
import { assessIpRisk, type IpRiskLevel } from '../../../shared/phishing/ipRisk';
import { resTone } from './common';
import type { SenderStage } from './hooks';

const riskTone: Record<IpRiskLevel, Tone> = { high: 'bad', medium: 'warn', low: 'good', unknown: 'neutral' };
const riskLabel: Record<IpRiskLevel, string> = { high: 'High risk', medium: 'Medium risk', low: 'Low risk', unknown: 'Unknown' };
const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const factorTone = { high: 'bad', medium: 'warn', info: 'neutral' } as const;

export function HeadersTab({ r, sender, findings = [] }: { r: ParseStageResult; sender?: SenderStage; findings?: Finding[] }) {
  const fx = r.forensics;
  return (
    <div className="space-y-4">
      {sender && <IpIntelligence sender={sender} findings={findings} />}
      {fx ? (
        <Card title="Authentication">
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
      ) : <Empty>No headers were supplied, so there is no routing or authentication data. Paste the raw headers for the strongest analysis.</Empty>}
    </div>
  );
}

/* ═════════════════════════════════════════════════ IP intelligence */

function IpIntelligence({ sender, findings }: { sender: SenderStage; findings: Finding[] }) {
  const ipSlots = sender.slots.filter((s) => s.req.check === 'ip');
  const skipped = sender.plan.skipped.find((c) => c.id === 'sender.ip');
  return (
    <section aria-labelledby="ph-ipintel" className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="ph-ipintel" className="text-[11px] font-semibold uppercase tracking-[.12em] text-muted">IP intelligence</h3>
        <span className="text-xs text-faint">Reputation describes the IP, not this particular message.</span>
      </div>
      {!ipSlots.length && <Empty>{skipped?.detail ?? 'No IP address was found in the headers, so there was nothing to look up.'}</Empty>}
      <div className="grid gap-4 xl:grid-cols-2">
        {ipSlots.map((s) => {
          const req = s.req as { ip: string; role: string; trust: string };
          if (s.state === 'running') return <Card key={req.ip} title={`IP ${req.ip}`}><Spinner label="Looking up" /></Card>;
          const d = s.res?.data;
          if (!d || d.check !== 'ip') {
            return (
              <Card key={req.ip} title={`IP ${req.ip}`} action={<Badge tone="neutral">Unknown</Badge>}>
                <p className="text-sm text-amber">The lookup did not complete: {s.error ?? s.res?.checks[0]?.detail ?? 'no result'}. An IP that could not be checked is not counted as clean.</p>
              </Card>
            );
          }
          const ipFindings = findings.filter((f) => f.indicator?.type === 'ip' && f.indicator.value === req.ip);
          return <IpCard key={req.ip} v={d.value} role={req.role} trust={req.trust} findings={ipFindings} />;
        })}
      </div>
    </section>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-line/50 py-1.5 text-sm last:border-0">
      <span className="shrink-0 text-muted">{k}</span>
      <span className="min-w-0 break-words text-right text-fg">{children}</span>
    </div>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 mt-3 text-[10px] font-semibold uppercase tracking-wider text-faint">{title}</div>
      {children}
    </div>
  );
}

const na = <span className="text-faint">not available</span>;
const pct = (n: number) => `${n}%`;
const date = (s: string | null | undefined) => (s && !Number.isNaN(Date.parse(s)) ? new Date(s).toLocaleDateString() : '—');

function IpCard({ v, role, trust, findings }: { v: IpLookup; role: string; trust: string; findings: Finding[] }) {
  const risk = assessIpRisk(v);
  const rep = v.reputation;
  const vt = v.virustotal;
  const pd = v.pulsedive;
  const nt = v.netType;
  const failed = v.providers.filter((p) => !p.ok && !p.skipped);
  const typeBadges: { label: string; tone: Tone }[] = [
    ...(nt?.isTor || rep?.isTor ? [{ label: 'Tor', tone: 'bad' as Tone }] : []),
    ...(nt?.isAbuser ? [{ label: 'known abuser', tone: 'bad' as Tone }] : []),
    ...(nt?.isProxy ? [{ label: 'proxy', tone: 'warn' as Tone }] : []),
    ...(nt?.isVpn ? [{ label: 'VPN', tone: 'warn' as Tone }] : []),
    ...(nt?.isDatacenter ? [{ label: 'datacenter', tone: 'neutral' as Tone }] : []),
    ...(nt?.isMobile ? [{ label: 'mobile', tone: 'neutral' as Tone }] : []),
    ...(nt?.isCrawler ? [{ label: 'crawler', tone: 'neutral' as Tone }] : []),
  ];

  return (
    <Card
      title={<span className="flex items-center gap-2"><span>IP</span><Copyable value={v.ip} ioc /></span>}
      action={<span className="flex items-center gap-2"><Badge tone={riskTone[risk.level]}>{riskLabel[risk.level]}</Badge><a className="text-xs text-teal hover:underline" href={`/ip?q=${v.ip}`} onClick={(e) => { e.preventDefault(); navigate(`/ip?q=${v.ip}`); }}>full lookup</a></span>}
    >
      <div className="flex flex-wrap gap-1.5 text-xs">
        <Badge tone="info">{role.replace(/_/g, ' ')}</Badge>
        <Badge tone={trust === 'trusted' ? 'accent' : 'neutral'} title={trust === 'trusted' ? 'Recorded by the receiving organisation' : 'Taken from a header the sender could have written'}>{trust.replace(/_/g, ' ')}</Badge>
        {risk.sharedProvider && <Badge tone="neutral" title="Shared mail infrastructure: its reputation says little about this message">shared {risk.sharedProvider} infrastructure</Badge>}
        {typeBadges.map((b) => <Badge key={b.label} tone={b.tone}>{b.label}</Badge>)}
      </div>

      {/* Risk factors: what drove the rating, plus findings the investigation raised about this IP */}
      <Group title="Risk factors">
        {risk.factors.length || findings.length ? (
          <ul className="space-y-1.5">
            {risk.factors.map((x) => (
              <li key={x.text} className="flex items-start gap-2 text-sm">
                <Badge tone={factorTone[x.level]}>{x.level === 'info' ? 'note' : x.level}</Badge>
                <span className="min-w-0 text-fg/90">{x.text} <span className="text-xs text-faint">· {x.source}</span></span>
              </li>
            ))}
            {findings.filter((f) => !risk.factors.some((x) => f.source === x.source)).map((f, i) => (
              <li key={`${f.id}${i}`} className="flex items-start gap-2 text-sm" title={f.detail}>
                <Badge tone={sevTone[f.severity]}>{f.severity}</Badge>
                <span className="min-w-0 text-fg/90">{f.title} <span className="text-xs text-faint">· {f.source}</span></span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">{risk.level === 'unknown' ? 'No reputation provider answered for this IP.' : 'No risk factors reported by the providers that answered. Not proof of safety.'}</p>
        )}
      </Group>

      <Group title="Reputation">
        <Row k="AbuseIPDB">{rep ? <span className={rep.abuseConfidence >= 75 ? 'text-rose' : rep.abuseConfidence >= 25 ? 'text-amber' : ''}>{pct(rep.abuseConfidence)} confidence · {rep.totalReports} reports · {rep.distinctReporters} reporters</span> : na}</Row>
        {rep && <Row k="Last reported">{rep.lastReportedAt ? date(rep.lastReportedAt) : 'never'}{rep.usageType ? ` · ${rep.usageType}` : ''}</Row>}
        <Row k="VirusTotal">{vt ? (vt.observed ? <span className={vt.malicious >= 3 ? 'text-rose' : vt.malicious + vt.suspicious > 0 ? 'text-amber' : ''}>{vt.malicious} malicious · {vt.suspicious} suspicious · {vt.harmless} harmless{vt.reputation !== null ? ` · reputation ${vt.reputation}` : ''}</span> : 'not seen') : na}</Row>
        <Row k="Pulsedive">{pd ? (pd.observed ? <span className={/high|critical/i.test(pd.risk) ? 'text-rose' : /medium/i.test(pd.risk) ? 'text-amber' : ''}>risk {pd.risk}{pd.lastSeen ? ` · last seen ${date(pd.lastSeen)}` : ''}</span> : 'not observed') : na}</Row>
        {pd?.observed && pd.riskFactors.length > 0 && <Row k="Pulsedive factors">{pd.riskFactors.slice(0, 4).map((x) => x.description).join('; ')}</Row>}
      </Group>

      <Group title="Network">
        <Row k="ASN / organisation">{[v.network?.asn, v.network?.org].filter(Boolean).join(' · ') || '—'}</Row>
        {v.network?.isp && v.network.isp !== v.network.org && <Row k="ISP">{v.network.isp}</Row>}
        {v.network?.prefix && <Row k="Prefix"><span className="font-mono text-xs">{v.network.prefix}</span></Row>}
        <Row k="Reverse DNS"><span className="font-mono text-xs">{v.reverseDns[0] ?? v.ptrName ?? 'none'}</span></Row>
        {nt?.companyName && <Row k="Hosting company">{nt.companyName}{nt.companyType ? ` (${nt.companyType})` : ''}</Row>}
        <Row k="Location">{[v.geo?.city, v.geo?.region, v.geo?.country ?? v.geo?.countryCode].filter(Boolean).join(', ') || '—'}</Row>
      </Group>

      {v.exposure && (v.exposure.ports.length > 0 || v.exposure.vulns.length > 0) && (
        <Group title="Exposure">
          <Row k="Open ports"><span className="font-mono text-xs">{v.exposure.ports.slice(0, 12).join(', ') || 'none'}</span></Row>
          {v.exposure.vulns.length > 0 && <Row k="Known vulnerabilities"><span className="font-mono text-xs text-amber">{v.exposure.vulns.slice(0, 6).join(', ')}{v.exposure.vulns.length > 6 ? ` +${v.exposure.vulns.length - 6}` : ''}</span></Row>}
        </Group>
      )}

      {failed.length > 0 && <p className="mt-3 text-xs text-amber">Not checked: {failed.map((p) => p.name).join(', ')} did not respond. Missing answers are not counted as clean.</p>}
    </Card>
  );
}
