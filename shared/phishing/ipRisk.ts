/**
 * One risk rating for an IP lookup, combining every intelligence provider the lookup returned (AbuseIPDB, VirusTotal,
 * Pulsedive, ipapi.is network type, Shodan-style exposure). Used by the dashboard's IP Reputation panel and the
 * Domain & IP Intelligence tab so both always agree.
 *
 * Like the rest of the investigation this describes the IP, not the message: shared mail infrastructure (Google,
 * Microsoft, mailing services) is flagged so a clean or dirty shared IP is not over-read. A lookup where no
 * reputation provider answered is "unknown", never "low".
 */
import type { IpLookup } from '../types';
import { sharedProviderOf } from './sender';

export type IpRiskLevel = 'high' | 'medium' | 'low' | 'unknown';
export interface IpRiskFactor { level: 'high' | 'medium' | 'info'; text: string; source: string }
export interface IpRisk { level: IpRiskLevel; factors: IpRiskFactor[]; sharedProvider: string | null; providersAnswered: number }

const RANK: Record<IpRiskFactor['level'], number> = { high: 2, medium: 1, info: 0 };

export function assessIpRisk(v: IpLookup): IpRisk {
  const f: IpRiskFactor[] = [];
  const rep = v.reputation;
  const vt = v.virustotal;
  const pd = v.pulsedive;
  const nt = v.netType;

  if (rep) {
    if (rep.abuseConfidence >= 75) f.push({ level: 'high', source: 'AbuseIPDB', text: `Abuse confidence ${rep.abuseConfidence}% from ${rep.totalReports} report${rep.totalReports === 1 ? '' : 's'} by ${rep.distinctReporters} reporter${rep.distinctReporters === 1 ? '' : 's'}` });
    else if (rep.abuseConfidence >= 25) f.push({ level: 'medium', source: 'AbuseIPDB', text: `Abuse confidence ${rep.abuseConfidence}% (${rep.totalReports} report${rep.totalReports === 1 ? '' : 's'})` });
    else if (rep.totalReports >= 5) f.push({ level: 'info', source: 'AbuseIPDB', text: `${rep.totalReports} past abuse reports, but low current confidence (${rep.abuseConfidence}%)` });
    if (rep.isWhitelisted) f.push({ level: 'info', source: 'AbuseIPDB', text: 'Whitelisted by AbuseIPDB (a known, legitimate network)' });
  }
  // A whitelisted or shared provider IP (Google, Microsoft, mailing services) flagged by one or two vendors is almost
  // always a false positive; it is reported as a note so it cannot raise the rating on its own.
  const vouched = !!rep?.isWhitelisted || !!sharedProviderOf(v);
  if (vt?.observed) {
    const n = vt.malicious + vt.suspicious;
    if (vt.malicious >= 3) f.push({ level: 'high', source: 'VirusTotal', text: `${vt.malicious} security vendors flag this IP as malicious` });
    else if (vt.malicious >= 1 || vt.suspicious >= 2) {
      const text = `${vt.malicious} malicious / ${vt.suspicious} suspicious vendor verdict${n === 1 ? '' : 's'}`;
      f.push(vouched
        ? { level: 'info', source: 'VirusTotal', text: `${text}; likely a false positive on a ${rep?.isWhitelisted ? 'whitelisted' : 'shared provider'} network` }
        : { level: 'medium', source: 'VirusTotal', text });
    }
  }
  if (pd?.observed) {
    const r = pd.risk.toLowerCase();
    const threats = pd.threats.map((t) => t.name).slice(0, 3);
    if (r === 'critical' || r === 'high') f.push({ level: 'high', source: 'Pulsedive', text: `Pulsedive risk ${r}${threats.length ? ` (${threats.join(', ')})` : ''}` });
    else if (r === 'medium') f.push({ level: 'medium', source: 'Pulsedive', text: `Pulsedive risk medium${threats.length ? ` (${threats.join(', ')})` : ''}` });
    else if (threats.length) f.push({ level: 'info', source: 'Pulsedive', text: `Linked to ${threats.join(', ')}` });
    if (pd.feeds.length) f.push({ level: 'info', source: 'Pulsedive', text: `Listed in ${pd.feeds.length} threat feed${pd.feeds.length === 1 ? '' : 's'}: ${pd.feeds.slice(0, 3).map((x) => x.name).join(', ')}` });
  }
  if (nt?.isTor || rep?.isTor) f.push({ level: 'high', source: 'ipapi.is', text: 'Tor exit node: mail servers do not normally send from Tor' });
  if (nt?.isAbuser) f.push({ level: 'medium', source: 'ipapi.is', text: 'Network listed as a known source of abuse' });
  if (nt?.isProxy) f.push({ level: 'medium', source: 'ipapi.is', text: 'Open or anonymising proxy' });
  if (nt?.isVpn) f.push({ level: 'medium', source: 'ipapi.is', text: `VPN exit${nt.vpnService ? ` (${nt.vpnService})` : ''}` });
  const abuserScore = parseFloat(nt?.companyAbuserScore ?? '');
  if (Number.isFinite(abuserScore) && abuserScore >= 0.01) f.push({ level: abuserScore >= 0.05 ? 'medium' : 'info', source: 'ipapi.is', text: `Hosting network abuse score ${(abuserScore * 100).toFixed(1)}%` });
  if (nt?.isDatacenter && !nt.isVpn && !nt.isProxy) f.push({ level: 'info', source: 'ipapi.is', text: `Hosted in a datacenter${nt.datacenter ? ` (${nt.datacenter})` : ''}` });
  if (v.exposure?.vulns.length) f.push({ level: 'medium', source: 'Shodan', text: `${v.exposure.vulns.length} known vulnerabilit${v.exposure.vulns.length === 1 ? 'y' : 'ies'} on exposed services (possibly a compromised server)` });

  // Providers that returned an answer (an answer of "not seen" counts: it is still a clean lookup, not a missing one).
  const providersAnswered = [rep, vt, pd, nt].filter(Boolean).length;
  const sharedProvider = sharedProviderOf(v);
  const top = f.reduce((m, x) => Math.max(m, RANK[x.level]), -1);
  const level: IpRiskLevel = top === 2 ? 'high' : top === 1 ? 'medium' : providersAnswered ? 'low' : 'unknown';
  f.sort((a, b) => RANK[b.level] - RANK[a.level]);
  return { level, factors: f, sharedProvider, providersAnswered };
}
