/**
 * Step 2: sender and infrastructure intelligence.
 *
 * Pure planning + conversion code. The Worker runs one lookup per request (to stay inside per-invocation subrequest
 * limits); this module decides WHICH lookups an email needs and turns each raw lookup result into Findings.
 *
 * Calibration principles
 *  - Reputation says something about the IP / domain / address, not about this particular message. Findings therefore
 *    carry `exactness`, and shared mail infrastructure (Google, Microsoft, mailing services) is called out explicitly:
 *    a clean or dirty shared IP says little about whether THIS message is phishing.
 *  - A lookup that fails or is skipped is reported as such and never counted as clean.
 */
import type { EmailCheck, EmailReputation, IpLookup, WhoisResult, EmailAuth } from '../types';
import type { ParseStageResult } from './parse';
import { check, makeFinding } from './findings';
import { FREE_MAIL, isFreeMail, registrableOf } from './domains';
import type { CheckResult, DomainRole, EmailRole, Finding, IpRole, TrustLevel } from './types';

/* ------------------------------------------------------------- wire types */

export interface SpfEvaluationView {
  domain: string; ip: string;
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'permerror' | 'temperror';
  matched: string | null; lookups: number; record: string | null; notes: string[];
}

export type SenderCheckRequest =
  | { check: 'ip'; ip: string; role: IpRole; trust: TrustLevel }
  | { check: 'domain'; domain: string; roles: DomainRole[] }
  | { check: 'auth'; domain: string; role: 'from' | 'return_path'; reportedDmarc: string | null }
  | { check: 'spf'; domain: string; ip: string; reported: string | null; trust: TrustLevel }
  | { check: 'usercheck'; email: string; roles: EmailRole[] }
  | { check: 'ipqs'; email: string; roles: EmailRole[] };

export type SenderCheckData =
  | { check: 'ip'; value: IpLookup }
  | { check: 'domain'; value: WhoisResult }
  | { check: 'auth'; value: EmailAuth }
  | { check: 'spf'; value: SpfEvaluationView }
  | { check: 'usercheck'; value: EmailCheck }
  | { check: 'ipqs'; value: EmailReputation };

export interface SenderCheckResponse {
  request: SenderCheckRequest;
  findings: Finding[];
  checks: CheckResult[];
  data: SenderCheckData | null;
}

/* ---------------------------------------------------------------- helpers */

/** Domains whose WHOIS / DNS posture says nothing about a sender: consumer mailboxes and the large mail platforms. */
const PLATFORM_DOMAINS = new Set([
  ...FREE_MAIL, 'google.com', 'microsoft.com', 'outlook.com', 'office365.com', 'amazonses.com', 'amazon.com', 'sendgrid.net', 'sendgrid.com', 'mailchimp.com', 'mcsv.net', 'mandrillapp.com',
  'mailgun.org', 'mailgun.com', 'sparkpostmail.com', 'salesforce.com', 'exacttarget.com', 'constantcontact.com', 'hubspot.com', 'hubspotemail.net', 'zendesk.com', 'servicenow.com', 'sendinblue.com', 'brevo.com',
]);
export const isPlatformDomain = (d: string | null | undefined) => { const r = registrableOf(d); return !!r && PLATFORM_DOMAINS.has(r); };

const SHARED_PROVIDERS: [RegExp, string][] = [
  [/\bgoogle\b|gmail/i, 'Google'], [/microsoft|outlook|office ?365|protection\.outlook/i, 'Microsoft'], [/amazon|aws|\bses\b/i, 'Amazon'],
  [/sendgrid|twilio/i, 'SendGrid'], [/mailchimp|rocket science|mandrill|intuit mailchimp/i, 'Mailchimp'], [/mailgun|sinch/i, 'Mailgun'], [/sparkpost|messagebird/i, 'SparkPost'],
  [/zoho/i, 'Zoho'], [/yahoo|verizon media|oath/i, 'Yahoo'], [/proofpoint/i, 'Proofpoint'], [/mimecast/i, 'Mimecast'], [/sendinblue|brevo/i, 'Brevo'], [/postmark|wildbit/i, 'Postmark'],
  [/salesforce|exacttarget/i, 'Salesforce'], [/fastmail/i, 'Fastmail'], [/cloudflare/i, 'Cloudflare'],
];
export function sharedProviderOf(d: IpLookup): string | null {
  const hay = [d.network?.org, d.network?.isp, d.network?.domain, d.netType?.companyName, ...d.reverseDns].filter(Boolean).join(' | ');
  return SHARED_PROVIDERS.find(([re]) => re.test(hay))?.[1] ?? null;
}

const RESIDENTIAL_PTR = /(\b|[-.])(dynamic|dyn|dsl|adsl|cable|dhcp|pool|ppp|broadband|residential|customer|client|cust)(\b|[-.\d])|\b\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}\b/i;

/* ------------------------------------------------------------------ plan */

export interface SenderPlan { requests: SenderCheckRequest[]; skipped: CheckResult[] }

/** Decides which lookups this email needs. Bounded: at most 3 IPs, 4 domains, 2 auth checks, 1 SPF re-check, 2 addresses. */
export function planSenderChecks(r: ParseStageResult): SenderPlan {
  const requests: SenderCheckRequest[] = [];
  const skipped: CheckResult[] = [];
  const fx = r.forensics;

  // IPs: the connecting IP first, then clues
  const ips = r.indicators.ips.filter((i) => i.ip).slice(0, 3);
  if (!ips.length) skipped.push(check('sender.ip', 'sender', 'Sender IP intelligence', 'skipped', null, 'No sender IP could be established from the headers or the form.'));
  for (const i of ips) requests.push({ check: 'ip', ip: i.ip, role: i.role, trust: i.trust });

  // domains: registrable, de-duplicated, never consumer mailboxes or large mail platforms
  const want: DomainRole[] = ['from', 'return_path', 'reply_to', 'claimed_org'];
  const seen = new Map<string, DomainRole[]>();
  for (const d of r.indicators.domains) {
    const roles = d.roles.filter((x) => want.includes(x));
    const reg = registrableOf(d.domain);
    if (!roles.length || !reg || isPlatformDomain(reg)) continue;
    seen.set(reg, [...new Set([...(seen.get(reg) ?? []), ...roles])]);
  }
  const doms = [...seen].sort((a, b) => Number(b[1].includes('from')) - Number(a[1].includes('from'))).slice(0, 4);
  if (!doms.length) skipped.push(check('sender.domain', 'sender', 'Sender domain registration', 'not_applicable', null, 'The sender uses a consumer mailbox or large mail platform, whose registration says nothing about this message.'));
  for (const [domain, roles] of doms) requests.push({ check: 'domain', domain, roles });

  // DNS posture of the From (and Return-Path) domains
  const fromDomain = fx?.addresses.from[0]?.domain ?? null;
  const rpDomain = fx?.addresses.returnPath?.domain ?? null;
  const authTargets: { domain: string; role: 'from' | 'return_path' }[] = [];
  if (fromDomain && !isPlatformDomain(fromDomain)) authTargets.push({ domain: fromDomain, role: 'from' });
  if (rpDomain && registrableOf(rpDomain) !== registrableOf(fromDomain) && !isPlatformDomain(rpDomain)) authTargets.push({ domain: rpDomain, role: 'return_path' });
  if (!authTargets.length) skipped.push(check('sender.auth_dns', 'sender', 'Sender domain mail security (SPF / DMARC)', 'not_applicable', null, 'No sender domain to inspect, or it is a consumer mailbox / large mail platform.'));
  for (const t of authTargets) requests.push({ check: 'auth', domain: t.domain, role: t.role, reportedDmarc: fx?.authentication.dmarc?.result ?? null });

  // Independent SPF re-check of the connecting IP against the envelope domain
  const connecting = fx?.ips.find((i) => i.role === 'connecting');
  const envDomain = fx?.authentication.spf?.domain ?? rpDomain;
  if (connecting && envDomain && !isFreeMail(envDomain)) requests.push({ check: 'spf', domain: envDomain, ip: connecting.ip, reported: fx?.authentication.spf?.result ?? null, trust: fx?.authentication.spf?.trust ?? 'unverified' });
  else skipped.push(check('sender.spf_recheck', 'sender', 'Independent SPF re-check', 'skipped', null, !connecting ? 'No trusted connecting IP to test.' : 'No envelope sender domain, or it is a consumer mailbox.'));

  // Address check with UserCheck.com (the address is sent to that service)
  const addrs: { email: string; roles: EmailRole[] }[] = r.indicators.emails.filter((e) => e.roles.some((x) => x === 'from' || x === 'reply_to' || x === 'supplied')).slice(0, 2).map((e) => ({ email: e.address, roles: e.roles }));
  if (!addrs.length) skipped.push(check('sender.usercheck', 'sender', 'Sender address check (UserCheck)', 'not_applicable', null, 'No sender address available.'));
  else for (const a of addrs) requests.push({ check: 'usercheck', email: a.email, roles: a.roles });

  // Mailbox reputation with IPQualityScore (same addresses; the address is sent to that service, which probes its mail server)
  if (!addrs.length) skipped.push(check('sender.ipqs', 'sender', 'Sender mailbox reputation (IPQualityScore)', 'not_applicable', null, 'No sender address available.'));
  else for (const a of addrs) requests.push({ check: 'ipqs', email: a.email, roles: a.roles });

  return { requests, skipped };
}

/* ------------------------------------------------------------ converters */

const F = (f: Parameters<typeof makeFinding>[0]) => makeFinding({ trust: 'independently_verified', ...f });

export const labelOf = (req: SenderCheckRequest): string =>
  req.check === 'ip' ? `IP intelligence: ${req.ip}`
  : req.check === 'domain' ? `Domain registration: ${req.domain}`
  : req.check === 'auth' ? `Mail security DNS: ${req.domain}`
  : req.check === 'spf' ? `Independent SPF re-check: ${req.ip} vs ${req.domain}`
  : req.check === 'ipqs' ? `Mailbox reputation (IPQS): ${req.email}`
  : `Address check: ${req.email}`;

export const idOf = (req: SenderCheckRequest): string => `sender.${req.check}.${req.check === 'ip' ? req.ip : req.check === 'usercheck' || req.check === 'ipqs' ? req.email : req.domain}`;

export function convertIp(req: Extract<SenderCheckRequest, { check: 'ip' }>, d: IpLookup): { findings: Finding[]; check: CheckResult } {
  const exact = req.role === 'connecting';
  const base = { dimension: 'infrastructure' as const, exactness: exact ? ('exact' as const) : ('related' as const), indicator: { type: 'ip' as const, value: req.ip } };
  const f: Finding[] = [];
  const provider = sharedProviderOf(d);
  const ctx = provider ? ` ${provider} infrastructure is shared by many senders, so reputation here says little about this particular message.` : '';
  const who = `${req.ip}${d.network?.org ? ` (${d.network.org}${d.network.asn ? `, ${d.network.asn}` : ''})` : ''}`;

  if (provider && exact) f.push(F({ ...base, id: 'sender_infra_shared_provider', severity: 'info', title: `Sent through ${provider} infrastructure`, detail: `The message reached the receiver from ${who}. Large mail platforms deliver legitimate and malicious mail alike: a genuine provider does not make the message genuine, and a clean IP does not clear it.`, source: 'ip-intelligence' }));

  const a = d.reputation;
  if (a && !a.isWhitelisted && a.abuseConfidence >= 25) {
    f.push(F({ ...base, id: 'sender_ip_abuse_reports', severity: a.abuseConfidence >= 75 ? 'high' : 'medium', title: `Sender IP has abuse reports (${a.abuseConfidence}% confidence)`, detail: `AbuseIPDB lists ${who} with ${a.totalReports} report(s) from ${a.distinctReporters} reporter(s)${a.lastReportedAt ? `, last on ${a.lastReportedAt.slice(0, 10)}` : ''}.${ctx}`, source: 'AbuseIPDB', reliability: 'high' }));
  }
  const v = d.virustotal;
  if (v && v.malicious > 0) {
    f.push(F({ ...base, id: 'sender_ip_vt_detections', severity: v.malicious >= 10 ? 'high' : v.malicious >= 3 ? 'medium' : 'low', title: `${v.malicious} VirusTotal engine(s) flag the sender IP`, detail: `${v.malicious} malicious and ${v.suspicious} suspicious verdicts out of ${v.malicious + v.suspicious + v.harmless + v.undetected} engines.${ctx}`, source: 'VirusTotal', reliability: 'medium' }));
  }
  const p = d.pulsedive;
  if (p && p.observed) {
    const risk = p.risk.toLowerCase();
    if (['high', 'critical'].includes(risk) || risk === 'medium' || p.threats.length) {
      f.push(F({ ...base, id: 'sender_ip_pulsedive', severity: ['high', 'critical'].includes(risk) ? 'high' : risk === 'medium' ? 'medium' : 'low', title: `Pulsedive rates the sender IP "${p.risk}" risk`, detail: `${p.threats.length ? `Linked threats: ${p.threats.slice(0, 4).map((t) => t.name).join(', ')}. ` : ''}${p.feeds.length ? `Seen in ${p.feeds.length} feed(s).` : ''}${ctx}`.trim(), source: 'Pulsedive', reliability: 'medium' }));
    }
  }
  if (d.netType?.isTor) f.push(F({ ...base, id: 'sender_ip_tor', severity: 'medium', title: 'Sender IP is a Tor exit node', detail: 'Legitimate organisations do not send business mail from Tor.', source: 'ipapi.is', reliability: 'high' }));
  else if (d.netType?.isProxy || d.netType?.isVpn) f.push(F({ ...base, id: 'sender_ip_anonymizer', severity: 'low', title: `Sender IP belongs to a ${d.netType.isVpn ? 'VPN' : 'proxy'}${d.netType.vpnService ? ` (${d.netType.vpnService})` : ''}`, detail: 'Anonymising services hide the true origin; some legitimate users also use them.', source: 'ipapi.is' }));
  if (d.netType?.isAbuser) f.push(F({ ...base, id: 'sender_ip_known_abuser', severity: 'medium', title: 'Sender network is flagged for abuse by ipapi.is', detail: `${d.netType.companyName ?? 'The operator'} has an elevated abuser score${d.netType.companyAbuserScore ? ` (${d.netType.companyAbuserScore})` : ''}.${ctx}`, source: 'ipapi.is' }));
  if (d.exposure?.tags.some((t) => /compromised|malware/i.test(t))) f.push(F({ ...base, id: 'sender_ip_compromised', severity: 'high', title: 'Shodan tags the sender IP as compromised / malware-related', detail: `Tags: ${d.exposure.tags.join(', ')}.`, source: 'Shodan InternetDB', reliability: 'medium' }));

  if (exact && d.isPublic) {
    if (!d.reverseDns.length) f.push(F({ ...base, id: 'sender_ip_no_ptr', severity: 'low', title: 'Sender IP has no reverse DNS', detail: 'Properly run mail servers have a PTR record; its absence is common for throwaway infrastructure and compromised hosts.', source: 'DNS PTR', trust: 'independently_verified' }));
    else if (RESIDENTIAL_PTR.test(d.reverseDns[0])) f.push(F({ ...base, id: 'sender_ip_residential_ptr', severity: 'low', title: 'Sender IP looks like a dynamic / residential address', detail: `Reverse DNS is ${d.reverseDns[0]}, a naming pattern for consumer connections. Business mail normally comes from dedicated mail servers.`, source: 'DNS PTR' }));
  }

  const ok = d.providers.filter((x) => x.ok).length;
  const notOk = d.providers.filter((x) => !x.ok).map((x) => `${x.name}${x.skipped ? ' (skipped)' : ''}`);
  const rep = d.reputation ? `abuse ${d.reputation.abuseConfidence}%` : null;
  const summary = [d.network?.asn, d.network?.org, d.geo?.countryCode, rep, provider ? `${provider} infra` : null].filter(Boolean).join(' · ') || 'looked up';
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), ok ? 'complete' : 'failed', ok ? summary : null, notOk.length ? `Not available: ${notOk.join(', ')}. Missing sources are not treated as clean.` : undefined) };
}

export function convertDomain(req: Extract<SenderCheckRequest, { check: 'domain' }>, w: WhoisResult): { findings: Finding[]; check: CheckResult } {
  const exact = req.roles.includes('from');
  const base = { dimension: 'infrastructure' as const, exactness: exact ? ('exact' as const) : ('related' as const), indicator: { type: 'domain' as const, value: req.domain }, source: w.source === 'rdap' ? 'RDAP' : 'WHOIS' };
  const f: Finding[] = [];
  const roleText = req.roles.map((r) => r.replace(/_/g, ' ')).join(' / ');
  if (w.ageDays !== null && w.ageDays < 90) {
    f.push(F({ ...base, id: 'sender_domain_new', severity: w.ageDays < 7 ? 'high' : w.ageDays < 30 ? 'medium' : 'low', title: `Sender domain (${roleText}) was registered ${w.ageDays} day(s) ago`, detail: `${req.domain} is very new. Newly registered domains are over-represented in phishing, but also in legitimate new businesses and campaigns.`, reliability: 'high' }));
  }
  if (!w.registered) f.push(F({ ...base, id: 'sender_domain_unregistered', severity: exact ? 'medium' : 'low', title: `No registration record for ${req.domain}`, detail: 'The registry reports no record. The domain may not exist (a forged sender) or its TLD may not publish RDAP data.', reliability: 'low' }));
  if (w.daysToExpiry !== null && w.daysToExpiry < 0) f.push(F({ ...base, id: 'sender_domain_expired', severity: 'low', title: `${req.domain} registration has expired`, detail: 'Expired domains can be re-registered by anyone and used to impersonate the former owner.' }));
  const summary = w.registered ? `${w.ageDays !== null ? `${w.ageDays} day(s) old` : 'registered'}${w.registrar?.name ? ` · ${w.registrar.name}` : ''}` : 'no registration record';
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), 'complete', summary, w.source === 'apilayer' ? 'Data from the WHOIS fallback provider.' : undefined) };
}

export function convertAuth(req: Extract<SenderCheckRequest, { check: 'auth' }>, a: EmailAuth): { findings: Finding[]; check: CheckResult } {
  const from = req.role === 'from';
  const base = { dimension: 'authentication' as const, exactness: 'exact' as const, indicator: { type: 'domain' as const, value: req.domain }, source: 'DNS' };
  const f: Finding[] = [];
  const policy = a.dmarc.parsed?.policy ?? null;
  if (from) {
    if (!a.spf.found && !a.dmarc.found) f.push(F({ ...base, id: 'sender_domain_unprotected', severity: 'low', title: `${req.domain} publishes neither SPF nor DMARC`, detail: 'Anyone can send mail that appears to come from this domain without being rejected, so a forged message from it is easy.', reliability: 'high' }));
    else if (a.summary.spoofable) f.push(F({ ...base, id: 'sender_domain_spoofable', severity: 'low', title: `${req.domain} does not enforce DMARC`, detail: `DMARC ${a.dmarc.found ? `policy is p=${policy}` : 'is missing'}, so receivers are not told to reject forged mail from this domain.`, reliability: 'high' }));
    if (req.reportedDmarc === 'fail' && (policy === 'reject' || policy === 'quarantine')) {
      f.push(F({ ...base, id: 'dmarc_policy_not_applied', severity: 'medium', title: `DMARC failed but ${req.domain} requests p=${policy}`, detail: 'The domain asks receivers to block mail that fails DMARC, yet this message was delivered. The receiver may have overridden the policy (forwarding, an allow-list), or the supplied headers do not tell the whole story.', reliability: 'medium' }));
    }
    if (!a.hasMx && !a.spf.found) f.push(F({ ...base, id: 'sender_domain_no_mail_setup', severity: 'low', title: `${req.domain} has no mail servers and no SPF record`, detail: 'A domain that cannot receive mail or declare senders is unusual for a real correspondent; replies would go nowhere.', reliability: 'medium' }));
  }
  const summary = `SPF ${a.spf.found ? 'found' : 'missing'} · DMARC ${a.dmarc.found ? `p=${policy ?? '?'}` : 'missing'} · ${a.hasMx ? 'has MX' : 'no MX'}`;
  const dnsFail = a.providers.length > 0 && a.providers.every((p) => !p.ok);
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), dnsFail ? 'failed' : 'complete', dnsFail ? null : summary) };
}

export function convertSpf(req: Extract<SenderCheckRequest, { check: 'spf' }>, ev: SpfEvaluationView): { findings: Finding[]; check: CheckResult } {
  const base = { dimension: 'authentication' as const, exactness: 'exact' as const, indicator: { type: 'ip' as const, value: req.ip }, source: 'SPF re-check' };
  const f: Finding[] = [];
  const reported = req.reported;
  const inconclusive = ['permerror', 'temperror', 'none'].includes(ev.result);
  if (ev.result === 'pass') {
    f.push(F({ ...base, id: 'spf_independent_pass', severity: 'info', title: `${req.domain}'s SPF policy authorises ${req.ip}`, detail: `Re-checked against current DNS: matched ${ev.matched ?? 'a mechanism'}. This shows the IP may send for ${req.domain} (the envelope domain), not that the visible From address is genuine.`, reliability: 'high' }));
    if (reported && ['fail', 'softfail'].includes(reported)) f.push(F({ ...base, id: 'spf_independent_disagrees', severity: 'low', title: 'SPF re-check passes but the headers report a failure', detail: `The receiver recorded SPF "${reported}", yet current DNS authorises the IP. The record may have changed since delivery.`, reliability: 'medium' }));
  } else if (ev.result === 'fail' || ev.result === 'softfail') {
    f.push(F({ ...base, id: 'spf_independent_fail', severity: ev.result === 'fail' ? 'medium' : 'low', title: `${req.domain}'s SPF policy does not authorise ${req.ip}`, detail: `Re-checked against current DNS: ${ev.result}${ev.matched ? ` (${ev.matched})` : ''}.${reported === 'pass' ? ' The headers claim SPF passed, which contradicts this: the record may have changed, or the headers may have been altered.' : ''}`, reliability: 'high' }));
    if (reported === 'pass') f.push(F({ ...base, id: 'spf_independent_disagrees', severity: 'medium', title: 'Headers report SPF pass, but the policy does not authorise the sender IP', detail: 'Either DNS changed after delivery or the Authentication-Results header does not reflect a real check.', reliability: 'medium', trust: 'derived' }));
  }
  const summary = `${ev.result}${ev.matched ? ` via ${ev.matched}` : ''} · ${ev.lookups} DNS lookup(s)`;
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), inconclusive && ev.result !== 'none' ? 'failed' : 'complete', summary, ev.notes.join(' ') || undefined) };
}

export function convertUserCheck(req: Extract<SenderCheckRequest, { check: 'usercheck' }>, r: EmailCheck): { findings: Finding[]; check: CheckResult } {
  const exact = req.roles.includes('from') || req.roles.includes('supplied');
  const base = { dimension: 'infrastructure' as const, exactness: exact ? ('exact' as const) : ('related' as const), indicator: { type: 'email' as const, value: r.email }, source: 'UserCheck.com', reliability: 'medium' as const };
  const f: Finding[] = [];
  if (r.spam) f.push(F({ ...base, id: 'sender_address_spam_domain', severity: 'medium', title: 'The sender address domain is associated with spam or abuse', detail: `UserCheck lists ${r.domain} as associated with spam or abuse. This is evidence about the domain, which a legitimate sender could share.` }));
  if (r.disposable) f.push(F({ ...base, id: 'sender_address_disposable', severity: 'low', title: 'Sender uses a disposable address', detail: 'Throwaway mailboxes are used to avoid accountability.' }));
  if (r.mx === false) f.push(F({ ...base, id: 'sender_address_no_mx', severity: 'low', title: 'The sender address domain cannot receive mail', detail: `${r.domain} has no valid MX records, so replies to this address cannot be delivered. Real senders almost always can receive mail.` }));
  if (r.didYouMean) f.push(F({ ...base, id: 'sender_address_misspelt_domain', severity: 'medium', title: `The sender address domain looks like a misspelling of ${r.didYouMean.split('@').pop()}`, detail: 'UserCheck flags the domain as a likely typo of a well-known domain, a common lookalike trick.' }));
  if (r.freeSubdomain) f.push(F({ ...base, id: 'sender_address_free_subdomain', severity: 'low', title: 'The sender address is on a free or dynamic-DNS subdomain', detail: 'Anyone can create such a subdomain at no cost, so it carries no organisational identity.' }));
  const bits = [r.disposable ? 'disposable' : null, r.spam ? 'spam domain' : null, r.mx === false ? 'no MX' : null, r.publicDomain ? 'public mailbox provider' : null, r.relayDomain ? 'relay service' : null, r.roleAccount ? 'role account' : null].filter(Boolean);
  const summary = `${bits.length ? bits.join(' · ') : 'no flags'}${r.domainAgeDays !== null ? ` · domain ${r.domainAgeDays} day(s) old` : ''}`;
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), 'complete', summary) };
}


/** IPQS fraud score at or above which an address counts as suspicious / risky (IPQS's own guidance: 75+ suspicious, 90+ risky). */
export const IPQS_SUSPICIOUS = 75;
export const IPQS_RISKY = 90;

/**
 * IPQualityScore mailbox reputation → findings. Reputation describes the ADDRESS, and a phishing message can spoof a
 * clean one, so nothing here is strong on its own. Breach exposure (`leaked`) is shown but never scored: a large share of
 * genuine addresses have been in a breach.
 */
export function convertIpqs(req: Extract<SenderCheckRequest, { check: 'ipqs' }>, r: EmailReputation): { findings: Finding[]; check: CheckResult } {
  const exact = req.roles.includes('from') || req.roles.includes('supplied');
  const base = { dimension: 'infrastructure' as const, exactness: exact ? ('exact' as const) : ('related' as const), indicator: { type: 'email' as const, value: r.email }, source: 'IPQualityScore', reliability: 'medium' as const };
  const f: Finding[] = [];
  if (r.recentAbuse) f.push(F({ ...base, id: 'sender_address_recent_abuse', severity: 'medium', title: 'The sender address was involved in verified abuse in the past few days', detail: `IPQualityScore has seen confirmed abuse (such as fake sign-ups or chargebacks) from ${r.email} recently. It describes the address, which a phishing message may be spoofing.` }));
  if (r.fraudScore !== null && r.fraudScore >= IPQS_SUSPICIOUS) {
    const risky = r.fraudScore >= IPQS_RISKY;
    f.push(F({ ...base, id: 'sender_address_fraud_score', severity: risky ? 'medium' : 'low', title: `The sender address has a ${risky ? 'high' : 'elevated'} fraud score (${r.fraudScore}/100)`, detail: `IPQualityScore rates addresses from 0 to 100 on reputation and recent behaviour; it treats 75 and above as suspicious and 90 and above as risky.` }));
  }
  if (r.domainTrust === 'malicious' || r.domainTrust === 'suspicious') {
    const bad = r.domainTrust === 'malicious';
    f.push(F({ ...base, id: 'sender_address_domain_untrusted', severity: bad ? 'high' : 'medium', title: `IPQualityScore rates the sender's domain as ${r.domainTrust}`, detail: `${r.domain} is classed as ${r.domainTrust} by IPQualityScore's domain reputation. This is evidence about the domain, which a legitimate sender could share.` }));
  }
  if (r.valid === false && r.dnsValid !== false) f.push(F({ ...base, id: 'sender_address_mailbox_missing', severity: 'low', title: 'The sender mailbox does not exist', detail: `The mail server for ${r.domain} reports that ${r.email} is not a real mailbox, so replies would bounce. Phishing often uses invented or spoofed addresses that cannot receive mail.` }));
  if (r.disposable) f.push(F({ ...base, id: 'sender_address_disposable', severity: 'low', title: 'Sender uses a disposable address', detail: 'Throwaway mailboxes are used to avoid accountability.' }));
  if (r.dnsValid === false) f.push(F({ ...base, id: 'sender_address_no_mx', severity: 'low', title: 'The sender address domain cannot receive mail', detail: `${r.domain} has no valid mail DNS records, so replies to this address cannot be delivered. Real senders almost always can receive mail.` }));
  if (r.suggestedDomain && r.suggestedDomain.toLowerCase() !== r.domain) f.push(F({ ...base, id: 'sender_address_misspelt_domain', severity: 'medium', title: `The sender address domain looks like a misspelling of ${r.suggestedDomain}`, detail: 'IPQualityScore flags the domain as a likely typo of a well-known domain, a common lookalike trick.' }));
  if (r.riskyTld) f.push(F({ ...base, id: 'sender_address_risky_tld', severity: 'low', title: 'The sender address uses a top-level domain often tied to abuse', detail: `IPQualityScore marks the TLD of ${r.domain} as frequently used for scams, malware or phishing. Many genuine sites use it too.` }));

  const validity = r.valid === true ? 'mailbox exists' : r.valid === false ? 'mailbox not found' : r.timedOut ? 'mail server timed out' : 'mailbox unconfirmed';
  const bits = [r.recentAbuse ? 'recent abuse' : null, r.disposable ? 'disposable' : null, r.honeypot ? 'spam trap' : null, r.leaked ? 'in a breach' : null, r.domainTrust && r.domainTrust !== 'not rated' ? `domain ${r.domainTrust}` : null].filter(Boolean);
  const summary = `${r.fraudScore !== null ? `fraud score ${r.fraudScore}` : 'no fraud score'} · ${validity}${bits.length ? ` · ${bits.join(' · ')}` : ''}`;
  return { findings: f, check: check(idOf(req), 'sender', labelOf(req), 'complete', summary) };
}
