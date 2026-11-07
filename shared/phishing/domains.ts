/** Domain helpers for the phishing modules. Pure, runtime-agnostic. */
import { normalizeHostname } from '../domain';
import { parseTargetUrl } from '../url';

/** Public-suffix-aware registrable domain of a host ("mail.example.co.uk" -> "example.co.uk"). Null for IPs and junk. */
export function registrableOf(host: string | null | undefined): string | null {
  if (!host) return null;
  const h = normalizeHostname(host);
  if (!h) return null;
  const r = parseTargetUrl(`http://${h}`);
  return r.ok ? (r.value.registrableDomain ?? h) : h;
}

export function sameOrg(a: string | null | undefined, b: string | null | undefined): boolean {
  const x = registrableOf(a);
  const y = registrableOf(b);
  return !!x && !!y && x === y;
}

/** Consumer mailbox providers: a Reply-To / From here says nothing about the organisation a message claims to be from. */
export const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com',
  'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru', 'zoho.com', 'tutanota.com', 'tuta.io', 'fastmail.com',
]);
export const isFreeMail = (domain: string | null | undefined): boolean => {
  const r = registrableOf(domain);
  return !!r && FREE_MAIL.has(r);
};

/** Mail gateways / security relays that sit in front of a mailbox: the IP they report is theirs, not the true sender's. */
export const GATEWAY_ORGS = new Set([
  'pphosted.com', 'proofpoint.com', 'ppe-hosted.com', 'mimecast.com', 'mimecast-offshore.com', 'messagelabs.com', 'symanteccloud.com', 'barracudanetworks.com',
  'cudasvc.com', 'iphmx.com', 'sophos.com', 'trendmicro.com', 'trendmicro.eu', 'forcepoint.net', 'mailcontrol.com', 'fireeyecloud.com', 'agari.com', 'hornetsecurity.com',
  'antispamcloud.com', 'spamh.com', 'mailguard.com.au', 'cloudfilter.net',
]);
