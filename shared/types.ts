/** Wire types shared by the Pages Functions (producers) and the React app (consumers). */
import type { Issue } from './emailAuth';
import type { HeaderAudit, CookieInfo } from './security';
import type { IPScope } from './ip';

export type { Issue };

export interface ApiMeta { ts: string; cached?: boolean }
export type ApiResponse<T> =
  | { ok: true; data: T; meta: ApiMeta }
  | { ok: false; error: { code: string; message: string } };

export interface ProviderStatus { name: string; ok: boolean; ms: number; error?: string; skipped?: boolean }

/* ------------------------------------------------------------------- IP */
export interface IpLookup {
  ip: string;
  version: 4 | 6;
  scope: IPScope;
  scopeLabel: string;
  isPublic: boolean;
  ptrName: string;
  geo: { country: string | null; countryCode: string | null; region: string | null; city: string | null; postal: string | null; latitude: number | null; longitude: number | null; timezone: string | null } | null;
  network: { asn: string | null; org: string | null; isp: string | null; domain: string | null; prefix: string | null } | null;
  /** Network-type signals from ipapi.is (null when ipapi.is was unavailable and a fallback geo provider was used). */
  netType: {
    isVpn: boolean; isProxy: boolean; isTor: boolean; isDatacenter: boolean; isMobile: boolean; isCrawler: boolean; isAbuser: boolean;
    companyName: string | null; companyType: string | null; companyAbuserScore: string | null; asnAbuserScore: string | null;
    datacenter: string | null; vpnService: string | null;
  } | null;
  /** Which provider supplied the location/network fields. */
  geoSource: 'ipapi.is' | 'ipwho.is' | 'ipapi.co' | null;
  reverseDns: string[];
  exposure: { ports: number[]; hostnames: string[]; vulns: string[]; tags: string[]; cpes: string[] } | null;
  reputation: { abuseConfidence: number; totalReports: number; distinctReporters: number; lastReportedAt: string | null; usageType: string | null; isTor: boolean; isWhitelisted: boolean } | null;
  pulsedive: {
    risk: string; riskRecommended: string | null; observed: boolean; lastSeen: string | null; lastUpdated: string | null; link: string;
    threats: { name: string; category: string | null; risk: string | null }[];
    feeds: { name: string; category: string | null; organization: string | null }[];
    riskFactors: { description: string; risk: string | null }[];
  } | null;
  virustotal: { malicious: number; suspicious: number; harmless: number; undetected: number; reputation: number | null; votesMalicious: number; votesHarmless: number; asOwner: string | null; lastAnalysis: string | null; link: string; observed: boolean } | null;
  flags: string[];
  providers: ProviderStatus[];
}

/* ------------------------------------------------------------------ DNS */
export interface DnsRecordOut { name: string; type: string; ttl: number; data: string }
export interface DnsLookup {
  name: string;
  resolver: string;
  /** per record type */
  results: { type: string; status: string; authenticated: boolean; records: DnsRecordOut[] }[];
  providers: ProviderStatus[];
}
export interface DnsPropagation {
  name: string;
  type: string;
  consistent: boolean;
  resolvers: { resolver: string; status: string; ms: number; authenticated: boolean; records: DnsRecordOut[]; error?: string }[];
  note: string;
}

/* --------------------------------------------------------------- Domain */
export interface WhoisResult {
  domain: string;
  registered: boolean;
  registrar: { name: string | null; ianaId: string | null; url: string | null; abuseEmail: string | null; abusePhone: string | null } | null;
  registrant: { name: string | null; organization: string | null; country: string | null; redacted: boolean } | null;
  dates: { registered: string | null; updated: string | null; expires: string | null };
  ageDays: number | null;
  daysToExpiry: number | null;
  status: string[];
  nameservers: string[];
  dnssecSigned: boolean | null;
  rdapUrl: string | null;
  issues: Issue[];
}

export interface CertEntry {
  id: number | string;
  commonName: string;
  names: string[];
  issuer: string;
  notBefore: string;
  notAfter: string;
  serial: string;
  loggedAt: string | null;
  validNow: boolean;
  daysRemaining: number;
}
export interface CertResult {
  domain: string;
  /** Which Certificate Transparency provider answered: ctlogs.dev (primary) or crt.sh (fallback). */
  source: 'ctlogs.dev' | 'crt.sh';
  total: number;
  active: number;
  certificates: CertEntry[];
  issuers: { issuer: string; count: number }[];
  subdomains: string[] | null;
  wildcard: boolean;
  note: string;
  issues: Issue[];
}

export interface HttpCheck {
  target: string;
  finalUrl: string;
  status: number;
  httpsReachable: boolean;
  httpUpgradesToHttps: boolean | null;
  chain: { url: string; status: number; location: string | null; ttfbMs: number; ip: string | null }[];
  totalMs: number;
  server: { header: string; value: string }[];
  contentType: string | null;
  audit: HeaderAudit;
  cookies: CookieInfo[];
  addresses: string[];
  issues: Issue[];
}

/* ---------------------------------------------------------------- Email */
export interface EmailAuth {
  domain: string;
  hasMx: boolean;
  mx: { priority: number; host: string }[];
  spf: { found: boolean; records: number; parsed: import('./emailAuth').SpfAnalysis | null; totalLookups: number | null; issues: Issue[] };
  dmarc: { found: boolean; foundAt: string | null; parsed: import('./emailAuth').DmarcAnalysis | null; issues: Issue[] };
  dkim: { selector: string; found: boolean; parsed: import('./emailAuth').DkimAnalysis | null }[];
  mtaSts: { found: boolean; record: string | null };
  summary: import('./emailAuth').AuthSummary;
  providers: ProviderStatus[];
}

/* -------------------------------------------------------------- Network */
export interface LatencySample { ok: boolean; status?: number; ttfbMs?: number; totalMs?: number; error?: string }
export interface LatencyResult {
  target: string;
  address: string | null;
  samples: LatencySample[];
  stats: { min: number; avg: number; max: number; jitter: number; successRate: number } | null;
  vantage: { colo: string | null; country: string | null; note: string };
}
