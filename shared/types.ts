/** Wire types shared by the Worker API (producers) and the React app (consumers). */
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

/* ----------------------------------------------------------------- File */
export interface FileReputation {
  hash: string;
  algo: 'md5' | 'sha1' | 'sha256';
  /** Best-known SHA-256 (the input itself, or taken from VirusTotal when an MD5/SHA-1 was given). */
  sha256: string | null;
  virustotal: {
    observed: boolean; malicious: number; suspicious: number; harmless: number; undetected: number;
    typeDescription: string | null; meaningfulName: string | null; names: string[]; size: number | null;
    md5: string | null; sha1: string | null; sha256: string | null; reputation: number | null; tags: string[];
    threatLabel: string | null; threatNames: string[]; threatCategories: string[];
    firstSeen: string | null; lastAnalysis: string | null; timesSubmitted: number | null; link: string;
  } | null;
  malwarebazaar: {
    observed: boolean; fileName: string | null; fileType: string | null; signature: string | null; tags: string[];
    firstSeen: string | null; reporter: string | null; deliveryMethod: string | null; originCountry: string | null; clamav: string[]; link: string;
  } | null;
  circl: { known: boolean; fileName: string | null; fileSize: number | null; trust: number | null; sources: string[]; knownMalicious: string | null } | null;
  hybrid: { observed: boolean; verdict: string | null; threatScore: number | null; avDetect: number | null; family: string | null; fileType: string | null; link: string } | null;
  flags: string[];
  providers: ProviderStatus[];
}

export interface FileUploadResult { analysisId: string; sha256: string; size: number; link: string }

export interface FileAnalysisReport {
  id: string;
  status: 'queued' | 'in-progress' | 'completed';
  sha256: string | null;
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number; total: number } | null;
  detections: { engine: string; category: string; result: string | null }[];
  link: string | null;
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
  /** Where the record came from: RDAP (registry data), or the APILayer WHOIS fallback for TLDs without RDAP. */
  source: 'rdap' | 'apilayer';
  registrar: { name: string | null; ianaId: string | null; url: string | null; abuseEmail: string | null; abusePhone: string | null } | null;
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

/* ------------------------------------------------------------------ URL */
export type UrlSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type UrlVerdict = 'malicious' | 'suspicious' | 'no_detections' | 'unknown';

/** One finding. `source` is 'heuristic' for local checks, otherwise the provider that reported it. */
export interface UrlSignal {
  id: string;
  severity: UrlSeverity;
  source: string;
  title: string;
  detail?: string;
  /** true when an authoritative source confirms the exact URL (enough on its own for a "malicious" verdict) */
  confirmed?: boolean;
  link?: string;
}

export interface UrlTraceHop { url: string; status: number | null; location: string | null; ip: string | null; ms: number; contentType: string | null; download: boolean; error?: string }

export interface UrlLookup {
  input: string;
  url: string;
  lookupUrl: string;
  parts: {
    scheme: string; host: string; hostUnicode: string; isIp: boolean; ipObfuscated: boolean; port: number | null;
    path: string; query: string; hasUserinfo: boolean; registrableDomain: string | null; tld: string | null; platform: string | null;
  };
  verdict: UrlVerdict;
  /** 0-100 risk score (informational; the verdict is decided by the rules in shared/url.ts) */
  score: number;
  confidence: 'high' | 'medium' | 'low';
  summary: string;
  /** intelligence sources that returned a usable verdict for this URL (not merely a response) */
  checked: number;
  attempted: number;
  signals: UrlSignal[];
  intel: {
    urlhaus: { listed: boolean; status: string | null; threat: string | null; tags: string[]; dateAdded: string | null; reference: string | null; host: { listed: boolean; urlCount: number; online: number; blacklists: Record<string, string> } } | null;
    safeBrowsing: { matches: { threatType: string; platformType: string }[] } | null;
    cloudflareDns: { blocked: boolean | null; note: string } | null;
    virustotal: { found: boolean; malicious: number; suspicious: number; harmless: number; undetected: number; engines: string[]; lastAnalysis: string | null; categories: string[]; link: string | null } | null;
    pulsedive: { observed: boolean; risk: string | null; threats: string[]; feeds: string[]; link: string | null } | null;
    urlscan: { scans: number; exactMatches: number; latest: { date: string | null; url: string | null; country: string | null; malicious: boolean | null; score: number | null; categories: string[]; brands: string[]; resultUrl: string | null } | null } | null;
  };
  domain: { name: string; ageDays: number | null; registered: string | null; registrar: string | null; resolves: boolean | null; addresses: string[] } | null;
  trace: { performed: boolean; hops: UrlTraceHop[]; finalUrl: string | null; error?: string } | null;
  providers: ProviderStatus[];
}

/* -------------------------------------------------- Email address reputation */
/** Reputation of one e-mail ADDRESS (EmailRep.io). Address-level evidence, not message-level. */
export interface EmailReputation {
  email: string;
  reputation: 'none' | 'low' | 'medium' | 'high' | null;
  suspicious: boolean;
  /** How many places on the internet reference the address (more = more established). */
  references: number;
  details: {
    blacklisted: boolean; maliciousActivity: boolean; maliciousActivityRecent: boolean;
    credentialsLeaked: boolean; dataBreach: boolean; spam: boolean;
    freeProvider: boolean; disposable: boolean; deliverable: boolean | null; validMx: boolean | null;
    spoofable: boolean | null; dmarcEnforced: boolean | null; suspiciousTld: boolean; newDomain: boolean;
    daysSinceDomainCreation: number | null; firstSeen: string | null; lastSeen: string | null; profiles: string[];
  };
  providers: ProviderStatus[];
}
