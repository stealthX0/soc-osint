import type { IpLookup } from '../../shared/types';

/** An IP lookup with every provider answering and nothing found, for tests to override. */
export const ipLookup = (over: Partial<IpLookup> = {}): IpLookup => ({
  ip: '203.0.113.45', version: 4, scope: 'public' as never, scopeLabel: 'Public', isPublic: true, ptrName: '45.113.0.203.in-addr.arpa',
  geo: { country: 'Netherlands', countryCode: 'NL', region: 'North Holland', city: 'Amsterdam', postal: null, latitude: null, longitude: null, timezone: null },
  network: { asn: 'AS64500', org: 'Example Hosting BV', isp: 'Example Hosting BV', domain: 'hosting.example', prefix: '203.0.113.0/24' },
  netType: { isVpn: false, isProxy: false, isTor: false, isDatacenter: true, isMobile: false, isCrawler: false, isAbuser: false, companyName: 'Example Hosting BV', companyType: 'hosting', companyAbuserScore: '0.002', asnAbuserScore: null, datacenter: null, vpnService: null },
  geoSource: 'ipapi.is', reverseDns: ['mail-gw.paypa1-secure.example'], exposure: null,
  reputation: { abuseConfidence: 0, totalReports: 0, distinctReporters: 0, lastReportedAt: null, usageType: 'Data Center/Web Hosting/Transit', isTor: false, isWhitelisted: false },
  pulsedive: { risk: 'none', riskRecommended: null, observed: false, lastSeen: null, lastUpdated: null, link: '', threats: [], feeds: [], riskFactors: [] },
  virustotal: { malicious: 0, suspicious: 0, harmless: 60, undetected: 30, reputation: 0, votesMalicious: 0, votesHarmless: 0, asOwner: null, lastAnalysis: null, link: '', observed: true },
  flags: [], providers: [{ name: 'AbuseIPDB', ok: true, ms: 120 }, { name: 'VirusTotal', ok: true, ms: 200 }],
  ...over,
});
