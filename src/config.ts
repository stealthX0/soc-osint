export const SITE_NAME = 'Spectrix';
export const TAGLINE = 'Network Intelligence & CyberSec Toolkit';

export interface NavItem { to: string; label: string; icon: string; blurb: string; group: 'tools' | 'library' }

export const NAV: NavItem[] = [
  { to: '/ip', label: 'IP Intelligence', icon: 'globe', blurb: 'Geolocation, ASN, exposure and reputation', group: 'tools' },
  { to: '/dns', label: 'DNS Intelligence', icon: 'network', blurb: 'A, AAAA, MX, TXT, NS lookups and propagation', group: 'tools' },
  { to: '/domain', label: 'Domain Intelligence', icon: 'domain', blurb: 'WHOIS/RDAP, certificates and HTTP security', group: 'tools' },
  { to: '/url', label: 'URL Intelligence', icon: 'shield', blurb: 'Malicious URL, phishing and redirect analysis', group: 'tools' },
  { to: '/email', label: 'Email Intelligence', icon: 'mail', blurb: 'SPF, DKIM, DMARC and header analysis', group: 'tools' },
  { to: '/phishing', label: 'Phishing Investigation', icon: 'eye', blurb: 'Headers, authentication, links and attachments of a suspicious email', group: 'tools' },
  { to: '/file', label: 'File Analysis', icon: 'file', blurb: 'Local static triage and hash reputation (VirusTotal, MalwareBazaar)', group: 'tools' },
  { to: '/network', label: 'Network Diagnostics', icon: 'pulse', blurb: 'HTTP latency and subnet calculator', group: 'tools' },
  { to: '/utilities', label: 'Utilities', icon: 'wrench', blurb: 'IP conversion, range to CIDR, defang', group: 'tools' },
  { to: '/playbooks', label: 'Playbooks', icon: 'list', blurb: 'Step-by-step investigation routes', group: 'library' },
  { to: '/resources', label: 'Resource Directory', icon: 'library', blurb: 'Curated OSINT tools and references', group: 'library' },
];
