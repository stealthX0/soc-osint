export interface Env {
  /** Static assets binding (the built React app in dist/). Configured under [assets] in wrangler.toml. */
  ASSETS: Fetcher;
  /** Optional KV namespace for cross-isolate rate limiting. Falls back to per-isolate memory. */
  RATE_LIMIT?: KVNamespace;
  /** Requests allowed per client per minute (cost-weighted). Default 60. */
  RATE_LIMIT_PER_MIN?: string;
  /** Comma-separated list of extra origins allowed to call the API (CORS). Same-origin is always allowed. */
  ALLOWED_ORIGINS?: string;
  /** Optional provider keys. Every provider degrades gracefully when its key is absent. */
  ABUSEIPDB_API_KEY?: string;
  /** ipapi.is API key (optional): the primary IP provider works without one, a key gives a higher quota. https://ipapi.is */
  IPAPI_IS_API_KEY?: string;
  /** Pulsedive API key: threat-intel risk rating, linked threats and feeds for the IP. https://pulsedive.com */
  PULSEDIVE_API_KEY?: string;
  /** ctlogs.dev API key (optional): primary Certificate Transparency source. Works keyless with a small shared quota; a free key from https://account.ctlogs.dev raises it. */
  CTLOGS_API_KEY?: string;
  /** VirusTotal API key (free tier: ~4 req/min, 500/day): multi-engine verdicts for the IP. */
  VIRUSTOTAL_API_KEY?: string;
  /** Hybrid Analysis API key (free, https://www.hybrid-analysis.com): sandbox verdict for a SHA-256. */
  HYBRID_ANALYSIS_API_KEY?: string;
  /** URL intelligence sources (all optional) */
  /** abuse.ch Auth-Key (free, https://auth.abuse.ch): one key serves URLhaus (URL Intelligence) and MalwareBazaar (File Analysis). */
  ABUSECH_AUTH_KEY?: string;
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  /** Optional overrides for the global per-provider quota budgets (see takeProviderBudget). Defaults match free tiers. */
  VIRUSTOTAL_RPM?: string;
  VIRUSTOTAL_DAILY?: string;
  ABUSEIPDB_DAILY?: string;
  PULSEDIVE_RPM?: string;
  PULSEDIVE_DAILY?: string;
  HYBRIDANALYSIS_RPM?: string;
  HYBRIDANALYSIS_DAILY?: string;
  SAFEBROWSING_DAILY?: string;
  URLSCAN_RPM?: string;
}

/** Minimal request context handed to every route handler and to the middleware. */
export interface Ctx {
  request: Request;
  env: Env;
  waitUntil(p: Promise<unknown>): void;
  /** In the middleware: runs the matched route (or, for non-API paths, the static asset). */
  next(): Promise<Response>;
}

export type Handler = (ctx: Ctx) => Promise<Response> | Response;
