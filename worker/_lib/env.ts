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
  /** IPinfo Lite token (free): reliable ASN + country. https://ipinfo.io/lite */
  IPINFO_TOKEN?: string;
  /** GreyNoise Community API key (free): is this IP internet background noise / a known benign service? */
  GREYNOISE_API_KEY?: string;
  /** VirusTotal API key (free tier: ~4 req/min, 500/day): multi-engine verdicts for the IP. */
  VIRUSTOTAL_API_KEY?: string;
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
