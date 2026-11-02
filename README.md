# ThreatLens: network intelligence & cybersecurity toolkit

A free, account-less web app that merges several public data sources into readable reports for **IP**, **DNS**,
**domain**, **e-mail authentication** and **network diagnostics**, plus a curated **resource directory** of
452 OSINT tools and 8 investigation playbooks (converted from the original single-file SOC dashboard).

```
 Browser (React + TypeScript + Tailwind, static, code-split)
     │  HTTPS  /api/*
     ▼
 Cloudflare Worker (static assets + API)  ── middleware: CORS, rate limit (cost-weighted), security headers, error envelope
     │   worker/index.ts → routes.ts → worker/api/{ip,dns,domain,email,network,util}/*.ts   (each wrapped in route())
     │   worker/_lib: doh, safeFetch (SSRF guard), cache, ratelimit, spf
     ▼
 External providers: Cloudflare/Google/Quad9 DoH · ipapi.is (primary; ipwho.is / ipapi.co fallbacks) · RIPEstat · Shodan InternetDB ·
                     Pulsedive + AbuseIPDB (optional keys) · RDAP (rdap.org) · crt.sh (Certificate Transparency)
```

## Layout

| Path | Purpose |
|---|---|
| `src/` | React app: `pages/` (one per tool), `components/`, `lib/` (router, API client, search, storage), `data/` (generated JSON) |
| `worker/` | Worker API. `index.ts` is the entry, `routes.ts` the route table, `_lib/` shared infrastructure, `api/<module>/<endpoint>.ts` the routes |
| `shared/` | Pure TypeScript used by **both** sides: IP/CIDR math, domain parsing, SPF/DKIM/DMARC linting, header analysis, wire types |
| `scripts/extract-data.mjs` | One-off converter from the legacy dashboard HTML to `src/data/*.json` |
| `tests/` | `node:test` suites (run through `tsx`): shared libs, SSRF guard, every endpoint with mocked providers, middleware, search |

## Develop

```bash
npm install
npm run build          # type-check (app + worker) and build to dist/
npm run dev:api        # terminal 1: Worker + static files on :8788 (copy .dev.vars.example to .dev.vars)
npm run dev            # terminal 2: Vite on :5173, proxies /api to :8788
npm test
```

## Deploy (Cloudflare Workers)

```bash
npx wrangler login
npm run deploy                                       # typecheck + vite build + wrangler deploy
npx wrangler secret put IPAPI_IS_API_KEY             # optional: ipapi.is key (primary IP provider works without one; a key raises the quota)
npx wrangler secret put PULSEDIVE_API_KEY             # optional: Pulsedive, threat-intel risk rating, linked threats and feeds
npx wrangler secret put ABUSEIPDB_API_KEY            # optional: abuse confidence score
npx wrangler secret put VIRUSTOTAL_API_KEY           # optional: VirusTotal (free, ~4 req/min), multi-engine verdicts
```

Or use Workers Builds (dashboard → Workers & Pages → Create → Import a repository): build command `npm run build`,
deploy command `npx wrangler deploy`.
Static files in `dist/` are served by the Workers static-assets binding; the Worker only runs for `/api/*`.
Optional hardening: create a KV namespace, uncomment the `[[kv_namespaces]]` block in `wrangler.toml` for
cross-isolate rate limits, and add a Cloudflare WAF rate-limiting rule for hard guarantees.
Note: the edge cache (Cache API) only stores entries on a custom domain, not on `*.workers.dev`.

## API

All endpoints return `{ ok: true, data, meta }` or `{ ok: false, error: { code, message } }`.

| Endpoint | Notes |
|---|---|
| `GET /api/ip/lookup?q=` | geo + ASN + VPN/proxy/Tor/datacenter flags (ipapi.is primary; ipwho.is then ipapi.co only as fallbacks), announced prefix (RIPEstat), Shodan InternetDB exposure, PTR, Pulsedive and AbuseIPDB (if keyed). Omit `q` for the caller's IP. Private ranges never leave the server |
| `GET /api/dns/lookup?name=&type=&resolver=` | `type` = ALL or a record type; an IP is converted to a PTR query |
| `GET /api/dns/propagation?name=&type=` | compares Cloudflare, Google and Quad9 |
| `GET /api/domain/whois?domain=` | RDAP (structured WHOIS successor) |
| `GET /api/domain/ssl?domain=&subdomains=1` | Certificate Transparency history via crt.sh |
| `GET /api/domain/http?target=` | **active**: redirect chain, security-header grade, cookies, HTTP→HTTPS check |
| `GET /api/email/auth?domain=&selectors=` | SPF (recursive lookup count), DKIM probe, DMARC (with parent fallback), MX, MTA-STS, grade |
| `POST /api/email/headers` | `{ "headers": "..." }`: hop trace, auth results, spoofing findings. Nothing stored |
| `GET /api/network/latency?target=&samples=` | **active**: HTTP time-to-first-byte from the Cloudflare edge |
| `GET /api/network/subnet?cidr=&contains=` | IPv4/IPv6 subnet calculator |
| `GET /api/util/ip-convert?value=` · `GET /api/util/ip-range?start=&end=` | notation conversion · range → minimal CIDR set |

## Security model

* **SSRF:** every outbound request to a user-supplied host goes through `worker/_lib/safeFetch.ts`: http/https only, ports 80/443/8080/8443,
  no credentials, all resolved addresses must be globally routable (RFC1918, loopback, link-local/cloud-metadata, CGNAT, multicast, reserved, IPv4-mapped IPv6 all blocked),
  redirects followed manually with each hop re-validated, size/time/redirect caps. Residual risk: DNS rebinding between check and connect; Workers cannot reach private networks, which bounds impact.
* **Passive vs active:** DNS, RDAP, CT, IP and e-mail lookups never contact the target. `/domain/http` and `/network/latency` do, and the UI says so.
* **Rate limiting:** cost-weighted per client (probes cost more). Without a KV binding it is per-isolate (best effort).
* **Secrets:** provider keys live only in Worker secrets; each key is sent only to its own provider. ipapi.is takes its key as a `key` query parameter, Pulsedive a `key` query parameter; request shapes follow the providers' public docs but have not been exercised live.
* **Privacy:** no accounts, no analytics. Recent lookups and playbook progress live in `localStorage` only.

## Known limitations (by design of the platform)

* Workers cannot do ICMP ping, traceroute, raw TCP port scans or live TLS handshakes, so latency is HTTP TTFB and certificate data comes from Certificate Transparency logs, not the live server.
* DNS "propagation" compares three public anycast resolvers, not geographically distributed probes.
* DKIM selectors cannot be enumerated from DNS; common ones are probed and you can add your own.
* Free upstream providers have quotas; results are cached at the edge and provider failures are reported per source instead of hidden.

## Regenerating the resource data

```bash
node scripts/extract-data.mjs path/to/osint_soc_dashboard.html
```
