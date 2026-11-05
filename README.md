# Spectrix: network intelligence & cybersecurity toolkit

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
 External providers: Cloudflare/Google DoH · ipapi.is (primary; ipwho.is / ipapi.co fallbacks) · RIPEstat · Shodan InternetDB ·
                     Pulsedive + AbuseIPDB (optional keys) · RDAP (rdap.org) · ctlogs.dev (Certificate Transparency, primary) with crt.sh as fallback
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
npx wrangler secret put CTLOGS_API_KEY               # optional: ctlogs.dev, primary Certificate Transparency source (free key: account.ctlogs.dev)
npx wrangler secret put VIRUSTOTAL_API_KEY           # optional: VirusTotal (free, ~4 req/min), multi-engine verdicts (IPs, URLs, file hashes and file upload scans)
npx wrangler secret put HYBRID_ANALYSIS_API_KEY      # optional: File Analysis, Hybrid Analysis sandbox verdict (needs a SHA-256)
npx wrangler secret put ABUSECH_AUTH_KEY             # optional: URLhaus (URL Intelligence) and MalwareBazaar (File Analysis), one free abuse.ch Auth-Key: auth.abuse.ch
npx wrangler secret put GOOGLE_SAFE_BROWSING_API_KEY # optional: URL Intelligence, Google Safe Browsing (free for non-commercial use)
npx wrangler secret put URLSCAN_API_KEY              # optional: URL Intelligence, urlscan.io (search works without a key at a lower rate limit)
```

Or use Workers Builds (dashboard → Workers & Pages → Create → Import a repository): build command `npm run build`,
deploy command `npx wrangler deploy`.
Static files in `dist/` are served by the Workers static-assets binding; the Worker only runs for `/api/*`.
Recommended hardening: run `npm run setup:kv` once (creates the `RATE_LIMIT` KV namespace and enables the binding in
`wrangler.toml`), redeploy, and add a Cloudflare WAF rate-limiting rule on `/api/*` for hard guarantees.
Without KV, rate limits and provider budgets are per-isolate (best effort).
Note: the edge cache (Cache API) only stores entries on a custom domain, not on `*.workers.dev`.

## API

All endpoints return `{ ok: true, data, meta }` or `{ ok: false, error: { code, message } }`.

| Endpoint | Notes |
|---|---|
| `GET /api/ip/lookup?q=` | geo + ASN + VPN/proxy/Tor/datacenter flags (ipapi.is primary; ipwho.is then ipapi.co only as fallbacks), announced prefix (RIPEstat), Shodan InternetDB exposure, PTR, Pulsedive and AbuseIPDB (if keyed). Omit `q` for the caller's IP. Private ranges never leave the server |
| `GET /api/dns/lookup?name=&type=&resolver=` | `type` = ALL or a record type; an IP is converted to a PTR query |
| `GET /api/dns/propagation?name=&type=` | compares Cloudflare and Google |
| `GET /api/url/lookup?q=&trace=0\|1` | Malicious-URL analysis: URLhaus, Google Safe Browsing, VirusTotal, Pulsedive, urlscan.io, Cloudflare Security DNS, RDAP domain age and offline heuristics (homograph/IDN, brand impersonation, `@` tricks, obfuscated IPs, risky file types). `trace=1` follows redirects and checks the final destination too. Returns a verdict, findings with sources, and per-source evidence |
| `GET /api/domain/whois?domain=` | RDAP (structured WHOIS successor) |
| `GET /api/domain/ssl?domain=&subdomains=1` | Certificate Transparency history via ctlogs.dev (optional `CTLOGS_API_KEY`), falling back to crt.sh if ctlogs.dev errors, times out or is rate limited. The response says which one answered |
| `GET /api/domain/http?target=` | **active**: redirect chain, security-header grade, cookies, HTTP→HTTPS check |
| `GET /api/email/auth?domain=&selectors=` | SPF (recursive lookup count), DKIM probe, DMARC (with parent fallback), MX, MTA-STS, grade |
| `POST /api/email/headers` | `{ "headers": "..." }`: hop trace, auth results, spoofing findings. Nothing stored |
| `GET /api/network/latency?target=&samples=` | **active**: HTTP time-to-first-byte from the Cloudflare edge |
| `GET /api/network/subnet?cidr=&contains=` | IPv4/IPv6 subnet calculator |
| `GET /api/file/hash?hash=` | File reputation by MD5/SHA-1/SHA-256 only (no file content): VirusTotal, MalwareBazaar, CIRCL hashlookup (keyless, known files), Hybrid Analysis (SHA-256) |
| `POST /api/file/upload?confirm=1&name=` | Raw file body (max 32 MB) forwarded to VirusTotal for scanning. Requires `confirm=1` (the UI shows a privacy warning and a checkbox); nothing is stored. Returns an analysis id |
| `GET /api/file/analysis?id=` | Polls a VirusTotal scan started by the upload endpoint (the UI backs off to spare the shared 4/min quota) |
| `GET /api/util/ip-convert?value=` · `GET /api/util/ip-range?start=&end=` | notation conversion · range → minimal CIDR set |

## File analysis

The **File Analysis** page inspects a file entirely in the browser (`shared/fileAnalysis.ts`): MD5/SHA-1/SHA-256, magic-byte type vs extension, double extensions and RTL-override names, entropy, PE headers/sections/imports, ZIP/Office macros, PDF auto-actions, RTF objects, script patterns and extracted strings. This is triage, not a verdict. Only the hash is sent to the Worker for reputation lookups; the file is uploaded only if the visitor ticks the consent box, and only to VirusTotal.
## URL Intelligence: how results are decided

* **Only external evidence can make a URL "malicious".** A URLhaus listing, a Google Safe Browsing match, five or more VirusTotal engines, or two independent sources at "high" give a *malicious* verdict. Local heuristics (look-alike domains, brand names on foreign domains, deceptive `@`, raw/obfuscated IPs, executable downloads, young domains) can at most make a URL *suspicious*.
* **A clean result is "no detections", never "safe".** The report states how many sources actually checked the URL. VirusTotal's "never scanned", Pulsedive's "unknown" and urlscan's "no prior scans" are *not* counted as checks, because they say nothing about the URL. With no usable source the verdict is "not assessed".
* **Single detections are not verdicts.** One VirusTotal engine is a medium finding; a young domain alone is suspicious, not malicious. Shared hosting platforms (`pages.dev`, `github.io` ...) are never judged by their parent domain's age or reputation.
* **Cloudflare Security DNS** counts as a block only when the filtered resolver (1.1.1.2) answers `0.0.0.0` while the unfiltered one returns real addresses; if both are sinkholed it is ignored.
* **Active trace is opt-in.** Visiting a suspect link can tell the sender that a specific recipient opened it, and sites may cloak from scanners, so the trace is off by default, refuses private addresses at every hop, never reads response bodies, and checks the *destination* with the same sources.
* **Privacy.** The full URL (minus `#fragment` and any username/password) is sent to the providers you enabled. Private/internal hosts and IPs are analysed locally and never leave the Worker. Do not submit links containing private tokens.
* Provider quota budgets (VirusTotal, Pulsedive, urlscan, Safe Browsing) are shared with the IP lookup; see the quota notes below.

## Security model

* **SSRF:** every outbound request to a user-supplied host goes through `worker/_lib/safeFetch.ts`: http/https only, ports 80/443/8080/8443,
  no credentials, all resolved addresses must be globally routable (RFC1918, loopback, link-local/cloud-metadata, CGNAT, multicast, reserved, IPv4-mapped IPv6 all blocked),
  redirects followed manually with each hop re-validated, size/time/redirect caps. Residual risk: DNS rebinding between check and connect; Workers cannot reach private networks, which bounds impact.
* **Passive vs active:** DNS, RDAP, CT, IP and e-mail lookups never contact the target. `/domain/http` and `/network/latency` do, and the UI says so.
* **Rate limiting:** cost-weighted per client (probes cost more). Without a KV binding it is per-isolate (best effort).
* **Provider quota budgets:** VirusTotal (4/min, 450/day), AbuseIPDB (900/day) and Pulsedive calls draw on a global budget, so a burst of
  lookups cannot exhaust a free-tier key; when a budget is spent that provider is skipped (shown as paused) and the lookup still works.
  Raise them for paid keys with `VIRUSTOTAL_RPM`, `VIRUSTOTAL_DAILY`, `ABUSEIPDB_DAILY`, `PULSEDIVE_RPM`, `PULSEDIVE_DAILY`, `SAFEBROWSING_DAILY`, `URLSCAN_RPM` (plain vars in `wrangler.toml`).
* **Request bodies** (`/api/email/headers`) are read through a bounded stream, so oversized or chunked uploads are rejected early with 413.
* **Privacy:** looked-up IPs, and your own IP when `q` is omitted, are sent to the IP data providers listed above; the e-mail header analyser sends nothing anywhere.
* **Secrets:** provider keys live only in Worker secrets; each key is sent only to its own provider. ipapi.is takes its key as a `key` query parameter, Pulsedive a `key` query parameter; request shapes follow the providers' public docs but have not been exercised live.
* **Privacy:** no accounts, no analytics. Recent lookups and playbook progress live in `localStorage` only.

## Known limitations (by design of the platform)

* Workers cannot do ICMP ping, traceroute, raw TCP port scans or live TLS handshakes, so latency is HTTP TTFB and certificate data comes from Certificate Transparency logs, not the live server.
* DNS "propagation" compares two public anycast resolvers, not geographically distributed probes.
* DKIM selectors cannot be enumerated from DNS; common ones are probed and you can add your own.
* Free upstream providers have quotas; results are cached at the edge and provider failures are reported per source instead of hidden.

## Regenerating the resource data

```bash
node scripts/extract-data.mjs path/to/osint_soc_dashboard.html
```
