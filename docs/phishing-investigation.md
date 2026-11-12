# Phishing Investigation

`/phishing` answers one question about a suspicious email: **is it a phishing attempt, malicious, suspicious or likely legitimate, and what evidence supports that?** It investigates the message as a whole (who really sent it, whether it authenticates, where its links lead, what is attached and what it asks the reader to do) instead of only checking whether a domain or IP is on a blacklist. An email can come from a genuine Gmail or Microsoft 365 server and still be phishing; a suspicious-looking IP does not prove a particular message is malicious.

The result is **decision support for an analyst**. "Likely legitimate" is never "safe", and the numeric weights are initial values that have not been validated against labelled mail (see [calibration](phishing-calibration.md)).

## 1. How an investigation runs

The page runs small stages and merges what each returns. Every stage returns the same two things: **findings** (one observation with its severity, source, how exact it is and how far it can be trusted) and **check rows** (one visible status line per lookup, so a failed or skipped check never looks clean). The verdict engine is a pure function over those.

| Stage | Endpoint | Outbound requests | Rate-limit cost | What it does |
|---|---|---|---|---|
| Parse | `POST /api/phishing/parse` | none | 2 | Header forensics (trusted receiver boundary, labelled SPF/DKIM/DMARC), MIME body, links with gateway unwrapping, attachment hashes and static analysis, local link screening, sender identity (brand / look-alike), wording analysis |
| Sender | `POST /api/phishing/sender` | one lookup per call | 2 | IP intelligence, domain registration, mail-security DNS, independent SPF re-check, sender address reputation (IPQualityScore first, UserCheck fallback). Reuses `/api/ip/lookup`, `/api/domain/whois`, `/api/email/auth` |
| Links | `POST /api/phishing/urls` | OpenPhish feed + at most 3 full lookups | 8 | Ranks links from offline evidence, checks all against the OpenPhish feed, runs the existing URL intelligence on the top few. Runs automatically after Analyse (full lookup on the top 3 links) |
| Attachments | `POST /api/phishing/attachments` | one hash per call | 2 | Hash reputation through `/api/file/hash` |
| Verdict | none (in the browser, `shared/phishing/verdict.ts`) | none | | Rules, scoring, coverage, confidence |

Why small stages: a Worker has a limited number of outbound requests per invocation (50 on the free plan), and one URL lookup alone fans out to many providers. Each stage endpoint is its own invocation with its own allowance, and the page runs a few in parallel. If you are on the free plan keep `maxDeep` at 1 (the page already requests one full URL lookup per call).

`worker/_lib/internal.ts` lets a stage call Spectrix's own lookups in-process: their validation, SSRF guard, caching and shared provider budgets still apply, only the per-client rate limiter is skipped (the calling endpoint is limited once at its own cost).

## 2. What leaves the app, and to whom

| Data | Sent to | When |
|---|---|---|
| Pasted headers, body, subject, attachment bytes | **nobody**: they are parsed in memory by the Worker and never stored, logged or forwarded (except the translation row below) | always |
| Subject and the first 5,000 characters of the body (2,000 for Chinese, Japanese, Korean, Thai and similar scripts), sender-written text only | **Cloudflare Workers AI** (`@cf/meta/m2m100-1.2b`, hosted by Cloudflare, zero data retention), for machine translation into English | only when the wording is not English. The language is detected locally first (franc-min). Free allocation only: at most `TRANSLATE_DAILY` (default 40) messages a day, sized to the 10,000 free neurons/day; on the Workers Free plan calls beyond the allowance are refused, never billed. `TRANSLATE_CONTENT=false` switches it off; without the `[ai]` binding nothing is sent |
| Public sender IPs | the IP intelligence providers (ipapi.is, RIPE, Shodan InternetDB, AbuseIPDB, VirusTotal, Pulsedive, as configured) | when the sender stage runs. Private and reserved addresses are never sent |
| Sender and related domains | RDAP / WHOIS, DNS-over-HTTPS resolvers | when the sender stage runs. Consumer mailboxes and large mail platforms are skipped |
| Sender e-mail address | IPQualityScore Email Validation, falling back to UserCheck.com | IPQS is always tried first (the address is sent to IPQS, which also probes the address's mail server): fraud score, recent abuse, mailbox existence, risky TLD; breach exposure is shown but never scored. UserCheck is used **only** when IPQS cannot answer: its daily cap (`IPQS_DAILY`, default 35) is spent, it returns an error or quota/limit error, or `IPQS_API_KEY` is not set. The reason for a fallback is always written to the Worker log (`[ipqs-fallback] …`) and shown on the dashboard, unless `IPQS_FALLBACK_DETAILS` is `false` |
| Link URLs | the URL intelligence providers (VirusTotal, URLhaus, Google Safe Browsing, Pulsedive, urlscan.io), DNS resolvers, and **the link destination itself (Cloudflare fetches it, with SSRF protection)** | automatically after Analyse (the top 3 links get a full lookup) |
| File hashes | the hash intelligence providers (VirusTotal, MalwareBazaar, CIRCL, Hybrid Analysis, as configured) | automatically after Analyse. Files are never uploaded; a file attached in the form is analysed in the browser and only its hash is sent |

A test (`tests/phishing-hardening.test.ts`) fails if the message text, subject, display name or a file name ever appears in an outbound request, if a private IP is sent anywhere, or if an API key appears in a response.

## 3. Trust model

Evidence carries a trust label and the verdict engine discounts it accordingly.

* **receiver-reported**: written by the receiving mail system (still "as supplied": pasted headers can be edited).
* **unverified**: typed in by the analyst, or a header that cannot be tied to the receiving server.
* **verified by Spectrix**: reproduced by Spectrix (a DNS lookup, an independent SPF evaluation, a provider answer).
* **derived**: computed from other evidence (a mismatch between two headers).

Forged `Received` headers below the point where the receiving organisation accepted the message are only ever treated as claims. The IP that connected to the receiving server is the sending infrastructure; a manually supplied IP is a clue that is compared with the headers, never authority. Spectrix cannot re-verify DKIM signatures or reproduce the receiver's SPF check from pasted headers; it re-runs the SPF policy against current DNS as independent evidence and flags any disagreement.

## 4. The verdict

See the "How the verdict is decided" section of the README for the principles and `shared/phishing/verdict.ts` for the code. In short: **rules decide, the score guides**; an exact confirmed-malicious URL or file is Malicious whatever else is missing; authentication failure alone or a bad IP alone is never more than Suspicious; passing authentication never lowers risk; failed or missing checks lower confidence and can force Inconclusive; findings about the same fact are counted once.

## 4b. Report, history and the dashboard

The result page has six tabs: Overview (verdict, pipeline strip, key facts, top findings, wording analysis, indicators, export), Email Headers, Sender Intelligence, URL Analysis, Attachment Analysis and Evidence & Timeline (all findings with filters, every check with its status, a timeline and the raw provider results).

* **Export.** `shared/phishing/report.ts` builds one plain object (`schemaVersion: 1`) from the verdict, findings and checks, and renders it as ticket text, Markdown or JSON (or print / save as PDF). Every URL, domain, IP and address in a report is defanged. A report never contains the pasted body, the headers or attachment content, only summary fields and the short evidence excerpts attached to findings, and it states that the weights are uncalibrated.
* **History.** The last 20 investigations are kept in this browser's `localStorage` (`spectrix.phishing.history.v1`), as the report object only: the pasted input is never stored. It can be switched off or cleared on the page, and nothing is synced anywhere.
* **No opt-in switches.** The sender address check, the link investigation and the attachment hash lookups all run automatically after Analyse, and the report is shown only once every one of them has finished; history is on by default and stores the report only.

## 5. Finding catalogue

Every finding a stage can emit and how the engine scores it. Base points are before the multipliers (exactness, reliability, trust, freshness, shared-infrastructure context). **Counted once with** names the group inside which overlapping findings are combined (strongest in full, the rest at 25%, capped at 150%). This section is generated by `npx tsx scripts/phishing-docs.ts`; a test fails when it is out of date.

<!-- finding-catalogue:start -->

#### Attachments

| Finding id | Base points | Counted once with | Meaning |
|---|---|---|---|
| `attachment_hash_malicious` | critical 45, high 30 | attachment | The exact file hash is confirmed as malware (MalwareBazaar, many VirusTotal engines, or a sandbox verdict). |
| `attachment_hash_suspicious` | 12 | attachment | A few security engines or a sandbox flag the exact file hash. |
| `attachment_hash_known_good` | 0 | attachment | The hash matches a known legitimate file (CIRCL / NSRL). Supporting evidence only. |
| `attachment_hash_unknown` | 0 | attachment | No provider has seen the hash. Unknown is not the same as safe. |
| `attachment_dangerous_type` | high 18, medium 8 | attachment | An executable, script, disk image, archive, web page or macro-enabled document attachment. |
| `attachment_double_extension` | 25 | attachment | A document extension followed by an executable one, or a name disguised with spaces or right-to-left characters. |
| `attachment_type_mismatch` | high 22, medium 12 | attachment | The real file type (from its content) differs from its extension or declared type. |
| `attachment_macro_present` | high 20, medium 12 | attachment | An Office file contains a VBA macro project, or one that runs automatically on open. |
| `attachment_html_credential_form` | 28 | attachment | An HTML/SVG attachment contains a password field or a form posting to an external site. |
| `attachment_pdf_active_content` | 10 | attachment | A PDF contains JavaScript, launch actions or embedded files. |
| `attachment_archive_dangerous_content` | 22 | attachment | An archive contains an executable, script or other dangerous file. |
| `attachment_password_protected` | 10 | attachment | The archive or document is encrypted, so its content could not be inspected. |
| `attachment_embedded_urls` | 0 | attachment | URLs found inside the file (information; fed to the link stage). |
| `attachment_high_entropy` | 2 | attachment | The content looks packed or encrypted (supporting signal only). |
| `attachment_not_inspected` | 0 | attachment | The file could not be analysed (too large, unreadable or unsupported): a coverage gap. |

#### URLs and destinations

| Finding id | Base points | Counted once with | Meaning |
|---|---|---|---|
| `url_listed_phishing` | 45 | url reputation | The exact URL is listed as phishing by a trusted source (OpenPhish feed or Google Safe Browsing). |
| `url_listed_malware` | 45 | url reputation | The exact URL is listed as distributing malware (URLhaus or Google Safe Browsing). |
| `url_engine_detections` | critical 40, high 25, medium 12, low 5 | url reputation | Security engines at VirusTotal flag the URL as malicious. |
| `url_engine_suspicious` | 5 | url reputation | A few engines at VirusTotal consider the URL suspicious. |
| `url_scan_malicious` | 20 | url reputation | A urlscan.io scan of the URL was judged malicious. |
| `url_host_scan_malicious` | 8 | url reputation | urlscan.io judged other pages on the same host malicious. |
| `url_threat_intel_rating` | high 14, medium 8, low 3 | url reputation | Pulsedive rates the URL or its host as risky. |
| `url_dns_blocked` | 15 | url reputation | A security DNS resolver blocks the domain. |
| `url_host_listed` | 10 | url reputation | The host (not the exact URL) is listed by a threat feed. |
| `url_blocklisted_host` | 10 | url reputation | The host appears on a blocklist. |
| `url_brand_mismatch` | 14 | brand mismatch weak | The link goes to a domain that is not the brand the message claims to be from. |
| `url_lookalike_domain` | high 18, medium 14, low 6 | link impersonation | The link domain imitates a well-known brand (typo, digit swap, brand in the name). |
| `url_homograph_domain` | 20 | link impersonation | The link domain uses look-alike letters from another alphabet. |
| `url_deceptive_userinfo` | 15 | link impersonation | The URL puts a trusted name before an @ so the real host is hidden ("https://paypal.com@evil.example"). |
| `url_userinfo` | 4 | url hygiene | The URL contains credentials before the host. |
| `url_ip_host` | 6 | url hygiene | The link points at a raw IP address instead of a domain name. |
| `url_obfuscated_ip` | 12 | url hygiene | The IP in the link is written in decimal, octal or hex to hide it. |
| `url_redirect_to_ip` | 10 | url hygiene | The link redirects to a raw IP address. |
| `url_redirect_cross_domain` | 2 | url hygiene | The link redirects to a different registrable domain. |
| `url_redirect_chain` | 2 | url hygiene | The link goes through several redirects. |
| `url_open_redirect_param` | 3 | url hygiene | The URL carries a redirect parameter that could be abused to send you elsewhere. |
| `url_obfuscation_pattern` | 2 | url hygiene | Encoded or unusual characters in the URL path or query. |
| `url_credential_wording` | 5 | url hygiene | The URL is full of account / sign-in / verify words. |
| `url_login_without_tls` | 5 | url hygiene | A sign-in style page served without HTTPS. |
| `url_double_extension` | 15 | url hygiene | The URL names a file with a document extension followed by an executable one. |
| `url_risky_file_type` | 12 | url hygiene | The URL points straight at an executable, script or archive download. |
| `url_download_on_open` | 10 | url hygiene | Opening the URL triggers a file download. |
| `url_shortener` | 3 | url hygiene | A link-shortening service hides the real destination. |
| `url_unusual_tld` | 3 | url hygiene | The link uses a top-level domain heavily associated with abuse. |
| `url_domain_young` | high 10, medium 7, low 3 | url hygiene | The link domain was registered very recently. |
| `url_domain_dead` | 3 | url hygiene | The link domain does not resolve. |
| `link_text_mismatch` | 14 | link impersonation | The visible link text shows one site but the link goes to another. |
| `dangerous_link_scheme` | 8 | none | A link uses a javascript: or data: scheme. |

#### Authentication and headers

| Finding id | Base points | Counted once with | Meaning |
|---|---|---|---|
| `auth_all_failed` | 22 | auth failure | SPF, DKIM and DMARC all failed: nothing ties the message to the From domain. |
| `spf_fail` | 6 | auth failure | The receiving server reports an SPF failure. |
| `spf_softfail` | 2 | auth failure | The receiving server reports an SPF soft failure. |
| `spf_none` | 0 | none | No SPF verdict for the sending IP. |
| `dkim_fail` | 4 | auth failure | No DKIM signature verified. |
| `dmarc_fail` | 8 | auth failure | DMARC failed: SPF or DKIM did not align with the From domain. |
| `dmarc_none` | 2 | none | The From domain has no enforceable DMARC result. |
| `dmarc_policy_not_applied` | 8 | auth failure | DMARC failed against a domain that requests quarantine or reject, yet the message was delivered. |
| `spf_independent_fail` | medium 6, low 2 | auth failure | Spectrix re-ran SPF against current DNS and the sending IP is not authorised. |
| `spf_independent_disagrees` | medium 6, low 2 | auth failure | Spectrix's SPF re-check disagrees with the result in the headers. |
| `spf_independent_pass` | 0 | none | Spectrix re-ran SPF and the sending IP is authorised by the envelope domain. Supporting evidence only. |
| `auth_conflict` | 6 | none | The authentication evidence contradicts itself (headers altered, or receiver policy differs). |
| `arc_chain_failed` | 6 | auth failure | The ARC chain was reported as failed after forwarding. |
| `multiple_from_headers` | 20 | none | The message has more than one From header, a known spoofing trick. |
| `from_missing` | 3 | none | No usable From address. |
| `reply_to_mismatch` | medium 10, low 3 | none | Replies are routed to a different organisation (or a free mailbox) than the sender. |
| `return_path_mismatch` | low 2, info 0 | none | The Return-Path domain differs from the From domain (normal for mailing services). |
| `dkim_domain_mismatch` | 3 | auth failure | No DKIM signature belongs to the From domain. |
| `dkim_not_covering_from` | 3 | none | A DKIM signature does not cover the From header. |
| `dkim_weak_algorithm` | 0 | none | A DKIM signature uses SHA-1. |
| `spf_domain_mismatch` | 2 | auth failure | SPF passed for a different domain than the From domain. |
| `message_id_domain_mismatch` | 0 | none | The Message-ID was generated by a different domain (information). |
| `auth_results_unverified` | 2 | none | Authentication-Results could not be tied to the receiving server. |
| `auth_results_extra_headers` | 0 | none | Older Authentication-Results headers were ignored. |
| `auth_missing` | 0 | none | No authentication results in the supplied headers. |
| `headers_unparsable` | 0 | none | No valid header lines were found. |
| `supplied_sender_mismatch` | 8 | none | The sender address the analyst entered differs from the headers. |
| `supplied_ip_not_in_headers` | 0 | none | The sender IP the analyst entered is not in the headers. |
| `date_header_skewed` | 2 | none | The Date header differs from the first Received time by more than a day. |
| `received_timestamps_inconsistent` | 3 | none | Received timestamps go backwards. |
| `untrusted_received_hops` | 0 | none | Received headers precede the trusted boundary and could be forged (information). |
| `x_originating_ip_present` | 0 | none | An X-Originating-IP header is present (unverified clue). |
| `bec_payment_reply_redirect` | 20 | payment request | Asks for payment while Reply-To routes answers to a different organisation (invoice fraud / BEC pattern). |

#### Sender identity and infrastructure

| Finding id | Base points | Counted once with | Meaning |
|---|---|---|---|
| `sender_header_differs` | 2 | none | The Sender header names a different domain than From. |
| `sender_domain_lookalikes_claimed_org` | 25 | sender impersonation | The sender domain imitates the organisation the message claims to be from. |
| `sender_domain_homograph` | 25 | sender impersonation | The sender domain uses look-alike letters from another alphabet. |
| `sender_domain_lookalike` | 18 | sender impersonation | The sender domain imitates a well-known brand. |
| `sender_domain_brand_misuse` | 15 | sender impersonation | A brand name is embedded in a domain that does not belong to it. |
| `sender_domain_differs_from_claimed_org` | 12 | sender impersonation | The sender is not at the organisation the message claims to be from. |
| `sender_domain_credential_words` | 6 | sender impersonation | The sender domain is packed with account / security words. |
| `sender_domain_risky_tld` | 3 | none | The sender domain uses a top-level domain heavily associated with abuse. |
| `display_name_brand_spoof` | high 18, medium 12 | sender impersonation | The display name uses a brand the sending domain does not own. |
| `display_name_embeds_address` | 10 | none | The display name shows a different address or domain than the real sender. |
| `role_impersonation_freemail` | 14 | none | An executive or internal-team title in the display name, sent from a consumer mailbox. |
| `sender_domain_new` | high 12, medium 8, low 3 | domain registration | The sender domain was registered very recently. |
| `sender_domain_unregistered` | medium 8, low 3 | domain registration | No registration record for the sender domain. |
| `sender_domain_expired` | 3 | domain registration | The sender domain registration has expired. |
| `sender_domain_unprotected` | 3 | none | The sender domain publishes neither SPF nor DMARC. |
| `sender_domain_spoofable` | 2 | none | The sender domain does not enforce DMARC. |
| `sender_domain_no_mail_setup` | 3 | none | The sender domain has no mail servers and no SPF record. |
| `sender_ip_abuse_reports` | high 12, medium 6 | ip reputation | The sending IP has abuse reports (AbuseIPDB). |
| `sender_ip_vt_detections` | high 12, medium 6, low 2 | ip reputation | Security engines at VirusTotal flag the sending IP. |
| `sender_ip_pulsedive` | high 10, medium 5, low 2 | ip reputation | Pulsedive rates the sending IP as risky. |
| `sender_ip_known_abuser` | 5 | ip reputation | The sending network is flagged for abuse. |
| `sender_ip_tor` | 8 | ip reputation | The sending IP is a Tor exit node. |
| `sender_ip_anonymizer` | 3 | ip reputation | The sending IP belongs to a VPN or proxy. |
| `sender_ip_compromised` | 12 | ip reputation | Shodan tags the sending IP as compromised or malware-related. |
| `sender_ip_no_ptr` | 2 | none | The sending IP has no reverse DNS. |
| `sender_ip_residential_ptr` | 3 | none | The sending IP looks like a dynamic or residential address. |
| `sender_infra_shared_provider` | 0 | none | The message was sent through large shared mail infrastructure (information; discounts IP-reputation findings). |
| `sender_address_spam_domain` | 8 | address reputation | The sender address domain is associated with spam or abuse (UserCheck). |
| `sender_address_disposable` | 3 | address reputation | The sender uses a disposable address. |
| `sender_address_no_mx` | 3 | address reputation | The sender address domain has no mail servers, so it cannot receive replies. |
| `sender_address_misspelt_domain` | 6 | address reputation | The sender address domain looks like a misspelling of a well-known domain. |
| `sender_address_free_subdomain` | 2 | address reputation | The sender address is on a free or dynamic-DNS subdomain. |
| `sender_address_recent_abuse` | 8 | address reputation | IPQualityScore saw verified abuse from the sender address in the past few days. |
| `sender_address_fraud_score` | medium 6, low 3 | address reputation | The sender address has an IPQualityScore fraud score of 75 or more (medium at 90+). |
| `sender_address_mailbox_missing` | 4 | address reputation | The sender mailbox does not exist according to its mail server (IPQualityScore). |
| `sender_address_risky_tld` | 2 | address reputation | The sender address uses a top-level domain often tied to abuse (IPQualityScore). |

#### Message wording

| Finding id | Base points | Counted once with | Meaning |
|---|---|---|---|
| `content_urgency` | low 4, info 0 | lure wording | Urgent wording, strongest when it threatens consequences. |
| `content_credential_request` | 8 | lure wording | Asks to verify, reset or re-enter account credentials. |
| `content_financial_request` | 5 | lure wording | Asks about bank, card or payment details. |
| `content_gift_card_request` | 22 | payment request | Asks for gift cards or their codes. |
| `content_payment_redirection` | 24 | payment request | Says bank details have changed or asks for payment to a new account. |
| `content_payroll_diversion` | 22 | payment request | Asks to change payroll or direct-deposit details. |
| `content_bec_request` | medium 14, low 6 | none | A short, link-free request typical of business-email-compromise. |
| `content_extortion` | 22 | none | Threatens exposure unless a cryptocurrency payment is made. |
| `content_delivery_scam` | 4 | lure wording | A parcel-delivery problem notice. |
| `content_advance_fee` | 4 | lure wording | Prize, inheritance or windfall wording. |
| `content_document_share_lure` | 4 | lure wording | A document, voicemail or fax "shared with you" lure. |
| `content_attachment_lure` | 4 | lure wording | Wording pushing you to open an attached invoice, receipt or voicemail. |
| `content_qr_lure` | medium 12, low 5 | lure wording | Tells you to scan a QR code. |
| `content_image_only_body` | 4 | none | The message is mostly images, which evade text and link checks. |
| `content_hidden_text` | 4 | none | A large amount of CSS-hidden text. |
| `content_text_obfuscation` | medium 10, low 3 | none | Look-alike letters or invisible characters inside words. |
| `content_brand_impersonation` | 10 | sender impersonation | The message speaks as a brand the sender does not own. |
| `content_multiple_lure_signals` | 14 | lure wording | Several different lure types appear together. |
| `content_payment_demand` | medium 10, low 4 | payment request | Instructs you to pay, strongest when it demands payment now by a named method ("pay via ACH today"). |
| `content_forwarded_thread` | 3 | none | Forwards a thread from an unrelated organisation with only a short note (a common way to fake prior approval). |
| `content_language_not_analysed` | 0 | none | The wording is not in a language the rules can read (information; widens the evidence gap). |

<!-- finding-catalogue:end -->

## 6. Operating it

| Setting | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `PULSEDIVE_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLSCAN_API_KEY`, `HYBRID_ANALYSIS_API_KEY`, `ABUSECH_AUTH_KEY`, `IPAPI_IS_API_KEY`, `APILAYER_API_KEY` | Optional provider keys already used by the other tools (see the README). A missing key shows that provider as skipped, never clean |
| `USERCHECK_API_KEY`, `USERCHECK_DAILY` | UserCheck.com key: fallback for the sender address check when IPQS is unavailable; optional daily cap |
| `IPQS_RELAY_URL`, `IPQS_RELAY_SECRET` | Route IPQS lookups through the relay in `relay/ipqs-vercel` (deployed on Vercel), because IPQS rejects the key from Cloudflare Workers. The relay holds the IPQS key; the Worker sends only the address and the shared secret (32+ characters). Unset = call IPQS directly |
| `IPQS_FALLBACK_DETAILS` | `false` hides on the dashboard why an address check fell back from IPQS to UserCheck (shown by default; always logged) |
| `AI` ([ai] binding), `TRANSLATE_CONTENT`, `TRANSLATE_DAILY` | Machine translation of non-English e-mails with Workers AI before the wording rules run. Free allocation only (default cap 40 messages/day); `TRANSLATE_CONTENT=false` turns it off. Without translation, non-English wording is reported as not analysed (never as clean) |
| `IPQS_API_KEY`, `IPQS_DAILY` | IPQualityScore key for the sender address check (primary provider); daily cap, default 35, after which UserCheck answers for the rest of the day |
| `OPENPHISH_FEED_URL`, `OPENPHISH_DAILY` | Optional https-only override of the OpenPhish community feed, and its daily download budget (default 300) |
| `RATE_LIMIT` (KV) and `RATE_LIMIT_PER_MIN` | Shared per-client rate limit (default 60 cost units a minute). Without KV the counters are per isolate |

* Provider budgets (VirusTotal per minute, AbuseIPDB per day, ...) are shared across all tools, so a busy investigation can pause a provider for other users; it is then reported as skipped.
* The OpenPhish feed is downloaded about every 30 minutes at most and reused; a failed refresh falls back to the previous copy and is marked stale. An empty or oversized feed is reported as a failure, not as "no listings".
* CPU time: an ordinary HTML email took about 4 ms to parse in a local measurement, and a hostile multi-megabyte message a few hundred milliseconds. Workers CPU accounting differs from a laptop, and the free plan's per-request CPU allowance is small, so use a paid plan if you expect to receive large or hostile input.

## 7. Hardening

| Limit | Value |
|---|---|
| Request body: parse / links / sender and attachments | 3 MB / 600 KB / 8 KB |
| Headers | 100 KB |
| Body | 2,000,000 characters (200,000 read for wording) |
| URLs entered by hand / attachments listed | 50 / 20 |
| Unique links analysed | 200 (more is reported as truncated and counts as an evidence gap) |
| MIME parts / nesting | 120 / 6 (beyond that is a critical evidence gap) |
| Full URL lookups per request | 3 hard cap, the page asks for 1 |

* All HTML and text scanning is linear: tag, comment and block scanners remember where the next `>` or closing tag is and refuse tags longer than 2,000 characters. 2 MB of unclosed `<a href>` once took about a minute; it now takes under 0.2 s. Regression tests cover these shapes and run with a time budget.
* A message that is padded to hide a bad link among hundreds of harmless ones, or to push an attachment past the MIME limits, is reported as incompletely examined and can never be cleared.
* Message text is only ever rendered as text. Nothing is executed, fetched or interpreted from the message except the links the analyst chooses to investigate, which go through the shared SSRF guard (public addresses only, every redirect revalidated, size and time limits).
* The wording rules treat the message as untrusted data: fixed patterns, no model.

## 8. Known limits

* The wording rules read English. Messages in other scripts are marked "not analysed"; fewer indicators there does not mean clean.
* QR codes inside images are not decoded; a message that is mostly images is flagged, and "scan the QR code" wording is detected.
* Attachments get hash reputation and static analysis only; nothing is executed or detonated, and an encrypted or unreadable file is reported as a coverage gap.
* DKIM signatures are not cryptographically verified and ARC chains are read, not validated.
* The SPF re-check evaluates `ip4`, `ip6`, `a`, `mx`, `include` and `redirect`; `exists`, `ptr` and macros are reported as unsupported.
* Weights and thresholds are uncalibrated design values. Collect real samples and follow [phishing-calibration.md](phishing-calibration.md) before trusting the score.

## 9. Tests

`npm test` runs everything. The phishing suites are `tests/phishing-*.test.ts`: parsing and forensics (step1), sender intelligence (step2), URL intelligence (step3), attachments (step4), wording (step5), the verdict engine (step6), the calibration corpus, hardening and fuzzing, and this documentation. `npm run calibrate:phishing` prints the calibration report.
