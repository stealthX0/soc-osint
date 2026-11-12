# Calibrating the phishing verdict

The verdict engine's numbers (dimension weights, points per finding, thresholds) are **initial design values**. They give sensible answers on the 28 synthetic scenarios in `tests/fixtures/phishing-corpus.ts`, but those scenarios were written by the same people who chose the numbers, so agreement proves consistency, not accuracy. Real accuracy needs real mail. This guide is how to get there.

## What to tune, and where

| Want to change | Edit | Effect |
|---|---|---|
| How much one kind of evidence is worth | `POINTS` in `shared/phishing/verdictRules.ts` | Moves the risk score and the "strong single indicator" and "meaningful" tests |
| How alike findings combine | `groupOf`, `GROUP_REST_FACTOR`, `GROUP_CAP` | Stops one fact being counted several times |
| How much context matters | `EXACTNESS_FACTOR`, `RELIABILITY_FACTOR`, `TRUST_FACTOR`, `SHARED_INFRA_FACTOR`, `freshnessFactor` | Scales every finding |
| Where Suspicious / Likely legitimate begin | `THRESHOLDS` | Moves the grey zone only: rules still decide Malicious |
| Which evidence is conclusive | the rules in `computeVerdict` (`verdict.ts`) | Changes when an email is called Malicious |

Prefer changing `POINTS` or a multiplier over adding special cases. Keep these invariants (tests enforce them): passing authentication never lowers risk; an authentication failure alone or a bad IP alone is never Malicious; findings about the same fact are counted once; a failed or missing check never counts as clean; a message that was padded or truncated is never cleared.

## Collecting samples

1. Use messages from your own mailbox or ticket queue that an analyst has already judged (include plenty of legitimate mail: password resets, newsletters, invoices, calendar and shipping notices, internal mail).
2. **Anonymise** before they go into the repository: replace people, internal hostnames and your own domains with `*.example` names and documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); change recipient addresses; remove tokens and tracking IDs from URLs; keep the structure, the authentication results, the display-name and wording patterns and the link shapes. Never commit a real credential, a live malicious URL you have not defanged, or customer data.
3. Run the message through the page and record which lookups answered what.

## Adding a sample

Add an entry to `CORPUS` in `tests/fixtures/phishing-corpus.ts`:

```ts
{
  id: 'S10-short-name',
  description: 'what it is, in one line',
  expect: ['suspicious'],          // every verdict an analyst would accept
  input: { headers: mail({ from: 'x@y.example', fromName: '...', spf: 'fail', dkim: 'none', dmarc: 'fail' }), body: '...' },
  findings: [lookup('url_threat_intel_rating', 'high', 'url', { source: 'Pulsedive', indicator: { type: 'url', value: 'https://...' } })],
  checks: [...SENDER_DONE, ...LINKS_DONE],
}
```

`mail()` builds realistic headers; `lookup()` builds the finding a stage would have produced; `SENDER_DONE`, `LINKS_DONE` and `ATTACHMENT_DONE` mark the lookups that completed. Leave a check out, or use `bad(...)`, to model a lookup that failed.

## Running the report

```
npm run calibrate:phishing
```

It prints, per sample, what the analyst expects and what the engine decided, with risk, confidence and coverage; the agreement count; a confusion matrix; and how the agreement changes when each threshold is nudged. Read it for three things:

1. **Bad mail cleared as likely legitimate must be 0.** This is the mistake that matters most, and the script exits non-zero if it happens.
2. **Malicious samples not called Malicious** should be 0 for samples with direct evidence. If the evidence was only wording or heuristics, Suspicious is the right call.
3. **Flat sensitivity rows are good.** If agreement stays the same across a wide range of a threshold the choice is not fragile; a sharp drop beside the current value means that threshold is carrying too much and some points need adjusting instead.

Also look at the **confidence** column: samples with failed or missing checks should have visibly lower confidence than fully covered ones.

## A reasonable process

1. Gather 50 to 100 real, judged messages (at least a third legitimate), anonymise them and add them.
2. Run the report. For every disagreement decide who is right; if the analyst label is, change `POINTS` or a multiplier, not the sample.
3. Re-run the whole corpus after each change: an improvement in one place often moves another.
4. When the corpus is stable, hold some samples back and check them without tuning: that is your estimate of real accuracy.
5. Repeat when providers, wording rules or finding ids change. `npm test` fails if a finding id has no scoring rule or description.

## Trying numbers without editing the tables

`computeVerdict` accepts `tuning: { thresholds, points }` for experiments:

```ts
computeVerdict({ parse, findings, checks, tuning: { thresholds: { suspiciousRisk: 35 }, points: { reply_to_mismatch: 14 } } });
```

## 12 Nov 2026: combined risk and label-based confidence

- **Risk** is now a weighted "noisy OR" of the area scores (`combineFloor` 0.5, `combineScale` 1) instead of half the strongest area plus half the weighted average. The old average let a clean area dilute the others: adding one harmless link to a BEC sample lowered its risk from 45 to 42. The new scale runs higher, so `suspiciousRisk` moved 25 → 28 and `legitimateRisk` 12 → 15 (the only values that kept all 80 samples agreeing with no bad mail cleared). `nonMaliciousCap` 84 and `maliciousFloor` 85 keep the number consistent with the label.
- **Grouping**: the payment findings (`bec_payment_reply_redirect`, `content_payment_demand`, `content_payment_redirection`, `content_payroll_diversion`, `content_gift_card_request`) form one `payment_request` group, and `content_multiple_lure_signals` joined `lure_wording`, so one request for money is not counted three times.
- **Confidence** for Suspicious: `30 + 30 x margin + 15 x agreeing areas/3 + 10 x source quality + 15 x coverage` (margin = distance past the Suspicious line by risk or by the strongest single signal); Likely legitimate: `35 + 15 x margin + 40 x coverage (+8 when authentication supports it)`; Inconclusive: `20 + 35 x coverage`, capped below High. Conflicts −15, missing important checks −10, lookups still running −10.
- `tests/phishing-verdict-properties.test.ts` checks the properties on every corpus sample: no padding, adding a finding never lowers risk, risk consistent with the label, confidence ordered by strength.
- Margins are thin: `S02` sits exactly on 28 and `I12` at 26. Real labelled samples are needed before trusting the exact thresholds.

## 12 Nov 2026 (batch 2): high-risk Suspicious, content weight, rule reliability

- **High-risk Suspicious** (`Verdict.highRisk`), Sahil's decision: a corroborated BEC stays Suspicious, never Malicious. `bec_pattern` = `bec_payment_reply_redirect` plus one of `sender_address_fraud_score` (medium, i.e. 90+), `sender_address_recent_abuse`, `sender_domain_new` (medium/high, under 30 days), `sender_domain_lookalike`, `sender_domain_homograph`, `sender_domain_lookalikes_claimed_org`. `convergent_evidence` = three or more areas scoring at least `convergentAreaScore` 50 with risk at least `convergentRisk` 70. Either raises risk to at least `highRiskFloor` 75 (still capped at 84), adds 5 confidence, rewrites the headline and actions, and exports as `SUSPICIOUS (HIGH RISK)`.
- **Content weight** 0.10 → 0.15.
- **Reliability per content rule**: deterministic, specific matches (`content_text_obfuscation`, `content_payment_demand`, `content_payment_redirection`, `content_gift_card_request`, `content_payroll_diversion`, `content_extortion` at medium or above, and `bec_payment_reply_redirect`) are `high`; other specific rules `medium`; generic lure wording `low`.
- Thresholds unchanged (the sweep still selects suspiciousRisk 28, legitimateRisk 15); 80/80 agreement, no bad mail cleared. Only S28 (the real BEC with lookups) is high risk in the corpus.

## 12 Nov 2026: analyst labels and an offline sanity run on public mail

**Analyst labels.** The dashboard's "Your verdict" row saves a calibration record per investigation (`shared/phishing/calibrationRecord.ts`). `npm run calibrate:labels -- spectrix-labelled-set-YYYY-MM-DD.json` replays the records (no lookups are repeated) and prints agreement, a confusion matrix, bad mail cleared and threshold sensitivity. Replay reproduces the original label, risk and high-risk flag for every corpus sample (`tests/phishing-calibration-record.test.ts`). This is the intended route to real calibration data.

**Offline sanity run** (not committed; data is third-party). 300 recent phishing samples from the public `rf-peixoto/phishing_pot` repository and 400 genuine SpamAssassin `easy_ham` / `hard_ham` messages, with every lookup treated as completed and clean, so only the message's own evidence counts. This deliberately understates detection (in real use link, domain and IP lookups add evidence) and SpamAssassin mail is from 2002.

| | Likely legitimate | Inconclusive | Suspicious |
|---|---|---|---|
| Phishing, before fixes | 197 | 36 | 67 |
| Phishing, after fixes | 197 | 41 | 62 |
| Genuine, before fixes | 277 | 80 | 43 |
| Genuine, after fixes | 344 | 34 | 22 |

Fixed (false alarms on genuine mail):
- **Mailing lists**: Reply-To set to the list is no longer a Reply-To redirect when the message has `List-Id` and the Reply-To is the list address it was sent to (To / Cc / List-Post). A List-Id header alone does not hide a redirect to the recipient.
- **Brand mismatch flood**: a newsletter that mentions a brand had every ordinary link flagged "not a <brand> domain", each counted separately (one sample reached risk 84). Low-severity brand mismatches (ordinary links, not calls to action, forms or look-alikes) now form one group (`brand_mismatch_weak`). Five phishing samples that relied on that flood moved from Suspicious to Inconclusive; none was newly cleared.

Not fixed, for discussion (why most phishing came out Likely legitimate offline):
- Wording rules are English-only; many samples are Portuguese, German, French or Dutch.
- Spam-style scams (fake insurance, warranty, casino, weight-loss offers) under brand names in the display name with a random sender domain carry no rule; the brand list is small.
- Random or malformed sender addresses (`no-reply@cismhkommfulsq`, `5SDYMUIF@ECF0HIAM89VDME760W64LTS2W1N…`, a domain with an emoji or no TLD) are not scored.
- Mathematical-alphanumeric "styled" letters (e.g. a bold "Lidl" in the sender domain) are not treated as obfuscation (only Cyrillic / Greek mixing is).

