# Spectrix IPQS relay (Vercel)

IPQualityScore rejects Spectrix's API key ("Invalid or unauthorized key", EID 61771) whenever the request comes from
Cloudflare Workers, while the same key works from other servers. This tiny function runs on Vercel (outside
Cloudflare), makes the one IPQS Email Validation call for the Worker and returns IPQS's JSON unchanged.

```
Spectrix Worker ──POST {email} + x-relay-secret──▶ this relay (Vercel) ──key──▶ IPQS
                ◀──────── IPQS JSON as-is ────────                    ◀────────
```

- The IPQS key lives only here. The Worker sends just the address and a shared secret.
- Requests without the right `x-relay-secret` get 401. Only `POST /api/ipqs` with `{"email": "…"}` is accepted.
- The address travels in the POST body, so it is not in URLs or access logs. Nothing is stored.
- Spectrix's 35-a-day cap, 6-hour cache and UserCheck fallback still apply (they run in the Worker).

## Set up (about 10 minutes)

1. **Make a shared secret** (64 hex characters). In Windows PowerShell:
   ```powershell
   $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | % { $_.ToString('x2') }) -join ''
   ```
   Keep the output; it goes into both Vercel and Cloudflare.

2. **Create the Vercel project.** At vercel.com → Add New → Project → import the `stealthX0/soc-osint` repo.
   - **Root Directory:** `relay/ipqs-vercel` (Edit → pick the folder). This is important.
   - **Framework Preset:** Other. Leave build and output settings empty.

3. **Environment variables** (in the same screen, or Project → Settings → Environment Variables), for Production:
   - `IPQS_API_KEY` = your IPQS private key
   - `RELAY_SECRET` = the secret from step 1

   Click **Deploy**. Note the project URL, e.g. `https://spectrix-ipqs-relay.vercel.app`.

4. **Test the relay from your PC** (Command Prompt or PowerShell; use `curl.exe`, not the PowerShell alias):
   ```
   curl.exe -X POST https://YOUR-PROJECT.vercel.app/api/ipqs -H "content-type: application/json" -H "x-relay-secret: YOUR_SECRET" -d "{\"email\":\"test@gmail.com\"}"
   ```
   Expect JSON with `"success":true`. `{"success":false,"message":"Unauthorized."}` means the secret differs.

5. **Point Spectrix at the relay.** Cloudflare → Workers & Pages → `threatlens` → Settings → Variables and Secrets:
   - `IPQS_RELAY_URL` = `https://YOUR-PROJECT.vercel.app/api/ipqs`
   - `IPQS_RELAY_SECRET` = the same secret as `RELAY_SECRET` (add it as a Secret)

   Save (it redeploys). The next investigation shows the IPQS Mailbox card.

## Maintenance

- **Rotating the IPQS key:** update `IPQS_API_KEY` in Vercel (Settings → Environment Variables), then Redeploy.
  The Worker's own `IPQS_API_KEY` is not used while the relay is set, so you can delete it from Cloudflare.
- **Rotating the shared secret:** change `RELAY_SECRET` in Vercel and `IPQS_RELAY_SECRET` in Cloudflare together.
- **Retiring the relay** (e.g. if IPQS allows Cloudflare Workers): delete `IPQS_RELAY_URL` and `IPQS_RELAY_SECRET` in
  Cloudflare, put the key back in the Worker's `IPQS_API_KEY`, then delete the Vercel project.
- Vercel's free (Hobby) plan easily covers this volume (well under 50 calls a day).
