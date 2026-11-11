/**
 * Spectrix → IPQualityScore relay (Vercel serverless function, POST /api/ipqs).
 *
 * Why it exists: IPQS rejects Spectrix's key with "Invalid or unauthorized key (EID 61771)" whenever the request comes
 * from Cloudflare Workers, while the same key works from other servers. The Worker therefore asks this function, which
 * runs outside Cloudflare, to make the one IPQS call and hand back IPQS's JSON unchanged.
 *
 * Security:
 * - The IPQS key lives only here (IPQS_API_KEY); the Worker never sends it.
 * - Every request must carry the shared secret in `x-relay-secret` (RELAY_SECRET, ≥ 32 characters), compared in
 *   constant time. Anything else gets 401, so the URL is useless to anyone who finds it.
 * - The address arrives in a POST body, so it does not appear in request URLs or access logs. Nothing is stored.
 * - IPQS messages are scrubbed of the key before they are returned.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

const EMAIL = /^[^\s@<>()"',;:\\]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i;
const IPQS_TIMEOUT_MS = 9000;

/** Constant-time comparison of two strings of any length (hashing equalises the lengths). */
export function sameSecret(given, expected) {
  if (typeof given !== 'string' || typeof expected !== 'string') return false;
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

const clean = (v) => String(v ?? '').trim().replace(/^["'`]+|["'`]+$/g, '').trim();

/** Reads the JSON body whether or not the platform has already parsed it. */
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return null; } }
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (raw.length > 2048) return null; }
  try { return JSON.parse(raw || '{}'); } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('cache-control', 'no-store');
  res.setHeader('content-type', 'application/json; charset=utf-8');
  const send = (status, obj) => { res.statusCode = status; res.end(JSON.stringify(obj)); };

  if (req.method !== 'POST') return send(405, { success: false, message: 'Method not allowed.' });

  const secret = clean(process.env.RELAY_SECRET);
  const key = clean(process.env.IPQS_API_KEY);
  if (secret.length < 32 || !key) return send(503, { success: false, message: 'Relay not configured (RELAY_SECRET of 32+ characters and IPQS_API_KEY are required).' });
  if (!sameSecret(req.headers['x-relay-secret'], secret)) return send(401, { success: false, message: 'Unauthorized.' });

  const body = await readBody(req);
  const email = clean(body && body.email).toLowerCase();
  if (!email || email.length > 320 || !EMAIL.test(email)) return send(400, { success: false, message: 'A valid "email" is required.' });

  const addr = encodeURIComponent(email).replace(/%40/g, '@');
  const url = `https://www.ipqualityscore.com/api/json/email/${encodeURIComponent(key)}/${addr}?timeout=7&abuse_strictness=0`;
  let upstream;
  try {
    upstream = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(IPQS_TIMEOUT_MS) });
  } catch (e) {
    const timeout = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return send(504, { success: false, message: timeout ? 'IPQS did not answer in time.' : 'IPQS could not be reached.' });
  }
  let data;
  try { data = await upstream.json(); } catch { return send(502, { success: false, message: `IPQS returned HTTP ${upstream.status} without JSON.` }); }
  if (!data || typeof data !== 'object') return send(502, { success: false, message: 'IPQS returned an unexpected answer.' });
  if (typeof data.message === 'string') data.message = data.message.split(key).join('[key]');
  // IPQS reports its own errors (bad key, quota) as HTTP 200 + success:false; pass those through unchanged.
  return send(upstream.ok ? 200 : 502, data);
}
