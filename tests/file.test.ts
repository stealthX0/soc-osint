import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ctxFor, jsonRes, mockFetch } from './helpers';
import { onRequestGet as fileHash } from '../worker/api/file/hash';
import { onRequestPost as fileUpload, cleanFileName, MAX_UPLOAD_BYTES } from '../worker/api/file/upload';
import { onRequestGet as fileAnalysis } from '../worker/api/file/analysis';
import { resolve } from '../worker/routes';
import { resetRateLimitMemory } from '../worker/_lib/ratelimit';

type Fn = (c: never) => Response | Promise<Response>;
const call = async (fn: unknown, path: string, init?: RequestInit & { env?: Record<string, unknown> }) => {
  const res = await (fn as Fn)(ctxFor(path, init));
  return { status: res.status, body: (await res.json()) as any };
};
let mf: ReturnType<typeof mockFetch> | undefined;
afterEach(() => { mf?.restore(); resetRateLimitMemory(); });

const SHA = 'a'.repeat(64);
const MD5 = 'b'.repeat(32);
const vtFile = (over: Record<string, unknown> = {}) => ({
  data: { attributes: {
    last_analysis_stats: { malicious: 12, suspicious: 1, harmless: 0, undetected: 55 }, last_analysis_date: 1790000000, first_submission_date: 1780000000,
    type_description: 'Win32 EXE', meaningful_name: 'evil.exe', names: ['evil.exe', 'a.bin'], size: 1234, md5: MD5, sha1: 'c'.repeat(40), sha256: SHA, reputation: -40, tags: ['peexe'],
    popular_threat_classification: { suggested_threat_label: 'trojan.agenttesla/msil', popular_threat_name: [{ value: 'agenttesla', count: 9 }], popular_threat_category: [{ value: 'trojan', count: 12 }] },
    times_submitted: 7, ...over,
  } },
});
const keys = { VIRUSTOTAL_API_KEY: 'k-vt', ABUSECH_AUTH_KEY: 'k-mb', HYBRID_ANALYSIS_API_KEY: 'k-ha' };

describe('/api/file/hash', () => {
  it('rejects missing or malformed hashes', async () => {
    mf = mockFetch([]);
    assert.equal((await call(fileHash, '/api/file/hash')).status, 400);
    assert.equal((await call(fileHash, '/api/file/hash?hash=xyz')).status, 400);
    assert.equal((await call(fileHash, `/api/file/hash?hash=${'g'.repeat(64)}`)).status, 400);
    assert.equal(mf.calls.length, 0);
  });

  it('merges VirusTotal, MalwareBazaar, CIRCL and Hybrid Analysis, and each key goes only to its own host', async () => {
    const seen: Record<string, Record<string, string>> = {};
    let mbBody = '';
    mf = mockFetch([
      (u, init) => { if (u.hostname === 'www.virustotal.com') { seen.vt = init?.headers as any; return jsonRes(vtFile()); } },
      (u, init) => { if (u.hostname === 'mb-api.abuse.ch') { seen.mb = init?.headers as any; mbBody = String(init?.body); return jsonRes({ query_status: 'ok', data: [{ sha256_hash: SHA, file_name: 'evil.exe', file_type: 'exe', signature: 'AgentTesla', tags: ['exe', 'AgentTesla'], first_seen: '2026-10-01 10:00:00', reporter: 'abuse_ch', intelligence: { clamav: ['Win.Trojan.Agent'] } }] }); } },
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response(JSON.stringify({ message: 'Non existing SHA-256' }), { status: 404 }) : undefined),
      (u, init) => { if (u.hostname === 'www.hybrid-analysis.com') { seen.ha = init?.headers as any; return jsonRes({ verdict: 'malicious', threat_score: 100, multiscan_result: 80, vx_family: 'AgentTesla', type_short: ['peexe'] }); } },
    ]);
    const d = (await call(fileHash, `/api/file/hash?hash=${SHA}`, { env: keys })).body.data;
    assert.equal(d.algo, 'sha256');
    assert.equal(d.virustotal.malicious, 12);
    assert.equal(d.virustotal.threatLabel, 'trojan.agenttesla/msil');
    assert.deepEqual(d.virustotal.threatNames, ['agenttesla']);
    assert.equal(d.virustotal.link, `https://www.virustotal.com/gui/file/${SHA}`);
    assert.equal(d.malwarebazaar.observed, true);
    assert.equal(d.malwarebazaar.signature, 'AgentTesla');
    assert.deepEqual(d.malwarebazaar.clamav, ['Win.Trojan.Agent']);
    assert.equal(d.circl.known, false);
    assert.equal(d.hybrid.verdict, 'malicious');
    assert.equal(d.hybrid.threatScore, 100);
    assert.ok(d.flags.includes('VirusTotal: 12 engine(s) flag as malicious'));
    assert.ok(d.flags.includes('Known sample in MalwareBazaar (AgentTesla)'));
    assert.ok(d.flags.includes('Hybrid Analysis: malicious'));
    assert.equal(seen.vt['x-apikey'], 'k-vt');
    assert.equal(seen.mb['Auth-Key'], 'k-mb');
    assert.equal(seen.ha['api-key'], 'k-ha');
    assert.match(mbBody, /query=get_info/);
    assert.match(mbBody, new RegExp(`hash=${SHA}`));
    for (const c of mf.calls) assert.ok(!/k-vt|k-mb|k-ha/.test(c), 'keys never appear in URLs');
  });

  it('uses the SHA-256 returned by VirusTotal for Hybrid Analysis when given an MD5', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'www.virustotal.com' ? jsonRes(vtFile()) : undefined),
      (u) => (u.hostname === 'mb-api.abuse.ch' ? jsonRes({ query_status: 'hash_not_found' }) : undefined),
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 404 }) : undefined),
      (u) => (u.hostname === 'www.hybrid-analysis.com' ? jsonRes({ verdict: 'no specific threat', threat_score: null }) : undefined),
    ]);
    const d = (await call(fileHash, `/api/file/hash?hash=${MD5.toUpperCase()}`, { env: keys })).body.data;
    assert.equal(d.algo, 'md5');
    assert.equal(d.sha256, SHA);
    assert.ok(mf.calls.some((c) => c.includes(`/overview/${SHA}`)));
    assert.ok(mf.calls.some((c) => c.includes(`/lookup/md5/${MD5}`)), 'CIRCL queried with the md5 path');
    assert.equal(d.malwarebazaar.observed, false);
    assert.ok(!d.flags.some((f: string) => /Hybrid/.test(f)), '"no specific threat" is not flagged');
  });

  it('404s mean "never seen", not errors; unknown hashes show observed=false', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'www.virustotal.com' ? new Response('{}', { status: 404 }) : undefined),
      (u) => (u.hostname === 'mb-api.abuse.ch' ? jsonRes({ query_status: 'hash_not_found' }) : undefined),
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 404 }) : undefined),
      (u) => (u.hostname === 'www.hybrid-analysis.com' ? new Response('', { status: 404 }) : undefined),
    ]);
    const d = (await call(fileHash, `/api/file/hash?hash=${SHA}`, { env: keys })).body.data;
    assert.equal(d.virustotal.observed, false);
    assert.equal(d.malwarebazaar.observed, false);
    assert.equal(d.hybrid.observed, false);
    assert.deepEqual(d.flags, []);
    assert.ok(d.providers.every((p: any) => p.ok));
  });

  it('CIRCL known-file hits are reported and flagged', async () => {
    mf = mockFetch([(u) => (u.hostname === 'hashlookup.circl.lu' ? jsonRes({ FileName: 'notepad.exe', FileSize: '201216', 'hashlookup:trust': 100, source: 'NSRL', 'SHA-256': SHA }) : undefined)]);
    const d = (await call(fileHash, `/api/file/hash?hash=${SHA}`)).body.data;
    assert.equal(d.circl.known, true);
    assert.equal(d.circl.fileName, 'notepad.exe');
    assert.equal(d.circl.fileSize, 201216);
    assert.equal(d.circl.trust, 100);
    assert.deepEqual(d.circl.sources, ['NSRL']);
    assert.ok(d.flags.includes('Known file in CIRCL hashlookup'));
  });

  it('without keys only CIRCL is contacted and the others show as skipped', async () => {
    mf = mockFetch([(u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 404 }) : undefined)]);
    const d = (await call(fileHash, `/api/file/hash?hash=${SHA}`)).body.data;
    assert.deepEqual(mf.calls.map((c) => new URL(c).hostname), ['hashlookup.circl.lu']);
    const st = Object.fromEntries(d.providers.map((p: any) => [p.name, p]));
    assert.equal(st['VirusTotal (multi-engine verdicts)'].skipped, true);
    assert.equal(st['MalwareBazaar (abuse.ch)'].skipped, true);
    assert.equal(st['Hybrid Analysis (sandbox)'].skipped, true);
    assert.equal(d.virustotal, null);
  });

  it('a provider failure degrades to a failed badge while the others still answer', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'www.virustotal.com' ? new Response('', { status: 429 }) : undefined),
      (u) => (u.hostname === 'mb-api.abuse.ch' ? jsonRes({ query_status: 'ok', data: [{ sha256_hash: SHA, signature: 'Emotet' }] }) : undefined),
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 500 }) : undefined),
    ]);
    const r = await call(fileHash, `/api/file/hash?hash=${SHA}`, { env: { VIRUSTOTAL_API_KEY: 'k', ABUSECH_AUTH_KEY: 'k' } });
    assert.equal(r.status, 200);
    assert.equal(r.body.data.virustotal, null);
    assert.equal(r.body.data.malwarebazaar.signature, 'Emotet');
    const st = Object.fromEntries(r.body.data.providers.map((p: any) => [p.name, p]));
    assert.match(st['VirusTotal (multi-engine verdicts)'].error, /rate limit/i);
    assert.equal(st['CIRCL hashlookup (known files)'].ok, false);
  });

  it('a MalwareBazaar error status (e.g. bad key) is a failure, not "not found"', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'mb-api.abuse.ch' ? jsonRes({ query_status: 'unknown_auth_key' }) : undefined),
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 404 }) : undefined),
    ]);
    const d = (await call(fileHash, `/api/file/hash?hash=${SHA}`, { env: { ABUSECH_AUTH_KEY: 'bad' } })).body.data;
    assert.equal(d.malwarebazaar, null);
    assert.equal(d.providers.find((p: any) => p.name.startsWith('MalwareBazaar')).ok, false);
  });

  it('respects the VirusTotal global budget (4/min) shared with the rest of the site', async () => {
    mf = mockFetch([
      (u) => (u.hostname === 'www.virustotal.com' ? jsonRes(vtFile()) : undefined),
      (u) => (u.hostname === 'hashlookup.circl.lu' ? new Response('', { status: 404 }) : undefined),
    ]);
    let skipped = 0;
    for (let i = 0; i < 6; i++) {
      const h = String(i).repeat(64).slice(0, 64);
      const d = (await call(fileHash, `/api/file/hash?hash=${h}`, { env: { VIRUSTOTAL_API_KEY: 'k' } })).body.data;
      if (d.providers.find((p: any) => p.name.startsWith('VirusTotal')).skipped) skipped++;
    }
    assert.equal(skipped, 2);
  });
});

describe('/api/file/upload', () => {
  const body = () => new Uint8Array([1, 2, 3, 4, 5]);
  const post = (path: string, data: BodyInit | null, env: Record<string, unknown> = { VIRUSTOTAL_API_KEY: 'k-vt' }, headers: Record<string, string> = {}) =>
    call(fileUpload, path, { method: 'POST', body: data, headers, env });

  it('requires explicit consent', async () => {
    mf = mockFetch([]);
    const r = await post('/api/file/upload?name=a.bin', body());
    assert.equal(r.status, 400);
    assert.match(r.body.error.message, /confirm=1/);
    assert.equal(mf.calls.length, 0);
  });

  it('is a clear 503 when no VirusTotal key is configured', async () => {
    mf = mockFetch([]);
    const r = await post('/api/file/upload?confirm=1&name=a.bin', body(), {});
    assert.equal(r.status, 503);
    assert.equal(r.body.error.code, 'NOT_CONFIGURED');
  });

  it('rejects empty files and files over the 32 MB cap without calling VirusTotal', async () => {
    mf = mockFetch([]);
    assert.equal((await post('/api/file/upload?confirm=1&name=a.bin', new Uint8Array(0))).status, 400);
    const big = await post('/api/file/upload?confirm=1&name=a.bin', new Uint8Array(MAX_UPLOAD_BYTES + 1));
    assert.equal(big.status, 413);
    assert.equal(mf.calls.length, 0);
  });

  it('rejects an oversized declared Content-Length before reading', async () => {
    mf = mockFetch([]);
    const r = await post('/api/file/upload?confirm=1&name=a.bin', body(), { VIRUSTOTAL_API_KEY: 'k' }, { 'content-length': String(MAX_UPLOAD_BYTES + 10) });
    assert.equal(r.status, 413);
  });

  it('forwards the bytes as multipart with the key only to VirusTotal and returns the analysis id and sha256', async () => {
    let seenForm: FormData | undefined;
    let seenKey = '';
    mf = mockFetch([(u, init) => {
      if (u.hostname !== 'www.virustotal.com') return undefined;
      assert.equal(u.pathname, '/api/v3/files');
      assert.equal(init?.method, 'POST');
      seenForm = init?.body as FormData;
      seenKey = (init?.headers as Record<string, string>)['x-apikey'];
      return jsonRes({ data: { type: 'analysis', id: 'ZGVhZGJlZWZkZWFkYmVlZjEyMzQ1Njc4OTA=' } });
    }]);
    const r = await post('/api/file/upload?confirm=1&name=C%3A%5Cusers%5Cme%5Cinvoice%22.exe', body());
    assert.equal(r.status, 200);
    assert.equal(r.body.data.analysisId, 'ZGVhZGJlZWZkZWFkYmVlZjEyMzQ1Njc4OTA=');
    assert.equal(r.body.data.size, 5);
    assert.match(r.body.data.sha256, /^[a-f0-9]{64}$/);
    assert.equal(seenKey, 'k-vt');
    const file = seenForm!.get('file') as File;
    assert.equal(file.name, 'invoice_.exe', 'path stripped and quote neutralised');
    assert.equal(file.size, 5);
  });

  it('reports upstream failures and quota exhaustion cleanly', async () => {
    mf = mockFetch([(u) => (u.hostname === 'www.virustotal.com' ? new Response('', { status: 429 }) : undefined)]);
    const r = await post('/api/file/upload?confirm=1&name=a.bin', body());
    assert.equal(r.status, 502);
    assert.match(r.body.error.message, /rate limit/i);
    mf.restore();
    mf = mockFetch([(u) => (u.hostname === 'www.virustotal.com' ? jsonRes({ data: {} }) : undefined)]);
    assert.equal((await post('/api/file/upload?confirm=1&name=a.bin', body())).status, 502);
  });

  it('cleanFileName strips paths, control and bidi characters and bounds the length', () => {
    assert.equal(cleanFileName('C:\\a\\b\\c.txt'), 'c.txt');
    assert.equal(cleanFileName('../../etc/passwd'), 'passwd');
    assert.equal(cleanFileName('a\u202eb\r\n.exe'), 'a_b__.exe');
    assert.equal(cleanFileName(''), 'sample');
    assert.equal(cleanFileName('x'.repeat(500)).length, 120);
  });
});

describe('/api/file/analysis', () => {
  const ID = 'ZGVhZGJlZWZkZWFkYmVlZjEyMzQ1Njc4OTA=';
  it('validates the id and requires a key', async () => {
    mf = mockFetch([]);
    assert.equal((await call(fileAnalysis, '/api/file/analysis', { env: { VIRUSTOTAL_API_KEY: 'k' } })).status, 400);
    assert.equal((await call(fileAnalysis, '/api/file/analysis?id=../../x', { env: { VIRUSTOTAL_API_KEY: 'k' } })).status, 400);
    assert.equal((await call(fileAnalysis, `/api/file/analysis?id=${ID}`, { env: {} })).status, 503);
    assert.equal(mf.calls.length, 0);
  });
  it('reports queued scans without stats', async () => {
    mf = mockFetch([(u) => (u.hostname === 'www.virustotal.com' ? jsonRes({ data: { attributes: { status: 'queued', stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 } } } }) : undefined)]);
    const d = (await call(fileAnalysis, `/api/file/analysis?id=${ID}`, { env: { VIRUSTOTAL_API_KEY: 'k' } })).body.data;
    assert.equal(d.status, 'queued');
    assert.equal(d.stats, null);
    assert.deepEqual(d.detections, []);
  });
  it('returns stats and only malicious/suspicious detections when completed', async () => {
    mf = mockFetch([(u) => (u.hostname === 'www.virustotal.com' ? jsonRes({
      data: { attributes: { status: 'completed', stats: { malicious: 2, suspicious: 1, harmless: 0, undetected: 60, timeout: 1 }, results: {
        A: { category: 'malicious', result: 'Trojan.Gen', engine_name: 'A' }, B: { category: 'undetected', result: null, engine_name: 'B' },
        C: { category: 'suspicious', result: 'Heur.X', engine_name: 'C' }, D: { category: 'malicious', result: null, engine_name: 'D' },
      } } },
      meta: { file_info: { sha256: SHA } },
    }) : undefined)]);
    const d = (await call(fileAnalysis, `/api/file/analysis?id=${ID}`, { env: { VIRUSTOTAL_API_KEY: 'k' } })).body.data;
    assert.equal(d.status, 'completed');
    assert.deepEqual(d.stats, { malicious: 2, suspicious: 1, harmless: 0, undetected: 60, timeout: 1, total: 63 });
    assert.deepEqual(d.detections.map((x: any) => x.engine), ['A', 'C', 'D']);
    assert.equal(d.sha256, SHA);
    assert.equal(d.link, `https://www.virustotal.com/gui/file/${SHA}`);
  });
});

describe('routing and limits', () => {
  it('the three file endpoints are registered with the right methods', () => {
    assert.ok(resolve('GET', '/api/file/hash').handler);
    assert.ok(resolve('GET', '/api/file/analysis').handler);
    assert.ok(resolve('POST', '/api/file/upload').handler);
    assert.equal(resolve('GET', '/api/file/upload').handler, null); // upload is POST only
    assert.equal(resolve('GET', '/api/file/upload').known, true);
  });
});
