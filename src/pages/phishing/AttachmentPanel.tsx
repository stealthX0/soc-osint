import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Badge, Card, Copyable, DataTable, Empty, Spinner, type Tone } from '../../components/ui';
import { Icon } from '../../components/icons';
import { api, ApiClientError } from '../../lib/api';
import { fmtBytes, MAX_UPLOAD_BYTES, uploadFile } from '../../lib/fileApi';
import { navigate } from '../../lib/router';
import { hashBytes } from '../../../shared/fileAnalysis';
import { analyzeDroppedFile, convertActiveScan, type ActiveScanOutcome, type AttachmentHashRequest, type AttachmentHashResponse, type StaticResult } from '../../../shared/phishing/attachments';
import type { FileAnalysisReport } from '../../../shared/types';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { CheckResult, Finding, Severity } from '../../../shared/phishing/types';

const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const statusTone: Record<CheckResult['status'], Tone> = { complete: 'neutral', failed: 'bad', skipped: 'warn', not_applicable: 'neutral' };

interface LocalFile { index: number; name: string; size: number; md5: string; sha1: string; sha256: string; result: StaticResult; file: File }
type RepState = { status: 'loading' } | { status: 'done'; res: AttachmentHashResponse } | { status: 'error'; message: string };
type ScanState = { status: 'uploading' } | { status: 'scanning'; link: string | null } | { status: 'final'; outcome: ActiveScanOutcome };

/**
 * Waits between VirusTotal analysis polls. A small file usually finishes in 20–60 s, so polling starts early and stays at
 * about 4 a minute (the free-tier quota, shared with the other lookups); a poll refused for quota just waits for the next.
 */
const SCAN_POLL_DELAYS_S = [10, 10, 12, 12, 15, 15, 15, 15, 15, 15, 20, 20, 20, 25];
/** Longest the analysis waits for VirusTotal scans to finish before reporting them as still running. */
const SCAN_DEADLINE_MS = 200_000;
/** Longest wait after a quota refusal; normally the server's Retry-After (time to the next minute window) is used. */
const QUOTA_WAIT_MS = 60_000;
const quotaWait = (e: unknown) => Math.min(QUOTA_WAIT_MS, ((e instanceof ApiClientError && e.retryAfter) || 60) * 1000 + 500);
/** A VirusTotal report younger than this makes a fresh upload unnecessary: the existing multi-engine result is used. */
const KNOWN_REPORT_MAX_AGE_MS = 30 * 86_400_000;
/** VirusTotal already has a recent report for this file (from the hash lookup), so uploading it again only adds waiting. */
const knownToVt = (res: AttachmentHashResponse | null | undefined): string | null => {
  const vt = res?.data?.virustotal;
  if (!vt?.observed) return null;
  const at = vt.lastAnalysis ? Date.parse(vt.lastAnalysis) : NaN;
  if (!Number.isFinite(at) || Date.now() - at > KNOWN_REPORT_MAX_AGE_MS) return null;
  const total = vt.malicious + vt.suspicious + vt.harmless + vt.undetected;
  return `VirusTotal already scanned this exact file on ${new Date(at).toISOString().slice(0, 10)} (${vt.malicious} of ${total} engines flag it); that report is used instead of a new upload.`;
};
const sleep = (ms: number, alive: () => boolean) => new Promise<void>((res) => {
  const end = Date.now() + ms;
  const tick = () => (!alive() || Date.now() >= end ? res() : setTimeout(tick, Math.min(1000, end - Date.now())));
  tick();
});
const isQuota = (e: unknown) => e instanceof ApiClientError && (e.status === 429 || e.code === 'PROVIDER_BUDGET' || e.code === 'RATE_LIMITED');
const isNotConfigured = (e: unknown) => e instanceof ApiClientError && (e.code === 'NOT_CONFIGURED' || e.status === 503);

interface Row {
  index: number;
  name: string | null;
  declaredType: string | null;
  detectedType: string | null;
  size: number | null;
  hash: string | null;
  hashType: AttachmentHashRequest['hashType'] | null;
  origin: 'embedded' | 'supplied' | 'dropped';
  findings: Finding[];
}

export interface AttachmentStage {
  /** Findings from reputation lookups and from files dropped in the browser (the parse stage already carries the rest). */
  findings: Finding[];
  checks: CheckResult[];
  /** URLs found inside attachments, ready to feed to the link stage. */
  urls: string[];
  /** Raw hash-lookup responses (kept with the attachment results). */
  results: AttachmentHashResponse[];
  panel: ReactNode;
  /** True once the files attached in the form have been inspected and every hash lookup has returned (or failed). */
  settled: boolean;
}

/** The Attachment Analysis tab: the panel the hook built (drop zone, hash lookups, per-file findings). */
export function AttachmentTab({ att }: { att: AttachmentStage }) {
  return <>{att.panel}</>;
}

/** Badge for one provider row. A completed lookup is never shown as "clean": no detections is not proof of safety. */
function providerBadge(c: CheckResult): ReactNode {
  const name = c.label.split(' hash lookup')[0];
  const hit = c.status === 'complete' && !!c.result && (/^[1-9]\d* of \d+ engines/.test(c.result) || /listed as a malware sample|known malicious/.test(c.result));
  const tone: Tone = hit ? 'bad' : statusTone[c.status];
  return <Badge key={c.id} tone={tone} title={c.detail}>{name}: {c.status === 'complete' ? c.result : c.status === 'not_applicable' ? 'n/a' : c.status}</Badge>;
}

export function useAttachmentStage(r: ParseStageResult, files: File[] = []): AttachmentStage {
  const [locals, setLocals] = useState<LocalFile[]>([]);
  const [rep, setRep] = useState<Record<number, RepState>>({});
  const [scans, setScans] = useState<Record<number, ScanState>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [settled, setSettled] = useState(false);
  // A new analysis starts clean: dropped files and lookups belong to the message they were added to.
  const [forResult, setForResult] = useState(r);
  if (forResult !== r) { setForResult(r); setLocals([]); setRep({}); setScans({}); setErr(null); }

  const rows: Row[] = useMemo(() => {
    const forItem = (hash: string | null, name: string | null) =>
      r.findings.filter((f) => f.dimension === 'attachment' && f.indicator && ((hash && f.indicator.value === hash) || (name && f.indicator.value === name)));
    const embedded: Row[] = r.attachments.map((a, i) => ({
      index: i, name: a.filename, declaredType: a.declaredType, size: a.size, hash: a.hash, hashType: a.hashType,
      detectedType: r.attachmentStatic.find((s) => s.index === i)?.detectedType ?? null, origin: a.origin, findings: a.inline ? [] : forItem(a.hash, a.filename),
    })).filter((_, i) => !r.attachments[i].inline);
    const dropped: Row[] = locals.map((l) => ({
      index: l.index, name: l.name, declaredType: null, size: l.size, hash: l.sha256, hashType: 'sha256', detectedType: l.result.summary.detectedType, origin: 'dropped', findings: l.result.findings,
    }));
    return [...embedded, ...dropped];
  }, [r, locals]);

  const scanResults = useMemo(() => locals.flatMap((l) => {
    const st = scans[l.index];
    return st?.status === 'final' ? [{ index: l.index, ...convertActiveScan(st.outcome, { index: l.index, filename: l.name, sha256: l.sha256 }) }] : [];
  }), [locals, scans]);

  const findings = useMemo<Finding[]>(() => {
    const repFindings = Object.values(rep).flatMap((s) => (s.status === 'done' ? s.res.findings : []));
    // A file the hash lookup already flags is not counted a second time from its fresh scan.
    const flagged = new Set(repFindings.filter((f) => f.id === 'attachment_hash_malicious' || f.id === 'attachment_hash_suspicious').map((f) => f.indicator?.value));
    const scanFindings = scanResults.flatMap((x) => x.findings).filter((f) => !flagged.has(f.indicator?.value));
    return [...locals.flatMap((l) => l.result.findings), ...repFindings, ...scanFindings];
  }, [locals, rep, scanResults]);
  const checks = useMemo<CheckResult[]>(
    () => [...locals.map((l) => l.result.check), ...Object.values(rep).flatMap((s) => (s.status === 'done' ? s.res.checks : [])), ...scanResults.flatMap((x) => x.checks)],
    [locals, rep, scanResults],
  );
  const urls = useMemo(() => [...new Set([...r.attachmentStatic.flatMap((s) => s.urls), ...locals.flatMap((l) => l.result.summary.urls)])], [r, locals]);

  const lookup = async (row: Pick<Row, 'index' | 'name' | 'hash' | 'hashType'>): Promise<AttachmentHashResponse | null> => {
    if (!row.hash || !row.hashType) return null;
    setRep((p) => ({ ...p, [row.index]: { status: 'loading' } }));
    try {
      const body: AttachmentHashRequest = { hash: row.hash, hashType: row.hashType, index: row.index, ...(row.name ? { filename: row.name } : {}) };
      const { data } = await api<AttachmentHashResponse>('/api/phishing/attachments', { method: 'POST', body });
      setRep((p) => ({ ...p, [row.index]: { status: 'done', res: data } }));
      return data;
    } catch (e) {
      setRep((p) => ({ ...p, [row.index]: { status: 'error', message: e instanceof Error ? e.message : 'Lookup failed.' } }));
      return null;
    }
  };

  /**
   * Active scan: uploads each file to VirusTotal (the upload API the tool provides), then polls the analyses until they
   * finish or the deadline passes. Uploads go one at a time and back off when the shared VirusTotal quota is used up.
   */
  const activeScan = async (list: LocalFile[], alive: () => boolean, known: Record<number, AttachmentHashResponse | null> = {}) => {
    const final = (index: number, outcome: ActiveScanOutcome) => setScans((p) => ({ ...p, [index]: { status: 'final', outcome } }));
    const started = Date.now();
    const uploaded: { l: LocalFile; id: string; link: string | null }[] = [];
    for (const l of list) {
      if (!alive()) return;
      if (l.file.size > MAX_UPLOAD_BYTES) { final(l.index, { status: 'skipped', reason: `${fmtBytes(l.file.size)} is over the ${fmtBytes(MAX_UPLOAD_BYTES)} VirusTotal upload limit; only the hash was looked up.` }); continue; }
      const already = knownToVt(known[l.index]);
      if (already) { final(l.index, { status: 'known', reason: already }); continue; }
      setScans((p) => ({ ...p, [l.index]: { status: 'uploading' } }));
      for (let attempt = 0; ; attempt++) {
        try {
          const up = await uploadFile(l.file);
          uploaded.push({ l, id: up.analysisId, link: up.link });
          setScans((p) => ({ ...p, [l.index]: { status: 'scanning', link: up.link } }));
          break;
        } catch (e) {
          if (isNotConfigured(e)) { final(l.index, { status: 'skipped', reason: 'File upload is not enabled on this site (no VirusTotal key configured).' }); break; }
          if (isQuota(e) && attempt < 3 && Date.now() - started + quotaWait(e) < SCAN_DEADLINE_MS) { await sleep(quotaWait(e), alive); if (!alive()) return; continue; }
          final(l.index, { status: 'failed', reason: `Upload failed: ${e instanceof Error ? e.message : 'unknown error'}` });
          break;
        }
      }
    }
    let pending = uploaded;
    const deadline = started + SCAN_DEADLINE_MS;
    for (const delay of SCAN_POLL_DELAYS_S) {
      if (!pending.length || !alive()) break;
      if (Date.now() + delay * 1000 > deadline) break;
      await sleep(delay * 1000, alive);
      const still: typeof pending = [];
      let quota = false;
      for (const u of pending) {
        if (quota || !alive()) { still.push(u); continue; }
        try {
          const { data } = await api<FileAnalysisReport>('/api/file/analysis', { params: { id: u.id } });
          if (data.status === 'completed') final(u.l.index, { status: 'completed', report: data });
          else still.push(u);
        } catch (e) {
          if (isQuota(e)) quota = true; // wait for the next round
          still.push(u);
        }
      }
      pending = still;
    }
    for (const u of pending) final(u.l.index, { status: 'pending', link: u.link });
  };

  const checkAll = async () => {
    const todo = rows.filter((x) => x.hash);
    setBusy(true);
    // A few at a time: each request is its own Worker invocation and a hash lookup fans out to several providers.
    for (let i = 0; i < todo.length; i += 2) await Promise.all(todo.slice(i, i + 2).map(lookup));
    setBusy(false);
  };

  // Runs once per analysis: inspect the files attached in the form, look up every hash (embedded, typed or attached),
  // two at a time, then upload the attached files to VirusTotal for an active scan. The report is held back until this has finished, so the verdict never rests on half the evidence.
  useEffect(() => {
    let live = true;
    void (async () => {
      const added: LocalFile[] = [];
      const errs: string[] = [];
      for (const f of files) {
        try {
          const bytes = new Uint8Array(await f.arrayBuffer());
          const h = await hashBytes(bytes);
          const index = r.attachments.length + added.length;
          added.push({ index, name: f.name, size: f.size, ...h, result: analyzeDroppedFile(bytes, index, f.name, h.sha256), file: f });
        } catch { errs.push(`Could not read ${f.name}.`); }
      }
      if (!live) return;
      if (added.length) setLocals(added);
      if (errs.length) setErr(errs.join(' '));
      const todo = [
        ...r.attachments.flatMap((a, i) => (!a.inline && a.hash && a.hashType ? [{ index: i, name: a.filename, hash: a.hash, hashType: a.hashType }] : [])),
        ...added.map((l) => ({ index: l.index, name: l.name, hash: l.sha256, hashType: 'sha256' as const })),
      ];
      const known: Record<number, AttachmentHashResponse | null> = {};
      for (let i = 0; i < todo.length && live; i += 2) {
        const batch = todo.slice(i, i + 2);
        const res = await Promise.all(batch.map(lookup));
        batch.forEach((t, k) => { known[t.index] = res[k]; });
      }
      // Every attached / extracted file is also uploaded for a fresh multi-engine scan before the verdict is computed,
      // unless VirusTotal already has a recent report for that exact file.
      if (live && added.length) await activeScan(added, () => live, known);
      if (live) setSettled(true);
    })();
    return () => { live = false; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const hashed = rows.filter((x) => x.hash).length;
  const anyLoading = busy || Object.values(rep).some((s) => s.status === 'loading') || Object.values(scans).some((s) => s.status !== 'final');

  const panel = (
    <div className="space-y-4">
      {err && <p className="text-sm text-bad" role="alert">{err}</p>}

      {rows.length > 0 && (
        <div className="rounded-xl border border-line bg-bg2/60 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => void checkAll()} disabled={!hashed || anyLoading} className="inline-flex h-9 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={14} strokeWidth={2.4} /> Check hash reputation</button>
            {anyLoading && <Spinner label="Looking up hashes" />}
            {!hashed && <span className="text-xs text-muted">No hashes yet: paste one in the attachments box or drop the file here.</span>}
          </div>
          <p className="mt-2 text-xs text-muted">Each file’s hash is looked up at VirusTotal, MalwareBazaar, CIRCL hashlookup and Hybrid Analysis. Files you attach (or that were extracted from an email file) are also uploaded to VirusTotal for a fresh multi-engine scan; uploaded files are shared with VirusTotal and its security partners.</p>
        </div>
      )}

      {rows.length ? (
        <DataTable head={['File', 'Type', 'Hashes', 'Static findings', 'Reputation', 'Active scan']} rows={rows.map((x) => {
          const s = rep[x.index];
          const sc = scans[x.index];
          const local = locals.find((l) => l.index === x.index);
          const repChecks = s?.status === 'done' ? s.res.checks : [];
          const repFindings = s?.status === 'done' ? s.res.findings : [];
          const noDetections = s?.status === 'done' && !repFindings.some((f) => f.id === 'attachment_hash_malicious' || f.id === 'attachment_hash_suspicious');
          return [
            <div key="f" className="min-w-0"><span className="break-all text-sm">{x.name ?? <span className="text-faint">unnamed</span>}</span><div className="mt-1 flex flex-wrap gap-1"><Badge tone="info" title={ORIGIN[x.origin].title}>{ORIGIN[x.origin].label}</Badge>{x.size !== null && <Badge>{fmtBytes(x.size)}</Badge>}</div></div>,
            <div key="t" className="space-y-0.5 text-xs"><div><span className="text-faint">declared </span>{x.declaredType ?? '—'}</div><div><span className="text-faint">detected </span>{x.detectedType ?? (x.origin === 'supplied' ? 'not inspected (no file)' : '—')}</div></div>,
            <div key="h" className="space-y-1 text-xs">{local ? (<><div>SHA-256 <Copyable value={local.sha256} /></div><div>SHA-1 <Copyable value={local.sha1} /></div><div>MD5 <Copyable value={local.md5} /></div></>) : x.hash ? <div>{x.hashType?.toUpperCase()} <Copyable value={x.hash} /></div> : <span className="text-faint">none</span>}</div>,
            x.findings.length
              ? <ul key="s" className="space-y-1">{x.findings.map((f, i) => <li key={`${f.id}${i}`} className="flex items-start gap-1.5 text-xs"><Badge tone={sevTone[f.severity]}>{f.severity}</Badge><span title={f.detail}>{f.title}</span></li>)}</ul>
              : <span key="s" className="text-xs text-muted">{x.origin === 'supplied' ? 'Only the name was checked: no traits found by the name rules.' : 'No traits found. That does not mean the file is safe.'}</span>,
            <div key="r" className="space-y-1">
              {!s && <span className="text-xs text-faint">not looked up</span>}
              {s?.status === 'loading' && <Spinner label="Looking up" />}
              {s?.status === 'error' && <Badge tone="bad" title={s.message}>lookup failed</Badge>}
              <div className="flex flex-wrap gap-1">{repChecks.map(providerBadge)}</div>
              {repFindings.filter((f) => f.id !== 'attachment_hash_unknown').map((f, i) => <p key={`${f.id}${i}`} className="text-xs"><Badge tone={sevTone[f.severity]}>{f.severity}</Badge> {f.title}</p>)}
              {s?.status === 'done' && repFindings.some((f) => f.id === 'attachment_hash_unknown') && <p className="text-xs text-muted">Unknown is not the same as safe: no provider that responded has seen this file.</p>}
              {noDetections && !repFindings.some((f) => f.id === 'attachment_hash_unknown') && <p className="text-xs text-muted">No detections from the providers that responded. Not proof of safety.</p>}
            </div>,
            <ScanCell key="a" state={sc} origin={x.origin} />,
          ];
        })} />
      ) : <Empty>No attachments were found in the message or added to the form.</Empty>}

      {urls.length > 0 && (
        <Card title={`URLs and IPs found inside attachments (${urls.length})`}>
          <ul className="space-y-1 text-sm">{urls.map((u) => <li key={u} className="flex flex-wrap items-center gap-2"><Copyable value={u} ioc /><a className="text-xs text-teal hover:underline" href={`/url?q=${encodeURIComponent(u)}`} onClick={(e) => { e.preventDefault(); navigate(`/url?q=${encodeURIComponent(u)}`); }}>investigate</a></li>)}</ul>
        </Card>
      )}
    </div>
  );

  const results = useMemo(() => Object.values(rep).flatMap((x) => (x.status === 'done' ? [x.res] : [])), [rep]);

  return { findings, checks, urls, results, panel, settled };
}

/** How each row got here, in words an analyst recognises (the internal names describe the code path, not the source). */
const ORIGIN: Record<Row['origin'], { label: string; title: string }> = {
  embedded: { label: 'in message', title: 'Found inside the raw message you pasted.' },
  supplied: { label: 'hash only', title: 'A name or hash you typed; there is no file to inspect or upload.' },
  dropped: { label: 'file', title: 'The actual file: extracted from the e-mail file you loaded or attached in the form. Inspected on your device, looked up by hash and scanned on VirusTotal.' },
};

/** The "Active scan" cell: upload / scan progress and the fresh VirusTotal result. */
function ScanCell({ state, origin }: { state: ScanState | undefined; origin: 'embedded' | 'supplied' | 'dropped' }) {
  if (!state) return <span className="text-xs text-faint">{origin === 'dropped' ? 'waiting' : 'no file to upload (hash only)'}</span>;
  if (state.status === 'uploading') return <Spinner label="Uploading to VirusTotal" />;
  if (state.status === 'scanning') return <Spinner label="VirusTotal scanning" />;
  const o = state.outcome;
  if (o.status === 'known') return <Badge tone="neutral" title={o.reason}>already on VirusTotal</Badge>;
  if (o.status === 'skipped') return <Badge tone="warn" title={o.reason}>skipped</Badge>;
  if (o.status === 'failed') return <Badge tone="bad" title={o.reason}>scan failed</Badge>;
  if (o.status === 'pending') return <div className="space-y-1 text-xs"><Badge tone="warn">still scanning</Badge>{o.link && <a className="block text-teal hover:underline" href={o.link} target="_blank" rel="noreferrer noopener">open report</a>}</div>;
  const st = o.report.stats;
  if (!st) return <Badge tone="neutral">no result</Badge>;
  const tone: Tone = st.malicious >= 3 ? 'bad' : st.malicious + st.suspicious > 0 ? 'warn' : 'neutral';
  return (
    <div className="space-y-1 text-xs">
      <Badge tone={tone}>{st.malicious} / {st.total} malicious</Badge>
      {st.suspicious > 0 && <Badge tone="warn">{st.suspicious} suspicious</Badge>}
      {o.report.detections.length > 0 && <p className="text-muted">{[...new Set(o.report.detections.map((d) => d.result).filter(Boolean))].slice(0, 3).join(', ')}</p>}
      {o.report.link && <a className="block text-teal hover:underline" href={o.report.link} target="_blank" rel="noreferrer noopener">VirusTotal report</a>}
    </div>
  );
}
