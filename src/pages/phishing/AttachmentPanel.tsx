import { useMemo, useState, type ChangeEvent, type DragEvent, type ReactNode } from 'react';
import { Badge, Card, Copyable, DataTable, Empty, Spinner, type Tone } from '../../components/ui';
import { Icon } from '../../components/icons';
import { api } from '../../lib/api';
import { fmtBytes, MAX_LOCAL_BYTES } from '../../lib/fileApi';
import { navigate } from '../../lib/router';
import { hashBytes } from '../../../shared/fileAnalysis';
import { analyzeDroppedFile, type AttachmentHashRequest, type AttachmentHashResponse, type StaticResult } from '../../../shared/phishing/attachments';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { CheckResult, Finding, Severity } from '../../../shared/phishing/types';

const sevTone: Record<Severity, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const statusTone: Record<CheckResult['status'], Tone> = { complete: 'neutral', failed: 'bad', skipped: 'warn', not_applicable: 'neutral' };

interface LocalFile { index: number; name: string; size: number; md5: string; sha1: string; sha256: string; result: StaticResult }
type RepState = { status: 'loading' } | { status: 'done'; res: AttachmentHashResponse } | { status: 'error'; message: string };

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
  panel: ReactNode;
}

/** Badge for one provider row. A completed lookup is never shown as "clean": no detections is not proof of safety. */
function providerBadge(c: CheckResult): ReactNode {
  const name = c.label.split(' hash lookup')[0];
  const hit = c.status === 'complete' && !!c.result && (/^[1-9]\d* of \d+ engines/.test(c.result) || /listed as a malware sample|known malicious/.test(c.result));
  const tone: Tone = hit ? 'bad' : statusTone[c.status];
  return <Badge key={c.id} tone={tone} title={c.detail}>{name}: {c.status === 'complete' ? c.result : c.status === 'not_applicable' ? 'n/a' : c.status}</Badge>;
}

export function useAttachmentStage(r: ParseStageResult): AttachmentStage {
  const [locals, setLocals] = useState<LocalFile[]>([]);
  const [rep, setRep] = useState<Record<number, RepState>>({});
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // A new analysis starts clean: dropped files and lookups belong to the message they were added to.
  const [forResult, setForResult] = useState(r);
  if (forResult !== r) { setForResult(r); setLocals([]); setRep({}); setErr(null); }

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

  const findings = useMemo<Finding[]>(
    () => [...locals.flatMap((l) => l.result.findings), ...Object.values(rep).flatMap((s) => (s.status === 'done' ? s.res.findings : []))],
    [locals, rep],
  );
  const checks = useMemo<CheckResult[]>(
    () => [...locals.map((l) => l.result.check), ...Object.values(rep).flatMap((s) => (s.status === 'done' ? s.res.checks : []))],
    [locals, rep],
  );
  const urls = useMemo(() => [...new Set([...r.attachmentStatic.flatMap((s) => s.urls), ...locals.flatMap((l) => l.result.summary.urls)])], [r, locals]);

  const lookup = async (row: Row) => {
    if (!row.hash || !row.hashType) return;
    setRep((p) => ({ ...p, [row.index]: { status: 'loading' } }));
    try {
      const body: AttachmentHashRequest = { hash: row.hash, hashType: row.hashType, index: row.index, ...(row.name ? { filename: row.name } : {}) };
      const { data } = await api<AttachmentHashResponse>('/api/phishing/attachments', { method: 'POST', body });
      setRep((p) => ({ ...p, [row.index]: { status: 'done', res: data } }));
    } catch (e) {
      setRep((p) => ({ ...p, [row.index]: { status: 'error', message: e instanceof Error ? e.message : 'Lookup failed.' } }));
    }
  };

  const checkAll = async () => {
    const todo = rows.filter((x) => x.hash);
    setBusy(true);
    // A few at a time: each request is its own Worker invocation and a hash lookup fans out to several providers.
    for (let i = 0; i < todo.length; i += 2) await Promise.all(todo.slice(i, i + 2).map(lookup));
    setBusy(false);
  };

  const addFile = async (f: File | undefined | null) => {
    if (!f) return;
    setErr(null);
    if (f.size > MAX_LOCAL_BYTES) { setErr(`${f.name} is ${fmtBytes(f.size)}. Files over ${fmtBytes(MAX_LOCAL_BYTES)} cannot be analysed in the browser. Compute its SHA-256 yourself and add it to the attachments box instead.`); return; }
    try {
      // Analysed in memory on this device. The bytes are never sent anywhere; only the hash is, and only when you ask.
      const bytes = new Uint8Array(await f.arrayBuffer());
      const h = await hashBytes(bytes);
      const index = r.attachments.length + locals.length;
      setLocals((p) => [...p, { index, name: f.name, size: f.size, ...h, result: analyzeDroppedFile(bytes, index, f.name, h.sha256) }]);
    } catch { setErr(`Could not read ${f.name}.`); }
  };

  const hashed = rows.filter((x) => x.hash).length;
  const anyLoading = busy || Object.values(rep).some((s) => s.status === 'loading');

  const panel = (
    <div className="space-y-4">
      <div
        onDragOver={(e: DragEvent) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)}
        onDrop={(e: DragEvent) => { e.preventDefault(); setDragging(false); void addFile(e.dataTransfer.files?.[0]); }}
        className={`rounded-xl border-2 border-dashed p-5 text-center text-sm ${dragging ? 'border-teal bg-teal/10' : 'border-line2 bg-bg2/60'}`}
      >
        <Icon name="file" size={20} className="mx-auto mb-2 text-muted" />
        <p>Drop an attachment here to analyse it in your browser, or <label className="cursor-pointer text-teal hover:underline">choose a file<input type="file" className="sr-only" onChange={(e: ChangeEvent<HTMLInputElement>) => { void addFile(e.target.files?.[0]); e.target.value = ''; }} /></label>.</p>
        <p className="mt-1 text-xs text-faint">The file is analysed in memory on your device (up to {fmtBytes(MAX_LOCAL_BYTES)}) and never uploaded. Never open it to check it.</p>
      </div>
      {err && <p className="text-sm text-bad" role="alert">{err}</p>}

      {rows.length > 0 && (
        <div className="rounded-xl border border-line bg-bg2/60 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => void checkAll()} disabled={!hashed || anyLoading} className="inline-flex h-9 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={14} strokeWidth={2.4} /> Check hash reputation</button>
            {anyLoading && <Spinner label="Looking up hashes" />}
            {!hashed && <span className="text-xs text-muted">No hashes yet: paste one in the attachments box or drop the file here.</span>}
          </div>
          <p className="mt-2 text-xs text-muted">Only each file’s hash is sent, to VirusTotal, MalwareBazaar, CIRCL hashlookup and Hybrid Analysis. File names and contents are not. Uploading a file to VirusTotal is a separate action on the File page.</p>
        </div>
      )}

      {rows.length ? (
        <DataTable head={['File', 'Type', 'Hashes', 'Static findings', 'Reputation']} rows={rows.map((x) => {
          const s = rep[x.index];
          const local = locals.find((l) => l.index === x.index);
          const repChecks = s?.status === 'done' ? s.res.checks : [];
          const repFindings = s?.status === 'done' ? s.res.findings : [];
          const noDetections = s?.status === 'done' && !repFindings.some((f) => f.id === 'attachment_hash_malicious' || f.id === 'attachment_hash_suspicious');
          return [
            <div key="f" className="min-w-0"><span className="break-all text-sm">{x.name ?? <span className="text-faint">unnamed</span>}</span><div className="mt-1 flex flex-wrap gap-1"><Badge tone="info">{x.origin}</Badge>{x.size !== null && <Badge>{fmtBytes(x.size)}</Badge>}</div></div>,
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
          ];
        })} />
      ) : <Empty>No attachments were found or listed. Drop a file above to analyse it locally.</Empty>}

      {urls.length > 0 && (
        <Card title={`URLs and IPs found inside attachments (${urls.length})`}>
          <ul className="space-y-1 text-sm">{urls.map((u) => <li key={u} className="flex flex-wrap items-center gap-2"><Copyable value={u} ioc /><a className="text-xs text-teal hover:underline" href={`/url?q=${encodeURIComponent(u)}`} onClick={(e) => { e.preventDefault(); navigate(`/url?q=${encodeURIComponent(u)}`); }}>investigate</a></li>)}</ul>
        </Card>
      )}
    </div>
  );

  return { findings, checks, urls, panel };
}
