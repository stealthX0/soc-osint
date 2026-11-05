import { useEffect, useRef, useState, type DragEvent, type ReactNode } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, CopyButton, DataTable, ProviderStrip, Empty, Spinner, ErrorBox, type Tone } from '../components/ui';
import { Icon } from '../components/icons';
import { Result } from '../components/Result';
import { NotAvailable } from '../components/NotAvailable';
import { useApi } from '../lib/hooks';
import { api, ApiClientError } from '../lib/api';
import { uploadFile, fmtBytes, MAX_LOCAL_BYTES, MAX_UPLOAD_BYTES } from '../lib/fileApi';
import { navigate, useLocation } from '../lib/router';
import { pushRecent } from '../lib/storage';
import { analyzeFile, type FileAnalysis, type Severity } from '../../shared/fileAnalysis';
import type { FileAnalysisReport, FileReputation, FileUploadResult } from '../../shared/types';

const SEV_TONE: Record<Severity, Tone> = { high: 'bad', medium: 'warn', low: 'info', info: 'neutral' };
const LEVEL: Record<FileAnalysis['level'], { tone: Tone; label: string }> = {
  'no-findings': { tone: 'neutral', label: 'No suspicious traits found' },
  low: { tone: 'info', label: 'Low suspicion' },
  medium: { tone: 'warn', label: 'Suspicious' },
  high: { tone: 'bad', label: 'Highly suspicious' },
};
const POLL_DELAYS_S = [10, 15, 20, 30, 30, 30];

function HashRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="w-14 text-[11px] uppercase tracking-wider text-muted">{label}</span>
      <code className="break-all font-mono text-xs">{value}</code>
      <CopyButton text={value} />
    </div>
  );
}

function StringList({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div>
      <p className="mb-1 text-xs text-muted">{title} ({items.length})</p>
      <ul className="max-h-40 space-y-0.5 overflow-auto rounded-lg border border-line bg-bg2 p-2">
        {items.map((s) => <li key={s} className="break-all font-mono text-[11px] text-muted">{s}</li>)}
      </ul>
    </div>
  );
}

function LocalReport({ a }: { a: FileAnalysis }) {
  const lvl = LEVEL[a.level];
  const ordered = [...a.findings].sort((x, y) => ['high', 'medium', 'low', 'info'].indexOf(x.severity) - ['high', 'medium', 'low', 'info'].indexOf(y.severity));
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm break-all">{a.name}</span>
          <Badge tone={lvl.tone}>{lvl.label}</Badge>
          <Badge>{fmtBytes(a.size)}</Badge>
          <Badge title="Detected from the file's contents, not its name">{a.type}</Badge>
        </div>
        <div className="mt-3 space-y-1.5"><HashRow label="SHA-256" value={a.sha256} /><HashRow label="SHA-1" value={a.sha1} /><HashRow label="MD5" value={a.md5} /></div>
        <p className="mt-3 text-[11px] text-faint">
          Static check run in your browser: the file was not uploaded. Entropy {a.entropy.toFixed(2)} / 8
          {a.size > a.analyzedBytes ? `; strings were read from the first ${fmtBytes(a.analyzedBytes)}` : ''}. This is triage, not a verdict: &quot;no suspicious traits&quot; does not mean safe.
        </p>
      </Card>

      <Card title="Static findings">
        <ul className="space-y-2">
          {ordered.map((f, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge>
              <span><span className="font-medium">{f.title}</span>{f.detail && <span className="block text-xs text-muted">{f.detail}</span>}</span>
            </li>
          ))}
        </ul>
      </Card>

      {a.pe && (
        <Card title="Windows executable (PE)">
          <KV mono rows={[
            ['Architecture', `${a.pe.machine}, ${a.pe.bits}-bit${a.pe.isDll ? ', DLL' : ''}`], ['Subsystem', a.pe.subsystem], ['Compile time', a.pe.timestamp],
            ['Entry point (RVA)', `0x${a.pe.entryPoint.toString(16)}`], ['Signature block', a.pe.hasSignature ? 'present (not validated)' : 'none'],
            ['Appended data', a.pe.overlayBytes > 0 ? fmtBytes(a.pe.overlayBytes) : null],
          ]} />
          <div className="mt-4"><DataTable head={['Section', 'Virtual', 'Raw', 'Entropy', 'Flags']} rows={a.pe.sections.map((s) => [
            <span key="n" className="font-mono text-xs">{s.name || '(unnamed)'}</span>, fmtBytes(s.virtualSize), fmtBytes(s.rawSize),
            <span key="e" className={s.entropy > 7.2 ? 'text-amber' : ''}>{s.entropy.toFixed(2)}</span>,
            [s.executable ? 'exec' : '', s.writable ? 'write' : ''].filter(Boolean).join(' + ') || '—',
          ])} /></div>
          {a.pe.suspiciousImports.length > 0 && <div className="mt-4"><p className="mb-1 text-xs text-muted">Notable imported APIs</p><div className="flex flex-wrap gap-1.5">{a.pe.suspiciousImports.map((f) => <Badge key={f} tone="warn">{f}</Badge>)}</div></div>}
          {a.pe.imports.length > 0 && <div className="mt-4"><DataTable head={['Imported DLL', 'Functions']} rows={a.pe.imports.map((i) => [<span key="d" className="font-mono text-xs">{i.dll}</span>, i.functions.length])} /></div>}
        </Card>
      )}

      {a.archive && (
        <Card title={`Archive contents (${a.archive.totalEntries} entr${a.archive.totalEntries === 1 ? 'y' : 'ies'})`}>
          <DataTable head={['Name', 'Size', 'Notes']} rows={a.archive.entries.slice(0, 200).map((e) => [<span key="n" className="break-all font-mono text-xs">{e.name}</span>, fmtBytes(e.size), e.encrypted ? <Badge key="x" tone="warn">encrypted</Badge> : '']) } />
          {a.archive.truncated && <p className="mt-2 text-xs text-faint">Showing the first {a.archive.entries.length} entries.</p>}
        </Card>
      )}

      {(a.strings.urls.length + a.strings.ips.length + a.strings.emails.length + a.strings.registryKeys.length + a.strings.suspicious.length) > 0 && (
        <Card title="Interesting strings" action={<span className="text-[11px] text-faint">shown as text, never as links</span>}>
          <div className="grid gap-3 md:grid-cols-2">
            <StringList title="URLs" items={a.strings.urls} />
            <StringList title="IP addresses" items={a.strings.ips} />
            <StringList title="E-mail addresses" items={a.strings.emails} />
            <StringList title="Registry keys" items={a.strings.registryKeys} />
            {a.strings.suspicious.length > 0 && <div className="md:col-span-2"><p className="mb-1 text-xs text-muted">Suspicious keywords</p><div className="flex flex-wrap gap-1.5">{a.strings.suspicious.map((s) => <Badge key={s} tone="warn">{s}</Badge>)}</div></div>}
          </div>
        </Card>
      )}
    </div>
  );
}

function Reputation({ d }: { d: FileReputation }) {
  const vt = d.virustotal;
  const total = vt ? vt.malicious + vt.suspicious + vt.harmless + vt.undetected : 0;
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <code className="break-all font-mono text-[13px]">{d.hash}</code><CopyButton text={d.hash} /><Badge>{d.algo.toUpperCase()}</Badge>
          {d.flags.map((f) => <Badge key={f} tone={/malicious|MalwareBazaar|abuser/i.test(f) ? 'bad' : /CIRCL/.test(f) ? 'good' : 'warn'}>{f}</Badge>)}
          {d.flags.length === 0 && <Badge tone="neutral">no source flags this file</Badge>}
        </div>
        <p className="mt-2 text-[11px] text-faint">Only the hash is sent to these services, never the file. Unknown to a source does not mean safe: new or rare malware is often unlisted.</p>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Multi-engine verdicts (VirusTotal)" className="md:col-span-2">
          {vt ? (vt.observed ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                <div className={`text-3xl font-bold ${vt.malicious >= 5 ? 'text-rose' : vt.malicious + vt.suspicious > 0 ? 'text-amber' : 'text-green'}`}>{vt.malicious}<span className="text-lg text-muted"> / {total}</span></div>
                <p className="text-sm text-muted">security vendors flagged this file as malicious</p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Badge tone={vt.malicious > 0 ? 'bad' : 'good'}>{vt.malicious} malicious</Badge><Badge tone={vt.suspicious > 0 ? 'warn' : 'neutral'}>{vt.suspicious} suspicious</Badge>
                <Badge tone="good">{vt.harmless} harmless</Badge><Badge>{vt.undetected} undetected</Badge>
              </div>
              {(vt.threatLabel || vt.threatNames.length > 0) && (
                <div className="flex flex-wrap items-center gap-1.5 text-sm"><span className="text-muted">Threat label:</span>{vt.threatLabel && <Badge tone="bad">{vt.threatLabel}</Badge>}{vt.threatNames.map((n) => <Badge key={n} tone="warn">{n}</Badge>)}{vt.threatCategories.map((n) => <Badge key={n}>{n}</Badge>)}</div>
              )}
              <KV rows={[['Type', vt.typeDescription], ['Common name', vt.meaningfulName], ['Other names', vt.names.filter((n) => n !== vt.meaningfulName).join(', ') || null], ['Size', vt.size !== null ? fmtBytes(vt.size) : null], ['First seen', vt.firstSeen], ['Last analysed', vt.lastAnalysis], ['Submissions', vt.timesSubmitted !== null ? String(vt.timesSubmitted) : null], ['Community score', vt.reputation !== null ? String(vt.reputation) : null], ['Tags', vt.tags.join(', ') || null]]} />
              <a href={vt.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in VirusTotal <Icon name="ext" size={13} /></a>
              <p className="text-[11px] text-faint">Detections come from third-party engines and can include false positives. Zero detections does not prove a file is safe.</p>
            </div>
          ) : <p className="text-sm text-muted">VirusTotal has never seen this file. That is not a clean verdict: brand-new or targeted malware is often unknown.</p>
          ) : <NotAvailable providers={d.providers} provider="VirusTotal" secret="VIRUSTOTAL_API_KEY" />}
        </Card>

        <Card title="Malware samples (MalwareBazaar)">
          {d.malwarebazaar ? (d.malwarebazaar.observed ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-1.5"><Badge tone="bad">known malware sample</Badge>{d.malwarebazaar.signature && <Badge tone="warn">{d.malwarebazaar.signature}</Badge>}{d.malwarebazaar.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div>
              <KV rows={[['File name', d.malwarebazaar.fileName], ['Type', d.malwarebazaar.fileType], ['First seen', d.malwarebazaar.firstSeen], ['Reporter', d.malwarebazaar.reporter], ['Delivery', d.malwarebazaar.deliveryMethod], ['Origin', d.malwarebazaar.originCountry], ['ClamAV', d.malwarebazaar.clamav.join(', ') || null]]} />
              <a href={d.malwarebazaar.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in MalwareBazaar <Icon name="ext" size={13} /></a>
            </div>
          ) : <p className="text-sm text-muted">Not in MalwareBazaar&apos;s database of reported malware samples. That is not a clean verdict.</p>
          ) : <NotAvailable providers={d.providers} provider="MalwareBazaar" secret="ABUSECH_AUTH_KEY" />}
        </Card>

        <Card title="Known files (CIRCL hashlookup)">
          {d.circl ? (d.circl.known ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-1.5"><Badge tone={d.circl.knownMalicious ? 'bad' : 'good'}>{d.circl.knownMalicious ? 'listed as known malicious' : 'known file'}</Badge>{d.circl.trust !== null && <Badge title="Higher means the sources behind this entry are more trusted">trust {d.circl.trust}</Badge>}</div>
              <KV rows={[['File name', d.circl.fileName], ['Size', d.circl.fileSize !== null ? fmtBytes(d.circl.fileSize) : null], ['Sources', d.circl.sources.join(', ') || null]]} />
              <p className="text-[11px] text-faint">Known-file lists (such as NIST NSRL) mostly contain legitimate software, so a hit usually means a common, benign file. They are not a guarantee.</p>
            </div>
          ) : <p className="text-sm text-muted">Not in the known-file lists. That is normal for documents and anything unusual.</p>
          ) : <p className="text-sm text-amber">CIRCL hashlookup did not answer. Try again shortly.</p>}
        </Card>

        <Card title="Sandbox verdict (Hybrid Analysis)" className="md:col-span-2">
          {d.hybrid ? (d.hybrid.observed ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-1.5">
                {d.hybrid.verdict && <Badge tone={/malicious/i.test(d.hybrid.verdict) && !/no specific/i.test(d.hybrid.verdict) ? 'bad' : /suspicious/i.test(d.hybrid.verdict) ? 'warn' : 'neutral'}>{d.hybrid.verdict}</Badge>}
                {d.hybrid.threatScore !== null && <Badge tone={d.hybrid.threatScore >= 70 ? 'bad' : d.hybrid.threatScore >= 30 ? 'warn' : 'good'}>threat score {d.hybrid.threatScore}/100</Badge>}
                {d.hybrid.avDetect !== null && <Badge>AV detection {d.hybrid.avDetect}%</Badge>}
              </div>
              <KV rows={[['Family', d.hybrid.family], ['Type', d.hybrid.fileType]]} />
              <a href={d.hybrid.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open in Hybrid Analysis <Icon name="ext" size={13} /></a>
            </div>
          ) : <p className="text-sm text-muted">Hybrid Analysis has no report for this file.</p>
          ) : <NotAvailable providers={d.providers} provider="Hybrid Analysis" secret="HYBRID_ANALYSIS_API_KEY" />}
        </Card>
      </div>
      <ProviderStrip providers={d.providers} />
    </div>
  );
}

function UploadPanel({ file, rep }: { file: File; rep: FileReputation }) {
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiClientError | null>(null);
  const [up, setUp] = useState<FileUploadResult | null>(null);
  const [report, setReport] = useState<FileAnalysisReport | null>(null);
  const [polls, setPolls] = useState(0);
  const [checking, setChecking] = useState(false);
  const ctrl = useRef<AbortController | null>(null);

  useEffect(() => () => ctrl.current?.abort(), []);

  const check = async (id: string) => {
    setChecking(true);
    try { setReport((await api<FileAnalysisReport>('/api/file/analysis', { params: { id } })).data); setError(null); }
    catch (e) { setError(e instanceof ApiClientError ? e : new ApiClientError('Could not fetch the scan result.', 'UNKNOWN', 0)); }
    finally { setChecking(false); }
  };

  // Back off between polls: every poll spends one request of the site-wide VirusTotal quota (4/min on the free tier).
  useEffect(() => {
    if (!up || report?.status === 'completed' || polls >= POLL_DELAYS_S.length) return;
    const t = setTimeout(() => { void check(up.analysisId); setPolls((n) => n + 1); }, POLL_DELAYS_S[polls] * 1000);
    return () => clearTimeout(t);
  }, [up, polls, report?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = async () => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    setBusy(true); setError(null);
    try { setUp(await uploadFile(file, c.signal)); setPolls(0); }
    catch (e) { if (!(e instanceof DOMException)) setError(e instanceof ApiClientError ? e : new ApiClientError('Upload failed.', 'UNKNOWN', 0)); }
    finally { setBusy(false); }
  };

  const s = report?.stats;
  return (
    <Card title="Scan this file with VirusTotal">
      {!up ? (
        <div className="space-y-3">
          <p className="text-sm text-muted">VirusTotal has never seen this file. You can upload it for a fresh multi-engine scan (up to 32 MB).</p>
          <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
            <b>Privacy warning.</b> Uploaded files are shared with VirusTotal and its security partners and may be visible to other VirusTotal users. Never upload files containing personal, confidential or customer data.
          </div>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-1" /> I understand, and I want to upload <span className="font-mono break-all">{file.name}</span> ({fmtBytes(file.size)}).</label>
          <button onClick={start} disabled={!consent || busy} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="bolt" size={15} /> {busy ? 'Uploading…' : 'Upload and scan'}</button>
          {error && <ErrorBox error={error} />}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-muted">Uploaded ({fmtBytes(up.size)}). {report?.status === 'completed' ? 'Scan complete.' : 'Waiting for VirusTotal to scan it. This usually takes under a minute.'}</p>
          {report?.status !== 'completed' && (
            <div className="flex flex-wrap items-center gap-3">
              <Spinner label={report ? `Scan ${report.status}` : 'Queued'} />
              {polls >= POLL_DELAYS_S.length && <span className="text-xs text-amber">Still running. Auto-checking has paused to protect the shared quota.</span>}
              <button onClick={() => void check(up.analysisId)} disabled={checking} className="text-sm text-teal hover:underline disabled:opacity-50">Check now</button>
            </div>
          )}
          {error && <ErrorBox error={error} />}
          {report?.status === 'completed' && s && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                <div className={`text-3xl font-bold ${s.malicious >= 5 ? 'text-rose' : s.malicious + s.suspicious > 0 ? 'text-amber' : 'text-green'}`}>{s.malicious}<span className="text-lg text-muted"> / {s.total}</span></div>
                <p className="text-sm text-muted">security vendors flagged this file as malicious</p>
              </div>
              <div className="flex flex-wrap gap-1.5"><Badge tone={s.malicious > 0 ? 'bad' : 'good'}>{s.malicious} malicious</Badge><Badge tone={s.suspicious > 0 ? 'warn' : 'neutral'}>{s.suspicious} suspicious</Badge><Badge tone="good">{s.harmless} harmless</Badge><Badge>{s.undetected} undetected</Badge></div>
              {report.detections.length > 0 && <DataTable head={['Engine', 'Result']} rows={report.detections.map((x) => [x.engine, <span key="r" className="font-mono text-xs">{x.result ?? x.category}</span>])} />}
              {report.link && <a href={report.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-teal hover:underline">Open full report in VirusTotal <Icon name="ext" size={13} /></a>}
              <p className="text-[11px] text-faint">A clean scan does not prove a file is safe, and a few detections on an otherwise unknown file can be false positives.</p>
            </div>
          )}
        </div>
      )}
      <span className="sr-only">{rep.hash}</span>
    </Card>
  );
}

export default function FilePage() {
  const { params } = useLocation();
  const hash = (params.get('hash') ?? '').trim().toLowerCase();
  const [local, setLocal] = useState<FileAnalysis | null>(null);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<File | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const rep = useApi<FileReputation>('/api/file/hash', hash ? { hash } : null);

  // A hash that does not belong to the loaded file (typed in, or back/forward) drops the stale local report and file handle.
  useEffect(() => {
    if (local && hash && ![local.sha256, local.sha1, local.md5].includes(hash)) { setLocal(null); fileRef.current = null; }
  }, [hash]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (rep.data) pushRecent({ label: rep.data.hash.slice(0, 16) + '…', to: `/file?hash=${rep.data.hash}`, kind: 'Hash' });
  }, [rep.data?.hash]); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleFile(f: File | undefined) {
    if (!f) return;
    setLocalErr(null); setLocal(null); fileRef.current = null;
    if (f.size > MAX_LOCAL_BYTES) { setLocalErr(`${f.name} is ${fmtBytes(f.size)}. Files over ${fmtBytes(MAX_LOCAL_BYTES)} cannot be analysed in the browser. Compute its SHA-256 locally and paste the hash below instead.`); return; }
    setAnalyzing(true);
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      await new Promise((r) => setTimeout(r, 0)); // let the spinner paint before the synchronous scan
      const a = await analyzeFile(bytes, f.name);
      fileRef.current = f; setLocal(a);
      navigate(`/file?hash=${a.sha256}`);
    } catch {
      setLocalErr('Could not read that file. It may have been moved or is too large for this browser to load.');
    } finally { setAnalyzing(false); if (input.current) input.current.value = ''; }
  }
  const onDrop = (e: DragEvent) => { e.preventDefault(); setDragging(false); void handleFile(e.dataTransfer.files?.[0]); };

  const vtConfigured = rep.data?.providers.some((p) => p.name.startsWith('VirusTotal') && !p.skipped) ?? false;
  const canUpload = !!(local && fileRef.current && rep.data && rep.data.virustotal && !rep.data.virustotal.observed && vtConfigured);
  const tooBig = !!(local && local.size > MAX_UPLOAD_BYTES);

  let uploadSection: ReactNode = null;
  if (canUpload && !tooBig) uploadSection = <UploadPanel file={fileRef.current!} rep={rep.data!} />;
  else if (canUpload && tooBig) uploadSection = <Card title="Scan this file with VirusTotal"><p className="text-sm text-muted">This file is {fmtBytes(local!.size)}, over the {fmtBytes(MAX_UPLOAD_BYTES)} upload limit, so it cannot be submitted here. The hash lookup above still applies.</p></Card>;

  return (
    <div className="max-w-5xl">
      <PageHeader icon="file" title="File Analysis" blurb="Triage a file locally in your browser, then check its hash against VirusTotal, MalwareBazaar and known-file lists." badge={<Badge tone="good">file stays on your device</Badge>} />

      <div
        onDragOver={(e: DragEvent) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}
        className={`mb-4 rounded-xl border-2 border-dashed p-6 text-center transition ${dragging ? 'border-teal bg-teal/10' : 'border-line2 bg-panel/60'}`}
      >
        <Icon name="file" size={28} className="mx-auto text-teal" />
        <p className="mt-2 text-sm">Drop a file here, or</p>
        <button type="button" onClick={() => input.current?.click()} disabled={analyzing} className="mt-2 inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-4 text-sm font-semibold text-[#04202a] hover:brightness-110 disabled:opacity-50"><Icon name="search" size={15} strokeWidth={2.4} /> Choose a file</button>
        <input ref={input} type="file" className="sr-only" aria-label="Choose a file to analyse" onChange={(e) => void handleFile(e.target.files?.[0])} />
        <p className="mt-3 text-xs text-faint">Analysed in memory in your browser (up to {fmtBytes(MAX_LOCAL_BYTES)}). Nothing is uploaded unless you explicitly choose to scan it with VirusTotal.</p>
        {analyzing && <div className="mt-3 flex justify-center"><Spinner label="Analysing" /></div>}
        {localErr && <p role="alert" className="mt-3 text-sm text-rose">{localErr}</p>}
      </div>

      <LookupForm
        fields={[{ name: 'hash', label: 'Or look up a file hash (MD5, SHA-1 or SHA-256)', placeholder: 'e.g. 44d88612fea8a8f36de82e1278abb02f', mono: true }]}
        values={{ hash }} busy={rep.status === 'loading'}
        onSubmit={(v) => navigate(v.hash.trim() ? `/file?hash=${encodeURIComponent(v.hash.trim())}` : '/file')}
      />

      {local && <div className="mb-4"><LocalReport a={local} /></div>}

      <Result state={rep} idle={local ? null : <Empty>Choose a file to inspect it locally, or paste a hash. Only hashes are ever sent to reputation services.</Empty>}>
        {(d) => (
          <div className="space-y-4">
            <Reputation d={d} />
            {uploadSection}
          </div>
        )}
      </Result>
    </div>
  );
}
