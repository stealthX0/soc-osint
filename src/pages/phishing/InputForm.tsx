import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import { Badge } from '../../components/ui';
import { Icon } from '../../components/icons';
import { Section, field, label } from './common';
import { fmtBytes, MAX_LOCAL_BYTES, MAX_UPLOAD_BYTES } from '../../lib/fileApi';
import { EMAIL_FILE_ACCEPT, parseEmailFile } from '../../lib/emailFile';
import { EMPTY_FORM, EXAMPLE_FORM, MAX_ATTACHED_FILES, addAttachedFiles, checkEmlFile, emlLoadedMessage, fmtKB, looksLikeBody, measureForm, type FormFields } from './formHelpers';

export interface InputFormProps {
  f: FormFields;
  setF: (fn: (p: FormFields) => FormFields) => void;
  /** Files attached in the attachments box. They are hashed and inspected in the browser when Analyse is pressed. */
  files: File[];
  setFiles: (fn: (p: File[]) => File[]) => void;
  onSubmit: () => void;
  busy: boolean;
}

/** The guided two-section form: example loader, email file drop (.eml / .msg / .mbox), size indicator and attachment picker. */
export function InputForm({ f, setF, files, setFiles, onSubmit, busy }: InputFormProps) {
  const [emlMsg, setEmlMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const attachRef = useRef<HTMLInputElement>(null);
  const [attachErr, setAttachErr] = useState<string[]>([]);
  const set = (k: keyof FormFields) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const empty = !Object.values(f).some((v) => String(v).trim()) && files.length === 0;
  const size = measureForm(f);
  const bodyNotice = looksLikeBody(f.headers);

  // Files that came out of the last loaded email file: replaced when another email file is loaded, kept when added by hand.
  const fromEmail = useRef<Set<File>>(new Set());
  const loadFile = async (file: File | undefined | null) => {
    if (!file) return;
    const gate = checkEmlFile(file);
    if (!gate.ok) { setEmlMsg({ ok: false, text: gate.message }); return; }
    setEmlMsg({ ok: true, text: `Reading ${file.name}…` });
    try {
      const parsed = await parseEmailFile(file);
      setF((p) => ({ ...p, headers: parsed.headers, body: parsed.body }));
      const manual = files.filter((x) => !fromEmail.current.has(x));
      const { files: next, errors } = addAttachedFiles(manual, parsed.attachments, MAX_LOCAL_BYTES, fmtBytes);
      fromEmail.current = new Set(parsed.attachments);
      setFiles(() => next);
      setAttachErr(errors);
      const notes = parsed.notes.length ? ` ${parsed.notes.join(' ')}` : '';
      setEmlMsg({ ok: true, text: emlLoadedMessage(file.name, `.${parsed.format}`, parsed.attachments.length) + notes });
    } catch (e) {
      setEmlMsg({ ok: false, text: `Could not read ${file.name}: ${e instanceof Error ? e.message : 'unsupported or damaged file'}.` });
    }
  };
  const attach = (list: FileList | null | undefined) => {
    if (!list || !list.length) return;
    const chosen = Array.from(list);
    const { errors } = addAttachedFiles(files, chosen, MAX_LOCAL_BYTES, fmtBytes);
    setAttachErr(errors);
    setFiles((cur) => addAttachedFiles(cur, chosen, MAX_LOCAL_BYTES, fmtBytes).files);
  };
  const onDrop = (e: DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragging(false); void loadFile(e.dataTransfer.files?.[0]); };

  return (
    <div
      className={`ph-noprint mb-6 space-y-4 rounded-xl ${dragging ? 'outline-dashed outline-2 outline-offset-4 outline-teal' : ''}`}
      onDragOver={(e: DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}
    >
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={() => { setF(() => EXAMPLE_FORM); setFiles(() => []); fromEmail.current = new Set(); setAttachErr([]); setEmlMsg(null); }} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line2 px-3 text-xs text-fg hover:border-teal/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Load example</button>
        <span className="text-xs text-faint">A clearly fake training message (reserved example domains and documentation IPs). Nothing in it is real.</span>
      </div>

      <Section n={1} title="Email information" hint="Headers are the most valuable input: they reveal the real sending server and the authentication results. Spectrix extracts indicators automatically.">
        <div>
          <label htmlFor="ph-h" className={label}>Raw email headers <Badge tone="accent">recommended</Badge></label>
          <textarea id="ph-h" value={f.headers} onChange={set('headers')} rows={8} spellCheck={false} aria-describedby="ph-h-help" placeholder={'Paste the full headers ("Show original" in Gmail, "View message source" in Outlook / Thunderbird, or the Internet headers in Outlook properties)… or drop an email file (.eml, .msg or .mbox) anywhere on this form.'} className={`${field} resize-y font-mono text-xs`} />
          <div id="ph-h-help" className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            <button type="button" onClick={() => fileRef.current?.click()} className="text-teal hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Choose an email file</button>
            <input ref={fileRef} type="file" accept={EMAIL_FILE_ACCEPT} className="sr-only" tabIndex={-1} aria-label="Choose an email file" onChange={(e: ChangeEvent<HTMLInputElement>) => { void loadFile(e.target.files?.[0]); e.target.value = ''; }} />
            <span>or drop it here</span>
            {emlMsg && <span role="status" className={emlMsg.ok ? 'text-muted' : 'text-amber'}>{emlMsg.ok ? '✓ ' : '✕ '}{emlMsg.text}</span>}
          </div>
          {bodyNotice && <p role="status" className="mt-1.5 rounded-lg border border-amber/30 bg-amber/10 p-2 text-xs text-amber">This looks like a message body rather than headers (no header lines found). Put it in the Email body box, or paste the full headers; a whole email file also works here.</p>}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div><label htmlFor="ph-s" className={label}>Subject <span className="text-faint">(optional)</span></label><input id="ph-s" value={f.subject} onChange={set('subject')} className={field} placeholder="Taken from the headers when available" /></div>
        </div>
        <div><label htmlFor="ph-b" className={label}>Email body (optional)</label><textarea id="ph-b" value={f.body} onChange={set('body')} rows={6} spellCheck={false} placeholder="Paste the message body: plain text, HTML source, or the MIME body of an email. Filled in automatically when an email file is loaded. Links are extracted automatically." className={`${field} resize-y font-mono text-xs`} /></div>
        <p role="status" aria-live="polite" className={`text-xs ${size.level === 'over' ? 'text-red' : size.level === 'warn' ? 'text-amber' : 'text-faint'}`}>
          {size.level === 'over' ? '✕ Over the size limit: ' : size.level === 'warn' ? '! Close to the size limit: ' : 'Size: '}
          {fmtKB(size.requestBytes)} of {fmtKB(size.requestLimit)} used ({fmtKB(size.remaining)} left); headers {fmtKB(size.headerBytes)} of {fmtKB(size.headerLimit)}.
        </p>
      </Section>

      <Section n={2} title="Links and attachments">
        <div className="grid gap-3 md:grid-cols-2">
          <div><label htmlFor="ph-u" className={label}>URLs found in the email (one per line)</label><textarea id="ph-u" value={f.urls} onChange={set('urls')} rows={4} spellCheck={false} placeholder={'Links in the body are extracted automatically.\nDefanged URLs (hxxps://evil[.]com) are accepted.'} className={`${field} resize-y font-mono text-xs`} /></div>
          <div><label htmlFor="ph-a" className={label}>Attachment filenames or hashes (one per line)</label><textarea id="ph-a" value={f.attachments} onChange={set('attachments')} rows={4} spellCheck={false} placeholder={'invoice_4491.pdf\nreport.xlsm  <sha256>\n<md5 / sha1 / sha256>'} aria-describedby="ph-a-help" className={`${field} resize-y font-mono text-xs`} />
            <div id="ph-a-help" className="mt-1.5 space-y-1.5 text-xs text-muted">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <button type="button" onClick={() => attachRef.current?.click()} disabled={files.length >= MAX_ATTACHED_FILES} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line2 px-3 text-xs text-fg hover:border-teal/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal disabled:opacity-50"><Icon name="file" size={13} /> Attach file</button>
                <input ref={attachRef} type="file" multiple className="sr-only" tabIndex={-1} aria-label="Attach a file to analyse" onChange={(e: ChangeEvent<HTMLInputElement>) => { attach(e.target.files); e.target.value = ''; }} />
                <span>When you press Analyse, every attached file (and every attachment extracted from an email file) is inspected, looked up by hash, and uploaded to VirusTotal for an active scan (up to {fmtBytes(MAX_UPLOAD_BYTES)} each). Uploaded files are shared with VirusTotal and its security partners: do not attach files containing personal or confidential data. Never open a file to check it.</span>
              </div>
              {files.length > 0 && (
                <ul className="space-y-1" aria-label="Attached files">
                  {files.map((file, i) => (
                    <li key={`${file.name}-${file.size}-${i}`} className="flex items-center gap-2 rounded-lg border border-line bg-bg2/60 px-2 py-1">
                      <Icon name="file" size={13} className="shrink-0 text-muted" />
                      <span className="min-w-0 flex-1 break-all text-fg">{file.name}</span>
                      <span className="shrink-0 text-faint">{fmtBytes(file.size)}</span>
                      <button type="button" onClick={() => { setFiles((cur) => cur.filter((_, j) => j !== i)); setAttachErr([]); }} aria-label={`Remove ${file.name}`} className="shrink-0 text-muted hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">✕</button>
                    </li>
                  ))}
                </ul>
              )}
              {attachErr.length > 0 && <p role="alert" className="text-amber">{attachErr.join(' ')}</p>}
            </div>
          </div>
        </div>
      </Section>

      <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={onSubmit} disabled={empty || busy} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-5 text-sm font-semibold text-[#04202a] hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal disabled:opacity-50"><Icon name="search" size={15} strokeWidth={2.4} /> Analyse email</button>
        <button type="button" onClick={() => { setF(() => EMPTY_FORM); setFiles(() => []); fromEmail.current = new Set(); setAttachErr([]); setEmlMsg(null); }} className="text-sm text-muted hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Clear</button>
        <span className="text-xs text-faint">Analyse runs every lookup (sender IP, domains and address, links, file hashes and VirusTotal file scans) and shows the verdict only when all of them have finished. Attachments are uploaded to VirusTotal; the message text is not shared with any third party. Saved history is controlled in the History panel.</span>
      </div>
    </div>
  );
}
