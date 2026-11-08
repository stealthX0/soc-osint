import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import { Badge } from '../../components/ui';
import { Icon } from '../../components/icons';
import { Section, field, label } from './common';
import { EMPTY_FORM, EXAMPLE_FORM, checkEmlFile, emlLoadedMessage, fmtKB, looksLikeBody, measureForm, type FormFields } from './formHelpers';

export interface InputFormProps {
  f: FormFields;
  setF: (fn: (p: FormFields) => FormFields) => void;
  emailRep: boolean;
  setEmailRep: (v: boolean) => void;
  autoLinks: boolean;
  setAutoLinks: (v: boolean) => void;
  onSubmit: () => void;
  busy: boolean;
}

/** The guided three-section form: example loader, .eml drop, size indicator and the consent checkboxes. */
export function InputForm({ f, setF, emailRep, setEmailRep, autoLinks, setAutoLinks, onSubmit, busy }: InputFormProps) {
  const [emlMsg, setEmlMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const set = (k: keyof FormFields) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const empty = !Object.entries(f).some(([k, v]) => k !== 'origin' && String(v).trim());
  const size = measureForm(f);
  const bodyNotice = looksLikeBody(f.headers);

  const loadFile = (file: File | undefined | null) => {
    if (!file) return;
    const gate = checkEmlFile(file);
    if (!gate.ok) { setEmlMsg({ ok: false, text: gate.message }); return; }
    const reader = new FileReader();
    reader.onerror = () => setEmlMsg({ ok: false, text: `Could not read ${file.name}.` });
    reader.onload = () => { setF((p) => ({ ...p, headers: String(reader.result ?? '') })); setEmlMsg({ ok: true, text: emlLoadedMessage(file.name, file.size) }); };
    reader.readAsText(file);
  };
  const onDrop = (e: DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragging(false); loadFile(e.dataTransfer.files?.[0]); };

  return (
    <div
      className={`ph-noprint mb-6 space-y-4 rounded-xl ${dragging ? 'outline-dashed outline-2 outline-offset-4 outline-teal' : ''}`}
      onDragOver={(e: DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}
    >
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={() => { setF(() => EXAMPLE_FORM); setEmlMsg(null); }} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line2 px-3 text-xs text-fg hover:border-teal/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Load example</button>
        <span className="text-xs text-faint">A clearly fake training message (reserved example domains and documentation IPs). Sets the origin to Training / test.</span>
      </div>

      <Section n={1} title="Email information" hint="Headers are the most valuable input: they reveal the real sending server and the authentication results. Spectrix extracts indicators automatically.">
        <div>
          <label htmlFor="ph-h" className={label}>Raw email headers <Badge tone="accent">recommended</Badge></label>
          <textarea id="ph-h" value={f.headers} onChange={set('headers')} rows={8} spellCheck={false} aria-describedby="ph-h-help" placeholder={'Paste the full headers ("Show original" in Gmail, "View message source" in Outlook / Thunderbird, or the Internet headers in Outlook properties)… or drop a .eml file anywhere on this form.'} className={`${field} resize-y font-mono text-xs`} />
          <div id="ph-h-help" className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            <button type="button" onClick={() => fileRef.current?.click()} className="text-teal hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Choose a .eml file</button>
            <input ref={fileRef} type="file" accept=".eml,message/rfc822,text/plain" className="sr-only" tabIndex={-1} aria-label="Choose a .eml file" onChange={(e: ChangeEvent<HTMLInputElement>) => { loadFile(e.target.files?.[0]); e.target.value = ''; }} />
            <span>or drop it here (up to 3 MB; read on this device only).</span>
            {emlMsg && <span role="status" className={emlMsg.ok ? 'text-muted' : 'text-amber'}>{emlMsg.ok ? '✓ ' : '✕ '}{emlMsg.text}</span>}
          </div>
          {bodyNotice && <p role="status" className="mt-1.5 rounded-lg border border-amber/30 bg-amber/10 p-2 text-xs text-amber">This looks like a message body rather than headers (no header lines found). Put it in the Email body box, or paste the full headers; a whole .eml also works here.</p>}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div><label htmlFor="ph-s" className={label}>Subject</label><input id="ph-s" value={f.subject} onChange={set('subject')} className={field} placeholder="Taken from the headers when available" /></div>
          <div>
            <span className={label} id="ph-origin">Where did this email come from?</span>
            <div className="flex gap-1" role="group" aria-labelledby="ph-origin">{([['reported', 'Reported by a user'], ['inbox', 'Found in a mailbox'], ['training', 'Training / test']] as const).map(([v, t]) => <button key={v} type="button" onClick={() => setF((p) => ({ ...p, origin: v }))} aria-pressed={f.origin === v} className={`flex-1 rounded-lg border px-2 py-2 text-xs focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal ${f.origin === v ? 'border-teal/50 bg-teal/10 text-teal' : 'border-line2 text-muted hover:text-fg'}`}>{t}</button>)}</div>
          </div>
        </div>
        <div><label htmlFor="ph-b" className={label}>Email body (optional)</label><textarea id="ph-b" value={f.body} onChange={set('body')} rows={6} spellCheck={false} placeholder="Paste the message body: plain text, HTML source, or the MIME body from a .eml. Links are extracted automatically." className={`${field} resize-y font-mono text-xs`} /></div>
        <p role="status" aria-live="polite" className={`text-xs ${size.level === 'over' ? 'text-red' : size.level === 'warn' ? 'text-amber' : 'text-faint'}`}>
          {size.level === 'over' ? '✕ Over the size limit: ' : size.level === 'warn' ? '! Close to the size limit: ' : 'Size: '}
          {fmtKB(size.requestBytes)} of {fmtKB(size.requestLimit)} used ({fmtKB(size.remaining)} left); headers {fmtKB(size.headerBytes)} of {fmtKB(size.headerLimit)}.
        </p>
      </Section>

      <Section n={2} title="Sender information" hint="Optional when headers are supplied. What you enter is treated as a clue and compared with the headers; it is never trusted over them.">
        <div className="grid gap-3 md:grid-cols-2">
          <div><label htmlFor="ph-e" className={label}>Sender email address</label><input id="ph-e" value={f.email} onChange={set('email')} className={`${field} font-mono`} placeholder="billing@example.com" /></div>
          <div><label htmlFor="ph-d" className={label}>Sender display name</label><input id="ph-d" value={f.displayName} onChange={set('displayName')} className={field} placeholder="PayPal Support" /></div>
          <div><label htmlFor="ph-o" className={label}>Claimed organisation website</label><input id="ph-o" value={f.domain} onChange={set('domain')} className={`${field} font-mono`} placeholder="paypal.com" /></div>
          <div><label htmlFor="ph-i" className={label}>Sender IP address (unverified)</label><input id="ph-i" value={f.ip} onChange={set('ip')} className={`${field} font-mono`} placeholder="Extracted from the headers when possible" /></div>
        </div>
      </Section>

      <Section n={3} title="Links and attachments">
        <div className="grid gap-3 md:grid-cols-2">
          <div><label htmlFor="ph-u" className={label}>URLs found in the email (one per line)</label><textarea id="ph-u" value={f.urls} onChange={set('urls')} rows={4} spellCheck={false} placeholder={'Links in the body are extracted automatically.\nDefanged URLs (hxxps://evil[.]com) are accepted.'} className={`${field} resize-y font-mono text-xs`} /></div>
          <div><label htmlFor="ph-a" className={label}>Attachment filenames or hashes (one per line)</label><textarea id="ph-a" value={f.attachments} onChange={set('attachments')} rows={4} spellCheck={false} placeholder={'invoice_4491.pdf\nreport.xlsm  <sha256>\n<md5 / sha1 / sha256>'} className={`${field} resize-y font-mono text-xs`} /></div>
        </div>
      </Section>

      <label className="flex cursor-pointer items-start gap-2 text-sm text-muted">
        <input type="checkbox" checked={emailRep} onChange={(e) => setEmailRep(e.target.checked)} className="mt-1 accent-teal" />
        <span>Check the sender address reputation with EmailRep.io. <span className="text-faint">The address is sent to that third-party service. The sender IP and domains are always looked up with Spectrix's IP and domain intelligence providers; the message text and attachments are never sent anywhere.</span></span>
      </label>
      <label className="flex cursor-pointer items-start gap-2 text-sm text-muted">
        <input type="checkbox" checked={autoLinks} onChange={(e) => setAutoLinks(e.target.checked)} className="mt-1 accent-teal" />
        <span>Investigate links automatically after parsing. <span className="text-faint">Off by default. When on, the message's URLs are sent to the link-intelligence providers as soon as parsing finishes, without waiting for the Investigate button.</span></span>
      </label>

      <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={onSubmit} disabled={empty || busy} className="inline-flex h-10 items-center gap-2 rounded-lg bg-teal px-5 text-sm font-semibold text-[#04202a] hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal disabled:opacity-50"><Icon name="search" size={15} strokeWidth={2.4} /> Analyse email</button>
        <button type="button" onClick={() => { setF(() => EMPTY_FORM); setEmlMsg(null); }} className="text-sm text-muted hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal">Clear</button>
        <span className="text-xs text-faint">Nothing is sent except the lookups you start. Investigating links is a separate, explicit step on the URL Analysis tab. Saved history is controlled in the History panel.</span>
      </div>
    </div>
  );
}
