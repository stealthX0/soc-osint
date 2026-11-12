import { Card, Badge, Empty, type Tone } from '../../components/ui';
import type { ContentAnalysis } from '../../../shared/phishing/content';

const confTone: Record<'low' | 'medium' | 'high', Tone> = { low: 'neutral', medium: 'warn', high: 'bad' };

export function ContentPanel({ a, subject }: { a: ContentAnalysis; subject: string | null }) {
  if (!a.analysed) return <Empty>No message text was supplied, so the wording could not be analysed. Paste the email body to check it for urgency, credential and payment requests and other lures.</Empty>;
  const recognised = a.intents.filter((i) => i.id !== 'unknown');
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">These are indicators for review, not a verdict: genuine password resets, invoices and security alerts use the same words. The strongest signal is several different lure types together, combined with the sender and link evidence.</p>
      {a.language?.status === 'translated' && (
        <div className="rounded-lg border border-sky/30 bg-sky/10 p-2 text-sm text-sky">
          <p>Written in <b>{a.language.name}</b>: machine-translated to English (Cloudflare Workers AI) before the wording rules ran. Quoted wording below is from the translation, which can be imperfect.</p>
          {a.language.translatedText && (
            <details className="mt-1.5 text-fg/85">
              <summary className="cursor-pointer text-xs text-sky">Show the English translation</summary>
              {a.language.translatedSubject && <p className="mt-1.5 text-xs"><span className="text-muted">Subject: </span>{a.language.translatedSubject}</p>}
              <pre className="mt-1.5 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-bg2 p-2 font-sans text-xs">{a.language.translatedText}</pre>
            </details>
          )}
        </div>
      )}
      {!a.languageSupported && <p className="rounded-lg border border-amber/30 bg-amber/10 p-2 text-sm text-amber">{a.language && a.language.status !== 'not_needed' ? `${a.language.detail} ` : 'Most of this message is not in Latin script. '}The wording rules read English, so the absence of indicators here does not mean the message is clean.</p>}
      <Card title="Likely intent">
        {recognised.length ? (
          <ul className="space-y-2 text-sm">{recognised.map((i) => <li key={i.id} className="flex flex-wrap items-center gap-2"><Badge tone={confTone[i.confidence]}>{i.confidence}</Badge><span className="font-medium">{i.label}</span><span className="text-xs text-muted">from: {i.reasons.join(', ')}</span></li>)}</ul>
        ) : <p className="text-sm text-muted">No phishing intent was recognised from the wording{subject ? ` of "${subject.slice(0, 80)}"` : ''}. That says nothing about the sender, links or attachments.</p>}
      </Card>
      {a.categories.length > 0 && (
        <Card title={`Wording that triggered a rule (${a.categories.length})`}>
          <ul className="space-y-3">{a.categories.map((c) => (
            <li key={c.id}>
              <div className="flex items-center gap-2"><span className="font-medium">{c.label}</span>{c.strong && <Badge tone="warn" title="States a consequence or asks for a specific sensitive action">strong</Badge>}</div>
              <div className="mt-1 space-y-1">{c.matches.map((m, i) => <code key={i} className="block break-words rounded border border-line bg-bg2 px-2 py-1 font-mono text-[11px] text-fg/80">{m.excerpt}</code>)}</div>
            </li>
          ))}</ul>
        </Card>
      )}
      {a.notes.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{a.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
    </div>
  );
}
