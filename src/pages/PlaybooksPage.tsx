import { Badge, Card, Empty, PageHeader } from '../components/ui';
import { Icon } from '../components/icons';
import { Link } from '../lib/router';
import { useStored } from '../lib/storage';
import { PLAYBOOKS, RESOURCES } from '../data';

type Done = Record<string, number[]>;

function Detail({ id }: { id: string }) {
  const book = PLAYBOOKS.find((b) => b.id === id);
  const [done, setDone] = useStored<Done>('tl-playbook-progress-v1', {});
  if (!book) return <Empty>Playbook not found. <Link to="/playbooks" className="text-teal hover:underline">See all playbooks</Link></Empty>;
  const mine = done[book.id] ?? [];
  const toggle = (i: number) => setDone((d) => ({ ...d, [book.id]: mine.includes(i) ? mine.filter((x) => x !== i) : [...mine, i] }));
  const pct = Math.round((mine.length / book.steps.length) * 100);

  return (
    <div className="max-w-3xl">
      <Link to="/playbooks" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-teal">← All playbooks</Link>
      <PageHeader icon="list" title={book.title} blurb={book.summary} />
      <div className="mb-5 flex items-center gap-3">
        <div className="h-2 flex-1 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Progress"><div className="h-full bg-teal transition-all" style={{ width: `${pct}%` }} /></div>
        <span className="text-xs text-muted">{mine.length}/{book.steps.length}</span>
        {mine.length > 0 && <button onClick={() => setDone((d) => ({ ...d, [book.id]: [] }))} className="text-xs text-muted hover:text-fg">Reset</button>}
      </div>
      <ol className="space-y-3">
        {book.steps.map((s, i) => {
          const checked = mine.includes(i);
          return (
            <li key={i}>
              <Card className={checked ? 'opacity-70' : ''}>
                <div className="flex gap-3">
                  <input type="checkbox" checked={checked} onChange={() => toggle(i)} aria-label={`Mark step ${i + 1} done`} className="mt-1 size-4 shrink-0 accent-teal" />
                  <div className="min-w-0 flex-1">
                    <h3 className={`font-medium ${checked ? 'line-through' : ''}`}>{i + 1}. {s.title} {s.active && <Badge tone="warn">active · needs authorisation</Badge>}</h3>
                    <p className="mt-1 text-sm text-muted">{s.detail}</p>
                    {s.toolIds.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {s.toolIds.map((tid) => { const t = RESOURCES.tools[tid]; return t ? <Link key={tid} to={`/resources?tool=${tid}`} className="inline-flex items-center gap-1 rounded-md border border-line2 px-2 py-0.5 text-xs text-muted hover:border-teal/40 hover:text-teal">{t.name}{t.opsec === 'active' && <span className="text-amber">●</span>}</Link> : null; })}
                      </div>
                    )}
                  </div>
                </div>
              </Card>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export default function PlaybooksPage({ id }: { id?: string }) {
  const [done] = useStored<Done>('tl-playbook-progress-v1', {});
  if (id) return <Detail id={id} />;
  return (
    <div className="max-w-4xl">
      <PageHeader icon="list" title="Investigation Playbooks" blurb="Step-by-step routes for common cases. Each step lists the tools to use; your progress is saved in this browser." />
      <div className="grid gap-3 sm:grid-cols-2">
        {PLAYBOOKS.map((b) => {
          const n = (done[b.id] ?? []).length;
          return (
            <Link key={b.id} to={`/playbooks/${b.id}`} className="group rounded-xl border border-line bg-panel/90 p-4 hover:border-teal/40">
              <div className="flex items-start justify-between gap-2"><h2 className="font-medium">{b.title}</h2><Icon name="arrow" className="mt-0.5 text-faint group-hover:text-teal" /></div>
              <p className="mt-1 text-sm text-muted">{b.summary}</p>
              <p className="mt-2 text-xs text-faint">{b.steps.length} steps{n > 0 ? ` · ${n} done` : ''}</p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
