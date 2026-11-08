import { FINDING_DESCRIPTIONS } from './findingCatalogue';
import { POINTS, groupOf } from './verdictRules';
import { makeFinding } from './findings';
import type { Severity } from './types';

export const CATALOGUE_START = '<!-- finding-catalogue:start -->';
export const CATALOGUE_END = '<!-- finding-catalogue:end -->';

const SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const prefix = (id: string): string => (id.startsWith('attachment_') ? 'Attachments' : id.startsWith('url_') || id.startsWith('link_') || id === 'dangerous_link_scheme' ? 'URLs and destinations' : id.startsWith('content_') ? 'Message wording' : id.startsWith('sender_') || id.startsWith('display_') || id.startsWith('role_') ? 'Sender identity and infrastructure' : 'Authentication and headers');

/** Markdown tables of every scored finding id: group, base points and meaning. Generated, never edited by hand. */
export function catalogueMarkdown(): string {
  const sections = new Map<string, string[]>();
  for (const [id, spec] of Object.entries(POINTS)) {
    const pts = typeof spec === 'number' ? String(spec) : SEV.filter((s) => spec[s] !== undefined).map((s) => `${s} ${spec[s]}`).join(', ');
    const g = groupOf(makeFinding({ id, dimension: 'content', severity: 'low', title: id, detail: '' }));
    const group = g ? g.split(':')[0].replace(/_/g, ' ') : 'none';
    const row = `| \`${id}\` | ${pts} | ${group} | ${FINDING_DESCRIPTIONS[id] ?? '**MISSING DESCRIPTION**'} |`;
    const key = prefix(id);
    sections.set(key, [...(sections.get(key) ?? []), row]);
  }
  return [...sections].map(([name, rows]) => `#### ${name}\n\n| Finding id | Base points | Counted once with | Meaning |\n|---|---|---|---|\n${rows.join('\n')}\n`).join('\n');
}

export function spliceCatalogue(doc: string, table: string): string {
  const a = doc.indexOf(CATALOGUE_START);
  const b = doc.indexOf(CATALOGUE_END);
  if (a < 0 || b < 0 || b < a) throw new Error('catalogue markers not found');
  return `${doc.slice(0, a + CATALOGUE_START.length)}\n\n${table}\n${doc.slice(b)}`;
}
