/** Tiny, dependency-free HTML helpers (Workers have no DOM). Good enough for e-mail: we only need text, attributes and anchors. */

const NAMED: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', middot: '·', euro: '€', pound: '£', yen: '¥', zwnj: '\u200c', zwj: '\u200d', shy: '\u00ad',
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
      } catch {
        return m;
      }
    }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

/**
 * Linear-time tag handling. Pasted e-mail is attacker-controlled and can be megabytes of unclosed or malformed tags, which
 * makes regexes such as /<a\b[^>]*>[\s\S]*?<\/a>/ quadratic (a 2 MB body took about a minute). Everything below walks the
 * string once, remembers where the next ">" or closing tag is, and refuses tags longer than MAX_TAG characters.
 */
export const MAX_TAG = 2000;

/** Finds the end ">" of each tag in ascending order without rescanning (amortised linear). */
export class TagEnds {
  private gt = -1;
  constructor(private readonly s: string) {}
  /** Index of the first ">" at or after `from`, or -1. */
  next(from: number): number {
    if (this.gt < from) {
      if (this.gt === -2) return -1; // already known: no ">" anywhere after the last search start
      this.gt = this.s.indexOf('>', from);
      if (this.gt < 0) { this.gt = -2; return -1; }
    }
    return this.gt;
  }
}

/** Calls fn(name, attrText, tagStart, tagEnd) for each opening tag whose name is in `names`, up to `cap` tags. */
export function eachTag(html: string, names: readonly string[], cap: number, fn: (name: string, attrs: string, start: number, end: number) => void): boolean {
  const re = new RegExp(`<(${names.join('|')})\\b`, 'gi');
  const ends = new TagEnds(html);
  let n = 0;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    const gt = ends.next(m.index);
    if (gt < 0) break; // no ">" left: nothing after this can be a complete tag
    if (gt - m.index > MAX_TAG) continue;
    if (++n > cap) return true;
    fn(m[1].toLowerCase(), html.slice(m.index + m[0].length, gt), m.index, gt + 1);
  }
  return false;
}

/** Removes every <...> tag (up to MAX_TAG long) in one pass. */
export function stripTags(html: string): string {
  const ends = new TagEnds(html);
  const out: string[] = [];
  let i = 0;
  for (;;) {
    const lt = html.indexOf('<', i);
    if (lt < 0) break;
    const gt = ends.next(lt);
    if (gt < 0) break;
    if (gt - lt > MAX_TAG) { out.push(html.slice(i, lt + 1)); i = lt + 1; continue; }
    out.push(html.slice(i, lt));
    i = gt + 1;
  }
  out.push(html.slice(i));
  return out.join('');
}

function stripComments(html: string): string {
  const out: string[] = [];
  let i = 0;
  for (;;) {
    const open = html.indexOf('<!--', i);
    if (open < 0) break;
    out.push(html.slice(i, open));
    const close = html.indexOf('-->', open + 4);
    if (close < 0) { i = html.length; break; } // an unclosed comment swallows the rest, as browsers do
    i = close + 3;
  }
  out.push(html.slice(i));
  return out.join('');
}

/** Drops <script>/<style>/<head>/<title> blocks. A block with no closing tag costs one search, never one per opening. */
function stripBlocks(html: string): string {
  const lower = html.toLowerCase();
  const re = /<(script|style|head|title)\b/g;
  const missing = new Set<string>();
  const ends = new TagEnds(lower);
  const out: string[] = [];
  let i = 0;
  for (;;) {
    re.lastIndex = i;
    const m = re.exec(lower);
    if (!m) break;
    out.push(html.slice(i, m.index));
    const name = m[1];
    const afterOpen = m.index + m[0].length;
    if (!missing.has(name)) {
      const close = lower.indexOf(`</${name}`, afterOpen);
      if (close >= 0) {
        const gt = lower.indexOf('>', close);
        i = gt < 0 ? html.length : gt + 1;
        continue;
      }
      missing.add(name);
    }
    const gt = ends.next(m.index);
    i = gt >= 0 && gt - m.index <= MAX_TAG ? gt + 1 : afterOpen; // drop just this opening tag
  }
  out.push(html.slice(i));
  return out.join('');
}

export function htmlToText(html: string): string {
  return decodeEntities(
    stripTags(
      stripComments(stripBlocks(html))
        .replace(/<br\s{0,20}\/?>|<\/(?:p|div|tr|li|h[1-6]|table|blockquote)\s{0,20}>/gi, '\n')
        .replace(/<\/t[dh]\s{0,20}>/gi, ' '),
    ),
  )
    .replace(/[ \t\u00a0]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Attributes of one tag's text (everything after the tag name). Values are entity-decoded; names are lower-cased. */
export function parseAttrs(attrText: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const m of attrText.matchAll(re)) {
    const name = m[1].toLowerCase();
    if (!(name in out)) out[name] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  }
  return out;
}

export const looksLikeHtml = (s: string): boolean => /<\/?(?:html|body|div|table|a|p|br|span|img|font|center|td|tr)\b/i.test(s);
