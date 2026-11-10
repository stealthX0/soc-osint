/**
 * Short, readable reasoning for the dashboard's Overview tab, built from the verdict engine's output.
 *
 * The engine's reasons carry a one-line title (what was found) and a long detail (why it matters, with caveats). The
 * dashboard shows: one sentence that states the outcome and what kind of evidence drove it, the strongest findings as
 * short points (titles only), and one closing line saying what is (or is not) confirmed. The long details stay in the
 * Sender / Link / Content / Evidence tabs and in the exported report.
 */
import type { Dimension, Severity } from './types';
import type { Verdict } from './verdict';

export interface ReasoningPoint { text: string; severity: Severity }
export interface ReasoningSummary {
  /** One sentence: the outcome and the evidence behind it. */
  summary: string;
  /** The strongest findings, most important first (at most `maxPoints`). */
  points: ReasoningPoint[];
  /** What the evidence does not establish, or the main mitigating fact. */
  caveat: string | null;
}

const AREA: Record<Dimension, string> = {
  authentication: 'sender authentication',
  infrastructure: 'sending infrastructure',
  url: 'links',
  attachment: 'attachments',
  content: 'message content',
};

const list = (xs: string[]) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);

/** "Sender domain: Hostname uses …" -> "Hostname uses …"; trims a trailing full stop. */
function tidy(title: string): string {
  const t = title.replace(/^(sender domain|reply-to|return-path|link|attachment|url|file):\s+/i, '').trim().replace(/\.$/, '');
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export function summarizeReasoning(v: Verdict, maxPoints = 5): ReasoningSummary {
  const reasons = v.reasons;
  const areas = [...new Set(reasons.map((r) => r.dimension))].map((d) => AREA[d]);
  const strong = reasons.filter((r) => r.severity === 'critical' || r.severity === 'high').length;
  const points = reasons.slice(0, maxPoints).map((r) => ({ text: tidy(r.title), severity: r.severity }));
  const n = reasons.length;
  const indicators = `${n} warning sign${n === 1 ? '' : 's'}`;

  let summary: string;
  let caveat: string | null = null;
  switch (v.label) {
    case 'malicious':
      // The rule text ends with the deciding finding's title (": <title>"), which is already the first point.
      summary = v.rule
        ? `Malicious: ${v.rule.text.split(': ')[0].replace(/\.$/, '')}.`
        : `Malicious: strong, direct evidence across ${list(areas)}.`;
      caveat = v.conflicts.length ? `Some evidence conflicts: ${v.conflicts[0]}` : null;
      break;
    case 'suspicious':
      summary = `Suspicious: ${indicators}${strong ? ` (${strong} serious)` : ''} across ${list(areas)} point to phishing.`;
      caveat = 'No link, file or sender was confirmed malicious by threat intelligence, so this stops short of Malicious. Verify through a separate channel before acting.';
      break;
    case 'likely_legitimate':
      summary = n
        ? `Likely legitimate: only minor oddities were found (${list(areas)}), with nothing pointing to phishing.`
        : 'Likely legitimate: no meaningful threat indicators were found and the main checks completed.';
      caveat = v.mitigating[0] ?? 'This is not a guarantee: an authenticated sender can still send phishing.';
      break;
    case 'inconclusive':
      summary = `Inconclusive: ${v.headline.replace(/\.$/, '')}.`;
      caveat = v.gaps.find((g) => g.critical)?.text ?? v.gaps[0]?.text ?? null;
      break;
    default:
      summary = v.headline;
  }
  if (v.label !== 'likely_legitimate' && v.mitigating.length && !caveat?.startsWith('Some evidence')) {
    const m = `${v.mitigating[0].charAt(0).toLowerCase()}${v.mitigating[0].slice(1)}`;
    // Next to a Malicious verdict, authentication is context (a compromised but genuine mailbox), not a point in its favour.
    caveat = `${caveat ? `${caveat} ` : ''}${v.label === 'malicious' ? `Note: ${m} An authenticated sender can still send phishing.` : `In its favour: ${m}`}`;
  }
  return { summary, points, caveat };
}
