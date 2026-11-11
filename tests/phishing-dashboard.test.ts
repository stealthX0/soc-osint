/** Dashboard verdict area (Key Findings, Risk by Area, Reasoning) and the per-tab findings and counts. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { parseSubmission } from '../shared/phishing/parse';
import { computeVerdict } from '../shared/phishing/verdict';
import { dedupeFindings, sortFindings } from '../shared/phishing/findings';
import { buildReport } from '../shared/phishing/report';
import { summarizeReasoning } from '../shared/phishing/summary';
import { EXAMPLE_FORM, buildInput } from '../src/pages/phishing/formHelpers';
import { InvestigationDashboard } from '../src/pages/phishing/InvestigationDashboard';
import { areaStates, type AnalysisTab } from '../src/pages/phishing/OverviewParts';

const linkStub = { stage: null, busy: false, error: null, run: async () => {}, remaining: [], investigatedAt: null, settled: true };
const senderDone = { plan: { requests: [], skipped: [] }, slots: [], findings: [], results: [], running: 0, finishedAt: null, settled: true };
const attDone = { findings: [], checks: [], urls: [], results: [], panel: createElement('div', null, 'ATTACHMENT-PANEL'), settled: true };

async function fixture() {
  const input = buildInput(EXAMPLE_FORM);
  const r = await parseSubmission(input);
  const findings = sortFindings(dedupeFindings(r.findings));
  const rows = r.checks;
  const verdict = computeVerdict({ parse: r, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, status: c.status, result: c.result ?? null, detail: c.detail })) });
  const report = buildReport({ verdict, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, stage: c.stage, status: c.status, result: c.result, detail: c.detail })), parse: r, generatedAt: '2026-11-07T10:30:00Z' });
  return { input, r, findings, rows, verdict, report };
}
const render = (f: Awaited<ReturnType<typeof fixture>>, initialTab: AnalysisTab = 'overview') => renderToString(createElement(InvestigationDashboard, {
  r: f.r, input: f.input, verdict: f.verdict, findings: f.findings, rows: f.rows, pipeline: [], report: f.report, timeline: [],
  sender: senderDone as never, links: linkStub as never, att: attDone as never, startedAt: Date.now(), initialTab,
}));

describe('dashboard verdict area', () => {
  it('Key Findings has a card for every area with findings, including attachments, and no "looks legitimate" claim', async () => {
    const f = await fixture();
    const out = render(f);
    const kf = out.slice(out.indexOf('Key Findings'), out.indexOf('Detailed Analysis'));
    for (const area of ['Authentication', 'Links', 'Attachments', 'Content']) assert.ok(kf.includes(area), area);
    assert.match(kf, /pdf\.exe|program, script or launcher/i, 'the attachment finding reaches Key Findings');
    assert.match(kf, /more finding/);
    assert.doesNotMatch(kf, /looks legitimate/);
  });

  it('an area with no data is neutral, never green', async () => {
    const f = await fixture();
    const v = { ...f.verdict, dimensions: f.verdict.dimensions.map((d) => ({ ...d, active: false })) };
    for (const a of areaStates(v, [])) assert.equal(a.tone, 'neutral', a.dim);
  });

  it('the overview shows Risk by Area, key evidence with severity words, what is missing and numbered actions', async () => {
    const f = await fixture();
    const out = render(f);
    for (const s of ['Risk by Area', 'Key evidence', 'What is missing', 'Recommended actions', 'Confidence:']) assert.ok(out.includes(s), s);
    const x = summarizeReasoning(f.verdict);
    for (const p of x.points) assert.ok(out.includes(p.text.replace(/"/g, '&quot;')), p.text);
    assert.ok(x.points.every((p) => typeof p.dimension === 'string'));
    assert.doesNotMatch(out, /\.\.<\/span>/, 'no doubled full stop in gap text');
  });
});

describe('analysis tabs', () => {
  it('has an Attachments tab with a finding count, and each tab shows its findings', async () => {
    const f = await fixture();
    const overview = render(f);
    assert.match(overview, />Attachments(?:<!-- -->)?<span[^>]*aria-label="2 findings"/);
    const att = render(f, 'attachments');
    assert.ok(att.includes('Attachment findings') && att.includes('ATTACHMENT-PANEL'));
    assert.ok(render(f, 'urls').includes('Link findings'));
    assert.ok(render(f, 'domain').includes('Authentication and infrastructure findings'));
    const sender = render(f, 'sender');
    assert.ok(sender.indexOf('Sender identity findings') < sender.indexOf('Sender reputation lookups'), 'identity findings come first');
  });
});
