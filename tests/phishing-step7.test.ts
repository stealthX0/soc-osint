import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { parseSubmission, type ParseStageResult } from '../shared/phishing/parse';
import { computeVerdict, VERDICT_TEXT, type Verdict, type VerdictLabel } from '../shared/phishing/verdict';
import { dedupeFindings, sortFindings } from '../shared/phishing/findings';
import {
  REPORT_DISCLAIMERS, buildReport, defangText, parseStoredReport, renderJson, renderMarkdown, renderTicketText, reportFilename, sanitizeFilenameStem, type Report, type ReportCheckInput,
} from '../shared/phishing/report';
import {
  HISTORY_KEY, HISTORY_MAX, clearHistory, deleteFromHistory, loadHistory, saveToHistory, summarizeEntry, type HistoryStore,
} from '../src/lib/phishingHistory';
import { EMPTY_FORM, EML_MAX_BYTES, EXAMPLE_FORM, buildInput, checkEmlFile, emlLoadedMessage, looksLikeBody, measureForm } from '../src/pages/phishing/formHelpers';
import { allCheckRows, buildPipeline, type CheckRowX } from '../src/pages/phishing/model';
import type { Finding } from '../shared/phishing/types';

import { InputForm } from '../src/pages/phishing/InputForm';
import { OverviewTab } from '../src/pages/phishing/OverviewTab';
import { HeadersTab } from '../src/pages/phishing/HeadersTab';
import { SenderTab } from '../src/pages/phishing/SenderTab';
import { UrlTab } from '../src/pages/phishing/UrlTab';
import { AttachmentTab, useAttachmentStage } from '../src/pages/phishing/AttachmentPanel';
import { EvidenceTab } from '../src/pages/phishing/EvidenceTab';
import { FinishedReport, ResultsShell } from '../src/pages/phishing/ResultsShell';
import { HistoryPanel } from '../src/pages/phishing/HistoryPanel';
import { ReportView } from '../src/pages/phishing/ReportView';

/* ------------------------------------------------------------------ fixtures */

async function fixture(over: Partial<typeof EXAMPLE_FORM> = {}) {
  const input = buildInput({ ...EXAMPLE_FORM, ...over });
  const r = await parseSubmission(input);
  const findings = sortFindings(dedupeFindings(r.findings));
  const rows: CheckRowX[] = r.checks;
  const verdict = computeVerdict({ parse: r, findings, checks: rows.map((c) => ({ id: c.id, label: c.label, status: c.status, result: c.result ?? null, detail: c.detail })) });
  const checks: ReportCheckInput[] = rows.map((c) => ({ id: c.id, label: c.label, stage: c.stage, status: c.status, result: c.result, detail: c.detail }));
  const report = buildReport({ verdict, findings, checks, parse: r, generatedAt: '2026-11-07T10:30:00Z' });
  return { input, r, findings, rows, verdict, checks, report };
}
const LABELS = Object.keys(VERDICT_TEXT) as VerdictLabel[];

function fakeStore(initial?: unknown): HistoryStore & { data: Record<string, unknown>; writes: number } {
  const s = { data: {} as Record<string, unknown>, writes: 0, read<T>(k: string, fb: T): T { return k in s.data ? (s.data[k] as T) : fb; }, write(k: string, v: unknown) { s.writes++; s.data[k] = JSON.parse(JSON.stringify(v)); } };
  if (initial !== undefined) s.data[HISTORY_KEY] = initial;
  return s;
}
const brokenStore: HistoryStore = { read() { throw new Error('blocked'); }, write() { throw new Error('blocked'); } };

/* ------------------------------------------------------------------ defanging */

describe('defangText', () => {
  it('defangs URLs, domains, IPv4, IPv6 and e-mail addresses', () => {
    assert.equal(defangText('go to https://evil.example/login?x=1 now'), 'go to hxxps://evil[.]example/login?x=1 now');
    assert.equal(defangText('mail bob@evil.example today'), 'mail bob[@]evil[.]example today');
    assert.equal(defangText('from 203.0.113.45 and mail.evil.example'), 'from 203[.]0[.]113[.]45 and mail[.]evil[.]example');
    assert.equal(defangText('v6 2001:db8:0:0:0:0:0:1 here'), 'v6 2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1 here');
    assert.equal(defangText('ftp://files.evil.example/a'), 'ftp://files[.]evil[.]example/a'.replace('ftp', 'ftp'));
  });
  it('is idempotent and leaves ordinary text alone', () => {
    const once = defangText('see http://evil.example/a and 203.0.113.9 or x@evil.example');
    assert.equal(defangText(once), once);
    assert.equal(defangText('Authentication failed (e.g. SPF) at step 3, risk 45/100.'), 'Authentication failed (e.g. SPF) at step 3, risk 45/100.');
  });
});

/* ------------------------------------------------------------------ buildReport */

describe('buildReport', () => {
  it('has a schema version, a timestamp and the tool name', async () => {
    const { report } = await fixture();
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.generatedAt, '2026-11-07T10:30:00.000Z');
    assert.match(report.tool, /Spectrix/);
    assert.deepEqual(Object.keys(report).sort(), ['actions', 'checkSummary', 'checks', 'conflicts', 'disclaimers', 'findings', 'gaps', 'generatedAt', 'indicators', 'message', 'mitigating', 'reasons', 'schemaVersion', 'senderDomain', 'tool', 'verdict'].sort());
  });

  it('defangs every indicator type, everywhere in the report', async () => {
    // The form no longer has a sender box; an IP is still accepted by the API, so supply one to cover the IP indicator type.
    const { report, input } = await fixture({ ip: '203.0.113.45' });
    const json = renderJson(report);
    for (const raw of ['paypa1-secure.example', 'paypal-support.example', 'mailbox-help.example', 'support@paypal-support.example', '203.0.113.45', 'bounce.paypa1-secure.example']) {
      assert.ok(!json.includes(raw), `${raw} must not appear un-defanged`);
    }
    assert.ok(json.includes('paypa1-secure[.]example'));
    assert.ok(json.includes('203[.]0[.]113[.]45'));
    assert.ok(json.includes('support[@]paypal-support[.]example'));
    assert.ok(!/https?:\/\//i.test(json), 'no live URL schemes');
    assert.ok(json.includes('hxxps://'), 'URLs are written as hxxps://');
    assert.ok(report.indicators.some((i) => i.type === 'url' && i.value.startsWith('hxxps://')));
    assert.ok(report.indicators.some((i) => i.type === 'ip' && i.value === '203[.]0[.]113[.]45'));
    assert.ok(report.indicators.some((i) => i.type === 'domain'));
    assert.ok(report.indicators.some((i) => i.type === 'email'));
    // and in text produced from findings
    for (const text of [renderTicketText(report), renderMarkdown(report)]) {
      assert.ok(!/\b203\.0\.113\.45\b/.test(text));
      assert.ok(!/paypa1-secure\.example/.test(text));
    }
    assert.ok(input.sender?.ip === '203.0.113.45', 'the live input is untouched');
  });

  it('never contains the message body, the headers or attachment bytes', async () => {
    const f = await fixture({
      body: `${EXAMPLE_FORM.body}\n\nZQXBODYMARKER-9f31 this sentence is only in the body and must stay out of every export.`,
      headers: `${EXAMPLE_FORM.headers}\nX-Spectrix-Marker: HDRMARKER-77aa-private-header-value`,
    });
    const all = [renderJson(f.report), renderTicketText(f.report), renderMarkdown(f.report)].join('\n');
    assert.ok(!all.includes('ZQXBODYMARKER'));
    assert.ok(!all.includes('HDRMARKER'));
    assert.ok(!all.includes('TRAINING0001'), 'raw Received lines are not copied');
    assert.ok(!JSON.stringify(f.report).includes('"raw"'));
    const keys = JSON.stringify(Object.keys(f.report));
    assert.ok(!/body|headers|raw/i.test(keys));
  });

  it('states the weights are uncalibrated decision support, and never calls anything safe or clean', async () => {
    const { report } = await fixture();
    assert.ok(report.disclaimers.some((d) => /uncalibrated/i.test(d) && /decision support/i.test(d)));
    for (const label of LABELS) {
      const r = buildReport({ ...(await fixture()), verdict: { ...(await fixture()).verdict, label }, parse: (await fixture()).r, generatedAt: Date.now() } as never);
      const rendered = [renderTicketText(r), renderMarkdown(r)].join('\n');
      assert.match(rendered, /uncalibrated/i);
    }
    const templated = [...REPORT_DISCLAIMERS, ...LABELS.flatMap((l) => [VERDICT_TEXT[l].label, VERDICT_TEXT[l].short])].join('\n');
    assert.doesNotMatch(templated, /\b(safe|clean)\b/i);
    const { report: rp } = await fixture();
    assert.doesNotMatch(renderTicketText(rp), /\b(is|are|looks) (safe|clean)\b/i);
    assert.doesNotMatch(renderMarkdown(rp), /\bsafe email\b|\bclean email\b/i);
  });

  it('covers all five verdict labels in the report and all three renderers', async () => {
    const base = await fixture();
    for (const label of LABELS) {
      const v: Verdict = { ...base.verdict, label };
      const r = buildReport({ verdict: v, findings: base.findings, checks: base.checks, parse: base.r, generatedAt: '2026-11-07T10:30:00Z' });
      assert.equal(r.verdict.label, label);
      assert.equal(r.verdict.labelText, VERDICT_TEXT[label].label);
      assert.ok(renderTicketText(r).includes(`Verdict: ${VERDICT_TEXT[label].label}`));
      assert.ok(renderMarkdown(r).includes(`## Verdict: ${VERDICT_TEXT[label].label}`));
      assert.equal(JSON.parse(renderJson(r)).verdict.label, label);
    }
    assert.equal(LABELS.length, 5);
  });

  it('summarises checks, including failed and skipped ones, and does not hide them', async () => {
    const base = await fixture();
    const checks: ReportCheckInput[] = [...base.checks, { id: 'x.1', label: 'VirusTotal: https://evil.example/a', stage: 'urls', status: 'failed', detail: 'timed out' }, { id: 'x.2', label: 'Pulsedive', stage: 'urls', status: 'skipped', detail: 'No key' }, { id: 'x.3', label: 'urlscan', stage: 'urls', status: 'running' }];
    const r = buildReport({ verdict: base.verdict, findings: base.findings, checks, parse: base.r, generatedAt: Date.now() });
    assert.equal(r.checkSummary.failed, base.checks.filter((c) => c.status === 'failed').length + 1);
    assert.equal(r.checkSummary.running, 1);
    assert.equal(r.checkSummary.total, checks.length);
    const ticket = renderTicketText(r);
    assert.match(ticket, /- failed: VirusTotal: hxxps:\/\/evil\[\.\]example\/a/);
    assert.match(ticket, /- skipped: Pulsedive/);
    assert.match(ticket, /- running: urlscan/);
  });

  it('keeps only short evidence excerpts from findings', async () => {
    const base = await fixture();
    const long: Finding = { id: 'x', dimension: 'content', severity: 'low', title: 't', detail: 'd', source: 's', exactness: 'exact', reliability: 'low', trust: 'derived', evidence: ['a'.repeat(5000), 'b', 'c', 'd', 'e', 'f', 'g'] };
    const r = buildReport({ verdict: base.verdict, findings: [long], checks: [], parse: base.r });
    assert.equal(r.findings[0].evidence.length, 5);
    assert.ok(r.findings[0].evidence[0].length <= 240);
  });
});

describe('the three renderers', () => {
  it('ticket text has the verdict, risk, reasons, missing items, actions, defanged indicators, check summary and date', async () => {
    const { report } = await fixture();
    const t = renderTicketText(report);
    assert.match(t, /^SPECTRIX PHISHING INVESTIGATION/);
    assert.match(t, /Date: 07\/11\/2026 10:30 UTC/);
    assert.match(t, new RegExp(`Verdict: ${report.verdict.labelText}`));
    assert.match(t, /Risk: \d+\/100 · Confidence: (low|medium|high)/);
    assert.match(t, /\nWHY\n1\. \[/);
    assert.match(t, /INDICATORS \(defanged\)/);
    assert.match(t, /CHECKS\n\d+ total: \d+ complete/);
    assert.match(t, /NOTES\n- The scoring weights/);
    if (report.gaps.length) assert.match(t, /WHAT IS MISSING/);
    if (report.actions.length) assert.match(t, /RECOMMENDED ACTIONS/);
  });

  it('markdown has headings and tables, escapes pipes, and JSON round-trips through the schema guard', async () => {
    const { report } = await fixture();
    const md = renderMarkdown(report);
    assert.match(md, /^# Spectrix Phishing Investigation/);
    assert.match(md, /\| Field \| Value \|/);
    assert.match(md, /## Checks/);
    const evil: Report = { ...report, message: { ...report.message, subject: 'a | b | c\nnew line' } };
    assert.ok(!/\| Subject \| a \| b/.test(renderMarkdown(evil)));
    const back = parseStoredReport(JSON.parse(renderJson(report)));
    assert.deepEqual(back, report);
  });

  it('file names are lower-case [a-z0-9-] with a fixed extension', async () => {
    const { report } = await fixture();
    for (const ext of ['md', 'json', 'txt'] as const) {
      const n = reportFilename({ ...report, message: { ...report.message, subject: '../../Évil/Subject: "<script>" & \\ name.exe ' } }, ext);
      assert.match(n, /^[a-z0-9-]+\.(md|json|txt)$/);
      assert.ok(n.endsWith(`.${ext}`));
      assert.ok(!n.includes('..') && !n.includes('/') && !n.includes('\\'));
    }
    assert.equal(sanitizeFilenameStem('../../etc/passwd'), 'etc-passwd');
    assert.equal(sanitizeFilenameStem('   '), 'report');
    assert.equal(sanitizeFilenameStem('Ünïcödé'), 'n-c-d');
    assert.equal(sanitizeFilenameStem('a'.repeat(200)).length, 60);
    assert.match(reportFilename(report, 'md'), /^spectrix-phishing-[a-z-]+-2026-11-07-/);
  });
});

describe('parseStoredReport', () => {
  it('rejects non-reports and drops unknown fields', async () => {
    const { report } = await fixture();
    for (const bad of [null, 5, 'x', [], {}, { schemaVersion: 2 }, { ...report, schemaVersion: 2 }, { ...report, verdict: { ...report.verdict, label: 'safe' } }, { ...report, generatedAt: 'nope' }]) assert.equal(parseStoredReport(bad), null);
    const tampered = { ...report, headers: 'RAW HEADERS', body: 'RAW BODY', message: { ...report.message, rawBody: 'x' } };
    const clean = parseStoredReport(tampered)!;
    assert.ok(!('headers' in clean) && !('body' in clean) && !('rawBody' in clean.message));
    assert.ok(!JSON.stringify(clean).includes('RAW BODY'));
  });
});

/* ------------------------------------------------------------------ history */

describe('phishing history store', () => {
  it('saves, reads back newest first, and keeps only the last 20', async () => {
    const { report } = await fixture();
    const store = fakeStore();
    for (let i = 0; i < 25; i++) saveToHistory({ ...report, message: { ...report.message, subject: `s${i}` } }, { store, now: 1_800_000_000_000 + i * 1000 });
    const h = loadHistory(store);
    assert.equal(h.length, HISTORY_MAX);
    assert.equal(h[0].report.message.subject, 's24');
    assert.equal(h[19].report.message.subject, 's5');
    assert.ok(h.every((e, i, a) => i === 0 || a[i - 1].savedAt >= e.savedAt));
  });

  it('replaces an entry with the same id instead of duplicating it, and deletes and clears', async () => {
    const { report } = await fixture();
    const store = fakeStore();
    saveToHistory(report, { store, id: 'run-1', now: 1_800_000_000_000 });
    saveToHistory({ ...report, verdict: { ...report.verdict, risk: 77 } }, { store, id: 'run-1', now: 1_800_000_005_000 });
    saveToHistory(report, { store, id: 'run-2', now: 1_800_000_006_000 });
    assert.deepEqual(loadHistory(store).map((e) => e.id), ['run-2', 'run-1']);
    assert.equal(loadHistory(store).find((e) => e.id === 'run-1')!.report.verdict.risk, 77);
    assert.deepEqual(deleteFromHistory('run-2', store).map((e) => e.id), ['run-1']);
    assert.deepEqual(clearHistory(store), []);
    assert.deepEqual(loadHistory(store), []);
  });

  it('survives corrupt JSON and damaged entries', async () => {
    const { report } = await fixture();
    for (const junk of ['garbage', 42, null, {}, [null, 3, 'x'], [{ id: 'a' }], [{ id: 'a', savedAt: 'x', report }], [{ id: 'a', savedAt: '2026-11-07T00:00:00Z', report: { schemaVersion: 9 } }]]) {
      assert.deepEqual(loadHistory(fakeStore(junk)), [], JSON.stringify(junk)?.slice(0, 40));
    }
    const mixed = loadHistory(fakeStore([{ id: 'ok', savedAt: '2026-11-07T00:00:00Z', report }, { id: 'bad' }, 'x']));
    assert.deepEqual(mixed.map((e) => e.id), ['ok']);
    // a refused report is not stored
    const store = fakeStore();
    saveToHistory({ nope: true } as never, { store });
    assert.equal(store.writes, 0);
  });

  it('stores only the report, an id and a timestamp: never the pasted input', async () => {
    const f = await fixture({ body: `${EXAMPLE_FORM.body}\nZQXBODYMARKER-9f31` });
    const store = fakeStore();
    const poisoned = { ...f.report, headers: f.input.headers, body: f.input.body, attachments: [{ name: 'x', bytes: [1, 2, 3] }], input: f.input } as never;
    saveToHistory(poisoned, { store, id: 'r1', now: 1_800_000_000_000 });
    const raw = JSON.stringify(store.data[HISTORY_KEY]);
    assert.ok(!raw.includes('ZQXBODYMARKER'));
    const keys = new Set<string>();
    const walkKeys = (v: unknown) => { if (Array.isArray(v)) v.forEach(walkKeys); else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { keys.add(k); walkKeys(x); } };
    walkKeys(store.data[HISTORY_KEY]);
    for (const k of ['headers', 'body', 'attachments', 'input', 'raw', 'bytes']) assert.ok(!keys.has(k), `no "${k}" key is stored`);
    const entry = (store.data[HISTORY_KEY] as Record<string, unknown>[])[0];
    assert.deepEqual(Object.keys(entry).sort(), ['id', 'report', 'savedAt']);
  });

  it('a blocked or throwing storage never throws into the UI', async () => {
    const { report } = await fixture();
    assert.deepEqual(loadHistory(brokenStore), []);
    assert.doesNotThrow(() => saveToHistory(report, { store: brokenStore }));
    assert.doesNotThrow(() => deleteFromHistory('x', brokenStore));
    assert.doesNotThrow(() => clearHistory(brokenStore));
    // and with no window at all (server rendering), the default store falls back quietly
    assert.doesNotThrow(() => loadHistory());
    assert.doesNotThrow(() => saveToHistory(report));
  });

  it('list rows show date, verdict, risk, subject cut to 80 characters and the From domain', async () => {
    const { report } = await fixture();
    const store = fakeStore();
    saveToHistory({ ...report, message: { ...report.message, subject: 'x'.repeat(200), fromDomain: 'paypal-support[.]example' } }, { store, id: 'r', now: Date.parse('2026-11-07T10:30:00Z') });
    const row = summarizeEntry(loadHistory(store)[0]);
    assert.equal(row.subject.length, 80);
    assert.ok(row.subject.endsWith('…'));
    assert.equal(row.fromDomain, 'paypal-support[.]example');
    assert.equal(row.date, '2026-11-07T10:30:00.000Z');
    assert.equal(row.labelText, report.verdict.labelText);
    assert.equal(row.risk, report.verdict.risk);
  });
});

/* ------------------------------------------------------------------ form helpers */

describe('guided input helpers', () => {
  it('email file size check: 10 MB limit, with a clear message', () => {
    assert.equal(EML_MAX_BYTES, 10 * 1024 * 1024);
    assert.deepEqual(checkEmlFile({ name: 'a.msg', size: 1000 }), { ok: true });
    assert.deepEqual(checkEmlFile({ name: 'a.eml', size: EML_MAX_BYTES }), { ok: true });
    const big = checkEmlFile({ name: 'huge.mbox', size: EML_MAX_BYTES + 1 });
    assert.equal(big.ok, false);
    if (!big.ok) assert.match(big.message, /huge\.mbox is 10\.0 MB\. Email files larger than 10\.0 MB are not loaded/);
    assert.equal(checkEmlFile({ name: 'e.eml', size: 0 }).ok, false);
    assert.equal(emlLoadedMessage('a.msg', '.msg', 2), 'Loaded a.msg (.msg): headers and body extracted. 2 attachments added below for scanning.');
  });

  it('notices text that looks like a body rather than headers', () => {
    assert.equal(looksLikeBody(EXAMPLE_FORM.headers), false);
    assert.equal(looksLikeBody(`${EXAMPLE_FORM.headers}\n\n${EXAMPLE_FORM.body}`), false, 'a whole .eml is fine');
    assert.equal(looksLikeBody('Dear customer,\n\nYour account will be suspended unless you verify it today by clicking the link below.'), true);
    assert.equal(looksLikeBody('<html><body><p>Hello, please verify your account here</p></body></html>'), true);
    assert.equal(looksLikeBody('https://evil.example/verify/account?token=abcdefghijklmnop'), true);
    assert.equal(looksLikeBody('short'), false);
    assert.equal(looksLikeBody(''), false);
  });

  it('reports how much of the size limit is used', () => {
    const small = measureForm(EMPTY_FORM);
    assert.equal(small.level, 'ok');
    assert.ok(small.remaining > 2_900_000);
    assert.equal(measureForm({ ...EMPTY_FORM, headers: 'a'.repeat(150_000) }).level, 'over');
    assert.equal(measureForm({ ...EMPTY_FORM, body: 'a'.repeat(2_800_000) }).level, 'over');
  });

  it('the built-in example is a clearly fake training sample on reserved domains and documentation IPs', () => {
    const text = Object.entries(EXAMPLE_FORM).filter(([k]) => k !== 'attachments').map(([, v]) => v).join('\n');
    const domains = [...text.matchAll(/\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,})\b/gi)].map((m) => m[0].toLowerCase()).filter((d) => !/^\d/.test(d) && d !== 'paypal.com' && !['smtp.mailfrom', 'header.from'].includes(d));
    assert.ok(domains.length > 3);
    for (const d of domains) assert.ok(d.endsWith('.example') || d === 'example.com' || d.endsWith('.example.com'), d);
    for (const ip of text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) assert.match(ip, /^203\.0\.113\.\d+$/);
    assert.match(EXAMPLE_FORM.body, /TRAINING SAMPLE/);
  });
});

/* ------------------------------------------------------------------ pipeline model */

describe('pipeline strip', () => {
  const row = (stage: CheckRowX['stage'], status: CheckRowX['status'], id = Math.random().toString()): CheckRowX => ({ id, label: id, stage, status });
  it('uses complete / running / not run / failed and counts failed and skipped checks', () => {
    const chips = buildPipeline([row('parse', 'complete'), row('headers', 'complete'), row('authentication', 'skipped'), row('sender', 'running'), row('sender', 'complete'), row('attachments', 'failed'), row('attachments', 'skipped'), row('content', 'not_applicable')], { provisional: false, unavailable: false });
    const by = Object.fromEntries(chips.map((c) => [c.id, c]));
    assert.deepEqual(chips.map((c) => c.label), ['Parse', 'Headers and authentication', 'Sender intelligence', 'Links', 'Attachments', 'Wording', 'Verdict']);
    assert.equal(by.parse.status, 'complete');
    assert.equal(by.headers.status, 'complete');
    assert.equal(by.headers.skipped, 1);
    assert.equal(by.sender.status, 'running');
    assert.equal(by.urls.status, 'not run', 'links nobody has investigated yet');
    assert.equal(by.attachments.status, 'failed');
    assert.deepEqual([by.attachments.failed, by.attachments.skipped], [1, 1]);
    assert.equal(by.content.status, 'not run', 'only not-applicable rows');
    assert.equal(by.verdict.status, 'complete');
    assert.equal(buildPipeline([], { provisional: true, unavailable: false }).at(-1)!.status, 'running');
    assert.equal(buildPipeline([], { provisional: false, unavailable: true }).at(-1)!.status, 'failed');
  });

  it('shows unfinished and errored sender requests as running and failed, never as complete', () => {
    const slots = [
      { req: { check: 'ip', ip: '203.0.113.1', role: 'connecting' }, state: 'running' as const },
      { req: { check: 'domain', domain: 'a.example', roles: ['from'] }, state: 'done' as const, error: 'The lookup failed.' },
    ];
    const rows = allCheckRows({ parse: [], skipped: [], slots: slots as never, links: [], attachments: [] });
    assert.deepEqual(rows.map((r) => r.status), ['running', 'failed']);
    assert.ok(rows.every((r) => r.stage === 'sender'));
  });
});

/* ------------------------------------------------------------------ server-render smoke tests */

/** React inserts <!-- --> between adjacent text nodes; they are removed so assertions read like the visible text. */
const html = (el: unknown) => renderToString(el as never).replace(/<!-- -->/g, '');
const noop = () => {};
const linkStub = { stage: null, busy: false, error: null, run: async () => {}, remaining: [], investigatedAt: null, settled: true };
const senderDone = { plan: { requests: [], skipped: [] }, slots: [], findings: [], results: [], running: 0, finishedAt: null, settled: true };
const attDone = { findings: [], checks: [], urls: [], results: [], panel: null, settled: true };

describe('server-render smoke tests: every tab and the form render without throwing', () => {
  it('the input form', () => {
    const out = html(createElement(InputForm, { f: EMPTY_FORM, setF: noop, files: [], setFiles: noop, onSubmit: noop, busy: false }));
    for (const s of ['Raw email headers', 'Email information', 'Links and attachments', 'Load example', 'Choose an email file', 'or drop it here', 'Analyse email', 'Attach file', 'Subject <span class="text-faint">(optional)</span>', '.eml,.msg,.mbox']) assert.ok(out.includes(s), s);
    for (const gone of ['Sender information', 'Sender email address', 'up to 3 MB', 'Where did this email come from?', 'Reported by a user', 'Found in a mailbox', 'Training / test', 'EmailRep', 'Investigate links automatically', 'type="checkbox"']) assert.ok(!out.includes(gone), `${gone} was removed`);
    assert.match(out, /id="ph-h"/);
    const filled = html(createElement(InputForm, { f: { ...EXAMPLE_FORM, headers: 'Dear customer, your account will be suspended unless you act today, please click here.' }, setF: noop, files: [], setFiles: noop, onSubmit: noop, busy: true }));
    assert.match(filled, /looks like a message body/);
    assert.match(filled, /of 3\.0 MB used/);
  });

  it('1 Overview', async () => {
    const f = await fixture();
    const pipeline = buildPipeline(allCheckRows({ parse: f.r.checks, skipped: [], slots: [], links: [], attachments: [] }), { provisional: false, unavailable: false });
    const out = html(createElement(OverviewTab, { r: f.r, verdict: f.verdict, findings: f.findings, pipeline, report: f.report, running: 0 }));
    for (const s of ['Investigation verdict', 'Pipeline', 'Key facts', 'Top findings', 'Message wording analysis', 'Indicators', 'Export report', 'Copy ticket text', 'Download Markdown', 'Download JSON', 'Print / save as PDF', 'Headers and authentication', 'Sender intelligence', 'not run']) assert.ok(out.includes(s), s);
    assert.match(out, /<details/);
    assert.ok(!/<details[^>]* open/.test(out.split('Message wording analysis')[0].slice(-200)), 'wording analysis is collapsed by default');
    assert.match(out, /initial values still being calibrated/);
  });

  it('2 Email Headers', async () => {
    const f = await fixture();
    const out = html(createElement(HeadersTab, { r: f.r }));
    assert.ok(out.length > 500);
    assert.match(out, /Authentication/);
    for (const gone of ['Sending infrastructure', 'Delivery path', 'What you entered vs what the headers say', 'as reported in the headers']) assert.ok(!out.includes(gone), gone);
    const none = html(createElement(HeadersTab, { r: await parseSubmission({ body: 'hello' }) }));
    assert.match(none, /Paste the raw headers/);
  });

  it('3 Sender Intelligence', async () => {
    const f = await fixture();
    const out = html(createElement(SenderTab, { slots: [], skipped: [], running: 0, findings: f.findings }));
    assert.match(out, /Sender identity findings/);
    assert.match(out, /Reputation describes the IP, domain or address/);
    const ident = html(createElement(SenderTab, { slots: [], skipped: [], running: 0, findings: f.findings.filter((x) => /brand|lookalike|display_name/i.test(x.id)) }));
    assert.ok(f.findings.some((x) => /brand|lookalike|display_name/i.test(x.id)), 'the sample trips an identity finding');
    assert.ok(!ident.includes('No brand, look-alike or display-name findings'));
  });

  it('4 URL Analysis', async () => {
    const f = await fixture();
    const out = html(createElement(UrlTab, { r: f.r, links: linkStub }));
    assert.match(out, /Investigate links/);
    assert.match(out, /This is an active check/);
    assert.match(out, /paypa1-secure\.example/);
    const empty = html(createElement(UrlTab, { r: await parseSubmission({ body: 'no links here at all' }), links: linkStub }));
    assert.match(empty, /No links were found/);
  });

  it('5 Attachment Analysis', async () => {
    const f = await fixture();
    const Harness = () => createElement(AttachmentTab, { att: useAttachmentStage(f.r) });
    const out = html(createElement(Harness));
    assert.doesNotMatch(out, /Drop an attachment here/, 'no adding files after the analysis was submitted');
    assert.match(out, /Invoice_4491\.pdf\.exe/);
    assert.match(out, /Check hash reputation/);
  });

  it('6 Evidence: findings and check status only (no timeline, no raw provider results)', async () => {
    const f = await fixture();
    const out = html(createElement(EvidenceTab, { findings: f.findings, checks: f.rows }));
    for (const s of ['All findings', 'Check status', 'Severity', 'Dimension', 'Source', 'Trust', 'Showing']) assert.ok(out.includes(s), s);
    for (const s of ['Timeline', 'Raw provider results', 'Investigation started']) assert.ok(!out.includes(s), s);
    assert.match(out, /skipped|complete/);
  });

  it('failed and skipped checks look different from complete ones, with a word and a symbol', async () => {
    const rows: CheckRowX[] = [
      { id: 'a', label: 'AAA', stage: 'sender', status: 'complete', result: 'ok' },
      { id: 'b', label: 'BBB', stage: 'sender', status: 'failed', result: null, detail: 'timed out' },
      { id: 'c', label: 'CCC', stage: 'urls', status: 'skipped', result: null, detail: 'No key' },
      { id: 'd', label: 'DDD', stage: 'urls', status: 'running' },
    ];
    const out = html(createElement(EvidenceTab, { findings: [], checks: rows }));
    for (const s of ['✓ complete', '✕ failed', '– skipped', '… running']) assert.ok(out.includes(s), s);
    const row = (label: string) => out.slice(out.indexOf(`>${label}<`), out.indexOf(`>${label}<`) + 700);
    assert.ok(!/text-green|border-green/.test(row('BBB').split('</tr>')[0]), 'failed is not styled green');
    assert.ok(!/text-green|border-green/.test(row('CCC').split('</tr>')[0]), 'skipped is not styled green');
    assert.ok(!/text-green|border-green/.test(row('DDD').split('</tr>')[0]), 'running is not styled green');
    assert.ok(/text-green/.test(row('AAA').split('</tr>')[0]));
  });

  it('the finished report: the investigation dashboard with its analysis tabs and focusable verdict heading', async () => {
    const f = await fixture();
    const out = html(createElement(FinishedReport, { r: f.r, input: f.input, sender: senderDone, links: linkStub, att: attDone, startedAt: Date.now(), historyEnabled: false }));
    for (const s of ['Email Investigation Dashboard', 'Investigation Summary', 'Input Details', 'Key Findings', 'Detailed Analysis', 'Overview', 'Sender Analysis', 'Link Analysis', 'Domain &amp; IP Intelligence', 'Content Analysis', 'Evidence']) assert.ok(out.includes(s), s);
    for (const gone of ['Indicators Checked', 'Link Details', 'IP Reputation']) assert.ok(!out.includes(gone), `${gone} panel was removed (it has its own tab)`);
    assert.match(out, /<h2[^>]*tabindex="-1"/);
  });

  it('Input Details shows the sender address only (no display name) and the internal Microsoft 365 sending device IP', async () => {
    const headers = [
      'Received: from SUB01.eurprd07.prod.outlook.com ([fe80::1]) by SUB01.eurprd07.prod.outlook.com ([fe80::1%4]) with mapi id 15.21.0592.009; Wed, 4 Nov 2026 08:13:34 +0000',
      'From: Works Council Example SAS <council@example-corp.com>', 'To: alex@example-corp.com', 'Subject: News', 'Date: Wed, 4 Nov 2026 08:13:34 +0000',
      'X-MS-Exchange-Organization-AuthAs: Internal', 'x-ms-exchange-organization-originalclientipaddress: 81.2.69.160', '', 'Hello',
    ].join('\n');
    const r = await parseSubmission({ headers });
    const out = html(createElement(FinishedReport, { r, input: { headers }, sender: senderDone, links: linkStub, att: attDone, startedAt: Date.now(), historyEnabled: false }));
    const card = out.slice(out.indexOf('Input Details'), out.indexOf('Input Details') + 3000);
    assert.match(card, /council@example-corp\.com/);
    assert.ok(!card.includes('Works Council Example SAS'), 'no display name in From');
    assert.match(card, /81\.2\.69\.160/, 'sending device IP shown as Sender IP');
    assert.ok(!/<div class="[^"]*truncate[^"]*">council@/.test(card), 'the address is never cut off');
    const aside = /<aside class="([^"]*)"/.exec(out)?.[1] ?? '';
    assert.ok(!/bg-|border-r/.test(aside), 'the sidebar has no backdrop of its own');
  });

  it('while lookups are outstanding the shell renders a progress list and no verdict at all', async () => {
    const f = await fixture();
    const out = html(createElement(ResultsShell, { r: f.r, input: f.input, files: [], startedAt: Date.now() }));
    assert.match(out, /every lookup has finished/);
    assert.match(out, /Sender intelligence/);
    for (const hidden of ['Investigation verdict', 'role="tablist"', 'provisional', 'Investigation results']) assert.ok(!out.includes(hidden), `${hidden} must not show before all checks finish`);
  });

  it('the history panel and the read-only report view', async () => {
    const f = await fixture();
    const out = html(createElement(HistoryPanel, { enabled: true, setEnabled: noop, version: 0 }));
    assert.match(out, /Save investigations on this device/);
    assert.match(out, /never stored/);
    assert.match(out, /checked/);
    const off = html(createElement(HistoryPanel, { enabled: false, setEnabled: noop, version: 0 }));
    assert.ok(!/checked=""/.test(off));
    const view = html(createElement(ReportView, { report: f.report }));
    assert.match(view, /saved report · read-only/);
    assert.match(view, /Indicators \(defanged/);
    assert.match(view, /hxxps:\/\/paypa1-secure\[\.\]example/);
  });

  it('message-derived text is escaped, never rendered as HTML', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    const f = await fixture({ subject: evil, attachments: `${evil}.exe`, displayName: `<script>alert(1)</script>` });
    const shell = html(createElement(FinishedReport, { r: f.r, input: f.input, sender: senderDone, links: linkStub, att: attDone, startedAt: Date.now(), historyEnabled: false }));
    assert.ok(!shell.includes(evil), 'raw tag never appears');
    assert.ok(!shell.includes('<script>alert'), 'raw script never appears');
    const view = html(createElement(ReportView, { report: f.report }));
    assert.ok(!view.includes(evil) && !view.includes('<script>alert'));
  });
});

/* ------------------------------------------------------------------ source rules */

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) { const p = join(dir, n); if (statSync(p).isDirectory()) walk(p, out); else if (/\.(ts|tsx)$/.test(n)) out.push(p); }
  return out;
}

describe('UI safety rules', () => {
  const files = [...walk('src/pages/phishing'), 'src/pages/PhishingPage.tsx', 'src/lib/phishingHistory.ts'];
  it('never uses dangerouslySetInnerHTML, never imports from worker/, adds no network calls of its own', () => {
    for (const p of files) {
      const t = readFileSync(p, 'utf8');
      assert.ok(!t.includes('dangerouslySetInnerHTML'), `${p}: dangerouslySetInnerHTML`);
      assert.ok(!/from ['"][./]*worker\//.test(t), `${p}: imports from worker/`);
      assert.ok(!/\bXMLHttpRequest\b|\bsendBeacon\b|new WebSocket|\bEventSource\b/.test(t), `${p}: unexpected network API`);
      for (const m of t.matchAll(/fetch\(\s*['"`]([^'"`]+)/g)) assert.fail(`${p}: direct fetch to ${m[1]}`);
    }
  });
  it('only calls the existing phishing endpoints', () => {
    const endpoints = new Set<string>();
    for (const p of files) for (const m of readFileSync(p, 'utf8').matchAll(/api[<(][^'"`]*['"`](\/api\/[a-z/]+)['"`]/g)) endpoints.add(m[1]);
    // /api/file/analysis: polling the VirusTotal active scan of attachments (uploads go through uploadFile in src/lib/fileApi.ts).
    for (const e of endpoints) assert.ok(['/api/phishing/parse', '/api/phishing/sender', '/api/phishing/urls', '/api/phishing/attachments', '/api/file/analysis'].includes(e), e);
    assert.ok(endpoints.size >= 4);
  });
  it('no outcome is described as safe or clean in any UI string we added', () => {
    for (const p of files.filter((f) => /Overview|Evidence|History|ReportView|ExportBar|InputForm/.test(f))) {
      const strings = [...readFileSync(p, 'utf8').matchAll(/>([^<>{}]{4,})</g)].map((m) => m[1]).join(' ');
      assert.doesNotMatch(strings, /\b(is|are|looks|marked) (safe|clean)\b/i, p);
    }
  });
});
