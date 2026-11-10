/** Email file loading for the phishing form: .eml, .mbox and .msg detection, header/body extraction and attachments. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectFormat, parseEmailFile } from '../src/lib/emailFile';
import { convertActiveScan } from '../shared/phishing/attachments';
import { parseSubmission } from '../shared/phishing/parse';

const MSG = [
  'Received: from mail-gw.paypa1-secure.example ([203.0.113.45]) by mx.example.com; Fri, 06 Nov 2026 08:14:22 +0000',
  'From: "PayPal Support" <support@paypal-support.example>',
  'To: victim@example.com',
  'Subject: Invoice attached',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="BOUND"',
  '',
  '--BOUND',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body><a href="https://paypa1-secure.example/verify">Verify</a></body></html>',
  '--BOUND',
  'Content-Type: application/octet-stream; name="Invoice_4491.pdf.exe"',
  'Content-Disposition: attachment; filename="Invoice_4491.pdf.exe"',
  'Content-Transfer-Encoding: base64',
  '',
  Buffer.from('MZ' + 'A'.repeat(4000)).toString('base64').replace(/(.{76})/g, '$1\n'),
  '--BOUND--',
  '',
].join('\r\n');

describe('email file loading', () => {
  it('detects the format from the signature and the extension', () => {
    assert.equal(detectFormat('x.bin', new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])), 'msg');
    assert.equal(detectFormat('box.mbox', new Uint8Array([70])), 'mbox');
    assert.equal(detectFormat('mail.txt', new TextEncoder().encode('From someone@example.com Fri')), 'mbox');
    assert.equal(detectFormat('m.eml', new TextEncoder().encode('Received: x')), 'eml');
  });

  it('.eml: headers and readable body go to the form, attachments come out as files', async () => {
    const r = await parseEmailFile(new File([MSG], 'm.eml'));
    assert.equal(r.format, 'eml');
    assert.match(r.headers, /^Received:/);
    assert.ok(!r.body.includes('TVo'), 'attachment payload is not left in the body');
    assert.deepEqual(r.attachments.map((a) => a.name), ['Invoice_4491.pdf.exe']);
    assert.equal(r.attachments[0].size, 4002);
    const parsed = await parseSubmission({ headers: r.headers, body: r.body });
    assert.equal(parsed.content.subject, 'Invoice attached');
    assert.deepEqual(parsed.links.map((l) => l.url), ['https://paypa1-secure.example/verify']);
    assert.deepEqual(parsed.content.warnings, []);
  });

  it('.mbox: the first message is loaded and the count is reported', async () => {
    const box = `From MAILER-DAEMON Fri Nov  6 08:14:22 2026\n${MSG.replace(/\r\n/g, '\n')}\n\nFrom x@y.example Fri Nov  6 09:00:00 2026\nFrom: a@b.example\nSubject: second\n\nhello\n`;
    const r = await parseEmailFile(new File([box], 'inbox.mbox'));
    assert.equal(r.format, 'mbox');
    assert.match(r.headers, /Subject: Invoice attached/);
    assert.equal(r.attachments.length, 1);
    assert.match(r.notes[0], /2 messages; the first one was loaded/);
  });

  it('rejects a file with no headers and a damaged .msg', async () => {
    await assert.rejects(parseEmailFile(new File(['just some words\n\nmore words'], 'x.eml')), /does not contain email headers/);
    await assert.rejects(parseEmailFile(new File([new Uint8Array(600)], 'x.msg')), /not an Outlook \.msg/);
  });
});

describe('active scan conversion', () => {
  const ctx = { index: 3, filename: 'a.exe', sha256: 'f'.repeat(64) };
  const report = (malicious: number, suspicious = 0) => ({ status: 'completed' as const, report: { id: 'x', status: 'completed' as const, sha256: ctx.sha256, stats: { malicious, suspicious, harmless: 0, undetected: 60 - malicious - suspicious, timeout: 0, total: 60 }, detections: [], link: 'https://www.virustotal.com/gui/file/x' } });
  it('scores fresh scans with the hash-lookup ids and thresholds', () => {
    assert.equal(convertActiveScan(report(12), ctx).findings[0].severity, 'critical');
    assert.equal(convertActiveScan(report(4), ctx).findings[0].id, 'attachment_hash_malicious');
    assert.equal(convertActiveScan(report(1), ctx).findings[0].id, 'attachment_hash_suspicious');
    assert.equal(convertActiveScan(report(0), ctx).findings.length, 0);
    assert.equal(convertActiveScan(report(0), ctx).checks[0].id, 'attach.3.scan.virustotal');
  });
  it('an unfinished or skipped scan is never clean', () => {
    const p = convertActiveScan({ status: 'pending', link: null }, ctx);
    assert.equal(p.findings.length, 0);
    assert.equal(p.checks[0].status, 'failed');
    assert.equal(convertActiveScan({ status: 'skipped', reason: 'too big' }, ctx).checks[0].status, 'skipped');
  });
});
