import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decodeMimeWords, parseAddressList } from '../shared/phishing/addresses';
import { extractMessage, parseHeaderValue } from '../shared/phishing/mime';
import { extractLinks } from '../shared/phishing/links';
import { analyzeEmailHeaders } from '../shared/phishing/forensics';
import { parseSubmission, validateInput } from '../shared/phishing/parse';
import { parseHeaderBlock, parseAuthResults } from '../shared/headers';

/** A spoofed PayPal mail delivered to Gmail, with a forged Received header below the trusted boundary. */
const PHISH = `Delivered-To: victim@gmail.com
Received: by 2002:a05:6a00:1 with SMTP id x1csp1;
        Tue, 3 Nov 2026 10:05:00 -0800 (PST)
Received: from mail-out.evil.example (mail-out.evil.example [45.33.32.156])
        by mx.google.com with ESMTPS id abc123
        for <victim@gmail.com>; Tue, 3 Nov 2026 10:04:50 -0800 (PST)
Received: from mail.paypal.com (mail.paypal.com [66.211.168.91])
        by mail-out.evil.example with ESMTP; Tue, 3 Nov 2026 17:59:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of bounce@evil.example does not designate 45.33.32.156 as permitted sender) smtp.mailfrom=bounce@evil.example;
       dkim=none;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
Received-SPF: fail (google.com: domain of bounce@evil.example does not designate 45.33.32.156 as permitted sender) client-ip=45.33.32.156;
Return-Path: <bounce@evil.example>
From: "PayPal Support" <service@paypal.com>
Reply-To: help.desk.9921@gmail.com
To: victim@gmail.com
Subject: =?UTF-8?B?QWN0aW9uIHJlcXVpcmVkOiB2ZXJpZnkgeW91ciBhY2NvdW50?=
Date: Tue, 3 Nov 2026 17:58:00 +0000
Message-ID: <abc@evil.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8`;

/** A legitimate Microsoft 365 message: Authentication-Results has no authserv-id. */
const M365 = `Received: from DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) by BN9PR12MB2222.namprd12.prod.outlook.com with HTTPS; Wed, 4 Nov 2026 09:00:05 +0000
Received: from mail-ej1-f43.google.com (209.85.218.43) by DM6PR12MB1111.namprd12.prod.outlook.com (2603:10b6:5:1::2) with Microsoft SMTP Server; Wed, 4 Nov 2026 09:00:04 +0000
Authentication-Results: spf=pass (sender IP is 209.85.218.43) smtp.mailfrom=partner.example; dkim=pass (signature was verified) header.d=partner.example;dmarc=pass action=none header.from=partner.example;compauth=pass reason=100
Received: from mail-ej1-f43.google.com (mail-ej1-f43.google.com [209.85.218.43]) by mx.partner.example with ESMTPS; Wed, 4 Nov 2026 09:00:03 +0000
Return-Path: <bounce@partner.example>
From: Alice Partner <alice@partner.example>
To: me@corp.example
Subject: Meeting notes
Date: Wed, 4 Nov 2026 09:00:00 +0000
Message-ID: <1@partner.example>`;

describe('Authentication-Results parsing', () => {
  it('handles a missing authserv-id (Microsoft 365) without dropping the first result', () => {
    const v = parseHeaderBlock(M365).find(([n]) => n === 'Authentication-Results')![1];
    const p = parseAuthResults([v]);
    assert.equal(p.authservId, null);
    assert.deepEqual(p.results.map((r) => `${r.method}=${r.result}`).slice(0, 3), ['spf=pass', 'dkim=pass', 'dmarc=pass']);
  });
  it('still reads the authserv-id when present', () => {
    assert.equal(parseAuthResults(['mx.google.com; spf=pass smtp.mailfrom=a.example']).authservId, 'mx.google.com');
  });
});

describe('addresses and encoded words', () => {
  it('decodes B and Q encoded words', () => {
    assert.equal(decodeMimeWords('=?UTF-8?B?QWN0aW9uIHJlcXVpcmVk?='), 'Action required');
    assert.equal(decodeMimeWords('=?iso-8859-1?Q?Caf=E9_Menu?='), 'Café Menu');
  });
  it('parses quoted display names with commas and comments', () => {
    const [a, b] = parseAddressList('"Doe, Jane" <jane@Example.COM>, bob@example.org (Bob)');
    assert.equal(a.display, 'Doe, Jane');
    assert.equal(a.address, 'jane@example.com');
    assert.equal(b.address, 'bob@example.org');
  });
});

describe('MIME', () => {
  it('parses RFC 2231 filenames and boundaries', () => {
    const h = parseHeaderValue(`multipart/mixed; boundary="b1"; name*=UTF-8''r%C3%A9sum%C3%A9.pdf`);
    assert.equal(h.params.boundary, 'b1');
    assert.equal(h.params.name, 'résumé.pdf');
  });
  it('extracts text, html and a base64 attachment from multipart/mixed', () => {
    const pairs = parseHeaderBlock('Content-Type: multipart/mixed; boundary="X"\nMIME-Version: 1.0');
    const body = [
      '--X', 'Content-Type: multipart/alternative; boundary="Y"', '',
      '--Y', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Caf=C3=A9 invoice attached=', ' today', '--Y',
      'Content-Type: text/html; charset=utf-8', '', '<p>Hello <a href="https://evil.example/x">www.paypal.com</a></p>', '--Y--',
      '--X', 'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"', 'Content-Transfer-Encoding: base64', '', 'JVBERi0xLjQK', '--X--',
    ].join('\r\n');
    const m = extractMessage(pairs, body);
    assert.equal(m.bodyKind, 'multipart');
    assert.match(m.text, /Café invoice attached today/);
    assert.ok(m.html?.includes('evil.example'));
    assert.equal(m.attachments.length, 1);
    assert.equal(m.attachments[0].filename, 'invoice.pdf');
    assert.equal(m.attachments[0].size, 9);
  });
  it('falls back to plain text when the declared boundary is absent', () => {
    const m = extractMessage(parseHeaderBlock('Content-Type: multipart/alternative; boundary="Z"'), 'just text https://a.example/x');
    assert.equal(m.bodyKind, 'plain');
    assert.ok(m.warnings.length > 0);
  });
});

describe('link extraction', () => {
  it('keeps the displayed text next to the real destination and flags the mismatch', () => {
    const { links } = extractLinks({ html: '<a href="https://evil.example/login?x=1&amp;y=2">https://www.paypal.com/signin</a>' });
    assert.equal(links.length, 1);
    assert.equal(links[0].host, 'evil.example');
    assert.equal(links[0].displayedHost, 'www.paypal.com');
    assert.equal(links[0].displayMismatch, true);
    assert.match(links[0].normalized, /x=1&y=2/);
  });
  it('does not flag matching display text', () => {
    const { links } = extractLinks({ html: '<a href="https://www.paypal.com/x">paypal.com</a>' });
    assert.equal(links[0].displayMismatch, false);
  });
  it('unwraps Safe Links so the real destination is investigated', () => {
    const wrapped = 'https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fa%3Fb%3D1&data=05%7C01&sdata=xyz';
    const { links } = extractLinks({ html: `<a href="${wrapped}">Open document</a>` });
    assert.equal(links[0].host, 'evil.example');
    assert.equal(links[0].wrapper?.service, 'Microsoft Defender Safe Links');
  });
  it('finds plain-text and defanged URLs, trims punctuation and de-duplicates', () => {
    const { links } = extractLinks({ text: 'See https://a.example/x), then hxxps://b[.]example/y. Again https://a.example/x', manual: ['c.example/z'] });
    assert.deepEqual(links.map((l) => l.host).sort(), ['a.example', 'b.example', 'c.example']);
    assert.equal(links.find((l) => l.host === 'a.example')!.count, 2);
  });
  it('skips mailto/tel and reports javascript: links', () => {
    const { links, skipped } = extractLinks({ html: '<a href="mailto:a@b.example">m</a><a href="javascript:alert(1)">x</a><a href="/relative">r</a>' });
    assert.equal(links.length, 0);
    assert.equal(skipped.length, 3);
    assert.ok(skipped.some((s) => s.reason.startsWith('javascript')));
  });
});

describe('header forensics: spoofed PayPal mail', () => {
  const f = analyzeEmailHeaders(PHISH, { email: 'service@paypal.com', domain: 'paypal.com', ip: '66.211.168.91' });
  const ids = f.findings.map((x) => x.id);
  it('treats only the receiver-added hop as trusted and finds the connecting IP there', () => {
    assert.equal(f.trust.connectingIp, '45.33.32.156');
    assert.equal(f.trust.connectingIpSource, 'trusted_received');
    assert.equal(f.trust.confidence, 'high');
    assert.equal(f.trust.claimedOriginIp, '66.211.168.91'); // the forged PayPal hop is only a claim
    assert.equal(f.hops.filter((h) => h.trust === 'trusted').length, 2); // Google's unnamed internal hop + mx.google.com
    assert.equal(f.hops.filter((h) => h.trust === 'untrusted').length, 1);
  });
  it('labels authentication as receiver-reported and flags the combined failure once', () => {
    assert.equal(f.authentication.spf?.trust, 'receiver_reported');
    assert.equal(f.authentication.dmarc?.policy, 'reject');
    assert.ok(ids.includes('auth_all_failed'));
    assert.ok(!ids.includes('spf_fail') && !ids.includes('dmarc_fail'), 'no double counting');
  });
  it('detects Reply-To and Return-Path mismatches', () => {
    assert.ok(ids.includes('reply_to_mismatch'));
    assert.ok(f.findings.find((x) => x.id === 'reply_to_mismatch')!.title.includes('free mailbox'));
    assert.ok(ids.includes('return_path_mismatch'));
  });
  it('decodes the subject', () => assert.equal(f.summary.subject, 'Action required: verify your account'));
  it('compares the supplied IP against the headers instead of trusting it', () => {
    const d = f.discrepancies.find((x) => x.field === 'sender_ip')!;
    assert.equal(d.kind, 'partial');
    assert.match(d.note, /untrusted/);
    assert.equal(f.ips.find((i) => i.role === 'connecting')!.ip, '45.33.32.156');
  });
  it('matches the supplied sender and flags nothing when it agrees', () => {
    assert.equal(f.discrepancies.find((x) => x.field === 'sender_email')!.kind, 'match');
    assert.ok(!ids.includes('supplied_sender_mismatch'));
  });
  it('flags a mismatching supplied sender', () => {
    const g = analyzeEmailHeaders(PHISH, { email: 'someone@else.example' });
    assert.ok(g.findings.some((x) => x.id === 'supplied_sender_mismatch'));
  });
});

describe('header forensics: legitimate Microsoft 365 mail', () => {
  const f = analyzeEmailHeaders(M365);
  it('reads the connecting IP through the Microsoft hops', () => {
    assert.equal(f.trust.connectingIp, '209.85.218.43');
    assert.equal(f.trust.receiverOrg, 'outlook.com');
  });
  it('reports aligned passing authentication as receiver-reported and raises no auth findings', () => {
    assert.equal(f.authentication.dmarc?.result, 'pass');
    assert.equal(f.authentication.spf?.trust, 'receiver_reported');
    assert.equal(f.authentication.alignment.spfAligned, true);
    assert.equal(f.authentication.alignment.dkimAligned, true);
    assert.deepEqual(f.findings.filter((x) => x.severity !== 'info').map((x) => x.id), []);
  });
});

describe('header forensics: multiple From headers and unverified auth', () => {
  it('flags duplicate From headers as high severity', () => {
    const f = analyzeEmailHeaders('From: a@one.example\nFrom: b@two.example\nSubject: x');
    assert.equal(f.findings.find((x) => x.id === 'multiple_from_headers')?.severity, 'high');
  });
  it('treats an Authentication-Results from an unrelated server as unverified', () => {
    const f = analyzeEmailHeaders('Received: from a.example ([1.2.3.4]) by mx.corp.example with ESMTP; Tue, 3 Nov 2026 10:00:00 +0000\nAuthentication-Results: mx.attacker.example; dmarc=pass header.from=bank.example\nFrom: x@bank.example');
    assert.equal(f.authentication.dmarc?.trust, 'unverified');
    assert.ok(f.findings.some((x) => x.id === 'auth_results_unverified'));
  });
});

describe('parseSubmission', () => {
  it('rejects empty submissions and wrong types', () => {
    assert.equal(validateInput({}).ok, false);
    assert.equal(validateInput({ headers: 5 }).ok, false);
    assert.equal(validateInput({ urls: ['https://a.example'] }).ok, true);
  });
  it('runs end to end on headers + HTML body + embedded attachment + supplied hash', async () => {
    const body = [
      '--X', 'Content-Type: text/html; charset=utf-8', '', '<a href="https://evil.example/login">https://www.paypal.com/verify</a>', '--X',
      'Content-Type: application/octet-stream; name="doc.html"', 'Content-Disposition: attachment; filename="doc.html"', 'Content-Transfer-Encoding: base64', '', 'PGh0bWw+PC9odG1sPg==', '--X--',
    ].join('\n');
    const headers = PHISH.replace('Content-Type: text/html; charset=utf-8', 'Content-Type: multipart/mixed; boundary="X"');
    const r = await parseSubmission({ headers, body, urls: ['https://second.example/a'], attachments: [{ name: 'x.exe', hash: 'a'.repeat(64) }, { hash: 'nothex' }], sender: { domain: 'amazon.com' } });
    assert.equal(r.links.filter((l) => !l.sources.includes('sender')).length, 2);
    assert.ok(r.links[0].sources.includes('sender'), 'the sender domain is investigated as a link, listed first');
    assert.equal(r.links.find((l) => l.host === 'evil.example')!.displayMismatch, true);
    assert.equal(r.attachments.length, 3);
    const emb = r.attachments.find((a) => a.origin === 'embedded')!;
    assert.equal(emb.filename, 'doc.html');
    assert.match(emb.hash!, /^[a-f0-9]{64}$/);
    assert.equal(emb.hashType, 'sha256');
    assert.equal(r.attachments.filter((a) => a.hash).length, 2);
    assert.ok(r.findings.some((f) => f.id === 'sender_domain_differs_from_claimed_org'));
    assert.deepEqual(r.indicators.urls.sort(), ['https://evil.example/login', 'https://second.example/a']);
    assert.ok(r.checks.every((c) => c.status !== 'failed'));
  });
  it('accepts a pasted .eml in the headers box (body after the blank line)', async () => {
    const r = await parseSubmission({ headers: `From: a@x.example\nSubject: hi\nContent-Type: text/plain\n\nVisit https://x.example/p` });
    assert.equal(r.links.filter((l) => !l.sources.includes('sender')).length, 1);
    assert.deepEqual([r.links[0].host, r.links[0].sources], ['x.example', ['sender']], 'a@x.example: x.example is looked up as the sender domain');
    assert.equal(r.content.subject, 'hi');
  });
  it('works without headers, keeping supplied sender data as unverified indicators', async () => {
    const r = await parseSubmission({ body: 'click https://a.example/x', sender: { email: 'Bob <bob@evil.example>', ip: '203.0.113.9' } });
    assert.equal(r.forensics, null);
    assert.equal(r.checks.find((c) => c.id === 'headers.parse')!.status, 'skipped');
    assert.equal(r.indicators.ips[0].trust, 'unverified');
    assert.equal(r.indicators.emails[0].address, 'bob@evil.example');
  });
});
