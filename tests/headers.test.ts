import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHeaders, parseHeaderBlock } from '../shared/headers';

const SAMPLE = `Delivered-To: victim@gmail.com
Received: by 2002:a05:6a00:1 with SMTP id x1csp1;
        Tue, 3 Nov 2026 10:05:00 -0800 (PST)
Received: from mail-out.evil.example (mail-out.evil.example [45.33.32.156])
        by mx.google.com with ESMTPS id abc123
        for <victim@gmail.com>; Tue, 3 Nov 2026 10:04:50 -0800 (PST)
Received: from [192.168.1.20] (unknown [93.184.216.34])
        by mail-out.evil.example with ESMTP; Tue, 3 Nov 2026 17:59:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of bounce@evil.example does not designate 45.33.32.156) smtp.mailfrom=bounce@evil.example;
       dkim=none;
       dmarc=fail (p=NONE) header.from=paypal.com
Received-SPF: fail (google.com: ...) client-ip=45.33.32.156;
Return-Path: <bounce@evil.example>
From: "PayPal Support" <service@paypal.com>
Reply-To: help@scam.example
To: victim@gmail.com
Subject: Your account
Date: Tue, 3 Nov 2026 17:58:00 +0000
Message-ID: <abc@evil.example>

body is ignored`;

describe('header parsing', () => {
  it('unfolds continuation lines and ignores the body', () => {
    const h = parseHeaderBlock(SAMPLE);
    assert.ok(h.every(([n]) => !/body/.test(n)));
    const ar = h.find(([n]) => n === 'Authentication-Results')![1];
    assert.match(ar, /spf=fail .* dkim=none; dmarc=fail/);
  });
});

describe('analysis', () => {
  const a = analyzeHeaders(SAMPLE);
  it('orders hops chronologically and computes delays', () => {
    assert.equal(a.hops.length, 3);
    assert.equal(a.hops[0].by, 'mail-out.evil.example');
    assert.equal(a.hops[1].from, 'mail-out.evil.example');
    assert.equal(a.hops[1].by, 'mx.google.com');
    assert.equal(a.hops[0].delaySeconds, null);
    assert.equal(a.hops[1].delaySeconds, 350); // 17:59:00Z -> 18:04:50Z
    assert.equal(a.hops[2].delaySeconds, 10); // 18:04:50Z -> 18:05:00Z (10:05 -0800)
    assert.equal(a.totalDelaySeconds, 360);
  });
  it('finds the origin IP, skipping the private 192.168.x hop address', () => {
    assert.deepEqual(a.hops[0].ips.sort(), ['192.168.1.20', '93.184.216.34']);
    assert.deepEqual(a.hops[0].publicIps, ['93.184.216.34']);
    assert.equal(a.originIp, '93.184.216.34');
  });
  it('extracts authentication results', () => {
    assert.equal(a.authentication.spf, 'fail');
    assert.equal(a.authentication.dkim, 'none');
    assert.equal(a.authentication.dmarc, 'fail');
    assert.equal(a.authentication.authservId, 'mx.google.com');
  });
  it('raises the expected findings', () => {
    const msgs = a.findings.map((f) => f.message).join('\n');
    assert.match(msgs, /SPF result is "fail"/);
    assert.match(msgs, /DMARC result is "fail"/);
    assert.match(msgs, /Reply-To domain \(scam\.example\)/);
    assert.match(msgs, /Return-Path domain \(evil\.example\)/);
  });
});

describe('edge cases', () => {
  it('reports empty/garbage input', () => {
    const a = analyzeHeaders('this is not a header block');
    assert.equal(a.headerCount, 0);
    assert.equal(a.findings[0].level, 'error');
  });
  it('handles CRLF', () => assert.equal(analyzeHeaders('From: a@b.com\r\nTo: c@d.com\r\n\r\nbody').headerCount, 2));
});
