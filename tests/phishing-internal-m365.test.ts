/**
 * Internal Microsoft 365 messages: sent by a signed-in user inside the same organisation, never crossing the internet.
 * SPF / DKIM / DMARC do not apply (not "missing"), and the sending device's IP recorded by Exchange is investigated.
 * All addresses and hosts below are fictitious.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSubmission } from '../shared/phishing/parse';
import { planSenderChecks, convertIp } from '../shared/phishing/sender';
import { computeVerdict } from '../shared/phishing/verdict';

const HOPS = `Received: from MBX01.eurprd07.prod.outlook.com (::1) by
 MBX02.eurprd07.prod.outlook.com with HTTPS; Wed, 4 Nov 2026 08:13:48 +0000
Received: from TRN01.eurprd07.prod.outlook.com
 (2603:10a6:150:321::11) by MBX01.eurprd07.prod.outlook.com
 (2603:10a6:150:356::19) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.21.592.9; Wed, 4 Nov 2026
 08:13:40 +0000
Received: from SUB01.eurprd07.prod.outlook.com
 ([fe80::1434:2a9a:e634:238]) by SUB01.eurprd07.prod.outlook.com
 ([fe80::1434:2a9a:e634:238%4]) with mapi id 15.21.0592.009; Wed, 4 Nov 2026
 08:13:34 +0000`;
const COMMON = `From: Works Council <council@example-corp.com>
To: Alex Example <alex@example-corp.com>
Subject: Newsletter
Date: Wed, 4 Nov 2026 08:13:34 +0000
Message-ID: <ABC123@SUB01.eurprd07.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8`;
const ORG = `X-MS-Exchange-Organization-AuthAs: Internal
X-MS-Exchange-Organization-AuthMechanism: 04
x-ms-exchange-organization-originalclientipaddress: 81.2.69.160`;
const BODY = '\n\nHello everyone, here is this month\'s programme of events.\n';

const INTERNAL = `${HOPS}\n${COMMON}\n${ORG}${BODY}`;

test('an internal Microsoft 365 message: SPF / DKIM / DMARC not applicable, sending device IP investigated', async () => {
  const r = await parseSubmission({ headers: INTERNAL });
  const fx = r.forensics!;
  assert.deepEqual(fx.internal, { platform: 'microsoft365', submittedVia: 'Outlook / Exchange (MAPI)', clientIp: '81.2.69.160' });
  for (const id of ['auth.spf', 'auth.dkim', 'auth.dmarc']) assert.equal(r.checks.find((c) => c.id === id)?.status, 'not_applicable', id);
  assert.match(r.checks.find((c) => c.id === 'headers.trust')?.result ?? '', /internal Microsoft 365 message; sent from 81\.2\.69\.160/);
  assert.ok(r.findings.some((f) => f.id === 'internal_m365_message'));
  assert.ok(!r.findings.some((f) => f.id === 'auth_missing'), 'no "paste the complete headers" advice');
  assert.deepEqual(r.indicators.ips.map((i) => [i.ip, i.role]), [['81.2.69.160', 'sender_client']]);

  const plan = planSenderChecks(r);
  assert.ok(plan.requests.some((q) => q.check === 'ip' && q.ip === '81.2.69.160' && q.role === 'sender_client'));
  assert.equal(plan.skipped.find((c) => c.id === 'sender.spf_recheck')?.status, 'not_applicable');

  // Not-applicable authentication checks are not gaps and do not lower coverage.
  const v = computeVerdict({ parse: r, findings: r.findings, checks: [...r.checks, ...plan.skipped].map((c) => ({ id: c.id, label: c.label, status: c.status, result: c.result ?? null, detail: c.detail })) });
  assert.ok(!v.gaps.some((g) => /SPF|DKIM|DMARC/.test(g.text)), JSON.stringify(v.gaps));
});

test('without a recorded client IP, sender IP intelligence is not applicable rather than skipped', async () => {
  const r = await parseSubmission({ headers: `${HOPS}\n${COMMON}\nX-MS-Exchange-Organization-AuthAs: Internal${BODY}` });
  assert.equal(r.forensics!.internal?.clientIp, null);
  assert.equal(planSenderChecks(r).skipped.find((c) => c.id === 'sender.ip')?.status, 'not_applicable');
  // a private client address is not used
  const p = await parseSubmission({ headers: `${HOPS}\n${COMMON}\nX-MS-Exchange-Organization-AuthAs: Internal\nx-ms-exchange-organization-originalclientipaddress: 10.1.2.3${BODY}` });
  assert.equal(p.forensics!.internal?.clientIp, null);
});

test('external mail cannot pass as internal by adding the Exchange header', async () => {
  // 1. first hop from an outside server (a forged AuthAs header from the sender)
  const external = `${HOPS}\nReceived: from mail.attacker.example (198.51.100.7) by EDGE01.eurprd07.prod.outlook.com with Microsoft SMTP Server; Wed, 4 Nov 2026 08:13:30 +0000\n${COMMON}\n${ORG}${BODY}`;
  const a = await parseSubmission({ headers: external });
  assert.equal(a.forensics!.internal, null);
  assert.ok(!a.indicators.ips.some((i) => i.role === 'sender_client'), 'the forged client IP header is ignored');
  assert.equal(a.checks.find((c) => c.id === 'auth.spf')?.status, 'skipped');
  // 2. even with only Microsoft hops, a HELO that merely claims a Microsoft name but Authentication-Results present = inbound
  const withAr = `${HOPS}\nAuthentication-Results: spf=pass smtp.mailfrom=example-corp.com; dkim=none; dmarc=pass header.from=example-corp.com\n${COMMON}\n${ORG}${BODY}`;
  assert.equal((await parseSubmission({ headers: withAr })).forensics!.internal, null);
  // 3. AuthAs Anonymous (how Exchange marks mail from the internet)
  assert.equal((await parseSubmission({ headers: INTERNAL.replace('AuthAs: Internal', 'AuthAs: Anonymous') })).forensics!.internal, null);
  // 4. a hop outside Microsoft 365
  assert.equal((await parseSubmission({ headers: INTERNAL.replace('by\n MBX02.eurprd07.prod.outlook.com', 'by\n mx.other-host.example') })).forensics!.internal, null);
});

test('the sending device IP is judged as a user connection, not a mail server', () => {
  const d = {
    ip: '81.2.69.160', version: 4, scope: 'public', scopeLabel: 'Public', isPublic: true, ptrName: '', geo: { country: 'France', countryCode: 'FR', region: null, city: null, postal: null, latitude: null, longitude: null, timezone: null },
    network: { asn: 'AS64500', org: 'Example Broadband', isp: null, domain: null, prefix: null },
    netType: { isVpn: false, isProxy: false, isTor: true, isDatacenter: false, isMobile: false, isCrawler: false, isAbuser: false, companyName: null, companyType: null, companyAbuserScore: null, asnAbuserScore: null, datacenter: null, vpnService: null },
    geoSource: 'ipapi.is', reverseDns: ['dsl-81-2-69-160.dynamic.example.net'], exposure: null, reputation: null, pulsedive: null, providers: [{ name: 'ipapi.is', ok: true }],
  };
  const out = convertIp({ check: 'ip', ip: '81.2.69.160', role: 'sender_client', trust: 'receiver_reported' }, d as never);
  const ids = out.findings.map((f) => f.id);
  assert.ok(ids.includes('sender_ip_tor'), 'a Tor exit still matters');
  assert.ok(!ids.includes('sender_ip_residential_ptr') && !ids.includes('sender_ip_no_ptr'), 'home / office connections are normal for a user');
  assert.equal(out.findings.find((f) => f.id === 'sender_ip_tor')?.exactness, 'exact');
});
