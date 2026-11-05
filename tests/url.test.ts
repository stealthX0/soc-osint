import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrlHeuristics, assessUrl, parseTargetUrl, type ParsedUrl } from '../shared/url';
import type { UrlSignal } from '../shared/types';

const parse = (s: string): ParsedUrl => {
  const r = parseTargetUrl(s);
  assert.ok(r.ok, `expected ${s} to parse: ${!r.ok ? r.error : ''}`);
  return r.value;
};
const ids = (s: string) => analyzeUrlHeuristics(parse(s)).map((x) => x.id);
const sev = (s: string) => analyzeUrlHeuristics(parse(s)).map((x) => `${x.id}:${x.severity}`);
const worst = (s: string) => {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const sigs = analyzeUrlHeuristics(parse(s));
  return sigs.length ? order[Math.min(...sigs.map((x) => order.indexOf(x.severity)))] : 'none';
};

describe('parseTargetUrl', () => {
  it('normalises, refangs and defaults to http', () => {
    const a = parse('hxxps://Evil[.]Example[.]com/Login?x=1#frag');
    assert.equal(a.scheme, 'https');
    assert.equal(a.host, 'evil.example.com');
    assert.equal(a.url, 'https://evil.example.com/Login?x=1');
    assert.ok(!a.url.includes('#'));
    assert.equal(parse('example.com/a').url, 'http://example.com/a');
    assert.equal(parse('example.com:8080/x').port, 8080);
  });
  it('rejects non-web schemes, junk and oversized input', () => {
    for (const bad of ['', '   ', 'javascript:alert(1)', 'mailto:a@b.com', 'data:text/html,hi', 'ftp://example.com/x', 'http://', 'http://exa mple.com', 'http://-bad-.com']) {
      assert.equal(parseTargetUrl(bad).ok, false, bad);
    }
    assert.equal(parseTargetUrl('http://a.com/' + 'x'.repeat(2100)).ok, false);
    assert.equal(parseTargetUrl('http://a.com/\u0000x').ok, false);
  });
  it('splits userinfo out of the lookup URL but keeps it for display', () => {
    const p = parse('https://paypal.com@evil.example/login');
    assert.equal(p.host, 'evil.example');
    assert.equal(p.hasUserinfo, true);
    assert.equal(p.userinfo, 'paypal.com');
    assert.ok(!p.lookupUrl.includes('paypal.com@'));
    assert.ok(p.url.includes('paypal.com@'));
  });
  it('detects obfuscated and plain IP hosts, including IPv6', () => {
    assert.deepEqual([parse('http://2130706433/x').host, parse('http://2130706433/x').ipObfuscated], ['127.0.0.1', true]);
    assert.equal(parse('http://0x7f.0.0.1/').ipObfuscated, true);
    assert.equal(parse('http://0177.0.0.1/').ipObfuscated, true);
    assert.equal(parse('http://127.1/').ipObfuscated, true);
    const plain = parse('http://203.0.113.9:8080/a.exe');
    assert.deepEqual([plain.isIp, plain.ipObfuscated, plain.port], [true, false, 8080]);
    const v6 = parse('http://[2001:db8::1]/x');
    assert.deepEqual([v6.isIp, v6.host], [true, '2001:db8::1']);
  });
  it('computes registrable domains, multi-label suffixes and shared platforms', () => {
    assert.equal(parse('https://a.b.example.com/').registrableDomain, 'example.com');
    assert.equal(parse('https://www.bbc.co.uk/').registrableDomain, 'bbc.co.uk');
    assert.equal(parse('https://shop.example.com.au/').registrableDomain, 'example.com.au');
    const p = parse('https://my-bank-login.pages.dev/');
    assert.deepEqual([p.registrableDomain, p.platform], ['my-bank-login.pages.dev', 'pages.dev']);
    assert.equal(parse('https://user.github.io/repo').registrableDomain, 'user.github.io');
  });
  it('decodes punycode for display', () => {
    assert.equal(parse('http://xn--80ak6aa92e.com/').hostUnicode, 'аррӏе.com');
  });
});

describe('heuristics: true positives', () => {
  it('flags raw and obfuscated IPs', () => {
    assert.ok(ids('http://203.0.113.9/payload').includes('ip-host'));
    assert.equal(worst('http://2130706433/x'), 'high');
  });
  it('flags the deceptive @ trick as high only when the userinfo looks like a domain', () => {
    assert.ok(sev('https://paypal.com@evil.example/').includes('userinfo-deception:high'));
    assert.ok(sev('https://admin:secret@files.example.net/').includes('userinfo:medium'));
  });
  it('flags homograph domains (mixed script and whole-script look-alikes)', () => {
    assert.ok(ids('http://xn--pypal-4ve.com/').includes('homograph-mixed'));
    const apple = analyzeUrlHeuristics(parse('http://xn--80ak6aa92e.com/'));
    assert.ok(apple.some((x) => x.id === 'homograph-skeleton' && x.severity === 'high' && /apple/.test(x.detail ?? '')));
    assert.deepEqual(ids('http://xn--mnchen-3ya.de/'), ['idn']); // a normal IDN is only informational
  });
  it('flags brand names on domains the brand does not own', () => {
    assert.ok(ids('https://www.paypal.com.secure-login.xyz/signin').includes('brand-paypal'));
    assert.ok(ids('https://paypal-verify-account.com/').includes('brand-paypal'));
    assert.ok(ids('https://microsoft.pages.dev/').includes('brand-microsoft'));
    assert.ok(ids('https://login.microsoft.evil.example/').includes('brand-microsoft'));
  });
  it('flags character-swap squats (paypa1, rnicrosoft) and the brand label on an abused TLD', () => {
    assert.ok(sev('https://paypa1.com/login').some((s) => s.startsWith('squat-paypal')));
    assert.ok(ids('https://rnicrosoft.com/').includes('squat-microsoft'));
    assert.ok(ids('https://paypal.xyz/').some((i) => i.startsWith('brand-tld-paypal') || i.startsWith('brand-paypal')));
  });
  it('flags credential-themed hostnames, plain-HTTP logins and risky files', () => {
    assert.ok(ids('http://secure-login-verify.example.net/').includes('cred-host'));
    assert.ok(ids('http://example.net/account/login').includes('login-no-tls'));
    assert.ok(ids('https://example.net/files/invoice.pdf.exe').includes('double-ext'));
    assert.equal(worst('https://example.net/files/invoice.pdf.exe'), 'high');
    assert.ok(ids('http://203.0.113.9/a/setup.exe').includes('risky-file'));
    assert.ok(ids('https://example.net/dl/pack.zip').includes('archive-file'));
  });
  it('notes shared hosting, shorteners, ports, TLDs and redirect parameters', () => {
    assert.ok(ids('https://x.vercel.app/').includes('shared-hosting'));
    assert.ok(ids('https://bit.ly/3abc').includes('shortener'));
    assert.ok(ids('http://example.com:8081/').includes('port'));
    assert.ok(ids('https://example.top/').includes('tld'));
    assert.ok(ids('https://example.com/go?url=https://other.example/').includes('open-redirect'));
  });
});

describe('heuristics: false positives on legitimate URLs', () => {
  const legit = [
    'https://www.google.com/search?q=weather',
    'https://mail.google.com/mail/u/0/',
    'https://accounts.google.com/signin/v2/identifier',
    'https://login.microsoftonline.com/common/oauth2/authorize',
    'https://github.com/anthropics/anthropic-sdk-python',
    'https://www.amazon.co.uk/dp/B08N5WRWNW',
    'https://www.amazon.nl/gp/cart',
    'https://support.apple.com/en-us/HT201222',
    'https://www.paypal.com/signin',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://www.bbc.co.uk/news',
    'https://stackoverflow.com/questions/1234/how-to-x',
    'https://docs.aws.amazon.com/lambda/latest/dg/welcome.html',
    'https://www.linkedin.com/in/someone',
    'https://zoom.us/j/123456789',
    'https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js',
    'https://example.com/',
    'https://www.pineapple.com/menu',
    'https://paypay.ne.jp/',
  ];
  for (const u of legit) {
    it(`no medium+ findings for ${u}`, () => {
      const bad = analyzeUrlHeuristics(parse(u)).filter((s) => ['critical', 'high', 'medium'].includes(s.severity));
      assert.deepEqual(bad.map((b) => b.id), [], `${u} -> ${bad.map((b) => b.title).join(' | ')}`);
    });
  }
  it('legitimate URLs never reach "suspicious" on heuristics alone', () => {
    for (const u of legit) {
      const a = assessUrl(analyzeUrlHeuristics(parse(u)), 0, 0);
      assert.notEqual(a.verdict, 'suspicious', u);
      assert.notEqual(a.verdict, 'malicious', u);
    }
  });
});

const ext = (source: string, severity: UrlSignal['severity'], extra: Partial<UrlSignal> = {}): UrlSignal => ({ id: `${source}-${severity}`, source, severity, title: `${source} says ${severity}`, ...extra });

describe('assessUrl: verdict rules', () => {
  it('heuristics alone can reach suspicious but never malicious', () => {
    const p = parse('https://www.paypal.com.secure-login.xyz/signin');
    const a = assessUrl(analyzeUrlHeuristics(p), 0, 0);
    assert.equal(a.verdict, 'suspicious');
    const worse = assessUrl(analyzeUrlHeuristics(parse('http://2130706433/invoice.pdf.exe')), 0, 0);
    assert.equal(worse.verdict, 'suspicious');
    assert.notEqual(worse.verdict, 'malicious');
  });
  it('a critical or confirmed external finding is malicious with high confidence', () => {
    assert.equal(assessUrl([ext('urlhaus', 'critical', { confirmed: true })], 1, 3).verdict, 'malicious');
    assert.equal(assessUrl([ext('safebrowsing', 'critical')], 1, 3).verdict, 'malicious');
    assert.equal(assessUrl([ext('urlhaus', 'high', { confirmed: true })], 1, 3).confidence, 'high');
  });
  it('two different sources at "high" make it malicious; one alone is only suspicious', () => {
    assert.equal(assessUrl([ext('pulsedive', 'high')], 1, 3).verdict, 'suspicious');
    assert.equal(assessUrl([ext('pulsedive', 'high'), ext('cloudflare-dns', 'high')], 2, 3).verdict, 'malicious');
    assert.equal(assessUrl([ext('pulsedive', 'high'), ext('pulsedive', 'high', { id: 'x2' })], 1, 3).verdict, 'suspicious');
  });
  it('a lone high heuristic signal is not upgraded to malicious by a count of heuristics', () => {
    const h: UrlSignal[] = [{ id: 'a', severity: 'high', source: 'heuristic', title: 'a' }, { id: 'b', severity: 'high', source: 'heuristic', title: 'b' }];
    assert.equal(assessUrl(h, 3, 3).verdict, 'suspicious');
  });
  it('clean results say "no detections" with coverage, never "safe"', () => {
    const a = assessUrl([], 3, 4);
    assert.equal(a.verdict, 'no_detections');
    assert.equal(a.confidence, 'high');
    assert.match(a.summary, /3 of 4/);
    assert.match(a.summary, /not a guarantee/i);
    assert.doesNotMatch(a.summary, /is safe|are safe|\bsafe\./i);
  });
  it('no answering source means "unknown", not "no detections"', () => {
    const a = assessUrl([], 0, 3);
    assert.equal(a.verdict, 'unknown');
    assert.equal(a.confidence, 'low');
    assert.equal(assessUrl([], 1, 3).confidence, 'low');
    assert.equal(assessUrl([], 2, 3).confidence, 'medium');
  });
  it('info signals never change the verdict', () => {
    assert.equal(assessUrl([ext('heuristic', 'info')], 2, 2).verdict, 'no_detections');
  });
});
