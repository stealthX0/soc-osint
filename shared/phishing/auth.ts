/**
 * E-mail authentication assessment from pasted headers.
 *
 * Important limits (also surfaced in the UI): Spectrix can only READ what the receiving server wrote. It cannot re-run the
 * receiver's SPF check or verify a DKIM signature from headers alone, and a pasted Authentication-Results line can be edited.
 * Every result therefore carries a trust label, and results that cannot be tied to the receiving server are "unverified".
 */
import { parseAuthResults, type AuthResult } from '../headers';
import { normalizeDomain } from '../domain';
import { registrableOf } from './domains';
import type { TrustBoundary } from './trust';
import type { TrustLevel } from './types';

export interface SpfView { result: string; trust: TrustLevel; domain: string | null; helo: string | null; ip: string | null; detail: string }
export interface DkimView { result: string; trust: TrustLevel; domain: string | null; selector: string | null; aligned: boolean | null; detail: string }
export interface DmarcView { result: string; trust: TrustLevel; policy: string | null; headerFrom: string | null; detail: string }

export interface DkimSignature {
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  signedHeaders: string[];
  coversFrom: boolean;
  weakAlgorithm: boolean;
  bodyLengthLimited: boolean;
  expires: string | null;
}

export interface ArcView {
  present: boolean;
  instances: number;
  /** Chain validation status written by the newest ARC sealer ("pass" | "fail" | "none"). Not re-verified here. */
  newestChainValidation: string | null;
  sealers: string[];
  /** Authentication results recorded by the first ARC hop (what the message looked like before forwarding). */
  originalResults: { method: string; result: string }[];
}

export interface AuthHeaderView { index: number; authservId: string | null; trust: TrustLevel; results: { method: string; result: string }[] }

export interface AuthAssessment {
  source: 'receiver_header' | 'unverified_header' | 'received_spf_only' | 'none';
  spf: SpfView | null;
  dkim: DkimView[];
  dmarc: DmarcView | null;
  other: { method: string; result: string; detail: string }[];
  headers: AuthHeaderView[];
  dkimSignatures: DkimSignature[];
  arc: ArcView;
  alignment: { fromDomain: string | null; spfAligned: boolean | null; dkimAligned: boolean | null };
  /** Places where the supplied evidence disagrees with itself. */
  conflicts: string[];
}

const hdrs = (pairs: [string, string][], name: string) => pairs.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);

function domainOf(v: string | undefined | null): string | null {
  if (!v) return null;
  const s = v.replace(/[<>"]/g, '').trim();
  return normalizeDomain(s.includes('@') ? s.slice(s.lastIndexOf('@') + 1) : s);
}

const tag = (v: string, t: string) => v.match(new RegExp(`(?:^|;)\\s*${t}\\s*=\\s*([^;]*)`, 'i'))?.[1]?.replace(/\s+/g, '').trim() ?? null;

export function parseDkimSignature(v: string): DkimSignature {
  const algorithm = tag(v, 'a');
  const signedHeaders = (tag(v, 'h') ?? '').toLowerCase().split(':').filter(Boolean);
  const x = Number(tag(v, 'x'));
  return {
    domain: tag(v, 'd')?.toLowerCase() ?? null,
    selector: tag(v, 's'),
    algorithm,
    signedHeaders,
    coversFrom: signedHeaders.includes('from'),
    weakAlgorithm: !!algorithm && /sha1/i.test(algorithm),
    bodyLengthLimited: tag(v, 'l') !== null,
    expires: Number.isFinite(x) && x > 0 ? new Date(x * 1000).toISOString() : null,
  };
}

function parseArc(pairs: [string, string][]): ArcView {
  const seals = hdrs(pairs, 'arc-seal').map((v) => ({ i: Number(tag(v, 'i')), cv: tag(v, 'cv')?.toLowerCase() ?? null, d: tag(v, 'd')?.toLowerCase() ?? null }));
  const ars = hdrs(pairs, 'arc-authentication-results').map((v) => ({ i: Number(v.match(/^\s*i\s*=\s*(\d+)/i)?.[1] ?? 0), v }));
  const newest = [...seals].sort((a, b) => b.i - a.i)[0];
  const first = ars.find((a) => a.i === 1) ?? [...ars].sort((a, b) => a.i - b.i)[0];
  const originalResults = first ? parseAuthResults([first.v.replace(/^\s*i\s*=\s*\d+\s*;/i, '')]).results.map((r) => ({ method: r.method, result: r.result })) : [];
  return {
    present: seals.length > 0 || ars.length > 0,
    instances: Math.max(seals.length, ars.length),
    newestChainValidation: newest?.cv ?? null,
    sealers: [...new Set(seals.map((s) => s.d).filter((d): d is string => !!d))],
    originalResults,
  };
}

export function assessAuthentication(pairs: [string, string][], trust: TrustBoundary, fromDomain: string | null, returnPathDomain: string | null): AuthAssessment {
  const arValues = hdrs(pairs, 'authentication-results');
  const receiverKnown = trust.basis !== 'none';

  const parsedHeaders = arValues.map((v, i) => {
    const p = parseAuthResults([v]);
    // The newest header (first in the file) is the one the receiving server prepended; older ones came from upstream systems or the sender.
    const fromReceiver = i === 0 && (p.authservId === null ? receiverKnown : !!trust.receiverOrg && registrableOf(p.authservId) === trust.receiverOrg);
    return { index: i + 1, authservId: p.authservId, results: p.results, trust: (fromReceiver ? 'receiver_reported' : 'unverified') as TrustLevel };
  });
  const primary = parsedHeaders.find((h) => h.trust === 'receiver_reported') ?? parsedHeaders[0] ?? null;

  const rs = hdrs(pairs, 'received-spf')[0] ?? null;
  const rsResult = rs?.trim().split(/\s+/)[0]?.toLowerCase() ?? null;
  const rsTrust: TrustLevel = receiverKnown ? 'receiver_reported' : 'unverified';

  const pick = (m: string): AuthResult[] => primary?.results.filter((r) => r.method === m) ?? [];
  const fromReg = registrableOf(fromDomain);

  // SPF
  let spf: SpfView | null = null;
  const spfAr = pick('spf')[0];
  if (spfAr && primary) {
    spf = {
      result: spfAr.result, trust: primary.trust, domain: domainOf(spfAr.props['smtp.mailfrom']), helo: domainOf(spfAr.props['smtp.helo']),
      ip: spfAr.detail.match(/(?:sender ip is|designates|client-ip=)\s*([0-9a-f:.]+)/i)?.[1] ?? null, detail: spfAr.detail,
    };
  } else if (rsResult) {
    spf = {
      result: rsResult, trust: rsTrust, domain: domainOf(rs!.match(/envelope-from=([^;\s]+)/i)?.[1]), helo: domainOf(rs!.match(/helo=([^;\s]+)/i)?.[1]),
      ip: rs!.match(/client-ip=([0-9a-f:.]+)/i)?.[1] ?? null, detail: rs!,
    };
  }
  if (spf && !spf.domain && returnPathDomain) spf.domain = returnPathDomain; // envelope sender is the Return-Path

  // DKIM
  const sigs = hdrs(pairs, 'dkim-signature').map(parseDkimSignature);
  const dkim: DkimView[] = pick('dkim').map((r) => {
    const domain = domainOf(r.props['header.d']) ?? domainOf(r.props['header.i']);
    return { result: r.result, trust: primary!.trust, domain, selector: r.props['header.s'] ?? null, aligned: domain && fromReg ? registrableOf(domain) === fromReg : null, detail: r.detail };
  });

  // DMARC
  const dm = pick('dmarc')[0];
  const dmarc: DmarcView | null = dm && primary
    ? { result: dm.result, trust: primary.trust, policy: dm.detail.match(/\bp=(none|quarantine|reject)/i)?.[1]?.toLowerCase() ?? null, headerFrom: domainOf(dm.props['header.from']), detail: dm.detail }
    : null;

  const other = (primary?.results ?? []).filter((r) => !['spf', 'dkim', 'dmarc'].includes(r.method)).map((r) => ({ method: r.method, result: r.result, detail: r.detail }));

  // Alignment (relaxed, organisational domain)
  const spfAligned = spf && spf.domain && fromReg ? spf.result === 'pass' && registrableOf(spf.domain) === fromReg : null;
  const passing = dkim.filter((d) => d.result === 'pass');
  const dkimAligned = !dkim.length ? null : passing.some((d) => d.aligned === true) ? true : passing.every((d) => d.domain) ? false : null;

  const conflicts: string[] = [];
  if (spfAr && rsResult && spfAr.result !== rsResult) conflicts.push(`Authentication-Results says SPF "${spfAr.result}" but Received-SPF says "${rsResult}".`);
  if (dmarc?.result === 'pass' && spfAligned === false && dkimAligned === false) conflicts.push('DMARC is reported as "pass", but neither the SPF domain nor any passing DKIM signature aligns with the From domain.');
  if (dmarc?.result === 'fail' && (spfAligned === true || dkimAligned === true)) conflicts.push('DMARC is reported as "fail", yet SPF or DKIM passed in alignment with the From domain.');

  const source: AuthAssessment['source'] = primary ? (primary.trust === 'receiver_reported' ? 'receiver_header' : 'unverified_header') : rsResult ? 'received_spf_only' : 'none';

  return {
    source, spf, dkim, dmarc, other,
    headers: parsedHeaders.map((h) => ({ index: h.index, authservId: h.authservId, trust: h.trust, results: h.results.map((r) => ({ method: r.method, result: r.result })) })),
    dkimSignatures: sigs, arc: parseArc(pairs),
    alignment: { fromDomain: fromReg, spfAligned, dkimAligned }, conflicts,
  };
}
