import { Card, Badge, KV, Empty } from '../../components/ui';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import { resTone } from './common';

export function HeadersTab({ r }: { r: ParseStageResult }) {
  const fx = r.forensics;
  return (
    <>
      {fx ? (
        <div className="space-y-4">
          <Card title="Authentication">
            <div className="mb-3 flex flex-wrap gap-2">
              {fx.authentication.spf ? <Badge tone={resTone(fx.authentication.spf.result)}>SPF: {fx.authentication.spf.result}</Badge> : <Badge>SPF: n/a</Badge>}
              {fx.authentication.dkim.length ? fx.authentication.dkim.map((d, i) => <Badge key={i} tone={resTone(d.result)}>DKIM: {d.result}{d.domain ? ` (${d.domain})` : ''}</Badge>) : <Badge>DKIM: n/a</Badge>}
              {fx.authentication.dmarc ? <Badge tone={resTone(fx.authentication.dmarc.result)}>DMARC: {fx.authentication.dmarc.result}{fx.authentication.dmarc.policy ? ` p=${fx.authentication.dmarc.policy}` : ''}</Badge> : <Badge>DMARC: n/a</Badge>}
              {fx.authentication.source !== 'none' && <Badge tone={fx.authentication.source === 'receiver_header' ? 'accent' : 'warn'}>{fx.authentication.source === 'receiver_header' ? 'from the receiving server' : 'not tied to the receiving server'}</Badge>}
            </div>
            <KV rows={[
              ['From domain', fx.authentication.alignment.fromDomain],
              ['SPF aligned with From', fx.authentication.alignment.spfAligned === null ? 'unknown' : fx.authentication.alignment.spfAligned ? 'yes' : 'no'],
              ['DKIM aligned with From', fx.authentication.alignment.dkimAligned === null ? 'unknown' : fx.authentication.alignment.dkimAligned ? 'yes' : 'no'],
              ['DKIM signatures', fx.authentication.dkimSignatures.map((s) => `${s.domain ?? '?'} (${s.selector ?? '?'})`).join(', ') || null],
              ['ARC', fx.authentication.arc.present ? `${fx.authentication.arc.instances} hop(s), newest chain ${fx.authentication.arc.newestChainValidation ?? 'unknown'}` : null],
            ]} mono />
            {fx.authentication.conflicts.length > 0 && <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-amber">{fx.authentication.conflicts.map((c) => <li key={c}>{c}</li>)}</ul>}
          </Card>
        </div>
      ) : <Empty>No headers were supplied, so there is no routing or authentication data. Paste the raw headers for the strongest analysis.</Empty>}
    </>
  );
}
