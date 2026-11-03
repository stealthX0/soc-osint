import { useState } from 'react';
import { PageHeader, LookupForm, Card, KV, Badge, DataTable, Empty, Tabs, CopyButton } from '../components/ui';
import { Result } from '../components/Result';
import { useApi } from '../lib/hooks';
import { navigate, useLocation } from '../lib/router';
import { defang, refang } from '../../shared/domain';
import type { IPConversion } from '../../shared/ip';

type Tab = 'convert' | 'range' | 'defang';
interface RangeResult { start: string; end: string; count: number; blocks: { cidr: string; firstAddress: string; lastAddress: string; totalAddresses: string }[] }

function Defanger() {
  const [text, setText] = useState('');
  const out = { defanged: defang(text), refanged: refang(text) };
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line bg-panel/90 p-3">
        <label htmlFor="df" className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-muted">URLs, domains, IPs or e-mail addresses (one per line)</label>
        <textarea id="df" rows={6} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder={'https://malicious.example.com/payload.exe\nattacker@evil.example\n198.51.100.23'} className="w-full resize-y rounded-lg border border-line2 bg-bg2 p-3 font-mono text-xs placeholder:text-faint focus:border-teal/60" />
        <p className="mt-1 text-xs text-faint">Runs entirely in your browser; nothing is sent anywhere.</p>
      </div>
      {text.trim() ? (
        <div className="grid gap-4 md:grid-cols-2">
          {([['Defanged (safe to share)', out.defanged], ['Refanged (live again)', out.refanged]] as const).map(([t, v]) => (
            <Card key={t} title={t} action={<CopyButton text={v} />}><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">{v}</pre></Card>
          ))}
        </div>
      ) : <Empty>Paste indicators above to make them safe to put in tickets and chat, or to reverse that.</Empty>}
    </div>
  );
}

export default function UtilitiesPage() {
  const { params } = useLocation();
  const tab = (['convert', 'range', 'defang'].includes(params.get('tab') ?? '') ? params.get('tab') : 'convert') as Tab;
  const value = params.get('value') ?? '';
  const start = params.get('start') ?? '';
  const end = params.get('end') ?? '';
  const conv = useApi<IPConversion>('/api/util/ip-convert', tab === 'convert' && value ? { value } : null);
  const range = useApi<RangeResult>('/api/util/ip-range', tab === 'range' && start && end ? { start, end } : null);

  return (
    <div className="max-w-5xl">
      <PageHeader icon="wrench" title="Utilities" blurb="Everyday helpers for analysts: convert IP notations, turn ranges into CIDR blocks, defang indicators." />
      <Tabs tabs={[{ id: 'convert', label: 'IP converter', icon: 'bolt' }, { id: 'range', label: 'Range to CIDR', icon: 'network' }, { id: 'defang', label: 'Defang / refang', icon: 'shield' }]} value={tab} onChange={(t) => navigate(`/utilities?tab=${t}`)} />

      {tab === 'convert' && (
        <>
          <LookupForm values={{ value }} busy={conv.status === 'loading'} submitLabel="Convert" fields={[{ name: 'value', label: 'IP address, decimal integer or 0x hex', placeholder: '192.168.1.1 · 3232235777 · 0xC0A80101 · 2001:db8::1' }]} onSubmit={(v) => navigate(`/utilities?tab=convert&value=${encodeURIComponent(v.value)}`)} />
          <Result state={conv} idle={<Empty>Enter an address in any notation to see every representation, including the reverse-DNS name.</Empty>}>
            {(d) => (
              <div className="space-y-4">
                <Card title={`IPv${d.version}`} action={<Badge>{d.scope}</Badge>}>
                  <KV mono rows={[
                    ['Canonical', d.canonical], ['Decimal', d.decimal], ['Hexadecimal', d.hex], ['Binary', <span key="b" className="break-all">{d.binary}</span>],
                    ['Octal (dotted)', d.octal], ['IPv4-mapped IPv6', d.ipv4MappedIPv6], ['Expanded', d.expanded], ['Compressed', d.compressed], ['Embedded IPv4', d.embeddedIPv4],
                    ['Reverse DNS name', <span key="r" className="break-all">{d.reverseDns}</span>],
                  ]} />
                  <p className="mt-3 text-xs text-faint">{d.scopeLabel}</p>
                </Card>
              </div>
            )}
          </Result>
        </>
      )}

      {tab === 'range' && (
        <>
          <LookupForm values={{ start, end }} busy={range.status === 'loading'} submitLabel="Convert" fields={[{ name: 'start', label: 'First address', placeholder: '10.0.0.5' }, { name: 'end', label: 'Last address', placeholder: '10.0.1.20' }]} onSubmit={(v) => navigate(`/utilities?tab=range&start=${encodeURIComponent(v.start)}&end=${encodeURIComponent(v.end)}`)} />
          <Result state={range} idle={<Empty>Enter the first and last address to get the smallest set of CIDR blocks that covers exactly that range.</Empty>}>
            {(d) => (
              <div className="space-y-4">
                <Card title={`${d.count} CIDR block${d.count === 1 ? '' : 's'}`} action={<CopyButton text={d.blocks.map((b) => b.cidr).join('\n')} label="Copy all" />}>
                  <DataTable head={['CIDR', 'First', 'Last', 'Addresses']} rows={d.blocks.map((b) => [<span key="c" className="font-mono">{b.cidr}</span>, <span key="f" className="font-mono text-xs">{b.firstAddress}</span>, <span key="l" className="font-mono text-xs">{b.lastAddress}</span>, BigInt(b.totalAddresses).toLocaleString('en-US')])} />
                </Card>
              </div>
            )}
          </Result>
        </>
      )}

      {tab === 'defang' && <Defanger />}
    </div>
  );
}
