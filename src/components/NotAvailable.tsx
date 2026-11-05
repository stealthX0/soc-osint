import type { ProviderStatus } from '../../shared/types';

/** Explains why an optional provider card is empty: no key, quota paused, or the request failed. */
export function NotAvailable({ providers, provider, secret, extra }: { providers: ProviderStatus[]; provider: string; secret: string; extra?: string }) {
  const p = providers.find((x) => x.name.startsWith(provider));
  if (p?.skipped && p.error && /budget/i.test(p.error)) {
    return <p className="text-sm text-amber">{provider} is temporarily paused to protect its API quota ({p.error}). Try again shortly.</p>;
  }
  if (p && !p.skipped && !p.ok) {
    return (
      <p className="text-sm text-amber">
        {provider} lookup failed{p.error ? `: ${p.error}` : '.'} Check that the <code className="font-mono">{secret}</code> secret holds a valid key, then try again in a couple of minutes.
      </p>
    );
  }
  return (
    <p className="text-sm text-faint">
      Not available. The site operator can enable this by setting {/^[AEIOU]/.test(secret) ? 'an' : 'a'} <code className="font-mono">{secret}</code> secret.{extra}
    </p>
  );
}
