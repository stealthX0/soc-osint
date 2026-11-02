import type { ReactNode } from 'react';
import type { ApiState } from '../lib/hooks';
import { Badge, ErrorBox, Spinner } from './ui';

/** Renders the right thing for each request state so pages only describe the success case. */
export function Result<T>({ state, children, idle }: { state: Pick<ApiState<T>, 'status' | 'data' | 'error' | 'cached'> & { reload?: () => void }; children: (data: T) => ReactNode; idle?: ReactNode }) {
  if (state.status === 'idle') return <>{idle ?? null}</>;
  if (state.status === 'loading') return <div className="py-6"><Spinner label="Querying providers" /></div>;
  if (state.status === 'error' && state.error) return <ErrorBox error={state.error} onRetry={state.reload} />;
  if (state.data === null) return null;
  return (
    <div>
      {state.cached && <div className="mb-3"><Badge tone="info" title="Served from edge cache to protect upstream quotas">cached result</Badge></div>}
      {children(state.data)}
    </div>
  );
}
