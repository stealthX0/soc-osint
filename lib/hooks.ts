import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiClientError } from './api';

export interface ApiState<T> {
  status: 'idle' | 'loading' | 'success' | 'error';
  data: T | null;
  error: ApiClientError | null;
  cached: boolean;
  reload: () => void;
}

/**
 * Fetches `path` whenever `params` changes. Pass `params = null` to stay idle.
 * In-flight requests are aborted when inputs change or the component unmounts,
 * so a slow earlier response can never overwrite a newer one.
 */
export function useApi<T>(path: string, params: Record<string, string | number | undefined> | null): ApiState<T> {
  const [state, setState] = useState<Omit<ApiState<T>, 'reload'>>({ status: 'idle', data: null, error: null, cached: false });
  const [nonce, setNonce] = useState(0);
  const key = params === null ? null : JSON.stringify([path, params, nonce]);
  const paramsRef = useRef(params);
  paramsRef.current = params;

  useEffect(() => {
    if (key === null || paramsRef.current === null) {
      setState({ status: 'idle', data: null, error: null, cached: false });
      return;
    }
    const ctrl = new AbortController();
    setState((s) => ({ ...s, status: 'loading', error: null }));
    api<T>(path, { params: paramsRef.current, signal: ctrl.signal }).then(
      (r) => setState({ status: 'success', data: r.data, error: null, cached: r.cached }),
      (e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        setState({ status: 'error', data: null, error: e instanceof ApiClientError ? e : new ApiClientError('Request failed.', 'UNKNOWN', 0), cached: false });
      },
    );
    return () => ctrl.abort();
  }, [key, path]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, reload };
}

/** One-shot request triggered by a user action (e.g. POST of pasted headers). */
export function useAction<T, A>(fn: (arg: A, signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<{ status: 'idle' | 'loading' | 'success' | 'error'; data: T | null; error: ApiClientError | null }>({ status: 'idle', data: null, error: null });
  const ctrl = useRef<AbortController | null>(null);
  const run = useCallback(
    async (arg: A) => {
      ctrl.current?.abort();
      const c = new AbortController();
      ctrl.current = c;
      setState({ status: 'loading', data: null, error: null });
      try {
        const data = await fn(arg, c.signal);
        if (!c.signal.aborted) setState({ status: 'success', data, error: null });
      } catch (e) {
        if (c.signal.aborted) return;
        setState({ status: 'error', data: null, error: e instanceof ApiClientError ? e : new ApiClientError('Request failed.', 'UNKNOWN', 0) });
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  const reset = useCallback(() => {
    ctrl.current?.abort();
    ctrl.current = null;
    setState({ status: 'idle', data: null, error: null });
  }, []);
  useEffect(() => () => ctrl.current?.abort(), []);
  return { ...state, run, reset };
}
