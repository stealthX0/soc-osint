import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../../lib/api';
import { planSenderChecks, type SenderCheckRequest, type SenderCheckResponse } from '../../../shared/phishing/sender';
import { assembleUrlStage, type RankedLink, type UrlStageResult } from '../../../shared/phishing/urlTriage';
import type { ParseStageResult } from '../../../shared/phishing/parse';
import type { PhishingInput } from '../../../shared/phishing/types';

export type Slot = { req: SenderCheckRequest; state: 'running' | 'done'; res?: SenderCheckResponse; error?: string };

/**
 * Runs the sender / infrastructure lookups one request at a time (3 in parallel), so each call has its own upstream budget.
 * Aborted when the result goes away. Also records when the last lookup returned, for the timeline.
 */
export function useSenderStage(parse: ParseStageResult, emailRep: boolean) {
  const plan = useMemo(() => planSenderChecks(parse, { emailRep }), [parse, emailRep]);
  const [slots, setSlots] = useState<Slot[]>([]);
  const [finishedAt, setFinishedAt] = useState<number | null>(null);
  useEffect(() => {
    const ac = new AbortController();
    setSlots(plan.requests.map((req) => ({ req, state: 'running' as const })));
    setFinishedAt(null);
    let next = 0;
    const worker = async () => {
      while (next < plan.requests.length && !ac.signal.aborted) {
        const i = next++;
        const req = plan.requests[i];
        let patch: Partial<Slot>;
        try {
          const { data } = await api<SenderCheckResponse>('/api/phishing/sender', { method: 'POST', body: req, signal: ac.signal });
          patch = { state: 'done', res: data };
        } catch (e) {
          if (ac.signal.aborted) return;
          patch = { state: 'done', error: e instanceof Error ? e.message : 'The lookup failed.' };
        }
        setSlots((cur) => cur.map((s, j) => (j === i ? { ...s, ...patch } : s)));
      }
    };
    void Promise.all([worker(), worker(), worker()]).then(() => { if (!ac.signal.aborted && plan.requests.length > 0) setFinishedAt(Date.now()); });
    return () => ac.abort();
  }, [plan]);
  const findings = useMemo(() => slots.flatMap((s) => s.res?.findings ?? []), [slots]);
  const results = useMemo(() => slots.flatMap((s) => (s.res ? [s.res] : [])), [slots]);
  const running = slots.filter((s) => s.state === 'running').length;
  return { plan, slots, findings, results, running, finishedAt };
}
export type SenderStage = ReturnType<typeof useSenderStage>;

/** Folds a later batch into what is already known, then rebuilds findings and check rows from the merged state. */
export function mergeStage(prev: UrlStageResult | null, next: UrlStageResult): UrlStageResult {
  const lookups = { ...(prev?.lookups ?? {}), ...next.lookups };
  const lookupErrors = Object.fromEntries(Object.entries({ ...(prev?.lookupErrors ?? {}), ...next.lookupErrors }).filter(([u]) => !lookups[u]));
  const ranked: RankedLink[] = next.ranked.map((l) => ({ ...l, tier: lookups[l.url] || lookupErrors[l.url] ? 'deep' : l.tier }));
  return assembleUrlStage({ ...next, ranked, lookups, lookupErrors, deepChecked: [...new Set([...(prev?.deepChecked ?? []), ...next.deepChecked])], maxDeep: 2 });
}

export interface LinkStage {
  stage: UrlStageResult | null;
  busy: boolean;
  error: string | null;
  /** Triage + feed check + the top link, then the runner-up in a second request. */
  run: () => Promise<void>;
  deepNext: () => Promise<void>;
  /** Candidates that have not had a full lookup yet. */
  remaining: string[];
  /** When the last investigation request returned (epoch ms), for the timeline. */
  investigatedAt: number | null;
}

/**
 * The link investigation. It sends URLs to providers, so it only runs when the analyst presses the button, or, if they
 * opted in with the "investigate links automatically" preference, once after parsing. One full lookup per request.
 */
export function useLinkStage(r: ParseStageResult, input: PhishingInput, auto = false): LinkStage {
  const [stage, setStage] = useState<UrlStageResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [investigatedAt, setInvestigatedAt] = useState<number | null>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);

  const payload = (deep?: string[]) => ({
    links: r.links.map((l) => ({ url: l.normalized, text: l.text, sources: l.sources, count: l.count, wrapped: !!l.wrapper })),
    context: {
      senderDomains: r.indicators.domains.filter((d) => d.roles.some((x) => ['from', 'return_path', 'dkim', 'sender_header'].includes(x))).map((d) => d.domain),
      claimedDomains: input.sender?.domain ? [input.sender.domain] : [],
      displayName: input.sender?.displayName || r.forensics?.addresses.from[0]?.display || undefined,
      subject: r.content.subject ?? input.subject,
      text: r.content.text.slice(0, 20_000),
    },
    // One full lookup per request: each lookup fans out into many outbound calls, and every request is its own Worker invocation with its own allowance.
    ...(deep ? { deep, maxDeep: deep.length } : { maxDeep: 1 }),
  });

  const call = async (deep?: string[]): Promise<UrlStageResult | null> => {
    try {
      const { data } = await api<UrlStageResult>('/api/phishing/urls', { method: 'POST', body: payload(deep), signal: abort.current?.signal });
      setStage((p) => mergeStage(p, data));
      setInvestigatedAt(Date.now());
      return data;
    } catch (e) {
      if (!abort.current?.signal.aborted) setError(e instanceof Error ? e.message : 'The link investigation failed.');
      return null;
    }
  };
  const pending = (st: UrlStageResult | null) => (st ? st.deepCandidates.filter((u) => !st.lookups[u] && !st.lookupErrors[u]) : []);

  const run = async () => {
    abort.current?.abort();
    abort.current = new AbortController();
    setBusy(true); setError(null);
    const first = await call();
    const next = pending(first)[0];
    if (first && next) await call([next]);
    setBusy(false);
  };
  const deepNext = async () => {
    abort.current ??= new AbortController();
    setBusy(true); setError(null);
    const next = pending(stage)[0];
    if (next) await call([next]);
    setBusy(false);
  };

  // Opt-in preference: investigate once after parsing. Off by default, in which case nothing here ever runs.
  useEffect(() => { if (auto && r.links.length > 0) void run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return { stage, busy, error, run, deepNext, remaining: pending(stage), investigatedAt };
}
