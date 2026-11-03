import { mock } from 'node:test';

export type Handler = (url: URL, init?: RequestInit) => Response | Promise<Response> | undefined;

/** Replaces global fetch for the duration of a test; unmatched requests throw so nothing hits the network. */
export function mockFetch(handlers: Handler[]) {
  const calls: string[] = [];
  const m = mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    calls.push(url.toString());
    for (const h of handlers) {
      const r = await h(url, init);
      if (r) return r;
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  });
  return { calls, restore: () => m.mock.restore() };
}

export const jsonRes = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/** DoH JSON response builder for tests. */
export function doh(table: Record<string, Record<string, string[]>>, opts: { ad?: boolean } = {}): Handler {
  const TYPE: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
  return (url) => {
    if (!/cloudflare-dns\.com|dns\.google/.test(url.hostname)) return undefined;
    const name = url.searchParams.get('name')!.toLowerCase();
    const type = url.searchParams.get('type')!;
    const rows = table[name]?.[type];
    if (!rows) return jsonRes({ Status: table[name] ? 0 : 3 });
    return jsonRes({
      Status: 0,
      AD: opts.ad ?? false,
      Answer: rows.map((data) => ({ name: `${name}.`, type: TYPE[type], TTL: 300, data })),
    });
  };
}

export function ctxFor(path: string, init: RequestInit & { env?: Record<string, unknown> } = {}) {
  const { env, ...rest } = init;
  const request = new Request(`https://app.test${path}`, rest);
  const waits: Promise<unknown>[] = [];
  return {
    request,
    env: env ?? {},
    params: {},
    data: {},
    waitUntil: (p: Promise<unknown>) => void waits.push(p),
    next: async () => new Response('next'),
  } as never;
}
