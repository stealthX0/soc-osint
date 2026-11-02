/** Pure path matcher (kept free of React so it can be unit-tested directly). */
export function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const a = pattern.split('/').filter(Boolean);
  const b = pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  if (a.length !== b.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i].startsWith(':')) params[a[i].slice(1)] = decodeURIComponent(b[i]);
    else if (a[i] !== b[i]) return null;
  }
  return params;
}
