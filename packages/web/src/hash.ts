/**
 * Takes a parameter out of the page's hash (`#name=value&…`): its value, or null if there is none. The
 * address bar, and so the history, is tidied up right away: the values are secrets (an e-mail link's
 * token) or one-off instructions (what a redirect sign-in needs next).
 */
export function takeHashParam(name: string): string | null {
  const params = new URLSearchParams(location.hash.slice(1));
  const value = params.get(name);
  if (value === null) return null;
  params.delete(name);
  const hash = params.toString();
  history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
  return value;
}
