import { toErrorCode, type MadauthError } from './result.js';

export type HttpResult<T> = { ok: true; data: T } | { ok: false; status: number; error: MadauthError };

export interface RequestInit {
  method?: 'GET' | 'POST';
  body?: unknown;
}

/** Calls the madAuth server with its cookies and turns every outcome into an {@link HttpResult}. */
export async function request<T>(serverUrl: string, path: string, init: RequestInit = {}): Promise<HttpResult<T>> {
  let response: Response;
  try {
    response = await fetch(`${serverUrl}${path}`, {
      method: init.method ?? 'GET',
      credentials: 'include',
      headers: init.body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: { code: 'network', message: `Could not reach the madAuth server at ${serverUrl}: ${(e as Error).message}` },
    };
  }
  const data = (await response.json().catch(() => undefined)) as (T & { error?: unknown; message?: unknown }) | undefined;
  if (response.ok) {
    // E.g. an SPA fallback page answering for /auth/... because the server is not behind this URL.
    if (data === undefined && response.status !== 204) {
      return {
        ok: false,
        status: response.status,
        error: { code: 'unknown', message: `${path} did not return JSON. Is the madAuth server at ${serverUrl}?` },
      };
    }
    return { ok: true, data: data as T };
  }
  return {
    ok: false,
    status: response.status,
    error: {
      code: toErrorCode(data?.error),
      message: typeof data?.message === 'string' ? data.message : `${path} failed with HTTP ${response.status}`,
    },
  };
}
