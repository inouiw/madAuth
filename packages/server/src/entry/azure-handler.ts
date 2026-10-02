import type { Cookie, HttpRequest, HttpResponseInit } from '@azure/functions';
import type { Hono } from 'hono';

const sameSiteValues = { strict: 'Strict', lax: 'Lax', none: 'None' } as const;

/** Parses one Set-Cookie header into the cookie object Azure Functions expects. */
export function parseSetCookie(header: string): Cookie {
  const [pair, ...attributes] = header.split(';').map((s) => s.trim());
  const eq = pair.indexOf('=');
  const cookie: Cookie = { name: pair.slice(0, eq), value: pair.slice(eq + 1) };
  for (const attribute of attributes) {
    const [key, ...rest] = attribute.split('=');
    const value = rest.join('=');
    switch (key.toLowerCase()) {
      case 'domain':
        cookie.domain = value;
        break;
      case 'path':
        cookie.path = value;
        break;
      case 'expires':
        cookie.expires = new Date(value);
        break;
      case 'max-age':
        cookie.maxAge = Number(value);
        break;
      case 'secure':
        cookie.secure = true;
        break;
      case 'httponly':
        cookie.httpOnly = true;
        break;
      case 'samesite':
        cookie.sameSite = sameSiteValues[value.toLowerCase() as keyof typeof sameSiteValues];
        break;
    }
  }
  return cookie;
}

/**
 * Forwards an Azure Functions v4 HTTP request to the madAuth app. Set-Cookie headers are passed as
 * `cookies`, because Azure would otherwise merge several of them into one header.
 */
export async function handleAzureRequest(app: Hono, request: HttpRequest): Promise<HttpResponseInit> {
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  const response = await app.fetch(
    new Request(request.url, {
      method: request.method,
      headers: request.headers,
      body: hasBody ? await request.arrayBuffer() : undefined,
    }),
  );
  const headers = new Headers(response.headers);
  headers.delete('set-cookie');
  return {
    status: response.status,
    headers,
    cookies: response.headers.getSetCookie().map(parseSetCookie),
    body: response.body ? new Uint8Array(await response.arrayBuffer()) : undefined,
  };
}
