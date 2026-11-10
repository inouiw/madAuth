// The device of a request, as a session records it: the browser's IP address, and the browser and operating system
// read from its user agent. Only shown to the user and the admins, never used to decide anything.
import { isIP } from 'node:net';
import type { Context } from 'hono';

export interface Device {
  /** The IP address; null if unknown. */
  ip: string | null;
  /** e.g. `Firefox`; null for a user agent madAuth doesn't know. */
  browser: string | null;
  /** e.g. `macOS`; null for one madAuth doesn't know. */
  os: string | null;
}

/** The browsers madAuth tells apart, the first that matches wins: Edge, Opera and Samsung's say "Chrome" too. */
const BROWSERS: [RegExp, string][] = [
  [/\bEdg(e|A|iOS)?\//, 'Edge'],
  [/\bOPR\/|\bOpera\b/, 'Opera'],
  [/\bSamsungBrowser\//, 'Samsung Internet'],
  [/\bFirefox\/|\bFxiOS\//, 'Firefox'],
  [/\bChrome\/|\bCriOS\/|\bChromium\//, 'Chrome'],
  [/\bVersion\/[\d.]+.*\bSafari\/|\b(iPhone|iPad).*\bAppleWebKit\//, 'Safari'],
];

/** The operating systems, the first that matches wins: iOS and Android say "like Mac OS X" and "Linux". */
const SYSTEMS: [RegExp, string][] = [
  [/\bWindows\b/, 'Windows'],
  [/\biPhone\b|\biPod\b/, 'iOS'],
  [/\biPad\b/, 'iPadOS'],
  [/\bAndroid\b/, 'Android'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bMac OS X\b|\bMacintosh\b/, 'macOS'],
  [/\bLinux\b/, 'Linux'],
];

const firstMatch = (list: [RegExp, string][], value: string): string | null => list.find(([pattern]) => pattern.test(value))?.[1] ?? null;

/**
 * The browser and the operating system of a user agent, by name only (no version), from a short list: an unknown
 * one is null, so nothing a client sends ends up in the store as it was sent.
 */
export function parseUserAgent(userAgent: string | undefined): Pick<Device, 'browser' | 'os'> {
  const value = userAgent ?? '';
  return { browser: firstMatch(BROWSERS, value), os: firstMatch(SYSTEMS, value) };
}

/** The longest IP address in text: an IPv6 address with an IPv4 tail. */
export const MAX_IP_LENGTH = 45;

/**
 * An IP address as a header or the runtime gives it, without a port (`203.0.113.7:5123`, `[2001:db8::1]:443`) and
 * an IPv4 address mapped into IPv6 as IPv4; null if it is none.
 */
export function normalizeIp(value: string | undefined): string | null {
  const trimmed = value?.trim() ?? '';
  const bracketed = /^\[([^\]]+)\](:\d+)?$/.exec(trimmed)?.[1];
  const withoutPort = bracketed ?? (/^[\d.]+:\d+$/.test(trimmed) ? trimmed.slice(0, trimmed.lastIndexOf(':')) : trimmed);
  const address = withoutPort.replace(/^::ffff:(?=[\d.]+$)/i, '');
  // At most 45 characters, the longest IPv6 address in text: a zone id (`fe80::1%eth0`) could make it longer, and
  // `user.signed_in` carries it, which must fit what AWS KMS signs (see webhook-size.test.ts).
  return address.length <= MAX_IP_LENGTH && isIP(address) ? address : null;
}

/** What the runtimes put into Hono's `c.env`: Node's socket (@hono/node-server), the event of AWS Lambda. */
interface RuntimeEnv {
  incoming?: { socket?: { remoteAddress?: string } };
  event?: { requestContext?: { http?: { sourceIp?: string }; identity?: { sourceIp?: string } } };
}

/**
 * The browser's IP address: the last entry of `header` when one is configured (CLIENT_IP_HEADER, the entry the
 * nearest proxy added, which the browser can't forge), else the peer address the runtime reports.
 */
export function clientIp(c: Context, header: string | undefined): string | null {
  if (header) return normalizeIp(c.req.header(header)?.split(',').at(-1));
  const env = c.env as RuntimeEnv | undefined;
  const context = env?.event?.requestContext;
  return normalizeIp(env?.incoming?.socket?.remoteAddress ?? context?.http?.sourceIp ?? context?.identity?.sourceIp);
}

/** The device of the request `c`. */
export function deviceOf(c: Context, header: string | undefined): Device {
  return { ip: clientIp(c, header), ...parseUserAgent(c.req.header('user-agent')) };
}
