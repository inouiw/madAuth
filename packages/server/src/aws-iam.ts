// Webhook calls signed with AWS IAM (WEBHOOK_AUTH=aws-iam), for a receiver behind a Lambda Function URL with AWS_IAM
// auth: madAuth signs each call with Signature Version 4, with the credentials of its environment (on Lambda, the
// function's role). AWS checks the signature before the receiver runs, and no secret is shared. See "Webhooks" in
// docs/server.md.
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';

/** Authenticates a webhook call: the headers to send it with, the given ones included. */
export type WebhookSigner = (call: { url: string; headers: Record<string, string>; body: string }) => Promise<{ headers: Record<string, string> } | { problem: string }>;

/** A request as the SigV4 signer of the AWS SDK (`SignatureV4` of @smithy/signature-v4) takes it. */
export interface SignableRequest {
  method: string;
  protocol: string;
  hostname: string;
  port?: number;
  path: string;
  query: Record<string, string | string[]>;
  headers: Record<string, string>;
  body: string;
}

/** The part of `SignatureV4` madAuth uses; it knows the service, the region and the credentials. */
export interface SigV4 {
  sign(request: SignableRequest): Promise<{ headers: Record<string, string> }>;
}

/** The region of a Lambda Function URL (`https://<id>.lambda-url.<region>.on.aws/`), or null for another URL. */
export function functionUrlRegion(url: string): string | null {
  const host = URL.canParse(url) ? new URL(url).hostname : '';
  return /^[a-z0-9]+\.lambda-url\.([a-z0-9-]+)\.on\.aws$/.exec(host)?.[1] ?? null;
}

type Data = string | ArrayBuffer | ArrayBufferView;

const bytes = (data: Data): Buffer =>
  typeof data === 'string' ? Buffer.from(data, 'utf8') : ArrayBuffer.isView(data) ? Buffer.from(data.buffer, data.byteOffset, data.byteLength) : Buffer.from(data);

/** SHA-256, or HMAC-SHA256 with a key, from node:crypto: the hash the signer is made with. */
export class Sha256 {
  private readonly hash: Hash | Hmac;

  constructor(key?: Data) {
    this.hash = key === undefined ? createHash('sha256') : createHmac('sha256', bytes(key));
  }

  update(data: Data): void {
    this.hash.update(bytes(data));
  }

  async digest(): Promise<Uint8Array> {
    return new Uint8Array(this.hash.digest());
  }
}

/** The query of a URL as the signer takes it: a key that repeats has its values in a list. */
function queryOf(params: URLSearchParams): Record<string, string | string[]> {
  return Object.fromEntries(
    [...new Set(params.keys())].map((key) => {
      const values = params.getAll(key);
      return [key, values.length === 1 ? values[0]! : values];
    }),
  );
}

/** Signs each call with `sigv4`: the request exactly as it is sent, its host and body included. */
export function createAwsIamSigner(sigv4: SigV4): WebhookSigner {
  return async ({ url, headers, body }) => {
    const target = new URL(url);
    const request: SignableRequest = {
      method: 'POST',
      protocol: target.protocol,
      hostname: target.hostname,
      ...(target.port ? { port: Number(target.port) } : {}),
      path: target.pathname,
      query: queryOf(target.searchParams),
      headers: { ...headers, host: target.host },
      body,
    };
    return sigv4.sign(request).then(
      // fetch sends the same host itself, from the URL.
      ({ headers: { host: _host, ...sent } }) => ({ headers: sent }),
      (e: unknown) => ({ problem: `could not sign the call with AWS IAM: ${e instanceof Error ? e.message : String(e)}` }),
    );
  };
}

/**
 * The signer for calls to a Function URL in `region`, from the AWS SDK. The credentials come from the SDK's default
 * chain: on Lambda the function's role, elsewhere e.g. the role of an ECS task or EC2 instance. The chain keeps them
 * and gets new ones before they expire.
 */
export async function awsIamSignerFromSdk(region: string): Promise<{ signer: WebhookSigner } | { problem: string }> {
  const signing = await import('@smithy/signature-v4').catch((e: Error) => e);
  if (signing instanceof Error) return { problem: `the AWS SDK's signer could not be loaded: npm install @smithy/signature-v4 (${signing.message})` };
  const credentials = await import('@aws-sdk/credential-provider-node').catch((e: Error) => e);
  if (credentials instanceof Error) {
    return { problem: `the AWS SDK's credentials could not be loaded: npm install @aws-sdk/credential-provider-node (${credentials.message})` };
  }
  const sigv4 = new signing.SignatureV4({ service: 'lambda', region, credentials: credentials.defaultProvider(), sha256: Sha256 });
  return { signer: createAwsIamSigner(sigv4) };
}
