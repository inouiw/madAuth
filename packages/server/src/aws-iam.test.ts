import { SignatureV4 } from '@smithy/signature-v4';
import { describe, expect, it } from 'vitest';
import { Sha256, awsIamSignerFromSdk, createAwsIamSigner, functionUrlRegion, type SignableRequest } from './aws-iam.js';

// The example credentials of AWS's Signature Version 4 test suite.
const credentials = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' };

describe('AWS IAM signer', () => {
  it('signs like the AWS Signature Version 4 test suite (get-vanilla), with the hash from node:crypto', async () => {
    const sigv4 = new SignatureV4({ service: 'service', region: 'us-east-1', credentials, sha256: Sha256, applyChecksum: false });

    const signed = await sigv4.sign(
      { method: 'GET', protocol: 'https:', hostname: 'example.amazonaws.com', path: '/', query: {}, headers: { host: 'example.amazonaws.com' } },
      { signingDate: new Date('2015-08-30T12:36:00Z') },
    );

    expect(signed.headers.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, ' +
        'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
  });

  it('takes the region from a Function URL, and knows no other URL', () => {
    expect(functionUrlRegion('https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.eu-central-1.on.aws/')).toBe('eu-central-1');
    expect(functionUrlRegion('https://abc123.lambda-url.us-gov-west-1.on.aws/webhook?x=1')).toBe('us-gov-west-1');
    expect(functionUrlRegion('https://hooks.example.com/x')).toBeNull();
    expect(functionUrlRegion('https://abc.lambda-url.eu-central-1.on.aws.example.com/')).toBeNull();
    expect(functionUrlRegion('not a url')).toBeNull();
  });

  it('signs the path, the query and the host of the URL, and leaves the host to fetch', async () => {
    const signed: SignableRequest[] = [];
    const sign = createAwsIamSigner({
      async sign(request) {
        signed.push(request);
        return { headers: { ...request.headers, authorization: 'AWS4-HMAC-SHA256 …' } };
      },
    });

    const result = await sign({ url: 'https://abc.lambda-url.eu-central-1.on.aws:8443/hook?a=1&b=2&a=3', headers: { 'webhook-id': 'msg_1' }, body: '{}' });

    expect(result).toEqual({ headers: { 'webhook-id': 'msg_1', authorization: 'AWS4-HMAC-SHA256 …' } });
    expect(signed).toEqual([
      {
        method: 'POST',
        protocol: 'https:',
        hostname: 'abc.lambda-url.eu-central-1.on.aws',
        port: 8443,
        path: '/hook',
        query: { a: ['1', '3'], b: '2' },
        headers: { 'webhook-id': 'msg_1', host: 'abc.lambda-url.eu-central-1.on.aws:8443' },
        body: '{}',
      },
    ]);
  });

  it('reports a call it could not sign, e.g. without credentials', async () => {
    const sigv4 = new SignatureV4({
      service: 'lambda',
      region: 'eu-central-1',
      credentials: async () => {
        throw new Error('Could not load credentials from any providers');
      },
      sha256: Sha256,
    });

    expect(await createAwsIamSigner(sigv4)({ url: 'https://abc.lambda-url.eu-central-1.on.aws/', headers: {}, body: '{}' })).toEqual({
      problem: 'could not sign the call with AWS IAM: Could not load credentials from any providers',
    });
    // Also what isn't an Error.
    const rejecting = createAwsIamSigner({ sign: () => Promise.reject('no role') });
    expect(await rejecting({ url: 'https://abc.lambda-url.eu-central-1.on.aws/', headers: {}, body: '{}' })).toEqual({ problem: 'could not sign the call with AWS IAM: no role' });
  });

  it('loads the signer and the default credentials from the AWS SDK', async () => {
    expect(await awsIamSignerFromSdk('eu-central-1')).toEqual({ signer: expect.any(Function) });
  });
});
