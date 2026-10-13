// A software authenticator for the tests: it makes passkeys (ES256) and answers like a browser would, so
// the passkey routes are checked against real WebAuthn data.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/** CBOR (RFC 8949), only what attestation objects and COSE keys need: maps, byte and text strings, integers. */
type Cbor = number | string | Uint8Array | Map<Cbor, Cbor> | { [key: string]: Cbor };

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  const bytes = Buffer.alloc(3);
  bytes[0] = (major << 5) | 25;
  bytes.writeUInt16BE(length, 1);
  return bytes;
}

export function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest();

/** Flags of the authenticator data: the user was present, verified, and (adding one) a credential follows. */
const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

/** The options the server sent, as far as the authenticator reads them. */
interface Options {
  challenge: string;
  rp?: { id: string };
  rpId?: string;
  user?: { id: string };
}

export interface SoftPasskey {
  id: string;
  privateKey: KeyObject;
  rpId: string;
  userHandle: string;
  counter: number;
}

/** A browser with one authenticator: it makes passkeys and signs in with them, at `origin`. */
export function softAuthenticator(origin: string) {
  const clientData = (type: string, challenge: string, overrides: Record<string, unknown> = {}) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false, ...overrides }));

  return {
    /** Answers `navigator.credentials.create()`: a new passkey for the options' domain and user. */
    create(options: Options, { verified = true, clientOverrides = {} }: { verified?: boolean; clientOverrides?: Record<string, unknown> } = {}) {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = publicKey.export({ format: 'jwk' });
      const coseKey = cbor(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
      const credentialId = randomBytes(32);
      const rpId = options.rp!.id;
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credentialId.length);
      const authData = Buffer.concat([sha256(rpId), Buffer.from([UP | (verified ? UV : 0) | AT]), Buffer.alloc(4), Buffer.alloc(16), length, credentialId, coseKey]);
      const passkey: SoftPasskey = { id: b64(credentialId), privateKey, rpId, userHandle: options.user!.id, counter: 0 };
      const response = {
        id: passkey.id,
        rawId: passkey.id,
        type: 'public-key',
        response: {
          clientDataJSON: b64(clientData('webauthn.create', options.challenge, clientOverrides)),
          attestationObject: b64(cbor({ fmt: 'none', attStmt: {}, authData })),
          transports: ['internal', 'hybrid'],
        },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform',
      };
      return { passkey, response };
    },

    /** Answers `navigator.credentials.get()` with `passkey`, counting its signatures up when `counts`. */
    get(
      options: Options,
      passkey: SoftPasskey,
      { verified = true, counts = false, rpId = passkey.rpId, userHandle = passkey.userHandle }: { verified?: boolean; counts?: boolean; rpId?: string; userHandle?: string } = {},
    ) {
      if (counts) passkey.counter++;
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(passkey.counter);
      const authData = Buffer.concat([sha256(rpId), Buffer.from([UP | (verified ? UV : 0)]), counter]);
      const json = clientData('webauthn.get', options.challenge);
      const signature = sign('sha256', Buffer.concat([authData, sha256(json)]), passkey.privateKey);
      return {
        id: passkey.id,
        rawId: passkey.id,
        type: 'public-key',
        response: { clientDataJSON: b64(json), authenticatorData: b64(authData), signature: b64(signature), userHandle },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform',
      };
    },
  };
}
