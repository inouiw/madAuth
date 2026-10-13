// The browser's side of passkeys (WebAuthn): turning the server's JSON options into what
// `navigator.credentials` takes, and its answer back into JSON. Browsers since 2024 do this themselves
// (`parseCreationOptionsFromJSON`, `toJSON`); older ones get the same done here.
import { fail, ok, type Result } from './result.js';

const toBytes = (value: string): ArrayBuffer => {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
};

const toBase64url = (buffer: ArrayBuffer | ArrayBufferView): string => {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

type Descriptor = { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] };
const descriptors = (list: Descriptor[] | undefined): PublicKeyCredentialDescriptor[] | undefined =>
  list?.map((d) => ({ ...d, id: toBytes(d.id) }));

/** The browser has passkeys at all. */
export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
}

/** Whether the browser can offer passkeys in the autofill of an e-mail field (`mediation: 'conditional'`). */
export async function conditionalSupported(): Promise<boolean> {
  if (!webauthnSupported() || typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false;
  return PublicKeyCredential.isConditionalMediationAvailable().catch(() => false);
}

export function creationOptions(json: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  return {
    ...json,
    challenge: toBytes(json.challenge),
    user: { ...json.user, id: toBytes(json.user.id) },
    excludeCredentials: descriptors(json.excludeCredentials as Descriptor[] | undefined),
  } as PublicKeyCredentialCreationOptions;
}

export function requestOptions(json: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  return {
    ...json,
    challenge: toBytes(json.challenge),
    allowCredentials: descriptors(json.allowCredentials as Descriptor[] | undefined),
  } as PublicKeyCredentialRequestOptions;
}

/** The browser's answer as the server takes it. */
export function credentialJSON(credential: PublicKeyCredential): unknown {
  if (typeof credential.toJSON === 'function') return credential.toJSON();
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const common = {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if ('attestationObject' in response && response.attestationObject) {
    return {
      ...common,
      response: {
        clientDataJSON: toBase64url(response.clientDataJSON),
        attestationObject: toBase64url(response.attestationObject),
        transports: typeof response.getTransports === 'function' ? response.getTransports() : undefined,
      },
    };
  }
  return {
    ...common,
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle ? toBase64url(response.userHandle) : undefined,
    },
  };
}

/**
 * Runs the browser's passkey dialog and returns its answer as JSON. The user closing the dialog (or no
 * passkey for this site) is `cancelled`; an authenticator that holds one of the user's passkeys already,
 * `already_added`.
 */
export async function ceremony(run: () => Promise<Credential | null>): Promise<Result<{ credential: unknown }>> {
  if (!webauthnSupported()) return fail('passkey_unsupported', 'This browser does not support passkeys.');
  let credential: Credential | null;
  try {
    credential = await run();
  } catch (e) {
    const name = (e as DOMException).name;
    if (name === 'NotAllowedError' || name === 'AbortError') return fail('cancelled', 'The passkey dialog was closed.');
    if (name === 'InvalidStateError') return fail('already_added', 'This device holds one of your passkeys already.');
    return fail('verification_failed', `The passkey dialog failed: ${(e as Error).message}`);
  }
  if (!credential) return fail('cancelled', 'The passkey dialog was closed.');
  return ok({ credential: credentialJSON(credential as PublicKeyCredential) });
}

/**
 * Tells the browser that the server doesn't know a passkey any more, so its password manager can delete it
 * (the WebAuthn Signal API, where there is one).
 */
export function signalUnknown(rpId: string | undefined, credentialId: string): void {
  const signal = (PublicKeyCredential as unknown as { signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void> }).signalUnknownCredential;
  if (rpId && typeof signal === 'function') void signal.call(PublicKeyCredential, { rpId, credentialId }).catch(() => {});
}
