import { madauthSchema, type Schema } from '../store/schema.js';

// Schema version 1, to test upgrades: users had no count of wrong codes and no claims, accounts no e-mail and
// no last code, and there were no settings, no recovery codes, no API keys and no OpenID Connect clients (nor a
// preferred second factor).
const { wrongCodes: _, claims: __, lastSmsAt: ___, signedUpAt: ____, signUpMethod: _____, preferredSecondFactor: ______, wrongDeviceCodes: _______, wrongDeviceCodeAt: ________, ...userFields } = madauthSchema.models.user.fields;
const {
  email: _a,
  lastUsedStep: _b,
  setupId: _c,
  phone: _d,
  primaryUserId: _e,
  secondFactor: _f,
  name: _g,
  credentialId: _h,
  signCount: _i,
  transports: _j,
  lastUsedAt: _k,
  rpId: _l,
  ...accountFields
} = madauthSchema.models.account.fields;
const { setting: _m, recoveryCode: _n, apiKey: _o, oidcClient: _p, oidcCode: _q, oidcRefreshToken: _r, oidcDeviceCode: _s, oidcNonce: _t, ...models } = madauthSchema.models;

export const schemaV1: Schema = { version: 1, models: { ...models, user: { fields: userFields }, account: { fields: accountFields } } };
