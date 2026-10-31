import { madauthSchema, type Schema } from '../store/schema.js';

// Schema version 1, to test upgrades: users had no count of wrong codes and no claims, accounts no e-mail and
// no last code, and there were no settings, no recovery codes and no API keys (nor a preferred second factor).
const { wrongCodes: _, claims: __, lastSmsAt: ___, signedUpAt: ____, signUpMethod: _____, preferredSecondFactor: ______, ...userFields } = madauthSchema.models.user.fields;
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
const { setting: _m, recoveryCode: _n, apiKey: _o, ...models } = madauthSchema.models;

export const schemaV1: Schema = { version: 1, models: { ...models, user: { fields: userFields }, account: { fields: accountFields } } };
