// Presets of the OpenID Connect providers (the kind `oidc` with `preset`, see providers.ts): GitLab, LinkedIn and
// Slack speak OpenID Connect, so a preset only fills in what an admin would otherwise type (the issuer, the name)
// and says where the provider departs from the generic flow (no PKCE, no nonce in the ID token, the secret in the
// form). The button's logo and colours are the web library's. See "GitLab setup", "LinkedIn setup" and "Slack
// setup" in docs/server.md, and docs/social-security.md.

export const OIDC_PRESETS = ['gitlab', 'linkedin', 'slack'] as const;
export type OidcPreset = (typeof OIDC_PRESETS)[number];

export const isOidcPreset = (value: unknown): value is OidcPreset => (OIDC_PRESETS as readonly unknown[]).includes(value);

/** What a preset fixes of the generic OpenID Connect flow. */
export interface PresetRules {
  /** What the button says when the admin gives no name. */
  name: string;
  /** The issuer, exactly as the provider's discovery document names it. */
  issuer: string;
  /** Whether an admin may give another issuer: a self-hosted GitLab. */
  ownIssuer: boolean;
  /** Whether the authorization request has PKCE; without it, the state and the client secret protect the code. */
  pkce: boolean;
  /** Whether the ID token must carry the sign-in's nonce; `false`: a nonce it carries must still be the sign-in's. */
  nonceRequired: boolean;
  /** How the code exchange authenticates, when the discovery document doesn't say it. */
  clientAuth?: 'client_secret_post';
}

export const PRESET_RULES: Record<OidcPreset, PresetRules> = {
  // https://docs.gitlab.com/integration/openid_connect_provider/: the standard flow, on gitlab.com or the
  // operator's own instance (its external URL is the issuer).
  gitlab: { name: 'GitLab', issuer: 'https://gitlab.com', ownIssuer: true, pkce: true, nonceRequired: true },
  // LinkedIn's discovery document names https://www.linkedin.com/oauth, its ID tokens too. It has PKCE only for
  // native apps (a separate endpoint), doesn't return the nonce, and takes the secret in the form only, which its
  // document doesn't say.
  linkedin: { name: 'LinkedIn', issuer: 'https://www.linkedin.com/oauth', ownIssuer: false, pkce: false, nonceRequired: false, clientAuth: 'client_secret_post' },
  // Slack's PKCE turns the app into a public client for good (an app setting): madAuth is a confidential one,
  // with the secret, the state and the nonce.
  slack: { name: 'Slack', issuer: 'https://slack.com', ownIssuer: false, pkce: false, nonceRequired: true },
};

/** The rules of a provider's preset, or the generic flow's for one without. */
export function rulesOf(preset: string | undefined): Pick<PresetRules, 'pkce' | 'nonceRequired' | 'clientAuth'> {
  return isOidcPreset(preset) ? PRESET_RULES[preset] : { pkce: true, nonceRequired: true };
}
