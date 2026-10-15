---
slug: google-one-tap-fedcm
title: Google One Tap and FedCM in 2026: what changed, and what didn't
seoTitle: Google One Tap & FedCM in 2026: what changed
description: Google One Tap now runs on the browser's FedCM API. What that means now that Chrome keeps third-party cookies, and what your server must check in the ID token.
published: 2026-10-15
---

Google One Tap is the small "Continue as Jan" prompt that signs a user in with their Google account in one click, without a redirect to Google. For years it worked through an iframe from `accounts.google.com` that read Google's cookies, which are third-party cookies on your site. In Chrome, One Tap now runs through a browser API instead: **FedCM**, the Federated Credential Management API.

Then Google announced in 2025 that Chrome would keep third-party cookies after all. So is FedCM still relevant? Yes, and this article explains why, what changed for developers, and what your server still has to check.

## What FedCM is

FedCM is a browser API for "sign in with an identity provider". Instead of the identity provider's iframe drawing the prompt, the **browser** draws it, and it talks to the identity provider itself:

1. Your page asks the browser for an identity credential from a provider, here Google.
2. The browser fetches the provider's configuration and asks it which accounts are signed in. The provider does not learn which site is asking.
3. The browser shows its own "Continue as …" dialog.
4. Only when the user agrees does the browser ask the provider for a token for this site and the chosen account, and it hands the token to the page.

Underneath, it is a call like this (Google's library makes it for you):

```js
const credential = await navigator.credentials.get({
  identity: { providers: [{ configURL: 'https://idp.example/fedcm.json', clientId: 'your-client-id' }] },
});
```

The point of the design: the identity provider can't track which sites a user visits before the user decides to sign in, and the flow needs no third-party cookies.

## The cookie twist

FedCM was built for a web without third-party cookies. Chrome had planned to phase them out, and Google Identity Services began moving One Tap onto FedCM in Chrome in 2024 to be ready for it. In April 2025 Google dropped that plan: Chrome keeps third-party cookies and introduces no new cookie prompt. In autumn 2025 it went further and retired most of the Privacy Sandbox APIs that were meant to replace cookies.

FedCM was not among them. Google kept it, together with CHIPS and Private State Tokens. So the change for One Tap in Chrome stays, and two reasons make it more than a Chrome detail:

- **Safari and Firefox block third-party cookies by default** anyway, with Intelligent Tracking Prevention and Total Cookie Protection. A sign-in that depends on them breaks for a large share of users regardless of Chrome.
- **The browser's own dialog** is consistent, can't be overlaid by the page, and is what users increasingly see on other sites too.

In short: nothing goes back. Build for FedCM.

## What changed for developers

For most sites, Google's library did the migration without any code change. A few things behave differently, though, and they explain most "One Tap stopped showing" reports:

- **You can't position the prompt.** The browser places its dialog; settings that moved Google's iframe have no effect.
- **Fewer status callbacks.** Most of the old notifications about why the prompt was not displayed or was skipped no longer report a reason. Don't build logic on them.
- **Iframes need permission.** If One Tap or the button runs in a cross-origin iframe, every parent iframe needs `allow="identity-credentials-get"`.
- **The cooldown is the browser's.** A user who closes the prompt doesn't see it again for a while, and the time grows each time. Users can also switch off "third-party sign-in" in Chrome's site settings. Always have a visible Google button as a fallback.
- **The button can use FedCM too.** With `use_fedcm_for_button: true`, the Google button opens the browser's dialog instead of a pop-up window.
- **Safari and Firefox get their own UI.** With `itp_support: true`, Google's library shows an upgraded One Tap experience in browsers with tracking prevention.

A typical setup with Google Identity Services:

```js
google.accounts.id.initialize({
  client_id: 'your-client-id.apps.googleusercontent.com',
  nonce, // from your server, see below
  callback: ({ credential }) => sendToServer(credential),
  use_fedcm_for_button: true,
  itp_support: true,
});
google.accounts.id.prompt(); // One Tap
google.accounts.id.renderButton(container, { text: 'continue_with' }); // the fallback
```

For development, add both `http://localhost:<port>` and `http://localhost` to the client's **Authorized JavaScript origins** in the Google Cloud Console.

## What the server must still check

FedCM changes how the prompt is shown, not what comes out of it: your page receives a **Google ID token**, a signed JWT, and passes it to your server. The server must not trust it before it has checked:

- the **signature**, with Google's published keys,
- the **issuer** (`accounts.google.com` or `https://accounts.google.com`),
- the **audience**: your own client ID, so a token issued for another app doesn't sign anyone in to yours,
- the **expiry**,
- the **nonce**: your server issues a fresh one per sign-in and accepts it once, so a captured token can't be replayed,
- **`email_verified`**, before you use the address for anything.

And identify the user by Google's **`sub`**, not by the e-mail address: a Google account keeps its `sub` when its address changes.

Watch out for one more thing when an app has several sign-in methods: a Google sign-in with the address of an existing password account must not just walk into that account. Whoever controls a Google account with that address would get past the password and any second factor.

## The alternative: the redirect flow

One Tap and FedCM run in the browser and need Google's script on your page. The classic OAuth redirect works everywhere: the browser goes to Google, the user agrees, and Google sends them back to your server with a code that the server exchanges for the token. It needs a client secret and a round trip through Google, but no third-party script and no browser support. Many apps offer One Tap for speed and keep the redirect for everything else.

## Google sign-in with madAuth

[madAuth](/) is an open-source authentication server you host yourself. It has both Google flows: `GoogleFedcm` uses One Tap and FedCM with the settings above, and `GoogleRedirect` uses the server-side redirect. The server verifies the ID token as described: signature, issuer, audience, expiry, nonce and a verified address, and it refuses a Google sign-in that would take over an account that signs in another way.

```ts
import { Madauth, GoogleFedcm, Passkey } from '@madauth/web';

// One Tap on page load when nobody is signed in; Google's button in the sign-in dialog as the fallback.
Madauth.initialize({ providers: [new GoogleFedcm(), new Passkey()] });
signInButton.onclick = () => Madauth.showSignInDialog();
```

The server needs `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` as well for the redirect flow. Pass `new GoogleFedcm({ autoPrompt: false })` to show Google only in the dialog. The setup is in the [server docs](https://github.com/inouiw/madAuth/blob/main/docs/server.md#google-cloud-console-setup), and the [demo](/demo/) switches between both flows.

## Summary

- In Chrome, One Tap runs through FedCM: the browser draws the prompt, and Google learns about your site only when the user agrees.
- Chrome kept third-party cookies, but FedCM stays, and Safari and Firefox block third-party cookies anyway.
- Expect a browser-placed prompt, fewer status callbacks, a cooldown and iframe permissions; keep a visible Google button.
- The server's job is unchanged: verify the ID token fully, use the nonce once, identify users by `sub`.

Google sign-in pairs well with passkeys. How they work, and why they stop phishing, is explained in [Passkeys explained](/posts/passkeys-explained/).
