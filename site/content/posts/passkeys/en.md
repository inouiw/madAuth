---
slug: passkeys-explained
title: Passkeys explained: how WebAuthn works and why phishing fails
seoTitle: Passkeys explained: how WebAuthn stops phishing
description: What a passkey is, what happens in a WebAuthn sign-in, why look-alike sites get nothing, and what your server must get right when you add passkeys to a web app.
published: 2026-10-15
---

A passkey replaces the password with a key pair. The user's device or password manager makes a new key pair for each site, keeps the private key and gives the site only the public key. To sign in, the device proves that it holds the private key, after the user unlocks it with a fingerprint, their face or a PIN. There is nothing to type, nothing to remember and nothing a fake login page could catch.

This article explains how that works under the hood (the standard is called WebAuthn), why it stops phishing where passwords and one-time codes don't, and what you need to get right when you add passkeys to your own web app.

## What a passkey is

A passkey is a public-key credential bound to one site, the *relying party*. Three parties take part:

- **The authenticator** makes and keeps the private key. That can be the phone or laptop itself (Touch ID, Windows Hello, Android's screen lock), a password manager such as iCloud Keychain, Google Password Manager or 1Password, or a hardware security key.
- **The browser** sits in between. It talks to the authenticator and, crucially, tells it which site is asking.
- **The server** stores the public key and checks signatures with it.

Most passkeys today are *synced*: the password manager copies them, end-to-end encrypted, to the user's other devices, so a new phone has the user's passkeys already. A security key keeps its passkeys on the device and never copies them. On a computer without the user's passkeys, the browser can show a QR code: the user scans it with their phone, the phone answers, and Bluetooth confirms that the phone is actually nearby.

## What happens when a user signs in

Every passkey sign-in is a small challenge-response protocol:

1. The server makes a random **challenge**, a value it has never used and will accept once.
2. The browser passes the challenge to the authenticator, together with the **origin** of the page (for example `https://app.example.com`) and the **relying party id**, the domain the passkey belongs to (for example `example.com`).
3. The authenticator looks for a passkey of that domain, **verifies the user** (fingerprint, face or PIN) and **signs** the challenge, the origin and the domain with the private key.
4. The server checks the signature with the stored public key, and checks that the challenge is its own, the origin is one of its apps and the domain is its own.

Signing up works the same way, except that the authenticator makes a new key pair and returns the public key. The server never sees the private key, and neither does the browser.

## Why phishing fails

With a password, the user decides where to type it, and a convincing copy of the login page at `examp1e-login.com` gets the real password. A code from an authenticator app or an SMS is no better: the fake page asks for the code too and passes it on to the real site within the 30 seconds it is valid.

With a passkey, the user doesn't decide anything that could go wrong:

- The **browser** puts the real origin of the page into what the authenticator signs. A fake page can't claim to be `app.example.com`, because the browser, not the page, fills that in.
- The **authenticator** only offers passkeys whose domain matches the page. On `examp1e-login.com` it has no passkey to offer at all.
- The **server** checks the signed origin and domain and refuses anything that wasn't made for it.

A look-alike site gets no answer that works anywhere else. This is the main reason passkeys are a real step up and not just a convenience.

## Why a data breach costs much less

The server stores public keys, and a public key is useless to an attacker: it can check signatures but not make them. A leaked passkey table gives attackers nothing to crack offline and nothing to try on other sites. Users who reuse a password everywhere have no equivalent problem with passkeys, because every site gets its own key pair.

## Possession and a fingerprint: two factors in one step

A passkey proves two things at once: the user has the device (possession), and the user unlocked it (a fingerprint or face, or a PIN they know). That is why a passkey on its own can replace "password plus second factor". The server should insist on it, though: it asks for **user verification** (`userVerification: 'required'`) and refuses an answer in which the authenticator didn't verify the user. Otherwise a security key without a PIN would sign in whoever holds it.

## Passkeys in the browser's autofill

Users don't have to find a "Sign in with a passkey" button. The browser can offer the user's passkeys in the autofill menu of the e-mail field, next to saved passwords. This is called *conditional mediation*. The field gets the `webauthn` token in its `autocomplete` attribute:

```html
<input type="email" name="email" autocomplete="username webauthn" />
```

and the page starts a passkey request that waits until the user picks a passkey from the menu:

```js
if (await PublicKeyCredential.isConditionalMediationAvailable?.()) {
  const credential = await navigator.credentials.get({
    mediation: 'conditional',
    publicKey: {
      challenge, // random bytes from your server, used once
      rpId: 'example.com',
      userVerification: 'required',
    },
  });
  // Send credential.response to the server: it checks the signature and signs the user in.
}
```

Because these passkeys are *discoverable* (they carry the user's id), the user doesn't type their address first, and the sign-in doesn't reveal whether an address has an account.

## What the server has to get right

The cryptography is done by the browser and the authenticator. What's left for the server is bookkeeping, and that is where the mistakes happen:

- **Use every challenge once.** Keep it short-lived (a few minutes), tie it to what it was made for (signing in, adding a passkey) and delete it when an answer arrives. An answer sent twice must sign in once.
- **Check the origin and the domain** against your own list. Don't trust what the page or the request says about itself.
- **Pick the relying party id deliberately.** A passkey made for `app.example.com` works there only; one made for `example.com` works on all its subdomains. Changing the domain later makes every existing passkey stop working.
- **Re-authenticate before adding a passkey.** A session someone took over, with a stolen cookie or a browser left open, must not give them a passkey of their own that outlives the session.
- **Don't let the last way in be removed.** A user who deletes their only passkey, or loses the phone that held it, needs another way to sign in, or an admin who can reset their sign-in after checking who is asking.
- **Tell the password manager when a passkey is gone.** Browsers that support the WebAuthn Signal API can be told that a credential no longer exists, so they stop offering it.
- **Check the signature counter** of security keys: an authenticator that keeps a counter must send a higher count each time. Synced passkeys send 0.

## Passkeys on their own, or as a second factor

You don't have to drop passwords to use passkeys. Two common setups:

- **Passkeys as a sign-in method:** users sign up with a passkey right away, or sign up with e-mail, Google or GitHub and add one, and from then on sign in with it alone.
- **Passkeys as a second factor:** users sign in with their password as before, and the server asks for a passkey afterwards. This is still phishing-resistant at the second step, unlike a code from an app or an SMS.

## Adding passkeys with madAuth

[madAuth](/) is an open-source authentication server you host yourself, with a login dialog that works in any framework. It implements the rules above: user verification is required, every challenge counts once, adding a passkey needs a sign-in within the last ten minutes, the last way in can't be removed, and removed passkeys are signalled to the browser. In the web app, passkeys are one more provider:

```ts
import { Madauth, Password, Passkey } from '@madauth/web';

Madauth.initialize({ providers: [new Password(), new Passkey()] });

signInButton.onclick = () => Madauth.signIn(); // the dialog, with passkeys in the e-mail field's autofill
addPasskeyButton.onclick = () => Madauth.setUpPasskey(); // for a signed-in user
```

An admin decides while the server runs whether passkeys sign in on their own or are only a second factor, and `PASSKEY_RP_ID` sets the domain the passkeys belong to. Users can sign up with a passkey alone: madAuth confirms their address by e-mail first, then the passkey is created. The details are in the [passkey security notes](https://github.com/inouiw/madAuth/blob/main/docs/passkey-security.md), and the [demo](/demo/) lets you add a passkey and sign in with it.

## Summary

- A passkey is a key pair per site: the private key stays with the user, the server stores only the public key.
- The browser signs the real origin into every answer, so phishing pages get nothing usable.
- A leaked database of public keys is worthless to attackers.
- With user verification required, one passkey sign-in counts as two factors.
- The server's job is bookkeeping: single-use challenges, origin checks, a deliberate domain, re-authentication and a way back in.

Passkeys sit well next to Google sign-in. How the "Continue as …" prompt works today is the topic of [Google One Tap and FedCM in 2026](/posts/google-one-tap-fedcm/).
