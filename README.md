# madAuth

A self-hostable alternative to Cognito / Auth0. Planned sign-in methods:

| Method | Status |
| --- | --- |
| Username & password | coming soon |
| Google sign-in | coming soon |
| Authenticator app (TOTP) | coming soon |
| Passwordless e-mail link | coming soon |
| SMS code | coming soon |

## Repository layout

```
packages/web   @madauth/web – sign-in UI as framework-agnostic web components (Lit)
apps/demo      demo page: plain HTML + TypeScript served by Vite, no framework
```

The UI ships as a standard custom element, so it works in plain HTML, React, Angular, Vue, Svelte and Capacitor apps.

## Getting started

```bash
npm install
npm run dev        # demo at http://localhost:5173
npm run build      # build library + demo
npm run typecheck
```

The demo imports the library source directly, so edits in `packages/web/src` hot-reload.

## Using the component

```html
<button id="sign-in">Sign in</button>
<madauth-login></madauth-login>

<script type="module">
  import '@madauth/web';
  const login = document.querySelector('madauth-login');
  document.querySelector('#sign-in').onclick = () => login.open();
  login.addEventListener('madauth-signed-in', (e) => console.log(e.detail));
  login.addEventListener('madauth-cancel', () => console.log('cancelled'));
</script>
```

Theming: set `--madauth-primary`, `--madauth-radius`, `--madauth-font`, or style `madauth-login::part(dialog)` / `::part(method)`.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts) (set `status: 'available'`).
2. Handle its `id` in [`packages/web/src/madauth-login.ts`](packages/web/src/madauth-login.ts) and dispatch `madauth-signed-in` on success.
