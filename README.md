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

Install dependencies:

```bash
npm install
```

Start the demo at http://localhost:5173:

```bash
npm run dev
```

Build the library and the demo:

```bash
npm run build
```

Run the type checker and the unit tests (Vitest + happy-dom):

```bash
npm run typecheck
npm test
```

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

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts) (set `status: 'available'`).
2. Handle its `id` in [`packages/web/src/madauth-login.ts`](packages/web/src/madauth-login.ts) and dispatch `madauth-signed-in` on success.
3. Add tests next to the code (`*.test.ts`) and run `npm test`.

## Contributing

Contributions are welcome! Open an issue to discuss an idea or report a bug, or send a pull request. Please make sure `npm run typecheck` and `npm test` pass.

## License

madAuth is released under the [MIT License](LICENSE).
