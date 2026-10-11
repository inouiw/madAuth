# @madauth/server

The server of [madAuth](https://github.com/inouiw/madAuth), a self-hostable alternative to Cognito / Auth0: Google, e-mail & password and authenticator-app (TOTP) sign-in with madAuth sessions. It runs with Node, in Docker, on AWS Lambda, on Azure Functions or inside your own Node server.

The browser side is [`@madauth/web`](https://www.npmjs.com/package/@madauth/web).

## Run it

With Node.js 22.13 or newer:

```bash
npm install @madauth/server
```

```bash
npx @madauth/server init
```

```bash
npx @madauth/server start --env-file .env
```

`init` asks a few questions and writes the configuration to `.env`, with a new signing key, then prints the next steps. `start` runs the server on port 8787. See [Getting started](https://github.com/inouiw/madAuth/blob/main/docs/getting-started.md).

With Docker:

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

Or inside your own Node server:

```ts
import { createApp, loadConfig } from '@madauth/server';

const app = createApp(await loadConfig(process.env)); // a Hono app: app.fetch(request) → response
```

The package also contains self-contained bundles for AWS Lambda (`dist/standalone/lambda.mjs`) and Azure Functions (`dist/standalone/azure.mjs`).

## Entry points

| Import | Contents |
| --- | --- |
| `@madauth/server` | `createApp`, `loadConfig`, the store adapter types and the SQL schema |
| `@madauth/server/verify` | verify a madAuth session in your own backend |
| `@madauth/server/webhook` | verify webhook calls in your receiver |
| `@madauth/server/sqlite` | the SQLite store |
| `@madauth/server/dynamodb` | the Amazon DynamoDB store |
| `@madauth/server/node`, `/lambda`, `/azure` | hosting entry points |
| `@madauth/server/testing` | a contract test suite for custom store adapters |

## Documentation

- [Getting started](https://github.com/inouiw/madAuth/blob/main/docs/getting-started.md): set up madAuth on your machine, step by step.
- [Running the madAuth server](https://github.com/inouiw/madAuth/blob/main/docs/server.md): the configuration, Google Cloud Console setup, the sign-in methods and their policies, the authenticator app, webhooks, hosting and custom store adapters.
- [Password security](https://github.com/inouiw/madAuth/blob/main/docs/password-security.md) and [Authenticator app security](https://github.com/inouiw/madAuth/blob/main/docs/totp-security.md): what the server does to protect accounts.

## License

MIT
