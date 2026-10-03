# @madauth/server

The server of [madAuth](https://github.com/inouiw/madAuth), a self-hostable alternative to Cognito / Auth0: Google and e-mail & password sign-in with madAuth sessions. It runs in Docker, on AWS Lambda, on Azure Functions or inside your own Node server.

The browser side is [`@madauth/web`](https://www.npmjs.com/package/@madauth/web).

## Run it

With Docker:

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

Or with Node.js 22.13 or newer:

```bash
npx @madauth/server generate-key
```

```bash
npm install @madauth/server
```

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

See [Running the madAuth server](https://github.com/inouiw/madAuth/blob/main/docs/server.md) for the configuration, Google Cloud Console setup, webhooks, hosting and custom store adapters.

## License

MIT
