# Authentication examples

Consumer examples compose public `@yielded/auth` exports with application-owned
identity, persistence, and delivery. `getting-started.ts` shows application
composition; `session-contract.ts` and `session-http.ts` show cookies, selected
routes, and a protected HttpApi group.

Run a declared example through `vp run -F @yielded/example-auth <task>`.
The programs use local example data and demo keys. For deployment, generate
independent random 32-byte keys encoded as unpadded base64url, store them in
secret configuration, and retain old keys while credentials or persisted records
reference them.

`auth-contract.ts` owns the shared named API; `auth-server.ts` mounts it beside
application routes. `auth-client.ts` declares the client and its atoms;
`auth-react.ts` uses ordinary Atom hooks. `auth-ssr.ts` shows request-owned server
rendering and browser hydration. Keep each Scope alive for its render or mounted
application lifetime.

[CryptoLive](../shared/crypto.ts) selects the portable crypto backend and shares
KDF admission with password hashing. Provider clients and key caches belong to
the server Layer's application scope.

The Studio example requires `Postgres.Database` and `TotpSecretKeys`. Provide
`Postgres.databaseLayer` with an Effect PostgreSQL client and your key Layer to
`makeStudioLive(binding)`.

`login-contract.ts`, `login-server.ts`, and `login-client.ts` compose email OTP +
GitHub with shared sessions, HTTP, and Atom workflows. Google is optional.
See the [OAuth guide](../../docs/src/content/docs/guide/oauth.mdx) for setup.

`example:github`, `example:strava`, and `example:strava-mcp` build their Atom browser
client and run a single-owner OAuth application with retained provider API access.
[Shared OAuth storage](../shared/oauth/storage.ts) supplies Effect SQL persistence
and allowlisted account provisioning without Drizzle. Open `/login` and configure
the provider callback at `/auth/{provider}/callback`.

Set `APP_ORIGIN`, `SESSION_KEY`, `OAUTH_TRANSACTION_KEY`, and `OAUTH_TOKEN_KEY`,
plus `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `GITHUB_USER_ID` for GitHub,
or `STRAVA_CLIENT_ID`, `STRAVA_CLIENT_SECRET`, and `STRAVA_ATHLETE_ID` for Strava.
The user/athlete ID allowlists the account that can sign in. The MCP example also
needs `MCP_SIGNING_KEY` and `MCP_REDIRECT_URI`; choose a static `MCP_CLIENT_ID` or
an allowed `MCP_CLIENT_METADATA_ORIGIN` for metadata discovery. Keep keys stable
across restarts and use separate storage for independent applications.

`example:slack` runs sign-in without retained API access and checks the configured
subject and verified workspace claim. The
[Slack guide](../../docs/src/content/docs/guide/slack.md) covers app configuration
and HTTPS forwarding.

`example:google`, `example:gitlab`, `example:huggingface`, `example:vercel`, and
`example:zoom` follow the same sign-in pattern. Google checks a verified `hd` claim
when `GOOGLE_HOSTED_DOMAIN` is set; GitLab uses `GITLAB_ISSUER` for a self-hosted
instance. Follow each provider guide for setup.

`example:line`, `example:railway`, and `example:roblox` follow the same sign-in
shape. LINE verifies web-login HS256 ID tokens. Railway merges UserInfo. Roblox
keeps the trailing-slash issuer and does not receive email.

Provider-account management is denied until you install an application-owned
exact-action verifier. If you enable remote revocation, supply a scheduler for
its jobs as described in the [OAuth reference](../../docs/src/content/docs/reference/oauth.md).

## Shared GitHub callback host

`example:oauth-proxy` runs a callback server and two independent apps. Register
`https://auth.example.com/oauth-proxy/github/callback` on one GitHub OAuth App.
The [composition](src/oauth-proxy-application.ts) registers localhost and the
configured preview, and gives each app its own SQLite storage and sessions.

Publish the callback server and preview over HTTPS, forwarding to Bun on
`127.0.0.1` ports 4000 and 3001. Follow the
[hosting requirements](../../docs/src/content/docs/reference/oauth.md#hosting-and-recovery)
for forwarded headers, private upstream access, and callback logging.

Set these environment variables for each process:

| Process         | Configuration                                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------------------------------- |
| Callback server | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `PROXY_ENCRYPTION_KEY`, `LOCAL_PROXY_SECRET`, `PREVIEW_PROXY_SECRET` |
| Each app        | `PROXY_SECRET`, `SESSION_KEY`, `OAUTH_TRANSACTION_KEY`, `GITHUB_USER_ID`                                         |

Generate independent keys and environment secrets from 32 random bytes encoded as
unpadded base64url. Each app's `PROXY_SECRET` matches its registration on the server.
Keep keys stable across restarts. Only the allowlisted `GITHUB_USER_ID` can sign in.

Run these in separate terminals from the repository root:

```sh
MODE=proxy APP_ORIGIN=https://auth.example.com PREVIEW_ORIGIN=https://preview.example.com \
  vp run @yielded/example-auth#example:oauth-proxy

MODE=local PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy

MODE=preview APP_ORIGIN=https://preview.example.com PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy
```

Open `http://localhost:3000/login` or `https://preview.example.com/login`.
After sign-in, `/account` shows that app's session. The example does not retain
provider API access.
