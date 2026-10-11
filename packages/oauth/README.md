# @yielded/oauth

Effect OAuth authorization-code and refresh flows, PKCE S256, and signed OpenID
Connect. Runtime dependencies are Effect and `@yielded/jose`; applications own
registered callbacks, provider configuration, permissions, identity, and grant storage.

Use `OAuth.make` for an installed client and `Oidc.makeVerifier` for its OIDC
verifier. Both require `HttpClient` and an owning `Scope`; keep that scope open
for their lifetime. `Pkce` requires Effect `Crypto`; verification also requires
`Signature` from `@yielded/crypto`. `Oidc.discover` retrieves metadata from the
exact trusted issuer, or from an explicit `metadataUrl` whose document issuer must
still equal that identifier. Closing a factory's scope cancels its work and prevents reuse.

`client.codeGrant` and `client.refreshGrant` return private `TokenReceipt` values.
Check the provider-specific receipt, then call `OAuth.tokens`. A receipt alone
does not establish a successful grant or authenticated identity. Tokens stay
redacted. For initial OIDC sign-in, require an ID token and call `verifier.verify`
with the captured verification time, nonce, access token, and authorization code.
On refresh, verify any returned ID token against the previous identity; accepting
an omitted ID token is application policy.

Each exchange, refresh, or revocation makes one request. An uncertain outcome
requires application recovery, not an automatic retry. Provider endpoints require
HTTPS. Custom HttpClients must preserve cancellation and disable retries,
redirects, and ambient cookies. Bound the complete workflow as well as individual
requests; keep token receipts out of logs and telemetry.

Each verifier owns a scoped JWKS cache. It never takes a key endpoint from a token
or serves expired keys after refresh failure. Configure the issuer's advertised
code flow and signing algorithms. HS256 is accepted only with a client secret of
at least 32 bytes. Keep S256 PKCE enabled unless the issuer cannot
support it. Other OAuth grants are outside this package's profile.

See the [public API comments](src/OAuth.ts), [OIDC options](src/Oidc.ts), and
[third-party notices](THIRD_PARTY_NOTICES.md).
