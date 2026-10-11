import type * as OAuth from "@yielded/oauth/OAuth";
import { Effect, Predicate, Redacted, Schema } from "effect";

import { OAuthProviderKey, OAuthGeneration } from "../../schema";
import {
  OAuthAuthorizationUrl,
  OAuthCallbackId,
  OAuthIssuer,
  OAuthRedirectUri,
} from "../../signInModels";
import { freezeOAuth } from "../../signInSnapshot";
import {
  TokenCompatibility,
  tokenCompatibility,
  githubVerifiedPrimaryEmail,
} from "./compatibility";
import { DiscoveryProfile, discoveryProfile } from "./discovery";
import {
  advertisedIdTokenAlgorithms,
  IdTokenSignedResponseAlg,
  OidcUserInfoMode,
  OpenIdConnectConfigurationError,
  type OidcProfileSchema,
  type OpenIdConnectOAuthProvider,
  type OpenIdConnectOAuthProtocolOptions,
  type OpenIdConnectOidcProvider,
} from "./models";
import { install, type NativeProvider } from "./native";

const boundedString = (maximum: number) =>
  Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(maximum));

const fields = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[A-Za-z][A-Za-z0-9._~-]{0,63}$/)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(Schema.makeFilter((record) => Object.keys(record).length <= 16));

const secret = Schema.RedactedFromValue(boundedString(4096));

export const authentication = Schema.Union([
  Schema.Struct({ method: Schema.Literal("client_secret_basic"), secret }),
  Schema.Struct({ method: Schema.Literal("client_secret_post"), secret }),
  Schema.Struct({ method: Schema.Literal("none"), publicClient: Schema.Literal(true) }),
]);

const common = {
  provider: OAuthProviderKey,
  configurationGeneration: OAuthGeneration,
  issuance: Schema.Literals(["active", "retired"]),
  issuer: OAuthIssuer,
  responseIssuerMode: Schema.Literals(["required", "unsupported", "discovered"]),
  clientId: boundedString(1024),
  authentication,
  callbacks: Schema.Array(
    Schema.Struct({ callbackId: OAuthCallbackId, redirectUri: OAuthRedirectUri }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(16)),
  scopes: Schema.Array(
    Schema.String.check(Schema.isPattern(/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/)),
  ).check(Schema.isMaxLength(32)),
  authorizationParameters: Schema.optionalKey(fields),
  tokenParameters: Schema.optionalKey(fields),
};

const optionsSchema = <R>() =>
  Schema.toType(
    Schema.Struct({
      providers: Schema.Array(
        Schema.Union([
          Schema.Struct({
            ...common,
            protocol: Schema.Literal("oidc"),
            [discoveryProfile]: Schema.optionalKey(DiscoveryProfile),
            idTokenSignedResponseAlg: Schema.Array(IdTokenSignedResponseAlg).check(
              Schema.isMinLength(1),
              Schema.isMaxLength(5),
            ),
            pkceS256: Schema.Boolean,
            userInfo: OidcUserInfoMode,
            profileSchema: Schema.declare<OidcProfileSchema>((input): input is OidcProfileSchema =>
              Schema.isSchema(input),
            ),
            maxAgeSeconds: Schema.optionalKey(
              Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 86400 })),
            ),
          }),
          Schema.Struct({
            ...common,
            protocol: Schema.Literal("oauth"),
            [tokenCompatibility]: Schema.optionalKey(TokenCompatibility),
            [githubVerifiedPrimaryEmail]: Schema.optionalKey(Schema.Boolean),
            authorizationEndpoint: boundedString(2048),
            tokenEndpoint: boundedString(2048),
            pkceS256: Schema.Boolean,
            identitySource: Schema.Struct({
              url: boundedString(2048),
              headers: Schema.optionalKey(fields),
              // A configured function is trusted application code; its result has a separate schema boundary.
              decodeIdentity: Schema.declare<
                OpenIdConnectOAuthProvider<R>["identitySource"]["decodeIdentity"]
              >(
                (
                  input,
                ): input is OpenIdConnectOAuthProvider<R>["identitySource"]["decodeIdentity"] =>
                  Predicate.isFunction(input),
              ),
            }),
          }),
        ]),
      ).check(Schema.isMinLength(1), Schema.isMaxLength(64)),
      timeoutSeconds: Schema.Finite.check(Schema.isBetween({ minimum: 1, maximum: 30 })),
    }),
  );

const reserved = new Set([
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "redirect_uri",
  "response_type",
  "response_mode",
  "state",
  "code",
  "code_verifier",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "scope",
  "iss",
  "grant_type",
  "max_age",
  "request",
  "request_uri",
  "authorization_details",
  "id_token_hint",
  "login_hint",
  "login_hint_token",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
  "requested_token_type",
]);

const forbiddenHeaders = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "host",
  "content-length",
  "content-type",
  "transfer-encoding",
  "connection",
  "upgrade",
  "trailer",
  "te",
]);

const configError = (reason: OpenIdConnectConfigurationError["reason"]) =>
  OpenIdConnectConfigurationError.make({ reason });

const protocolUrl = Effect.fnUntraced(function* (
  value: string,
  allowLoopback: boolean,
  malformedReason: OpenIdConnectConfigurationError["reason"],
) {
  const url = yield* Effect.try({
    try: () => new URL(value),
    catch: () => configError(malformedReason),
  });

  if (
    (url.protocol !== "https:" &&
      !(
        allowLoopback &&
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
      )) ||
    url.username !== "" ||
    url.password !== "" ||
    value.includes("#") ||
    // oxlint-disable-next-line no-control-regex -- Reject ambiguous protocol URL control characters.
    /[\s\\\u0000-\u001f\u007f]/u.test(value)
  )
    return yield* configError("metadata");

  return url;
});

/** Provider endpoints always require HTTPS. */
export const endpoint = (
  value: string,
  malformedReason: OpenIdConnectConfigurationError["reason"] = "metadata",
) => protocolUrl(value, false, malformedReason);

/** Local development callbacks may use HTTP on an exact loopback host. */
export const callbackEndpoint = (
  value: string,
  malformedReason: OpenIdConnectConfigurationError["reason"] = "metadata",
) => protocolUrl(value, true, malformedReason);

const checkParameters = Effect.fnUntraced(function* (
  parameters: Readonly<Record<string, string>> | undefined,
) {
  for (const key of Object.keys(parameters ?? {})) {
    if (reserved.has(key.toLowerCase())) return yield* configError("parameters");
  }
});

export type Provider<R> = OpenIdConnectOidcProvider | OpenIdConnectOAuthProvider<R>;

export interface InstalledProvider<R> extends NativeProvider {
  readonly provider: Provider<R>;
  readonly metadata: OAuth.Metadata;
}

const metadataSchema = Schema.Struct({
  issuer: OAuthIssuer,
  authorization_endpoint: boundedString(2048),
  token_endpoint: boundedString(2048),
  jwks_uri: Schema.optionalKey(boundedString(2048)),
  userinfo_endpoint: Schema.optionalKey(boundedString(2048)),
  code_challenge_methods_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  response_types_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  id_token_signing_alg_values_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  token_endpoint_auth_methods_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  authorization_response_iss_parameter_supported: Schema.optionalKey(Schema.Boolean),
});

export interface InstalledConfiguration<R> {
  readonly installed: ReadonlyArray<InstalledProvider<R>>;
  readonly timeoutSeconds: number;
}

export const prepareConfigurations = Effect.fn("OpenIdConnect.prepareConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const options = yield* Schema.decodeEffect(optionsSchema<R>())(input).pipe(
    Effect.mapError(() => configError("provider")),
  );

  // Detach secrets as well as arrays and records before retaining configuration.
  const providers = options.providers.map((provider): Provider<R> => {
    const detached = {
      callbacks: provider.callbacks.map((callback) => ({ ...callback })),
      scopes: [...provider.scopes],
      ...(provider.authorizationParameters === undefined
        ? {}
        : { authorizationParameters: { ...provider.authorizationParameters } }),
      ...(provider.tokenParameters === undefined
        ? {}
        : { tokenParameters: { ...provider.tokenParameters } }),
      authentication:
        provider.authentication.method === "none"
          ? { ...provider.authentication }
          : {
              ...provider.authentication,
              secret: Redacted.make(Redacted.value(provider.authentication.secret)),
            },
    };

    return provider.protocol === "oidc"
      ? { ...provider, ...detached }
      : {
          ...provider,
          ...detached,
          identitySource: {
            ...provider.identitySource,
            ...(provider.identitySource.headers === undefined
              ? {}
              : { headers: { ...provider.identitySource.headers } }),
          },
        };
  });

  const generations = new Set<string>();
  const active = new Set<string>();
  const names = new Set<string>();

  for (const provider of providers) {
    const generation = `${provider.provider.length}:${provider.provider}:${provider.configurationGeneration}`;

    if (generations.has(generation)) return yield* configError("generation");
    generations.add(generation);
    names.add(provider.provider);
    if (provider.issuance === "active") {
      if (active.has(provider.provider)) return yield* configError("generation");
      active.add(provider.provider);
    }
    const issuer = yield* endpoint(provider.issuer, "provider");

    if (provider.issuer.includes("?") || issuer.pathname.includes("/.well-known/"))
      return yield* configError("issuer");
    if (new Set(provider.scopes).size !== provider.scopes.length)
      return yield* configError("parameters");
    if ((provider.protocol === "oidc") !== provider.scopes.includes("openid"))
      return yield* configError("parameters");
    if (
      provider.protocol === "oidc" &&
      new Set(provider.idTokenSignedResponseAlg).size !== provider.idTokenSignedResponseAlg.length
    )
      return yield* configError("parameters");
    yield* checkParameters(provider.authorizationParameters);
    yield* checkParameters(provider.tokenParameters);
    const callbacks = new Set<string>();

    for (const callback of provider.callbacks) {
      const url = yield* callbackEndpoint(callback.redirectUri, "provider");

      if (
        url.href !== callback.redirectUri ||
        callback.redirectUri.includes("?") ||
        callbacks.has(callback.callbackId)
      )
        return yield* configError("callback");
      callbacks.add(callback.callbackId);
      for (const other of providers) {
        if (provider.issuer === other.issuer) continue;
        if (provider.responseIssuerMode === "required" && other.responseIssuerMode === "required")
          continue;
        if (other.callbacks.some((candidate) => candidate.redirectUri === callback.redirectUri))
          return yield* configError("callback");
      }
    }
    if (provider.protocol === "oauth") {
      yield* endpoint(provider.identitySource.url, "provider");
      for (const key of Object.keys(provider.identitySource.headers ?? {})) {
        if (forbiddenHeaders.has(key.toLowerCase())) return yield* configError("identity-source");
      }
      yield* Effect.try({
        try: () => new Headers(provider.identitySource.headers),
        catch: () => configError("provider"),
      });
    }
    freezeOAuth(provider);
  }
  if (active.size !== names.size) return yield* configError("generation");

  return { providers, timeoutSeconds: options.timeoutSeconds };
});

export const installProvider = Effect.fn("OpenIdConnect.installProvider")(function* <R>(
  provider: Provider<R>,
  raw: OAuth.Metadata,
  timeoutSeconds: number,
) {
  // oxlint-disable-next-line no-restricted-properties -- Discovered foreign metadata is not yet validated for this adapter profile.
  const metadata = yield* Schema.decodeEffect(metadataSchema)(raw).pipe(
    Effect.mapError(() => configError("metadata")),
  );

  if (metadata.issuer !== provider.issuer) return yield* configError("issuer");
  if (
    provider.responseIssuerMode !== "discovered" &&
    (metadata.authorization_response_iss_parameter_supported === true) !==
      (provider.responseIssuerMode === "required")
  )
    return yield* configError("metadata");
  const auth = yield* endpoint(metadata.authorization_endpoint);

  for (const key of auth.searchParams.keys()) {
    if (reserved.has(key.toLowerCase())) return yield* configError("parameters");
  }
  yield* endpoint(metadata.token_endpoint);

  const supportedAuthentication =
    metadata.token_endpoint_auth_methods_supported ??
    (provider.protocol === "oidc" ? ["client_secret_basic"] : undefined);

  if (
    supportedAuthentication !== undefined &&
    !supportedAuthentication.includes(provider.authentication.method)
  )
    return yield* configError("authentication");

  if (provider.protocol === "oidc") {
    const algorithms = advertisedIdTokenAlgorithms(
      metadata.id_token_signing_alg_values_supported,
      provider.idTokenSignedResponseAlg,
    );

    const usesHmac = algorithms?.includes("HS256") === true;
    const usesAsymmetric = algorithms?.some((algorithm) => algorithm !== "HS256") === true;

    if (usesHmac && usesAsymmetric) return yield* configError("parameters");
    if (usesHmac && provider.authentication.method === "none")
      return yield* configError("authentication");
    if (
      algorithms === undefined ||
      !metadata.response_types_supported?.includes("code") ||
      (usesAsymmetric && metadata.jwks_uri === undefined) ||
      (provider.pkceS256 && !metadata.code_challenge_methods_supported?.includes("S256")) ||
      (provider.userInfo === "merge" && metadata.userinfo_endpoint === undefined)
    )
      return yield* configError("metadata");
    if (metadata.jwks_uri !== undefined) yield* endpoint(metadata.jwks_uri);
    if (metadata.userinfo_endpoint !== undefined) yield* endpoint(metadata.userinfo_endpoint);
  } else {
    yield* endpoint(provider.identitySource.url);
  }
  freezeOAuth(metadata);

  const native = yield* install(
    {
      metadata,
      clientId: provider.clientId,
      authentication: provider.authentication,
      timeoutMs: timeoutSeconds * 1000,
      ...(provider.protocol === "oauth"
        ? { profile: provider.identitySource }
        : provider.userInfo === "merge" && metadata.userinfo_endpoint !== undefined
          ? { profile: { url: metadata.userinfo_endpoint } }
          : {}),
    },
    provider.protocol === "oauth" && provider[githubVerifiedPrimaryEmail] === true,
  );

  const placeholder = Redacted.make("a".repeat(43));

  for (const callback of provider.callbacks) {
    const url = yield* native.client
      .authorizationUrl({
        redirectUri: callback.redirectUri,
        scopes: provider.scopes,
        state: placeholder,
        ...(provider.pkceS256 ? { codeChallenge: Redacted.value(placeholder) } : {}),
        ...(provider.authorizationParameters === undefined
          ? {}
          : { parameters: provider.authorizationParameters }),
        ...(provider.protocol === "oidc"
          ? {
              nonce: placeholder,
              ...(provider.maxAgeSeconds === undefined
                ? {}
                : { maxAgeSeconds: provider.maxAgeSeconds }),
            }
          : {}),
      })
      .pipe(Effect.mapError(() => configError("parameters")));

    yield* Schema.decodeEffect(OAuthAuthorizationUrl)(Redacted.value(url)).pipe(
      Effect.mapError(() => configError("parameters")),
    );
  }

  return { provider, metadata, ...native };
});

export const installOAuthConfigurations = Effect.fn("OAuth.installConfigurations")(function* <
  R,
>(input: {
  readonly providers: ReadonlyArray<OpenIdConnectOAuthProvider<R>>;
  readonly timeoutSeconds: number;
}) {
  const { providers, timeoutSeconds } = yield* prepareConfigurations(input);
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    if (provider.protocol !== "oauth") return yield* configError("provider");
    installed.push(
      yield* installProvider(
        provider,
        {
          issuer: provider.issuer,
          authorization_endpoint: provider.authorizationEndpoint,
          token_endpoint: provider.tokenEndpoint,
          authorization_response_iss_parameter_supported:
            provider.responseIssuerMode === "required",
        },
        timeoutSeconds,
      ),
    );
  }

  return { installed, timeoutSeconds };
});
