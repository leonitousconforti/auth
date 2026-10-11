import * as Pkce from "@yielded/oauth/Pkce";
import { Cause, Crypto, DateTime, Effect, Fiber, Redacted, Schema, type Scope } from "effect";

import {
  reportAuthDiagnostic,
  reportAuthFailure,
  withoutObservability,
} from "../../../internal/diagnostics";
import { RequestBindingFlowId } from "../../../operations/requestBindingModels";
import { selectCallback } from "../../callback";
import { OAuthProtocol } from "../../OAuthProtocol";
import { OAuthProviderKey } from "../../schema";
import { OAuthProtocolRejected, OAuthRejected, OAuthUnavailable } from "../../signInErrors";
import {
  OAuthAuthorizationPrompt,
  OAuthCallbackId,
  OAuthCodeResponse,
  OAuthDisplayProfile,
  OAuthLoginHint,
  OAuthProtocolConfiguration,
  OAuthProtocolPreparation,
  OAuthTransactionSecrets,
  OAuthVerifiedExternalIdentity,
} from "../../signInModels";
import { snapshotOAuth } from "../../signInSnapshot";
import { tokenCompatibility } from "./compatibility";
import type { InstalledConfiguration } from "./configuration";
import { persistedResponseIssuerMode, type OpenIdConnectConfigurationError } from "./models";
import { decodeOidcProfile } from "./profile";
import { tokens } from "./receipt";

const beginInput = Schema.Struct({
  provider: OAuthProviderKey,
  callbackId: Schema.optionalKey(OAuthCallbackId),
  flowId: RequestBindingFlowId,
  prompt: Schema.optionalKey(OAuthAuthorizationPrompt),
  loginHint: Schema.optionalKey(OAuthLoginHint),
});

const userInfoSubject = Schema.Struct({
  sub: Schema.NonEmptyString.check(Schema.isMaxLength(1024)),
});

const exchangeInput = Schema.toType(
  Schema.Struct({
    configuration: OAuthProtocolConfiguration,
    response: OAuthCodeResponse,
    secrets: OAuthTransactionSecrets,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
  }),
);

const plainIdentitySchema = Schema.Struct({
  subject: OAuthVerifiedExternalIdentity.fields.identity.fields.subject,
  profile: Schema.optionalKey(OAuthDisplayProfile),
});

const unavailable = () => OAuthUnavailable.make({});
const rejected = () => OAuthProtocolRejected.make({});

// Final containment for application callbacks and supplied platform services.
// Expected validation failures are typed; defects never establish non-issuance.
const unavailableOnDefect = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.tapCause((cause) =>
      Cause.hasDies(cause) ? reportAuthFailure("oauth-protocol", cause) : Effect.void,
    ),
    Effect.catchCause((cause): Effect.Effect<never, E | OAuthUnavailable> => {
      if (Cause.hasInterrupts(cause)) return Effect.interrupt;
      if (Cause.hasDies(cause)) return Effect.fail(unavailable());

      return Effect.failCause(cause);
    }),
  );

export const makeOpenIdConnectOAuthProtocol = Effect.fn("makeOpenIdConnectOAuthProtocol")(
  // Capture one provider table; each generation retains its own receipt rules.
  function* <R, Setup>(
    installation: Effect.Effect<
      InstalledConfiguration<R>,
      OpenIdConnectConfigurationError | OAuthUnavailable,
      Setup
    >,
  ): Effect.fn.Return<
    OAuthProtocol["Service"],
    OpenIdConnectConfigurationError | OAuthUnavailable,
    R | Setup | Crypto.Crypto | Scope.Scope
  > {
    const context = (yield* Effect.context<R>()).pipe(withoutObservability);
    const crypto = yield* Crypto.Crypto;
    const scope = yield* Effect.scope;
    // Setup shares the protocol's containment for supplied platform services.
    const { installed, timeoutSeconds } = yield* installation;

    // Own application decoding as well as the native client's individual requests.
    const run = <A, E>(work: Effect.Effect<A, E>): Effect.Effect<A, E | OAuthUnavailable> =>
      Effect.acquireUseRelease(
        Effect.suspend(() =>
          scope.state._tag === "Closed" ? Effect.fail(unavailable()) : Effect.forkIn(work, scope),
        ),
        Effect.fnUntraced(function* (fiber) {
          const exit = yield* Fiber.await(fiber);

          if (scope.state._tag === "Closed") return yield* unavailable();

          return yield* exit;
        }),
        Fiber.interrupt,
      );

    const prepareAuthorization: OAuthProtocol["Service"]["prepareAuthorization"] = Effect.fn(
      "OpenIdConnect.prepareAuthorization",
    )(function* (input) {
      const request = yield* Schema.decodeEffect(beginInput)(input).pipe(
        Effect.mapError(() => OAuthRejected.make({})),
      );

      const entry = installed.find(
        ({ provider }) => provider.issuance === "active" && provider.provider === request.provider,
      );

      const provider = entry?.provider;

      const callback =
        provider === undefined
          ? undefined
          : selectCallback(provider.provider, provider.callbacks, request.callbackId);

      if (entry === undefined || provider === undefined || callback === undefined)
        return yield* OAuthRejected.make({});

      const state = yield* Pkce.random().pipe(
        Effect.provideService(Crypto.Crypto, crypto),
        Effect.mapError(unavailable),
      );

      const pkce = provider.pkceS256
        ? yield* Pkce.make().pipe(
            Effect.provideService(Crypto.Crypto, crypto),
            Effect.mapError(unavailable),
          )
        : undefined;

      const nonce =
        provider.protocol === "oidc"
          ? yield* Pkce.random().pipe(
              Effect.provideService(Crypto.Crypto, crypto),
              Effect.mapError(unavailable),
            )
          : undefined;

      const url = yield* entry.client
        .authorizationUrl({
          redirectUri: callback.redirectUri,
          scopes: provider.scopes,
          state,
          ...(pkce === undefined ? {} : { codeChallenge: pkce.challenge }),
          ...(nonce === undefined ? {} : { nonce }),
          ...(provider.authorizationParameters === undefined
            ? {}
            : { parameters: provider.authorizationParameters }),
          ...(provider.protocol === "oidc" && provider.maxAgeSeconds !== undefined
            ? { maxAgeSeconds: provider.maxAgeSeconds }
            : {}),
          ...(request.prompt === undefined ? {} : { prompt: request.prompt }),
          ...(request.loginHint === undefined ? {} : { loginHint: request.loginHint }),
        })
        .pipe(Effect.mapError(unavailable));

      const responseIssuerMode = persistedResponseIssuerMode(
        provider.responseIssuerMode,
        entry.metadata.authorization_response_iss_parameter_supported,
      );

      const result = {
        configuration: {
          provider: provider.provider,
          protocol: provider.protocol,
          configurationGeneration: provider.configurationGeneration,
          issuer: provider.issuer,
          responseIssuerMode,
          callbackId: callback.callbackId,
          redirectUri: callback.redirectUri,
        },
        authorizationUrl: url,
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
          state,
          ...(pkce === undefined ? {} : { pkceVerifier: pkce.verifier }),
          ...(nonce === undefined ? {} : { oidcNonce: nonce }),
        },
      };

      return yield* snapshotOAuth(OAuthProtocolPreparation, result);
    });

    const exchangeVerifiedIdentity: OAuthProtocol["Service"]["exchangeVerifiedIdentity"] =
      Effect.fn("OpenIdConnect.exchangeVerifiedIdentity")(function* (input) {
        const request = yield* snapshotOAuth(exchangeInput, input);
        const saved = request.configuration;

        const entry = installed.find(
          ({ provider }) =>
            provider.provider === saved.provider &&
            provider.configurationGeneration === saved.configurationGeneration,
        );

        if (entry === undefined) return yield* unavailable();
        const provider = entry.provider;

        const callback = provider.callbacks.find(
          (candidate) => candidate.callbackId === saved.callbackId,
        );

        const responseIssuerMode = persistedResponseIssuerMode(
          provider.responseIssuerMode,
          entry.metadata.authorization_response_iss_parameter_supported,
        );

        if (
          provider.protocol !== saved.protocol ||
          provider.issuer !== saved.issuer ||
          responseIssuerMode !== saved.responseIssuerMode ||
          callback?.redirectUri !== saved.redirectUri
        )
          return yield* unavailable();
        if (
          (provider.protocol === "oidc") !== (request.secrets.oidcNonce !== undefined) ||
          provider.pkceS256 !== (request.secrets.pkceVerifier !== undefined) ||
          Redacted.value(request.response.state) !== Redacted.value(request.secrets.state) ||
          (responseIssuerMode === "required"
            ? request.response.issuer !== provider.issuer
            : request.response.issuer !== undefined)
        )
          return yield* rejected();
        const startedAt = DateTime.toEpochMillis(request.verificationStartedAt);

        if (startedAt < 0 || startedAt > DateTime.toEpochMillis(yield* DateTime.now))
          return yield* rejected();

        const receipt = yield* entry.client
          .codeGrant({
            code: request.response.code,
            redirectUri: saved.redirectUri,
            ...(request.secrets.pkceVerifier === undefined
              ? {}
              : { pkceVerifier: request.secrets.pkceVerifier }),
            ...(provider.tokenParameters === undefined
              ? {}
              : { parameters: provider.tokenParameters }),
          })
          .pipe(Effect.mapError(unavailable));

        const grant = yield* tokens(
          receipt,
          provider.protocol === "oauth" ? provider[tokenCompatibility] : undefined,
          {
            scopes: provider.scopes,
            refreshRequired: false,
            operation: "authorization_code",
          },
        );

        if (provider.protocol === "oidc") {
          if (entry.verifier === undefined || grant.idToken === undefined)
            return yield* unavailable();

          const verified = yield* entry.verifier
            .verify(grant.idToken, {
              verificationStartedAt: request.verificationStartedAt,
              nonce: request.secrets.oidcNonce!,
              ...(provider.maxAgeSeconds === undefined
                ? {}
                : { maxAgeSeconds: provider.maxAgeSeconds }),
              accessToken: grant.accessToken,
              code: request.response.code,
            })
            .pipe(
              Effect.mapError((error) =>
                error._tag === "OAuthRejected" ? rejected() : unavailable(),
              ),
            );

          const claims =
            provider.userInfo === "merge"
              ? yield* Effect.gen(function* () {
                  const userInfo = yield* entry.client
                    .fetchProfile(grant.accessToken)
                    .pipe(Effect.mapError(unavailable));

                  const subject = yield* Schema.decodeUnknownEffect(userInfoSubject)(userInfo).pipe(
                    Effect.mapError(rejected),
                  );

                  if (subject.sub !== verified.subject) return yield* rejected();

                  return { ...userInfo, ...Redacted.value(verified.claims) };
                })
              : Redacted.value(verified.claims);

          const profile = yield* decodeOidcProfile(claims, provider.profileSchema);

          return yield* snapshotOAuth(OAuthVerifiedExternalIdentity, {
            identity: {
              provider: provider.provider,
              issuer: provider.issuer,
              subject: verified.subject,
            },
            ...(profile === undefined ? {} : { profile }),
            ...(verified.upstreamAuthenticatedAt === undefined
              ? {}
              : { upstreamAuthenticatedAt: verified.upstreamAuthenticatedAt }),
          });
        }

        const body = yield* entry.client
          .fetchProfile(grant.accessToken)
          .pipe(Effect.mapError(unavailable));

        if (provider.protocol !== "oauth") return yield* unavailable();

        const decoded = yield* Effect.suspend(() =>
          provider.identitySource.decodeIdentity(body),
        ).pipe(
          Effect.provideContext(context),
          Effect.catchCause(
            (cause): Effect.Effect<never, OAuthProtocolRejected | OAuthUnavailable> => {
              if (Cause.hasInterrupts(cause))
                return reportAuthFailure("oauth-identity", cause).pipe(
                  Effect.andThen(Effect.interrupt),
                );
              if (
                cause.reasons.length === 1 &&
                cause.reasons[0]?._tag === "Fail" &&
                Schema.is(OAuthProtocolRejected)(cause.reasons[0].error)
              )
                return Effect.fail(rejected());

              return reportAuthFailure("oauth-identity", cause).pipe(
                Effect.andThen(Effect.fail(unavailable())),
              );
            },
          ),
        );

        const enriched =
          entry.enrichIdentity === undefined
            ? decoded
            : yield* entry.enrichIdentity(decoded, grant.accessToken);

        const identity = yield* Schema.decodeEffect(plainIdentitySchema)(enriched).pipe(
          Effect.mapError(rejected),
        );

        return yield* snapshotOAuth(OAuthVerifiedExternalIdentity, {
          identity: {
            provider: provider.provider,
            issuer: provider.issuer,
            subject: identity.subject,
          },
          ...(identity.profile === undefined ? {} : { profile: identity.profile }),
        });
      });

    return OAuthProtocol.of({
      prepareAuthorization: (input) => run(unavailableOnDefect(prepareAuthorization(input))),
      exchangeVerifiedIdentity: (input) =>
        run(
          unavailableOnDefect(exchangeVerifiedIdentity(input)).pipe(
            Effect.timeoutOrElse({
              duration: timeoutSeconds * 1000,
              orElse: () => Effect.fail(unavailable()),
            }),
          ),
        ).pipe(
          Effect.tapError((error) =>
            reportAuthDiagnostic(
              "oauth-exchange",
              error._tag === "OAuthProtocolRejected" ? "rejected" : "unavailable",
            ),
          ),
        ),
    });
  },
  unavailableOnDefect,
);
