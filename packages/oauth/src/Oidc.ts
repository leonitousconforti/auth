import * as Jwk from "@yielded/jose/Jwk";
import * as Jwks from "@yielded/jose/Jwks";
import type * as Jws from "@yielded/jose/Jws";
import * as Jwt from "@yielded/jose/Jwt";
import {
  Clock,
  Context,
  Crypto,
  DateTime,
  Effect,
  Layer,
  Redacted,
  Schema,
  type Scope,
} from "effect";
import { Base64Url } from "effect/encoding";
import { HttpClient, HttpClientRequest } from "effect/http";

import { ConfigurationError, Rejected, Unavailable } from "./Errors";
import * as Ownership from "./internal/ownership";
import * as Transport from "./internal/transport";
import * as V from "./internal/validation";
import { JsonObject, Metadata, type RequestOptions } from "./OAuth";

export const IdTokenAlgorithm = Schema.Literals(["RS256", "PS256", "ES256", "EdDSA", "HS256"]);
export type IdTokenAlgorithm = typeof IdTokenAlgorithm.Type;

export const defaultIdTokenAlgorithms: readonly IdTokenAlgorithm[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
];

const idTokenAlgorithms: readonly IdTokenAlgorithm[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
  "HS256",
];

export interface DiscoverOptions extends RequestOptions {
  /** Fetch this document instead of issuer + `/.well-known/openid-configuration`.
   * The document issuer must still equal the trusted issuer identifier. */
  readonly metadataUrl?: string;
}

export interface VerifierOptions extends RequestOptions {
  readonly metadata: Metadata;
  readonly clientId: string;
  /** Algorithms this verifier will accept. Discovery must advertise at least one.
   * Defaults to RS256, PS256, ES256 and EdDSA. HS256 is accepted only when
   * requested here and a client secret is supplied. */
  readonly algorithms?: ReadonlyArray<IdTokenAlgorithm>;
  /** Require advertised S256 PKCE. Defaults to true. Set false only for issuers
   * that cannot complete authorization-code + PKCE. */
  readonly pkceS256?: boolean;
  /** Channel or client secret used as the HS256 HMAC key. Required when the
   * advertised algorithm set is HS256. */
  readonly clientSecret?: Redacted.Redacted<string>;
}

export interface VerificationInput {
  readonly verificationStartedAt: DateTime.Utc;
  readonly nonce: Redacted.Redacted<string>;
  readonly maxAgeSeconds?: number;
  readonly accessToken?: Redacted.Redacted<string>;
  readonly code?: Redacted.Redacted<string>;
  /** Refresh continuation: same subject, optional nonce must match, auth_time cannot change. */
  readonly previous?: { readonly subject: string; readonly authTime?: number };
}

export interface Verified {
  readonly claims: Redacted.Redacted<JsonObject>;
  readonly subject: string;
  readonly authTime?: number;
  readonly upstreamAuthenticatedAt?: DateTime.Utc;
}

type VerificationRequirements =
  | Exclude<Effect.Services<ReturnType<typeof Jws.verifyWithKeySet>>, Jwks.Jwks>
  | Jws.Requirements
  | Crypto.Crypto;

export interface Verifier {
  readonly verify: (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ) => Effect.Effect<Verified, Rejected | Unavailable, VerificationRequirements>;
}

const Configuration = Schema.Struct({
  metadata: Metadata,
  clientId: V.text(1024),
  ...V.RequestOptions.fields,
  algorithms: Schema.optionalKey(
    Schema.Array(IdTokenAlgorithm).check(Schema.isMinLength(1), Schema.isMaxLength(5)),
  ),
  pkceS256: Schema.optionalKey(Schema.Boolean),
  clientSecret: Schema.optionalKey(V.secret(4096)),
});

const VerifyInput = Schema.Struct({
  verificationStartedAt: Schema.DateTimeUtc,
  nonce: V.secret(256),
  maxAgeSeconds: Schema.optional(V.integer(0, 86400)),
  accessToken: Schema.optional(V.secret(16384)),
  code: Schema.optional(V.secret(16384)),
  previous: Schema.optional(
    Schema.Struct({ subject: V.text(1024), authTime: Schema.optional(V.NumericDate) }),
  ),
});

const IdClaims = Schema.Struct({
  iss: V.text(2048),
  sub: V.text(1024),
  aud: Schema.Union([
    V.text(1024),
    Schema.Array(V.text(1024)).check(Schema.isMinLength(1), Schema.isMaxLength(1)),
  ]),
  azp: Schema.optionalKey(V.text(1024)),
  exp: V.NumericDate,
  iat: V.NumericDate,
  nbf: Schema.optionalKey(V.NumericDate),
  auth_time: Schema.optionalKey(V.NumericDate),
  nonce: Schema.optionalKey(V.text(256)),
  // Leftmost half of the signing-algorithm hash, unpadded base64url: 22
  // characters for SHA-256 (RS256, PS256, ES256, HS256) and 43 for SHA-512 (Ed25519).
  at_hash: Schema.optionalKey(
    Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{21})?$/u)),
  ),
  c_hash: Schema.optionalKey(
    Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{21})?$/u)),
  ),
});

const tokenHash = (algorithm: string) =>
  algorithm === "EdDSA"
    ? { digest: "SHA-512" as const, octets: 32 }
    : algorithm === "RS256" ||
        algorithm === "PS256" ||
        algorithm === "ES256" ||
        algorithm === "HS256"
      ? { digest: "SHA-256" as const, octets: 16 }
      : undefined;

const DiscoverConfiguration = Schema.Struct({
  ...V.RequestOptions.fields,
  metadataUrl: Schema.optionalKey(V.Endpoint),
});

/** OIDC discovery uses the trusted issuer identifier, retaining its exact
 * spelling for claim comparison even if its network URL normalizes. */
export const discover = Effect.fnUntraced(function* (
  input: string,
  inputOptions: DiscoverOptions,
): Effect.fn.Return<Metadata, ConfigurationError | Unavailable, HttpClient.HttpClient> {
  const issuer = yield* V.configuration(V.Issuer, input, "issuer");

  const options = yield* V.configuration(DiscoverConfiguration, inputOptions);
  const url = new URL(options.metadataUrl ?? issuer);

  if (options.metadataUrl === undefined) {
    url.pathname = `${url.pathname.replace(/\/$/u, "")}/.well-known/openid-configuration`;
  }

  const http = yield* Transport.capture;

  const response = yield* Transport.request(
    http,
    HttpClientRequest.get(url.href).pipe(HttpClientRequest.acceptJson),
    options,
  );

  if (response.status !== 200) return yield* Unavailable.make({});
  const document = yield* Transport.json(response);
  const metadata = yield* V.configuration(Metadata, yield* V.reveal(document.body), "metadata");

  if (metadata.issuer !== issuer) return yield* ConfigurationError.make({ reason: "issuer" });

  return V.freeze(metadata);
});

const claimFailure = () => Rejected.make({ reason: "claims" });

/** Signed ID tokens using advertised RS256, PS256, ES256, EdDSA, or explicit
 * HS256. Asymmetric verification and the bounded JWKS cache belong to the
 * caller's Scope. HS256 uses the supplied client secret as the HMAC key and
 * does not install JWKS. Owner closure cancels and joins active verification,
 * returning Unavailable; caller interruption joins its operation without
 * closing the verifier. No process cache or automatic exchange retry is created. */
export const makeVerifier = Effect.fnUntraced(function* (
  input: VerifierOptions,
): Effect.fn.Return<
  Verifier,
  ConfigurationError | Unavailable,
  HttpClient.HttpClient | Scope.Scope
> {
  const options = yield* V.configuration(Configuration, input, "metadata");

  const metadata = V.freeze(options.metadata);

  const algorithms = idTokenAlgorithms.filter((algorithm) =>
    (options.algorithms ?? defaultIdTokenAlgorithms).includes(algorithm),
  );

  const advertised = algorithms.filter((algorithm) =>
    metadata.id_token_signing_alg_values_supported?.includes(algorithm),
  );

  const hmacOnly = advertised.length === 1 && advertised[0] === "HS256";

  if (
    advertised.length === 0 ||
    advertised.includes("HS256") !== hmacOnly ||
    !metadata.response_types_supported?.includes("code") ||
    ((options.pkceS256 ?? true) && !metadata.code_challenge_methods_supported?.includes("S256"))
  )
    return yield* ConfigurationError.make({ reason: "metadata" });
  if (hmacOnly && options.clientSecret === undefined)
    return yield* ConfigurationError.make({ reason: "authentication" });

  const jwksUri = metadata.jwks_uri;

  if (!hmacOnly && jwksUri === undefined)
    return yield* ConfigurationError.make({ reason: "metadata" });

  const hmacKey =
    hmacOnly && options.clientSecret !== undefined
      ? yield* Jwk.importSecret(
          Redacted.make({
            kty: "oct" as const,
            alg: "HS256" as const,
            k: Base64Url.encode(new TextEncoder().encode(yield* V.reveal(options.clientSecret))),
          }),
          "HS256",
        ).pipe(Effect.mapError(() => ConfigurationError.make({ reason: "authentication" })))
      : undefined;

  const keys =
    hmacOnly || jwksUri === undefined
      ? undefined
      : Context.get(
          yield* Layer.build(
            Jwks.layerRemote({
              url: jwksUri,
              timeoutMs: options.timeoutMs,
              maxResponseBytes: options.maxResponseBytes,
            }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, yield* Transport.capture))),
          ).pipe(Effect.mapError(() => Unavailable.make({}))),
          Jwks.Jwks,
        );

  const { use } = yield* Ownership.make;

  const verify = Effect.fnUntraced(function* (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ): Effect.fn.Return<Verified, Rejected | Unavailable, VerificationRequirements> {
    // Capture caller policy and secret values before key lookup or cryptography.
    const policy = yield* V.decode(VerifyInput, input);
    const start = DateTime.toEpochMillis(policy.verificationStartedAt);
    const expectedNonce = yield* V.reveal(policy.nonce);

    const accessToken =
      policy.accessToken === undefined ? undefined : yield* V.reveal(policy.accessToken);

    const code = policy.code === undefined ? undefined : yield* V.reveal(policy.code);

    // Jwt verifies the signature before any registered/application claim checks.
    // Unauthenticated malformed/key/signature failures must never burn a receipt.
    const jwtPolicy = {
      algorithms: advertised,
      issuer: metadata.issuer,
      audience: options.clientId,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"] as const,
      clockTolerance: 0,
    };

    const mapJwtError = (error: { readonly _tag: string }) =>
      error._tag === "JoseClaimValidationFailed" ? claimFailure() : Unavailable.make({});

    const verified =
      hmacKey !== undefined
        ? yield* Jwt.verify(JsonObject, token, hmacKey, jwtPolicy).pipe(
            Effect.mapError(mapJwtError),
          )
        : keys === undefined
          ? yield* Unavailable.make({})
          : yield* Jwt.verifyWithKeySet(JsonObject, token, jwtPolicy).pipe(
              Effect.provideService(Jwks.Jwks, keys),
              Effect.mapError(mapJwtError),
            );

    const claims = yield* V.decode(IdClaims, verified.claims).pipe(Effect.mapError(claimFailure));

    const now = (yield* Clock.currentTimeMillis) / 1000;

    if (
      start < 0 ||
      start > now * 1000 ||
      (claims.azp !== undefined && claims.azp !== options.clientId) ||
      claims.exp <= now ||
      claims.iat > now ||
      (claims.nbf !== undefined && claims.nbf > now) ||
      (claims.auth_time !== undefined && claims.auth_time > now)
    )
      return yield* claimFailure();
    if (policy.previous === undefined) {
      if (
        claims.nonce !== expectedNonce ||
        (policy.maxAgeSeconds !== undefined &&
          (claims.auth_time === undefined ||
            claims.auth_time + policy.maxAgeSeconds < Math.floor(now)))
      )
        return yield* claimFailure();
    } else if (
      claims.sub !== policy.previous.subject ||
      (claims.nonce !== undefined && claims.nonce !== expectedNonce) ||
      (claims.auth_time !== undefined && claims.auth_time !== policy.previous.authTime)
    )
      return yield* claimFailure();
    const hashProfile = tokenHash(verified.protectedHeader.alg);

    if (hashProfile === undefined) return yield* claimFailure();

    for (const [hash, secret] of [
      [claims.at_hash, accessToken],
      [claims.c_hash, code],
    ] as const) {
      if (hash === undefined) continue;
      if (secret === undefined) return yield* claimFailure();
      const crypto = yield* Crypto.Crypto;

      const digest = yield* crypto
        .digest(hashProfile.digest, new TextEncoder().encode(secret))
        .pipe(Effect.mapError(() => Unavailable.make({})));

      if (digest.length !== hashProfile.octets * 2) return yield* Unavailable.make({});
      if (hash !== Base64Url.encode(digest.subarray(0, hashProfile.octets)))
        return yield* claimFailure();
    }
    // Re-read time after optional digest I/O so expired tokens cannot escape.
    const finished = (yield* Clock.currentTimeMillis) / 1000;

    if (
      claims.exp <= finished ||
      (policy.previous === undefined &&
        policy.maxAgeSeconds !== undefined &&
        claims.auth_time !== undefined &&
        claims.auth_time + policy.maxAgeSeconds < Math.floor(finished))
    )
      return yield* claimFailure();

    return {
      claims: Redacted.make(V.freeze(verified.claims)),
      subject: claims.sub,
      ...(claims.auth_time === undefined
        ? {}
        : {
            authTime: claims.auth_time,
            upstreamAuthenticatedAt: DateTime.makeUnsafe(Math.min(start, claims.auth_time * 1000)),
          }),
    };
  }, use);

  return { verify };
});
